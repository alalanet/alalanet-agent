package main

// REPO-POL-NPMRC round 2 (ADR-0174 round 7, the review's P3s): a project's manifest and lockfile can point a target
// elsewhere though every registry setting is the public one — Yarn's resolutions and pnpm's (and npm's) overrides and
// catalogs to another package, a URL, a file or a link; a lockfile entry of a target resolved outside the public
// registry, which the package manager reuses. Each is a hold no exception covers. A lockfile larger than maxLockfile,
// or one that does not parse, counts as moved; bun.lockb, which this reader cannot read, too.

import (
	"bytes"
	"encoding/json"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/alalanet/alalanet-agent/internal/onejson"
)

// maxLockfile bounds a lockfile (a variable for tests).
var maxLockfile int64 = 32 << 20

// npmProjects reads the manifests and lockfiles of every directory up for the npm targets.
func (c *regCheck) npmProjects(ups []string) {
	for _, d := range ups {
		if b := c.read(filepath.Join(d, "package.json")); b != nil {
			c.manifest(filepath.Join(d, "package.json"), b)
		}
		for _, n := range []string{"package-lock.json", "npm-shrinkwrap.json"} {
			if b := c.readMax(filepath.Join(d, n), maxLockfile); b != nil {
				c.npmLock(filepath.Join(d, n), b)
			}
		}
		if b := c.readMax(filepath.Join(d, "yarn.lock"), maxLockfile); b != nil {
			c.yarnLock(filepath.Join(d, "yarn.lock"), b)
		}
		if b := c.readMax(filepath.Join(d, "pnpm-lock.yaml"), maxLockfile); b != nil {
			c.pnpmLock(filepath.Join(d, "pnpm-lock.yaml"), b)
		}
		if b := c.readMax(filepath.Join(d, "bun.lock"), maxLockfile); b != nil {
			c.bunLock(filepath.Join(d, "bun.lock"), b)
		}
		if b := c.readMax(filepath.Join(d, "bun.lockb"), maxLockfile); b != nil {
			c.moved(filepath.Join(d, "bun.lockb"), "is a binary lockfile this reader cannot read")
		}
	}
}

// npmTarget: a package name is one of the npm targets'.
func (c *regCheck) npmTarget(name string) bool { return c.npmNames[strings.ToLower(name)] }

// namesTarget: an override or resolution key names a target — the name alone, after a path (**/x, parent/x,
// parent>x), with a range or protocol after @.
func (c *regCheck) namesTarget(key string) bool {
	k := strings.ToLower(key)
	for n := range c.npmNames {
		for i := strings.Index(k, n); i >= 0; {
			end := i + len(n)
			before := i == 0 || strings.ContainsRune("/>*", rune(k[i-1]))
			after := end == len(k) || k[end] == '@'
			if before && after {
				return true
			}
			j := strings.Index(k[i+1:], n)
			if j < 0 {
				break
			}
			i += 1 + j
		}
	}
	return false
}

// plainRange: a version, range or tag (npm's grammar of repopolicy's npmVersion, with spaces for ranges like
// ">=1 <2"): the same package from the same registry.
var plainRange = regexp.MustCompile(`^[A-Za-z0-9.^~<>=*|x+ -]*$`)

// overrides judges an overrides, resolutions or catalog map: an entry that names a target and points it to anything
// but a plain range (npm:other@1, a URL, file:, link:, a git spec, $ref), or that is not a string, moves it; nested
// maps (npm's overrides) are read the same way.
func (c *regCheck) overrides(path, key string, v any) {
	m, ok := v.(map[string]any)
	if !ok {
		if v != nil {
			c.moved(path, "sets "+key+" in a form this reader does not place")
		}
		return
	}
	for _, k := range sortedKeys(m) {
		switch x := m[k].(type) {
		case string:
			if c.namesTarget(k) && !plainRange.MatchString(x) {
				c.moved(path, "points a target to another source ("+key+")")
			}
		case map[string]any:
			c.overrides(path, key, x)
		default:
			if c.namesTarget(k) {
				c.moved(path, "sets "+key+" of a target in a form this reader does not place")
			}
		}
	}
}

// manifest reads a package.json: resolutions (Yarn), overrides (npm), pnpm.overrides and pnpm.resolutions.
func (c *regCheck) manifest(path string, b []byte) {
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		c.moved(path, "could not be parsed, so what it points a target to is not known")
		return
	}
	c.overrides(path, "resolutions", m["resolutions"])
	c.overrides(path, "overrides", m["overrides"])
	c.patched(path, "patchedDependencies", m["patchedDependencies"]) // bun's
	if p, ok := m["pnpm"].(map[string]any); ok {
		c.overrides(path, "pnpm.overrides", p["overrides"])
		c.overrides(path, "pnpm.resolutions", p["resolutions"])
		c.patched(path, "pnpm.patchedDependencies", p["patchedDependencies"])
	}
	// corepack fetches the package manager packageManager names: a name@version, else what it runs is not known
	if pmv, ok := m["packageManager"]; ok {
		if s, ok := pmv.(string); !ok || !corepackSpec.MatchString(s) {
			c.moved(path, "names a package manager corepack fetches from elsewhere (packageManager)")
		}
	}
}

// corepackSpec: packageManager as corepack takes it from the public registry — a manager's name, @, a version, and an
// optional +hash (nodejs.org/api/corepack.html).
var corepackSpec = regexp.MustCompile(`^(npm|pnpm|yarn|bun)@[0-9][0-9A-Za-z.-]*(\+[a-z0-9]+\.[0-9a-f]+)?$`)

// patched: a patchedDependencies map (pnpm's, bun's) whose key names a target: the package manager changes the
// target's files during the install.
func (c *regCheck) patched(path, key string, v any) {
	m, ok := v.(map[string]any)
	if !ok {
		if v != nil {
			c.moved(path, "sets "+key+" in a form this reader does not place")
		}
		return
	}
	for k := range m {
		if c.namesTarget(k) {
			c.moved(path, "patches a target ("+key+")")
		}
	}
}

// registryTarball: url is the public registry's tarball of name at version:
// https://registry.npmjs.org/<name>/-/<basename>-<version>.tgz, the path the registry serves a package's tarball at —
// another package's tarball on the same host is not the target's (lockfile injection; lockfile-lint's
// --validate-package-names). The path must be exactly that one (round 9, R3): without a version no path is (the
// entry is not one this reader can check), and a dot segment, plain or escaped (%2e; u.Path is decoded), never is —
// Node's URL parser would remove it (/cli-0/../../evil-pkg/…).
func registryTarball(name, version, v string) bool {
	u, err := url.Parse(strings.TrimSpace(v))
	if err != nil || u.Scheme != "https" || u.User != nil || !npmPublic[strings.ToLower(u.Host)] {
		return false
	}
	name = strings.ToLower(name)
	base := name[strings.LastIndexByte(name, '/')+1:]
	return strings.ToLower(u.Path) == "/"+name+"/-/"+base+"-"+strings.ToLower(version)+".tgz"
}

// lockEntry is an entry of package-lock.json (packages, v2 and v3) or of its v1 dependencies tree.
type lockEntry struct {
	Name     string `json:"name"` // an alias's real package (v2, v3)
	Version  string `json:"version"`
	Resolved string `json:"resolved"`
	Link     bool   `json:"link"`
	// Dependencies: v1's tree of entries; in v2 and v3's packages, names to ranges (not entries, and not read)
	Dependencies map[string]json.RawMessage `json:"dependencies"`
}

// npmLock: an entry of a target (node_modules/<name> at any depth, or a v1 dependency) is a link or resolved
// outside the public registry; an entry without resolved is the configured registry's.
func (c *regCheck) npmLock(path string, b []byte) {
	var lock struct {
		Packages     map[string]lockEntry       `json:"packages"`
		Dependencies map[string]json.RawMessage `json:"dependencies"`
	}
	// As npm reads it, with JSON.parse (onejson.AsJSONParse): encoding/json read "resolved":"<a git URL>",
	// "re\u017folved":"<the registry's tarball>" as the registry's, and "link":true,"lin\u212a":false as no link.
	if err := onejson.AsJSONParse(b, &lock); err != nil {
		c.moved(path, "could not be parsed, so where it resolves a target is not known")
		return
	}
	// bad: a link, another package (an alias: name, or a v1 version npm:other@1), or a tarball that is not the
	// registry's own of the target
	bad := func(name string, e lockEntry) bool {
		return e.Link || e.Name != "" && !strings.EqualFold(e.Name, name) || strings.Contains(e.Version, ":") ||
			e.Resolved != "" && !registryTarball(name, e.Version, e.Resolved)
	}
	for k, e := range lock.Packages {
		name := k
		if i := strings.LastIndex(k, "node_modules/"); i >= 0 {
			name = k[i+len("node_modules/"):]
		}
		if c.npmTarget(name) && bad(name, e) {
			c.moved(path, "resolves a target outside the public registry")
		}
	}
	var walk func(map[string]json.RawMessage, int)
	walk = func(deps map[string]json.RawMessage, depth int) {
		for name, raw := range deps {
			var e lockEntry
			if onejson.AsJSONParse(raw, &e) != nil {
				continue // a range, not an entry
			}
			if c.npmTarget(name) && bad(name, e) {
				c.moved(path, "resolves a target outside the public registry")
			}
			if depth < 64 {
				walk(e.Dependencies, depth+1)
			}
		}
	}
	walk(lock.Dependencies, 0)
}

// descName: the package name of a descriptor or a pnpm key (name@range, @scope/name@npm:1, /name@1.0.0(peer@1)).
func descName(d string) (name, rest string) {
	d = strings.TrimPrefix(strings.TrimSpace(d), "/")
	i := strings.IndexByte(d[min(1, len(d)):], '@')
	if i < 0 {
		return d, ""
	}
	return d[:i+1], d[i+2:]
}

// yarnLock reads Yarn's lockfile, 1 or 2+: a block whose descriptors name a target must resolve on the public
// registry — Yarn 1's resolved URL on its host, Yarn 2+'s resolution "name@npm:<version>"; a block with neither (a
// file, a link, a patch, a URL) moves it.
func (c *regCheck) yarnLock(path string, b []byte) {
	in, ok := false, false
	target, version, resolved := "", "", "" // the block's; Yarn 1 does not care about the order of its keys
	end := func() {
		if resolved != "" {
			ok = registryTarball(target, version, resolved)
		}
		if in && !ok {
			c.moved(path, "resolves a target outside the public registry")
		}
		in, ok, target, version, resolved = false, false, "", "", ""
	}
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSuffix(raw, "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			end()
			for _, d := range strings.Split(strings.TrimSuffix(line, ":"), ",") {
				if name, _ := descName(unquote(strings.TrimSpace(d))); c.npmTarget(name) {
					in, target = true, name
				}
			}
			continue
		}
		if !in {
			continue
		}
		f := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(f, "version "), strings.HasPrefix(f, "version:"):
			version = unquote(strings.TrimSpace(strings.TrimLeft(strings.TrimPrefix(f, "version"), ": ")))
		case strings.HasPrefix(f, "resolved "):
			// judged at the block's end, with its version; #hash: a fragment, which the path does not hold
			resolved = unquote(strings.TrimSpace(strings.TrimPrefix(f, "resolved ")))
		case strings.HasPrefix(f, "resolution:"):
			name, rest := descName(unquote(strings.TrimSpace(strings.TrimPrefix(f, "resolution:"))))
			v, npm := strings.CutPrefix(rest, "npm:")
			ok = c.npmTarget(name) && npm && plainRange.MatchString(v)
		}
	}
	end()
}

// pnpmLock reads pnpm-lock.yaml: a packages or snapshots entry of a target with a tarball off the public registry, a
// git or directory resolution, or a version that is not a plain one; an importer's dependency on a target at a link,
// a file or a URL.
func (c *regCheck) pnpmLock(path string, b []byte) {
	m, ok := c.yamlMap(path, b)
	if !ok {
		return
	}
	for _, sec := range []string{"packages", "snapshots"} {
		pk, _ := m[sec].(map[string]any)
		for _, k := range sortedKeys(pk) {
			name, ver := pnpmKey(k)
			if !c.npmTarget(name) {
				continue
			}
			e, _ := pk[k].(map[string]any)
			res, _ := e["resolution"].(map[string]any)
			tarball, hasTarball := res["tarball"].(string)
			switch {
			case strings.Contains(ver, ":"):
				c.moved(path, "resolves a target outside the public registry")
			case hasTarball && !registryTarball(name, ver, tarball):
				c.moved(path, "resolves a target outside the public registry")
			case res["type"] != nil || res["directory"] != nil || res["repo"] != nil:
				c.moved(path, "resolves a target outside the public registry")
			}
		}
	}
	// The importers (v6 and v9), or a single project's dependencies at the top (v5 and v6): a target's version must be
	// a plain one — not link:, file:, a URL, or an alias's other package (evil@1.0.0, /evil@1.0.0).
	projects := []map[string]any{m}
	imps, _ := m["importers"].(map[string]any)
	for _, ik := range sortedKeys(imps) {
		if imp, ok := imps[ik].(map[string]any); ok {
			projects = append(projects, imp)
		}
	}
	for _, imp := range projects {
		for _, dk := range []string{"dependencies", "devDependencies", "optionalDependencies"} {
			deps, _ := imp[dk].(map[string]any)
			for _, name := range sortedKeys(deps) {
				if !c.npmTarget(name) {
					continue
				}
				v, _ := deps[name].(string)
				if e, ok := deps[name].(map[string]any); ok {
					v, _ = e["version"].(string)
				}
				if base := strings.FieldsFunc(v, func(r rune) bool { return r == '(' || r == '_' }); len(base) == 0 || !plainRange.MatchString(base[0]) {
					c.moved(path, "links a target from another source")
				}
			}
		}
	}
}

// pnpmKey: a packages or snapshots key's name and version: /name@1.0.0 and name@1.0.0(peer@1) (v6, v9), or
// /name/1.0.0_peer@1 (v5).
func pnpmKey(k string) (name, ver string) {
	k, _, _ = strings.Cut(k, "(")
	k = strings.TrimPrefix(k, "/")
	if i := strings.IndexByte(k[min(1, len(k)):], '@'); i >= 0 {
		return k[:i+1], k[i+2:]
	}
	if i := strings.LastIndexByte(k, '/'); i > 0 {
		ver, _, _ = strings.Cut(k[i+1:], "_")
		return k[:i], ver
	}
	return k, ""
}

// bunLock reads bun.lock (JSON with trailing commas): a packages entry of a target is ["name@version", "registry", …];
// a version that is not a plain one (github:, a URL, file:) or a registry that is not the public one moves it.
func (c *regCheck) bunLock(path string, b []byte) {
	var lock struct {
		Packages map[string][]json.RawMessage `json:"packages"`
	}
	if err := onejson.AsJSONParse(stripTrailingCommas(b), &lock); err != nil { // as bun reads it: exact names, the last
		c.moved(path, "could not be parsed, so where it resolves a target is not known")
		return
	}
	for k, e := range lock.Packages {
		want := c.bunTarget(k) // a top-level entry is its name, a nested one parent/name
		if want == "" {
			continue
		}
		var id, reg string
		if len(e) > 0 {
			_ = json.Unmarshal(e[0], &id)
		}
		if len(e) > 1 {
			_ = json.Unmarshal(e[1], &reg)
		}
		idName, ver := descName(id)
		if !strings.EqualFold(idName, want) || !plainRange.MatchString(ver) || ver == "" || reg != "" && !publicRegistry("npm", reg) {
			c.moved(path, "resolves a target outside the public registry")
		}
	}
}

// bunTarget: the target a bun.lock key names — itself, or as a nested parent/name — or "". The key is a dependency
// path of names joined with /, and a scoped name keeps its own slash: the name is the last segment, or the last two
// when the one before starts with @ (p/@x/b nests @x/b, @x/x is @x/x and not the target x). A suffix match picked b
// or @x/b in a map's order, and read @x/x as x (READER-REASON-ORDER-1, ADR-0159 round 48).
func (c *regCheck) bunTarget(k string) string {
	segs := strings.Split(strings.ToLower(k), "/")
	name := segs[len(segs)-1]
	if len(segs) > 1 && strings.HasPrefix(segs[len(segs)-2], "@") {
		name = segs[len(segs)-2] + "/" + name
	}
	if c.npmNames[name] {
		return name
	}
	return ""
}

// stripTrailingCommas removes the commas before } and ] outside strings.
func stripTrailingCommas(b []byte) []byte {
	var out bytes.Buffer
	inStr, esc := false, false
	for i := 0; i < len(b); i++ {
		ch := b[i]
		switch {
		case inStr:
			switch {
			case esc:
				esc = false
			case ch == '\\':
				esc = true
			case ch == '"':
				inStr = false
			}
		case ch == '"':
			inStr = true
		case ch == ',':
			j := i + 1
			for j < len(b) && (b[j] == ' ' || b[j] == '\t' || b[j] == '\n' || b[j] == '\r') {
				j++
			}
			if j < len(b) && (b[j] == '}' || b[j] == ']') {
				continue
			}
		}
		out.WriteByte(ch)
	}
	return out.Bytes()
}

// uvLock reads uv.lock: a package of a target whose source is not the public index ({ registry = PyPI }).
func (c *regCheck) uvLock(path string) {
	b := c.readMax(path, maxLockfile)
	if b == nil {
		return
	}
	var lock struct {
		Package []struct {
			Name   string         `toml:"name"`
			Source map[string]any `toml:"source"`
			Sdist  struct {
				URL string `toml:"url"`
			} `toml:"sdist"`
			Wheels []struct {
				URL string `toml:"url"`
			} `toml:"wheels"`
		} `toml:"package"`
	}
	if _, err := toml.Decode(string(b), &lock); err != nil {
		c.moved(path, "could not be parsed, so where it resolves a target is not known")
		return
	}
	for _, p := range lock.Package {
		if !c.names[pypiNormal(p.Name)] {
			continue
		}
		reg, ok := p.Source["registry"].(string)
		if len(p.Source) != 1 || !ok || !publicRegistry("pypi", reg) {
			c.moved(path, "resolves a target outside the public index")
		}
		// the files uv reuses from the lock are PyPI's own
		urls := []string{p.Sdist.URL}
		for _, w := range p.Wheels {
			urls = append(urls, w.URL)
		}
		for _, f := range urls {
			if f != "" && !pypiFile(f) {
				c.moved(path, "locks a target's file outside PyPI's file host")
			}
		}
	}
}

// pypiFile: a file URL on PyPI's file host over https.
func pypiFile(v string) bool {
	u, err := url.Parse(v)
	return err == nil && u.Scheme == "https" && u.User == nil && strings.EqualFold(u.Host, "files.pythonhosted.org")
}
