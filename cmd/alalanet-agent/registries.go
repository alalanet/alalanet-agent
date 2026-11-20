package main

// REPO-POL-NPMRC (ADR-0174 round 6). alalanet judges a package on the public registry (npm's, PyPI); the package
// manager may fetch it from another one that a config file names. An exception ("npm:@acme/cli is ours") must not
// cover such an install, so before an exception lets a hold go, the hook reads the settings that move the target's
// registry — its npm scope's, the default one, pip's and uv's index — and, when one points anywhere but the public
// registry, the hold gets a code no exception covers (unread:local). This only keeps an exception from applying: the
// server's verdict is never loosened, and an allow is not this check's (the server's allow of a package that comes from
// elsewhere is an older gap, not an exception's).
//
// What is read, with the tools' own docs (read 2026-11-15; ADR-0174 round 6 cites them):
//   - every directory from the workspace up to the filesystem's root: .npmrc (npm's project file, which pnpm, Yarn 1,
//     bun and deno also read), .yarnrc (Yarn 1), .yarnrc.yml (Yarn 2+, and the name YARN_RC_FILENAME gives),
//     pnpm-workspace.yaml (pnpm's registry and registries), bunfig.toml (bun's install.registry and install.scopes),
//     uv.toml and pyproject.toml's [tool.uv]; Yarn and uv walk up to the root, and npm's project root may be above
//     the git root, so every ancestor is read, not only the nearest;
//   - the site config of the Python prefixes the install may run in, where pip and uv look: pip.conf and pip.ini of
//     .venv (with pyvenv.cfg) in the workspace or a parent, of $VIRTUAL_ENV, $CONDA_PREFIX, $UV_PROJECT_ENVIRONMENT,
//     of the prefix a program path of the command line is in (.venv/bin/pip), and of pip and python on PATH;
//   - the user's files: ~/.npmrc (or NPM_CONFIG_USERCONFIG), ~/.yarnrc, ~/.yarnrc.yml, ~/.bunfig.toml, pnpm's rc,
//     auth.ini and config.yaml, pip's and uv's user files — the agent can write the home folder as easily as the
//     workspace (ADR-0174 round 3), and the tool reads them all the same;
//   - the system's: npm's global and built-in npmrc (and Yarn 1's yarnrc) under the prefix of node on PATH or
//     $PREFIX, /etc/pip.conf and its XDG and macOS places, /etc/uv/uv.toml;
//   - the environment the hook runs in: npm_config_*, pnpm_config_*, YARN_*, BUN_CONFIG_*, PIP_* and UV_* settings of
//     a registry, an index, a config file, offline mode. The agent's shell may not have this environment: what its
//     startup files and the line itself set is read too (registries_line.go, round 7).
//
// Round 7 (registries_line.go, registries_lock.go): what moves the source beyond the registry settings — the line
// changes directory, sources a file, names a requirements file, goes offline or moves the cache; the shell's startup
// files; manifest overrides, lockfiles, code the package manager runs (yarnPath, plugins, .pnpmfile), bun's .env.
//
// Every file is read by readRegular: a FIFO, a device, a link, a file too large or one that cannot be read counts as a
// moved registry, and so does a file that does not parse, a value or key by a variable, or a setting this reader cannot
// place. Settings are taken from every file, whatever the tools' precedence: a public registry in one file does not
// undo a moved one in another — stricter than the tools, never looser. Values are never shown: an address may carry a
// token.

import (
	"errors"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"syscall"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"

	"github.com/alalanet/alalanet-agent/internal/installread"
)

// maxRegistryConfig bounds a package manager's config file; a larger one is not read and counts as moved.
const maxRegistryConfig = 1 << 20

// regCheck is one reading of the registry settings for an install's targets.
type regCheck struct {
	pf     *policyFiles
	home   string
	env    [][2]string     // the hook's environment, as given
	npm    bool            // an npm target (npm, pnpm, Yarn, bun, deno install them)
	scopes map[string]bool // the npm targets' scopes, in lower case ("@acme")
	// npmNames: the npm targets' names, in lower case ("@acme/cli")
	npmNames map[string]bool
	pypi     bool // a PyPI target (pip, uv, pipx)
	// goTargets: the line's go: targets (ECO-1 Go, round 3): the user's Go settings are judged for them (goSettings)
	goTargets []string
	names     map[string]bool // the PyPI targets' normalised names
	yarnRC    []string        // the names Yarn 2+ reads its rc file by (.yarnrc.yml, or YARN_RC_FILENAME's)
	// projectEnv: UV_PROJECT_ENVIRONMENT's values (a relative one is the project's folder, read in every one up)
	projectEnv []string
	// progs: the programs the line runs (installread.Commands); followLinks: the user's own files are being read, which
	// may be links (readFollow)
	progs       map[string]bool
	pnpmExec    bool // the line runs pnpm exec (pn exec too): a workspace's shellMode runs its words in a shell (round 43)
	followLinks bool
	// ca, proxy: where a certificate authority of one's own, and a proxy, were set: together they let the proxy read
	// and change what the registry sends (round 9, R4); budget: the bytes this check may still read (maxReadBudget)
	ca, proxy string
	budget    int64
	cwd       string
	seen      map[string]bool
	// enumerated: the folders whose files the startup list takes all of (conf.d, functions); autoDirs: those whose
	// files are pinned on first sight and may go (Codex's shell snapshots) — both set by startupFiles (round 14)
	enumerated, autoDirs map[string]bool
	inStartup            bool   // a startup file's values are being judged (usersOwn)
	why                  string // the first setting that moves a registry, by its file or variable and key, never its value
}

// registryMoved says why the targets' registry may not be the public one alalanet judged ("" when nothing moves it).
// cwd is the workspace (absolute, or "" for none); command is the line, for the program paths it names.
func registryMoved(pf *policyFiles, cwd, command string, targets []string) string {
	c := newRegCheck(pf, cwd)
	for _, t := range targets {
		eco, rest, _ := strings.Cut(t, ":")
		switch eco {
		case "npm":
			c.npm = true
			name, _ := descName(rest)
			c.npmNames[strings.ToLower(name)] = true
			if scope, _, ok := strings.Cut(rest, "/"); ok && strings.HasPrefix(scope, "@") {
				c.scopes[strings.ToLower(scope)] = true
			}
		case "pypi":
			c.pypi = true
			c.names[pypiNormal(rest)] = true
		case "go":
			c.goTargets = append(c.goTargets, t)
		}
	}
	c.line(command)
	c.fromEnv()
	if len(c.goTargets) > 0 {
		c.goSettings()
	}
	if state := c.startupFiles(true); c.why == "" {
		c.pinCheck(state) // round 13: the startup files as pinned (startpin.go)
	}
	ups := ancestors(cwd)
	c.projectEnvFiles(ups)
	if c.npm {
		c.npmFiles(ups)
		c.npmProjects(ups)
	}
	if c.pypi {
		c.pypiFiles(cwd, ups, command)
		for _, d := range ups {
			c.uvLock(filepath.Join(d, "uv.lock"))
		}
	}
	if c.ca != "" && c.proxy != "" {
		c.moved(c.ca, "names a certificate authority of its own while a proxy carries the traffic ("+c.proxy+
			"), so the proxy can read and change what the registry sends")
	}
	return c.why
}

// goUserNames: the Go settings of the user's own that move where the go command fetches a module or whether it checks
// it, or run code (installread's names; HOME and CC are the user's own machine and not judged here).
var goUserNames = []string{"GOPROXY", "GOSUMDB", "GONOSUMDB", "GOPRIVATE", "GONOPROXY", "GOINSECURE", "GOFLAGS", "GOAUTH", "GOTOOLCHAIN"}

// goUser reads the user's Go settings: the hook's environment, then the go env file (GOENV, else the user's config
// folder as os.UserConfigDir finds it: %AppData% on Windows, ~/Library/Application Support on macOS, $XDG_CONFIG_HOME
// or ~/.config elsewhere), whose values count only where the environment sets none (go help environment). Each pair
// with where it was read.
func (c *regCheck) goUser() (pairs [][2]string, where map[string]string) {
	where = map[string]string{}
	env := map[string]string{}
	for _, kv := range c.env {
		env[kv[0]] = kv[1]
	}
	for _, k := range goUserNames {
		if v, ok := env[k]; ok && v != "" {
			pairs, where[k] = append(pairs, [2]string{k, v}), hookEnvWhere+k
		}
	}
	file := env["GOENV"]
	if file == "" {
		dir := ""
		switch runtime.GOOS {
		case "windows":
			dir = env["AppData"]
			if dir == "" {
				dir = env["APPDATA"]
			}
		case "darwin", "ios":
			if c.home != "" {
				dir = filepath.Join(c.home, "Library", "Application Support")
			}
		default:
			if x := env["XDG_CONFIG_HOME"]; filepath.IsAbs(x) {
				dir = x
			} else if c.home != "" {
				dir = filepath.Join(c.home, ".config")
			}
		}
		if dir != "" {
			file = filepath.Join(dir, "go", "env")
		}
	}
	if file == "" || file == "off" {
		return pairs, where
	}
	for _, l := range strings.Split(string(c.read(file)), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		if !ok || strings.HasPrefix(k, "#") || !slices.Contains(goUserNames, k) || where[k] != "" {
			continue
		}
		pairs, where[k] = append(pairs, [2]string{k, v}), file+" "+k
	}
	return pairs, where
}

// goSettings judges the user's Go settings for the line's go: targets (ECO-1 Go, round 3, P3-5): what moves the module
// moves it as a registry setting does, and no exception covers it.
func (c *regCheck) goSettings() {
	pairs, where := c.goUser()
	for _, kv := range pairs {
		if reasons, _ := installread.GoSettings([][2]string{kv}, c.goTargets); len(reasons) > 0 {
			c.moved(where[kv[0]], "moves where the go command fetches the module or what it runs ("+reasons[0]+")")
			return
		}
	}
}

// goPrivateHere: whether the user's own Go settings fetch a go: target of the line from somewhere other than the public
// Go proxy (GOPRIVATE, GONOPROXY, GONOSUMDB, GOINSECURE matching it, GOPROXY or GOSUMDB of their own): then the line is
// not sent to alalanet, whose check would read the module's path from proxy.golang.org and sum.golang.org and sign it
// into the public log (ECO-1 Go, round 3, P3-5); "" or the setting that makes it so.
func goPrivateHere(pf *policyFiles, cwd string, targets []string) string {
	var gts []string
	for _, t := range targets {
		switch {
		case strings.HasPrefix(t, "go:"):
			gts = append(gts, t)
		case strings.ContainsAny(t, " \t"):
			// the nested launch of "claude|codex mcp add … -- go run …": its own targets (round 4, P3-7)
			nested, _, _, _ := installread.ParseLine(t)
			for _, n := range nested {
				if strings.HasPrefix(n, "go:") {
					gts = append(gts, n)
				}
			}
		}
	}
	if len(gts) == 0 || pf == nil {
		return ""
	}
	c := newRegCheck(pf, cwd)
	pairs, where := c.goUser()
	for _, kv := range pairs {
		if _, private := installread.GoSettings([][2]string{kv}, gts); private {
			return where[kv[0]]
		}
	}
	return ""
}

// newRegCheck is a reading for the workspace cwd, with the user's home folder and the hook's environment.
func newRegCheck(pf *policyFiles, cwd string) *regCheck {
	c := &regCheck{pf: pf, scopes: map[string]bool{}, npmNames: map[string]bool{}, names: map[string]bool{}, seen: map[string]bool{},
		yarnRC: []string{".yarnrc.yml"}, progs: map[string]bool{}, budget: maxReadBudget, cwd: cwd}
	if pf.home != nil {
		if h, err := pf.home(); err == nil && filepath.IsAbs(h) {
			c.home = h
		}
	}
	if pf.environ != nil {
		for _, kv := range pf.environ() {
			if k, v, ok := strings.Cut(kv, "="); ok && k != "" {
				c.env = append(c.env, [2]string{k, v})
			}
		}
	}
	return c
}

func (c *regCheck) moved(where, what string) {
	if c.why == "" {
		c.why = where + " " + what
	}
}

// ancestors: dir and every directory above it, to the root ("" gives none).
func ancestors(dir string) []string {
	if dir == "" || !filepath.IsAbs(dir) {
		return nil
	}
	var out []string
	for d, i := filepath.Clean(dir), 0; i < 256; i++ {
		out = append(out, d)
		up := filepath.Dir(d)
		if up == d {
			break
		}
		d = up
	}
	return out
}

// vals: the values of the environment variables named name, without case (Windows' names and npm's npm_config_ are
// read without case; two spellings of one name are both taken).
func (c *regCheck) vals(name string) []string {
	var out []string
	for _, kv := range c.env {
		if strings.EqualFold(kv[0], name) {
			out = append(out, kv[1])
		}
	}
	return out
}

// read gives a config file's bytes: nil when there is none. A file that is there but is not a regular file (a FIFO, a
// device, a link, a directory), is larger than a config file or cannot be read counts as moved.
func (c *regCheck) read(path string) []byte { return c.readMax(path, maxRegistryConfig) }

// maxReadBudget bounds the bytes one check reads in all (a variable for tests): past it, what is left is not known.
var maxReadBudget int64 = 64 << 20

// set: a setting's value names something (not empty, null or false).
func set(v string) bool {
	switch strings.ToLower(strings.TrimSpace(unquote(strings.TrimSpace(v)))) {
	case "", "null", "false":
		return false
	}
	return true
}

func (c *regCheck) caAt(where string) {
	if c.ca == "" {
		c.ca = where
	}
}

func (c *regCheck) proxyAt(where string) {
	if c.proxy == "" {
		c.proxy = where
	}
}

// readFollow is read for a file a link may name (the user's own files).
func (c *regCheck) readFollow(path string) []byte {
	c.followLinks = true
	defer func() { c.followLinks = false }()
	return c.read(path)
}

// readMax is read with another bound (a lockfile's).
func (c *regCheck) readMax(path string, max int64) []byte {
	if c.why != "" || !filepath.IsAbs(path) || c.seen[path] {
		return nil
	}
	c.seen[path] = true
	read := readRegular
	if c.followLinks {
		read = readFollow
	}
	b, err := read(path, max)
	switch {
	case err == nil:
		if c.budget -= int64(len(b)); c.budget < 0 {
			c.moved(path, "is past the bytes this reader reads in one call, so what it sets is not known")
			return nil
		}
		return b
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, syscall.ENOTDIR):
		return nil
	}
	c.moved(path, "could not be read ("+why(err)+"), so the registry it may set is not known")
	return nil
}

var npmPublic = map[string]bool{"registry.npmjs.org": true, "registry.yarnpkg.com": true}
var pypiPublic = map[string]bool{"pypi.org": true, "pypi.python.org": true}

// publicRegistry: v is the public registry of eco, over https at its usual address — npm's (or Yarn's alias of it) at
// its root, PyPI's simple index — with no user, port, query or fragment. Anything else is not: a variable (${HOST},
// %HOST%) is not a public host, or not a URL at all.
func publicRegistry(eco, v string) bool {
	u, err := url.Parse(unquote(strings.TrimSpace(v)))
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	host, path := strings.ToLower(u.Host), strings.TrimSuffix(u.Path, "/") // the host with its port, if one is written
	if eco == "npm" {
		return npmPublic[host] && path == ""
	}
	return pypiPublic[host] && path == "/simple"
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

var compacter = strings.NewReplacer("-", "", "_", "")

// compact: a key without case, dashes or underscores (index-url, INDEX_URL, indexUrl).
func compact(k string) string { return strings.ToLower(compacter.Replace(strings.TrimSpace(k))) }

var pypiSeparators = regexp.MustCompile(`[-_.]+`)

// pypiNormal: a target's PyPI name, PEP 503's normal form (acme-tools from pypi:Acme_Tools@2.0.1).
func pypiNormal(t string) string {
	end := strings.IndexFunc(t, func(r rune) bool {
		return !(r == '-' || r == '_' || r == '.' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z')
	})
	if end >= 0 {
		t = t[:end]
	}
	return pypiSeparators.ReplaceAllString(strings.ToLower(t), "-")
}

// --- npm, pnpm, Yarn, bun ---

// npmKey judges one setting of npm's, pnpm's, Yarn's or bun's, in any of their spellings (an npmrc key, a
// npm_config_ variable's rest, a Yarn 1 flag): the default registry, the registry of a target's scope, a config file
// it names (read in turn), a prefix (its global and built-in npmrc), Yarn's rc file name.
func (c *regCheck) npmKey(where, key, val string) { c.npmSetting(where, key, val, false) }

// npmSetting is npmKey; env says the setting is the environment's, where a cache or store folder alone does not count
// (CI sets npm_config_cache; a cache matters with offline mode, which counts by itself).
func (c *regCheck) npmSetting(where, key, val string, env bool) {
	k := strings.ToLower(strings.TrimSpace(unquote(strings.TrimSpace(key))))
	if strings.HasPrefix(k, "//") && (strings.HasSuffix(k, ":cafile") || strings.HasSuffix(k, ":ca")) && set(val) {
		c.caAt(where) // a registry's own certificate authority
	}
	if strings.HasPrefix(k, "//") {
		return // a registry's own settings (//host/:_authToken): where to send a token, not where to install from
	}
	if strings.Contains(k, "$") {
		c.moved(where, "sets a key by a variable (it may be a registry)")
		return
	}
	switch ck := compact(k); {
	case ck == "registry", ck == "npmregistryserver":
		if !publicRegistry("npm", val) {
			c.moved(where, "sets the default registry ("+key+")")
		}
	case strings.HasSuffix(k, ":registry"):
		if scope := strings.TrimSuffix(k, ":registry"); c.scopes[scope] && !publicRegistry("npm", val) {
			c.moved(where, "sets the registry of "+scope)
		}
	case ck == "registries", ck == "npmscopes":
		c.moved(where, "sets "+key+", which this reader does not place")
	case ck == "strictssl", ck == "enablestrictssl":
		if !truthy(unquote(strings.TrimSpace(val))) {
			c.moved(where, "turns TLS checking off ("+key+"), so anyone on the way can change what the registry sends")
		}
	case ck == "cafile", ck == "ca", ck == "ca[]", ck == "cafilepath", ck == "httpscafilepath":
		if set(val) {
			c.caAt(where)
		}
	case ck == "proxy", ck == "httpsproxy", ck == "httpproxy":
		if set(val) {
			c.proxyAt(where)
		}
	case ck == "offline", ck == "preferoffline", ck == "enableofflinemode":
		if truthy(unquote(strings.TrimSpace(val))) {
			c.moved(where, "turns offline mode on ("+key+"): packages come from a cache, not the registry")
		}
	case ck == "cache", ck == "cachedir", ck == "cachefolder", ck == "storedir", ck == "cachedirectory":
		if !env {
			c.moved(where, "moves the cache or store ("+key+")")
		}
	case ck == "yarnpath", ck == "plugins", ck == "pnpmfile", ck == "globalpnpmfile":
		c.moved(where, "names code the package manager runs ("+key+")")
	case npmPrograms[ck]:
		// round 14 (R8-7): the shell the dependencies' scripts run under, node's options for every node child
		// (--require), the git of git dependencies, node-gyp's, pnpm's npm; npm itself sets npm_config_node_gyp in
		// the environment of the scripts it runs, so from the hook's own environment that one alone is not counted
		if set(val) && !(ck == "nodegyp" && strings.HasPrefix(where, hookEnvWhere)) {
			c.moved(where, "names a program the package manager runs ("+key+")")
		}
	case strings.HasPrefix(ck, "nodemirror"):
		c.moved(where, "names where the package manager downloads node from ("+key+")")
	case ck == "cwd":
		c.moved(where, "changes the directory the package manager reads ("+key+")")
	case ck == "userconfig", ck == "globalconfig":
		c.follow(where, key, val, c.npmrc)
	case ck == "prefix":
		c.follow(where, key, val, c.npmPrefix)
	case ck == "rcfilename":
		if n := unquote(strings.TrimSpace(val)); n == "" || strings.ContainsAny(n, `/\$`) || n == "." || n == ".." {
			c.moved(where, "names Yarn's rc file in a way this reader does not follow")
		} else {
			c.yarnRC = append(c.yarnRC, n)
		}
	}
}

// follow reads the file (or prefix) a setting names: an absolute path, or one under the home folder (~/); a relative
// path or a variable counts as moved — whose directory it is relative to is the tool's, not this reader's.
func (c *regCheck) follow(where, key, val string, read func(string)) {
	v := unquote(strings.TrimSpace(val))
	switch {
	case v == "":
	case strings.ContainsAny(v, "$%"):
		c.moved(where, "names its "+key+" by a variable")
	case strings.HasPrefix(v, "~/") && c.home != "":
		read(filepath.Join(c.home, v[2:]))
	case filepath.IsAbs(v):
		read(filepath.Clean(v))
	default:
		c.moved(where, "names a relative "+key)
	}
}

// npmrc reads an npmrc (npm's ini; pnpm's rc and auth.ini have its form): key = value lines; comments (; or #)
// skipped, a quoted value unquoted, an unquoted one cut at ; or # as npm's ini reader does. A line without = is a key
// set to true; a [section] line is a key of no setting's name.
func (c *regCheck) npmrc(path string) {
	b := c.read(path)
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || line[0] == ';' || line[0] == '#' {
			continue
		}
		key, val, _ := strings.Cut(line, "=")
		val = strings.TrimSpace(val)
		if v := unquote(val); v != val {
			val = v
		} else if i := strings.IndexAny(val, ";#"); i >= 0 {
			val = strings.TrimSpace(val[:i])
		}
		c.npmKey(path, key, val)
	}
}

// yarnrc reads Yarn 1's .yarnrc: `key value` lines, either quoted; a key ends at a space (or a colon after a quoted
// key); --flag and --command.flag are settings of that name.
func (c *regCheck) yarnrc(path string) {
	b := c.read(path)
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || line[0] == '#' {
			continue
		}
		var key, val string
		if line[0] == '"' {
			end := strings.IndexByte(line[1:], '"')
			if end < 0 {
				c.moved(path, "has a line this reader does not place")
				return
			}
			key, val = line[1:end+1], line[end+2:]
		} else {
			key, val, _ = strings.Cut(strings.ReplaceAll(line, "\t", " "), " ")
		}
		key = strings.TrimSuffix(key, ":")
		val = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(val), ":"))
		if flag, ok := strings.CutPrefix(key, "--"); ok {
			if _, after, dotted := strings.Cut(flag, "."); dotted {
				flag = after // --install.registry: install's --registry
			}
			key = flag
		}
		c.npmKey(path, key, unquote(val))
	}
}

// yamlMap: a YAML file of one document whose top is a mapping (an empty file is none); anything else counts as moved.
func (c *regCheck) yamlMap(path string, b []byte) (map[string]any, bool) {
	if b == nil {
		return nil, false
	}
	var m map[string]any
	d := yaml.NewDecoder(strings.NewReader(string(b)))
	err := d.Decode(&m)
	if errors.Is(err, io.EOF) {
		return nil, false
	}
	var more any
	if err == nil {
		if err = d.Decode(&more); errors.Is(err, io.EOF) {
			err = nil
		} else if err == nil {
			err = errors.New("a second document")
		}
	}
	if err != nil {
		c.moved(path, "could not be parsed, so the registry it may set is not known")
		return nil, false
	}
	return m, true
}

func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}

// npmValue: a registry address in a structured file; anything but a public one, or not a string, is moved.
func (c *regCheck) npmValue(where, key string, v any) {
	if s, ok := v.(string); !ok || !publicRegistry("npm", s) {
		c.moved(where, "sets "+key+" to another registry")
	}
}

// scopeOf: a scope as Yarn and bun name it (acme or @acme), in npm's form.
func scopeOf(s string) string {
	return "@" + strings.ToLower(strings.TrimPrefix(strings.TrimSpace(s), "@"))
}

// yarnBerry reads a .yarnrc.yml: npmRegistryServer, and npmScopes.<scope>.npmRegistryServer of a target's scope.
func (c *regCheck) yarnBerry(path string) {
	m, ok := c.yamlMap(path, c.read(path))
	if !ok {
		return
	}
	for _, k := range sortedKeys(m) {
		switch compact(k) {
		case "enableofflinemode":
			if b, ok := m[k].(bool); !ok || b {
				c.moved(path, "turns offline mode on ("+k+")")
			}
		case "enablestrictssl":
			if b, ok := m[k].(bool); !ok || !b {
				c.moved(path, "turns TLS checking off ("+k+")")
			}
		case "httpsproxy", "httpproxy":
			c.proxyAt(path)
		case "cafilepath", "httpscafilepath":
			c.caAt(path)
		case "cachefolder", "yarnpath", "plugins":
			c.moved(path, "sets "+k+": a cache or code the package manager uses")
		case "npmregistryserver":
			c.npmValue(path, k, m[k])
		case "npmscopes":
			scopes, ok := m[k].(map[string]any)
			if !ok {
				c.moved(path, "sets "+k+" in a form this reader does not place")
				continue
			}
			for _, s := range sortedKeys(scopes) {
				if !c.scopes[scopeOf(s)] {
					continue
				}
				sm, ok := scopes[s].(map[string]any)
				if !ok {
					c.moved(path, "sets the scope "+scopeOf(s)+" in a form this reader does not place")
					continue
				}
				for _, sk := range sortedKeys(sm) {
					if compact(sk) == "npmregistryserver" {
						c.npmValue(path, "the registry of "+scopeOf(s), sm[sk])
					}
				}
			}
		}
	}
}

// pnpmYAML reads pnpm-workspace.yaml or pnpm's config.yaml: registry, @scope:registry, and registries in both shapes —
// scope (default, @, @acme) to URL, and URL to {scopes: [...]}; a URL entry without a list of scopes routes what this
// reader cannot tell, so its URL must be public.
func (c *regCheck) pnpmYAML(path string) {
	m, ok := c.yamlMap(path, c.read(path))
	if !ok {
		return
	}
	for _, k := range sortedKeys(m) {
		lk := strings.ToLower(k)
		switch ck := compact(k); {
		case ck == "registry":
			c.npmValue(path, k, m[k])
		case strings.HasSuffix(lk, ":registry"):
			if c.scopes[strings.TrimSuffix(lk, ":registry")] {
				c.npmValue(path, k, m[k])
			}
		case ck == "strictssl":
			if b, ok := m[k].(bool); !ok || !b {
				c.moved(path, "turns TLS checking off ("+k+")")
			}
		case ck == "httpsproxy", ck == "httpproxy", ck == "proxy":
			c.proxyAt(path)
		case ck == "cafile", ck == "ca":
			c.caAt(path)
		case ck == "shellmode":
			// pnpm exec runs its command words through a shell under shellMode: true in pnpm-workspace.yaml (pnpm 10.34.9
			// and 11.28.12 ran 'probe X;probe Y'; ADR-0159 round 43, P3-3), as an explicit -c does. pnpm read only the
			// camelCase key; shell-mode is read too, on the safe side.
			if b, ok := m[k].(bool); c.pnpmExec && (!ok || b) {
				c.moved(path, "makes pnpm exec run its command words in a shell ("+k+")")
			}
		case ck == "offline", ck == "preferoffline":
			if b, ok := m[k].(bool); !ok || b {
				c.moved(path, "turns offline mode on ("+k+")")
			}
		case ck == "storedir", ck == "cachedir", ck == "pnpmfile", ck == "globalpnpmfile":
			c.moved(path, "sets "+k+": a store or code the package manager uses")
		case npmPrograms[ck], strings.HasPrefix(ck, "nodemirror"):
			c.moved(path, "names a program the package manager runs or where it downloads node from ("+k+")")
		case ck == "overrides", ck == "catalog", ck == "catalogs":
			c.overrides(path, k, m[k])
		case ck == "patcheddependencies":
			c.patched(path, k, m[k])
		case compact(k) == "registries":
			rs, ok := m[k].(map[string]any)
			if !ok {
				c.moved(path, "sets "+k+" in a form this reader does not place")
				continue
			}
			for _, rk := range sortedKeys(rs) {
				switch rv := rs[rk].(type) {
				case string:
					l := strings.ToLower(rk)
					if l == "default" || l == "@" || c.scopes[l] {
						c.npmValue(path, "the registry of "+rk, rv)
					} else if strings.Contains(rk, "/") {
						c.moved(path, "sets registries in a form this reader does not place")
					}
				case map[string]any:
					list, ok := rv["scopes"].([]any)
					routes := !ok
					for _, s := range list {
						name, ok := s.(string)
						routes = routes || !ok || name == "@" || c.scopes[strings.ToLower(name)]
					}
					if routes && !publicRegistry("npm", rk) {
						c.moved(path, "routes a target's scope (or one it cannot tell) to another registry")
					}
				default:
					c.moved(path, "sets registries in a form this reader does not place")
				}
			}
		}
	}
}

// bunfig reads a bunfig.toml: install.registry (a URL, or a table with url) and install.scopes.<scope> of a target's.
func (c *regCheck) bunfig(path string) {
	b := c.read(path)
	if b == nil {
		return
	}
	var m map[string]any
	if _, err := toml.Decode(string(b), &m); err != nil {
		c.moved(path, "could not be parsed, so the registry it may set is not known")
		return
	}
	inst, ok := m["install"].(map[string]any)
	if !ok {
		if m["install"] != nil {
			c.moved(path, "sets install in a form this reader does not place")
		}
		return
	}
	value := func(key string, v any) {
		if t, ok := v.(map[string]any); ok {
			v = t["url"]
		}
		c.npmValue(path, key, v)
	}
	if r, ok := inst["registry"]; ok {
		value("install.registry", r)
	}
	if inst["cafile"] != nil || inst["ca"] != nil {
		c.caAt(path)
	}
	if _, ok := inst["cache"]; ok {
		c.moved(path, "sets install.cache: packages may come from a cache, not the registry")
	}
	if s, ok := inst["scopes"]; ok {
		scopes, ok := s.(map[string]any)
		if !ok {
			c.moved(path, "sets install.scopes in a form this reader does not place")
			return
		}
		for _, k := range sortedKeys(scopes) {
			if c.scopes[scopeOf(k)] {
				value("the registry of "+scopeOf(k), scopes[k])
			}
		}
	}
}

// npmPrefix reads npm's global and built-in npmrc under a prefix (unix and Windows layouts) and Yarn 1's global yarnrc.
func (c *regCheck) npmPrefix(p string) {
	c.npmrc(filepath.Join(p, "etc", "npmrc"))
	c.npmrc(filepath.Join(p, "lib", "node_modules", "npm", "npmrc"))
	c.npmrc(filepath.Join(p, "node_modules", "npm", "npmrc"))
	c.yarnrc(filepath.Join(p, "etc", "yarnrc"))
}

func (c *regCheck) npmFiles(ups []string) {
	if c.scopes["@jsr"] {
		c.moved("the scope @jsr", "is installed from npm.jsr.io by pnpm's default, not from npm's registry")
	}
	for _, d := range ups {
		c.npmrc(filepath.Join(d, ".npmrc"))
		c.yarnrc(filepath.Join(d, ".yarnrc"))
		for _, n := range c.yarnRC {
			c.yarnBerry(filepath.Join(d, n))
		}
		c.pnpmYAML(filepath.Join(d, "pnpm-workspace.yaml"))
		c.bunfig(filepath.Join(d, "bunfig.toml"))
		for _, n := range []string{".pnpmfile.cjs", ".pnpmfile.mjs", filepath.Join(".yarn", "cache")} {
			if _, err := os.Lstat(filepath.Join(d, n)); err == nil {
				c.moved(filepath.Join(d, n), "is there: code the package manager runs, or a cache it installs from")
			}
		}
	}
	// The user's own files: a link is followed (dotfile managers link them; readFollow checks the opened file).
	c.followLinks = true
	var pnpmDirs, xdg []string
	if h := c.home; h != "" {
		c.npmrc(filepath.Join(h, ".npmrc"))
		c.yarnrc(filepath.Join(h, ".yarnrc"))
		c.yarnBerry(filepath.Join(h, ".yarnrc.yml"))
		c.bunfig(filepath.Join(h, ".bunfig.toml"))
		pnpmDirs = append(pnpmDirs, filepath.Join(h, ".config", "pnpm"), filepath.Join(h, "Library", "Preferences", "pnpm"),
			filepath.Join(h, "AppData", "Local", "pnpm", "config"))
	}
	xdg = c.vals("XDG_CONFIG_HOME")
	for _, x := range xdg {
		c.npmrc(filepath.Join(x, ".npmrc"))
		c.bunfig(filepath.Join(x, ".bunfig.toml"))
		pnpmDirs = append(pnpmDirs, filepath.Join(x, "pnpm"))
	}
	for _, l := range c.vals("LOCALAPPDATA") {
		pnpmDirs = append(pnpmDirs, filepath.Join(l, "pnpm", "config"))
	}
	for _, d := range pnpmDirs {
		c.npmrc(filepath.Join(d, "rc"))
		c.npmrc(filepath.Join(d, "auth.ini"))
		c.pnpmYAML(filepath.Join(d, "config.yaml"))
	}
	c.followLinks = false
	if c.pf.lookPath != nil {
		for _, p := range c.prefixesOf("node") {
			c.npmPrefix(p)
		}
	}
}

// prefixesOf: the installation prefixes of a program on PATH — the folder above its bin and the folder it is in (npm
// on Windows), for its path and for the file it links to.
func (c *regCheck) prefixesOf(name string) []string {
	p, err := c.pf.lookPath(name)
	if err != nil || !filepath.IsAbs(p) {
		return nil
	}
	paths := []string{p}
	if r, err := filepath.EvalSymlinks(p); err == nil && r != p {
		paths = append(paths, r)
	}
	var out []string
	for _, p := range paths {
		out = append(out, filepath.Dir(filepath.Dir(p)), filepath.Dir(p))
	}
	return out
}

// --- the environment ---

// fromEnv judges the hook's environment: npm's, pnpm's, Yarn's and bun's settings by their prefixes, $PREFIX, and pip's
// and uv's index and config file variables.
func (c *regCheck) fromEnv() {
	for _, kv := range c.env {
		c.envVar(hookEnvWhere+kv[0], kv[0], kv[1])
	}
}

// hookEnvWhere starts the name of a setting of the hook's own environment.
const hookEnvWhere = "the environment variable "

// usersOwn: a setting of the user's own — the hook's environment or a (pinned) startup file — not a project's.
func (c *regCheck) usersOwn(where string) bool {
	return c.inStartup || strings.HasPrefix(where, hookEnvWhere)
}

// npmPrograms: the npm and pnpm settings that name a program the install runs, by compact name (round 14, R8-7):
// script-shell, node-options, git, node-gyp, shell, pnpm's npm-path.
var npmPrograms = map[string]bool{"scriptshell": true, "nodeoptions": true, "git": true, "nodegyp": true, "shell": true,
	"npmpath": true}

// npmEnvPrefixes: the prefixes under which npm, pnpm, Yarn and bun read a setting from the environment.
var npmEnvPrefixes = []string{"NPM_CONFIG_", "PNPM_CONFIG_", "YARN_", "BUN_CONFIG_"}

// envVar judges one environment variable, from the environment or from a file that sets one (a startup file, .env).
func (c *regCheck) envVar(where, k, v string) {
	up := strings.ToUpper(k)
	switch up { // TLS, for every tool (round 9, R4)
	case "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "PIP_PROXY":
		if set(v) {
			c.proxyAt(where)
		}
	case "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "PIP_CERT":
		if set(v) {
			c.caAt(where)
		}
	case "NODE_TLS_REJECT_UNAUTHORIZED":
		if c.npm && strings.TrimSpace(v) == "0" {
			c.moved(where, "turns TLS checking off for node, so anyone on the way can change what the registry sends")
		}
	case "PIP_TRUSTED_HOST", "UV_INSECURE_HOST":
		if c.pypi && strings.TrimSpace(v) != "" {
			c.moved(where, "trusts a host without TLS checking")
		}
	}
	if c.npm {
		for _, p := range npmEnvPrefixes {
			if strings.HasPrefix(up, p) {
				c.npmSetting(where, k[len(p):], v, true)
			}
		}
		if k == "PREFIX" || runtime.GOOS == "windows" && up == "PREFIX" { // npm reads process.env.PREFIX
			c.follow(where, "prefix", v, c.npmPrefix)
		}
		if up == "COREPACK_NPM_REGISTRY" && strings.TrimSpace(v) != "" && !publicRegistry("npm", v) {
			c.moved(where, "fetches the package manager itself from another registry")
		}
	}
	if c.pypi {
		switch up {
		case "PIP_INDEX_URL", "UV_INDEX_URL", "UV_DEFAULT_INDEX":
			if !publicRegistry("pypi", indexURL(v)) {
				c.moved(where, "sets another index")
			}
		case "PIP_EXTRA_INDEX_URL", "UV_EXTRA_INDEX_URL", "UV_INDEX":
			for _, f := range strings.Fields(v) {
				if !publicRegistry("pypi", indexURL(f)) {
					c.moved(where, "adds another index")
				}
			}
		case "PIP_FIND_LINKS", "UV_FIND_LINKS":
			if strings.TrimSpace(v) != "" {
				c.moved(where, "adds a place to find packages")
			}
		case "PIP_NO_INDEX", "UV_NO_INDEX":
			if truthy(v) {
				c.moved(where, "turns the index off")
			}
		case "PIP_CONFIG_FILE":
			if v != os.DevNull {
				c.follow(where, "config file", v, c.pipConf)
			}
		case "UV_CONFIG_FILE":
			c.follow(where, "config file", v, func(p string) { c.uvToml(p, false) })
		case "UV_OFFLINE":
			if truthy(v) {
				c.moved(where, "turns offline mode on")
			}
		case "PIP_REQUIREMENT", "PIP_CONSTRAINT", "PIP_BUILD_CONSTRAINT", "UV_CONSTRAINT", "UV_OVERRIDE", "UV_BUILD_CONSTRAINT":
			if strings.TrimSpace(v) != "" {
				c.moved(where, "names a requirements, constraints or overrides file")
			}
		case "VIRTUAL_ENV", "CONDA_PREFIX":
			if v = strings.TrimSpace(v); filepath.IsAbs(v) {
				c.site(filepath.Clean(v))
			} else if v != "" {
				c.moved(where, "names a relative environment")
			}
		case "UV_PYTHON":
			// round 15 (R9-2): uv runs the interpreter it names to learn what it is (uv 0.13.7: a script ran)
			// round 16 (R10-3): from a project's file; the user's own environment and startup files keep their choice
			// (the pin covers a change to a startup file)
			if pythonByPath(v) && !c.usersOwn(where) {
				c.moved(where, "names the interpreter uv runs by its path")
			}
		case "UV_PYTHON_SEARCH_PATH", "UV_ENV_FILE", "UV_ASTRAL_MIRROR_URL", "UV_PYTHON_INSTALL_MIRROR",
			"UV_PYPY_INSTALL_MIRROR", "UV_PYODIDE_INSTALL_MIRROR", "UV_GRAALPY_INSTALL_MIRROR", "UV_PYTHON_DOWNLOADS_JSON_URL",
			"UV_S3_ENDPOINT_URL", "UV_GCS_ENDPOINT_URL", "UV_AZURE_ENDPOINT_URL", "UV_TORCH_BACKEND":
			// where uv looks for or downloads Python, an env file it loads, a storage endpoint or PyTorch's index
			// (docs.astral.sh/uv/reference/environment, read 2026-11-15)
			if strings.TrimSpace(v) != "" {
				c.moved(where, "names where uv finds or downloads Python, an index of its own or an env file it loads")
			}
		case "UV_PYTHON_INSTALL_DIR", "UV_PYTHON_BIN_DIR", "UV_PYTHON_CACHE_DIR", "UV_TOOL_DIR", "UV_TOOL_BIN_DIR":
			// the folders uv keeps Pythons and tools in: a project's file that moves them counts; the user's own
			// environment choosing them does not (the defaults are the user's folders too)
			if strings.TrimSpace(v) != "" && !c.usersOwn(where) {
				c.moved(where, "moves the folders uv keeps Pythons or tools in")
			}
		case "PIP_KEYRING_PROVIDER", "UV_KEYRING_PROVIDER":
			if strings.EqualFold(strings.TrimSpace(v), "subprocess") {
				c.moved(where, "runs a keyring program for the index")
			}
		case "PIP_PYTHON":
			// pip runs again under that interpreter, which reads its own prefix's site config
			if v = strings.TrimSpace(v); filepath.IsAbs(v) {
				c.site(filepath.Dir(filepath.Dir(v)))
				if r, err := filepath.EvalSymlinks(v); err == nil {
					c.site(filepath.Dir(filepath.Dir(r)))
				}
			} else if v != "" {
				c.moved(where, "names the interpreter pip runs under, which this reader cannot place")
			}
		case "UV_PROJECT":
			if strings.TrimSpace(v) != "" {
				c.moved(where, "moves uv's project, whose config this reader does not read")
			}
		case "UV_PROJECT_ENVIRONMENT":
			c.projectEnv = append(c.projectEnv, strings.TrimSpace(v))
		}
	}
}

// indexURL: an index as uv's UV_INDEX names it (name=URL), or a URL; a URL with = in it is cut there too, which is
// never the public index.
func indexURL(v string) string {
	if _, u, ok := strings.Cut(v, "="); ok {
		return u
	}
	return v
}

// truthy: pip's reading of a boolean (an empty string is not false: pip's docs); anything but a false word is true.
func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "0", "false", "no", "off":
		return false
	}
	return true
}

// --- pip, uv ---

// pipSetting judges one pip setting (its long name in any spelling): the index, an extra index, find-links, no-index.
func (c *regCheck) pipSetting(where, key, val string) {
	switch compact(key) {
	case "indexurl":
		if !publicRegistry("pypi", val) {
			c.moved(where, "sets another index ("+key+")")
		}
	case "extraindexurl":
		for _, f := range strings.Fields(val) {
			if !publicRegistry("pypi", f) {
				c.moved(where, "adds another index ("+key+")")
			}
		}
	case "findlinks":
		if strings.TrimSpace(val) != "" {
			c.moved(where, "adds a place to find packages ("+key+")")
		}
	case "noindex":
		if truthy(val) {
			c.moved(where, "turns the index off ("+key+")")
		}
	case "trustedhost":
		if strings.TrimSpace(val) != "" {
			c.moved(where, "trusts a host without TLS checking ("+key+")")
		}
	case "proxy":
		if set(val) {
			c.proxyAt(where)
		}
	case "cert":
		if set(val) {
			c.caAt(where)
		}
	case "requirement", "constraint", "buildconstraint":
		c.moved(where, "names a requirements or constraints file ("+key+")")
	case "python":
		// round 14 (R8-7): pip runs again under that interpreter (pip 26.3: python = <program> ran it)
		if set(val) {
			c.moved(where, "names the Python pip runs under ("+key+")")
		}
	case "keyringprovider":
		if strings.EqualFold(strings.TrimSpace(unquote(strings.TrimSpace(val))), "subprocess") {
			c.moved(where, "runs a keyring program for the index ("+key+")")
		}
	case "cachedir":
		c.moved(where, "moves the cache ("+key+")")
	}
}

// pipConf reads a pip.conf or pip.ini (Python's configparser): every section (pip applies [global] and the command's
// own), = or : between key and value, an indented line continues the value of the key before it (across a section
// line too: stricter than configparser, never looser).
func (c *regCheck) pipConf(path string) {
	b := c.read(path)
	key := ""
	for _, raw := range strings.Split(string(b), "\n") {
		raw = strings.TrimSuffix(raw, "\r")
		line := strings.TrimSpace(raw)
		switch {
		case line == "" || line[0] == '#' || line[0] == ';':
			continue
		case line[0] == '[':
			continue
		case raw[0] == ' ' || raw[0] == '\t':
			if key != "" {
				c.pipSetting(path, key, line)
			}
			continue
		}
		i := strings.IndexAny(line, "=:")
		if i < 0 {
			key = line
			c.pipSetting(path, key, "")
			continue
		}
		key = strings.TrimSpace(line[:i])
		c.pipSetting(path, key, strings.TrimSpace(line[i+1:]))
	}
}

// pythonByPath: a Python request that is a path (a separator, or a relative name such as .venv), which uv runs to
// learn what it is ("3.12", "cpython@3.12" and a name looked up on PATH are not).
func pythonByPath(v string) bool {
	v = strings.TrimSpace(unquote(strings.TrimSpace(v)))
	return strings.ContainsAny(v, `/\`) || strings.HasPrefix(v, ".")
}

// pythonVersion reads a .python-version (or .python-versions) file uv reads in the project's folder or one above it,
// and the user's (round 15, R9-2): a line that names an interpreter by its path counts as moved.
func (c *regCheck) pythonVersion(path string) {
	b := c.read(path)
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		if pythonByPath(line) {
			c.moved(path, "names the interpreter uv runs by its path")
			return
		}
	}
}

// strings of a TOML value: a string, or each string of an array; anything else is ok == false.
func tomlStrings(v any) (out []string, ok bool) {
	switch x := v.(type) {
	case string:
		return []string{x}, true
	case []any:
		for _, e := range x {
			s, ok := e.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}

// uvTable judges one table of uv's settings (the top of uv.toml or [tool.uv], or its [pip]).
func (c *regCheck) uvTable(path string, t map[string]any) {
	for _, k := range sortedKeys(t) {
		v := t[k]
		switch ck := compact(k); ck {
		case "indexurl", "extraindexurl", "findlinks":
			ss, ok := tomlStrings(v)
			if !ok {
				c.moved(path, "sets "+k+" in a form this reader does not place")
			}
			for _, s := range ss {
				c.pipSetting(path, k, s)
			}
		case "noindex":
			if b, ok := v.(bool); !ok || b {
				c.moved(path, "turns the index off ("+k+")")
			}
		case "offline":
			if b, ok := v.(bool); !ok || b {
				c.moved(path, "turns offline mode on ("+k+")")
			}
		case "cachedir":
			c.moved(path, "moves the cache ("+k+")")
		case "keyringprovider":
			if s, ok := v.(string); !ok || strings.EqualFold(s, "subprocess") {
				c.moved(path, "runs a keyring program for the index ("+k+")")
			}
		case "pythoninstallmirror", "pypyinstallmirror", "pythondownloadsjsonurl":
			c.moved(path, "names where uv downloads Python from ("+k+")")
		case "allowinsecurehost":
			if ss, ok := tomlStrings(v); !ok || len(ss) > 0 {
				c.moved(path, "trusts a host without TLS checking ("+k+")")
			}
		case "overridedependencies", "constraintdependencies", "buildconstraintdependencies":
			ss, ok := tomlStrings(v)
			if !ok {
				c.moved(path, "sets "+k+" in a form this reader does not place")
			}
			for _, s := range ss {
				if c.names[pypiNormal(s)] && strings.ContainsAny(s[len(pypiNormal(s)):], "@:/") {
					c.moved(path, "points a target elsewhere ("+k+")")
				}
			}
		case "index":
			list, ok := v.([]map[string]any) // [[index]] and an inline array of tables alike
			if !ok {
				c.moved(path, "sets "+k+" in a form this reader does not place")
			}
			for _, ix := range list {
				if s, ok := ix["url"].(string); !ok || !publicRegistry("pypi", s) {
					c.moved(path, "names another index ("+k+")")
				}
			}
		case "sources":
			srcs, ok := v.(map[string]any)
			if !ok {
				c.moved(path, "sets "+k+" in a form this reader does not place")
				continue
			}
			for _, name := range sortedKeys(srcs) {
				if c.names[pypiNormal(name)] {
					c.moved(path, "names where a target comes from ("+k+")")
				}
			}
		}
	}
}

// uvToml reads a uv.toml, or a pyproject.toml's [tool.uv] (none there is no setting).
func (c *regCheck) uvToml(path string, pyproject bool) {
	b := c.read(path)
	if b == nil {
		return
	}
	var m map[string]any
	if _, err := toml.Decode(string(b), &m); err != nil {
		c.moved(path, "could not be parsed, so the index it may set is not known")
		return
	}
	if pyproject {
		tool, _ := m["tool"].(map[string]any)
		uv, ok := tool["uv"]
		if !ok {
			return
		}
		if m, ok = uv.(map[string]any); !ok {
			c.moved(path, "sets [tool.uv] in a form this reader does not place")
			return
		}
	}
	c.uvTable(path, m)
	if p, ok := m["pip"]; ok {
		if pm, ok := p.(map[string]any); ok {
			c.uvTable(path, pm)
		} else {
			c.moved(path, "sets pip in a form this reader does not place")
		}
	}
}

// site reads the site config of a Python prefix (pip's "site" file: $VIRTUAL_ENV/pip.conf, pip.ini on Windows).
func (c *regCheck) site(prefix string) {
	c.pipConf(filepath.Join(prefix, "pip.conf"))
	c.pipConf(filepath.Join(prefix, "pip.ini"))
}

func isVenv(dir string) bool {
	_, err := os.Lstat(filepath.Join(dir, "pyvenv.cfg"))
	return err == nil
}

// commandWord splits a command line into words for the program paths in it.
var commandWord = regexp.MustCompile(`[^\s;&|()<>'"=` + "`" + `]+`)

func (c *regCheck) pypiFiles(cwd string, ups []string, command string) {
	// Where pip and uv look for an environment (docs.astral.sh/uv/pip/environments: VIRTUAL_ENV, CONDA_PREFIX, then
	// .venv in the directory or the nearest parent; a project's UV_PROJECT_ENVIRONMENT, relative to the project): the
	// variables are read by envVar, .venv and a relative UV_PROJECT_ENVIRONMENT in every directory up.
	for _, d := range ups {
		c.uvToml(filepath.Join(d, "uv.toml"), false)
		c.uvToml(filepath.Join(d, "pyproject.toml"), true)
		c.pythonVersion(filepath.Join(d, ".python-version"))
		c.pythonVersion(filepath.Join(d, ".python-versions"))
		if v := filepath.Join(d, ".venv"); isVenv(v) {
			c.site(v)
		}
		for _, e := range c.projectEnv {
			if e != "" && !filepath.IsAbs(e) {
				c.site(filepath.Join(d, e))
			}
		}
	}
	for _, e := range c.projectEnv {
		if filepath.IsAbs(e) {
			c.site(filepath.Clean(e))
		}
	}
	// A program the line runs by its path (.venv/bin/pip, /opt/py/bin/python -m pip): the prefix it is in — every word
	// of the line, at most maxPyNames*4 prefixes; past them the read is incomplete (round 4: the first 64 words were read
	// and the rest dropped unread)
	prefixes := map[string]bool{}
	for _, w := range commandWord.FindAllString(command, -1) {
		dir := filepath.Dir(w)
		if b := filepath.Base(dir); (b == "bin" || b == "Scripts") && strings.ContainsAny(w, `/\`) {
			if !filepath.IsAbs(dir) {
				if cwd == "" {
					continue
				}
				dir = filepath.Join(cwd, dir)
			}
			if p := filepath.Dir(dir); !prefixes[p] {
				if len(prefixes) >= maxPyNames*4 {
					c.moved("the line", "runs programs from more folders than this reader reads, so the pip configuration of the rest is not known")
					break
				}
				prefixes[p] = true
				c.site(p)
			}
		}
	}
	if c.pf.lookPath != nil {
		names, over := pyNames(command)
		for _, n := range names {
			for _, p := range c.prefixesOf(n) {
				c.site(p)
			}
		}
		if over {
			c.moved("the line", "names more Python launchers than this reader looks up, so the pip configuration of the rest is not known")
		}
	}
	var pips, uvs []string
	if h := c.home; h != "" {
		pips = append(pips, filepath.Join(h, ".config", "pip", "pip.conf"), filepath.Join(h, ".pip", "pip.conf"),
			filepath.Join(h, "Library", "Application Support", "pip", "pip.conf"), filepath.Join(h, "AppData", "Roaming", "pip", "pip.ini"),
			filepath.Join(h, "pip", "pip.ini"))
		uvs = append(uvs, filepath.Join(h, ".config", "uv", "uv.toml"), filepath.Join(h, "AppData", "Roaming", "uv", "uv.toml"))
		c.pythonVersion(filepath.Join(h, ".config", "uv", ".python-version")) // uv python pin --global
	}
	for _, x := range c.vals("XDG_CONFIG_HOME") {
		pips = append(pips, filepath.Join(x, "pip", "pip.conf"))
		uvs = append(uvs, filepath.Join(x, "uv", "uv.toml"))
	}
	for _, x := range c.vals("XDG_DATA_HOME") {
		pips = append(pips, filepath.Join(x, "pip", "pip.conf"))
	}
	for _, x := range c.vals("APPDATA") {
		pips = append(pips, filepath.Join(x, "pip", "pip.ini"))
		uvs = append(uvs, filepath.Join(x, "uv", "uv.toml"))
	}
	for _, x := range c.vals("HOME") {
		pips = append(pips, filepath.Join(x, "pip", "pip.ini")) // Windows' legacy %HOME%\pip\pip.ini
	}
	if c.pf.system {
		pips = append(pips, "/etc/pip.conf", "/etc/xdg/pip/pip.conf", "/Library/Application Support/pip/pip.conf", `C:\ProgramData\pip\pip.ini`)
		uvs = append(uvs, "/etc/uv/uv.toml", "/etc/xdg/uv/uv.toml", `C:\ProgramData\uv\uv.toml`)
		for _, v := range c.vals("XDG_CONFIG_DIRS") {
			for _, x := range filepath.SplitList(v) {
				pips = append(pips, filepath.Join(x, "pip", "pip.conf"))
				uvs = append(uvs, filepath.Join(x, "uv", "uv.toml"))
			}
		}
		for _, x := range c.vals("PROGRAMDATA") {
			pips = append(pips, filepath.Join(x, "pip", "pip.ini"))
			uvs = append(uvs, filepath.Join(x, "uv", "uv.toml"))
		}
	}
	c.followLinks = true // the user's and the system's files, which may be links
	for _, p := range pips {
		c.pipConf(p)
	}
	for _, p := range uvs {
		c.uvToml(p, false)
	}
	c.followLinks = false
}

// pyNames: the programs whose install prefix holds pip's configuration for a line — pip's and Python's default names,
// and each Python launcher or pip the line runs by its bare name (python3.12 -m pip, pip3.12, py; PIP-VERSIONED-1
// round 3), at most maxPyNames. The launchers that run pip (pip3.12, python3.12 -m pip) come before the others, and over
// is true when the line names more than the reader looks up (round 4, re-review P3: the rest was dropped unread).
func pyNames(command string) (names []string, over bool) {
	names = []string{"pip", "pip3", "python", "python3"}
	var runsPip, others []string
	for _, cm := range installread.Commands(command) {
		if !installread.PythonLauncher(cm.Prog) || slices.Contains(runsPip, cm.Prog) || len(cm.Words) > 0 && strings.ContainsAny(cm.Words[0], `/\`) {
			continue // a program run by its path is read by its prefix above
		}
		kind, mod, _ := installread.PythonRun(cm.Prog, cm.Words[min(1, len(cm.Words)):])
		if !installread.PythonInterp(cm.Prog) || kind == installread.PyModule && mod == "pip" {
			runsPip = append(runsPip, cm.Prog)
		}
	}
	for _, w := range commandWord.FindAllString(command, -1) {
		if n := installread.LaunchBase(w); !strings.ContainsAny(w, `/\`) && installread.PythonLauncher(n) && !slices.Contains(others, n) {
			others = append(others, n)
		}
	}
	for _, n := range append(runsPip, others...) {
		switch {
		case slices.Contains(names, n):
		case len(names) >= maxPyNames:
			over = true
		default:
			names = append(names, n)
		}
	}
	return names, over
}

// maxPyNames: how many program names pyNames gives for one line (each is looked up on PATH)
const maxPyNames = 16
