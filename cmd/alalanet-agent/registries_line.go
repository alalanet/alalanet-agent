package main

// REPO-POL-NPMRC (ADR-0174 rounds 7 and 8). The hook's working directory and environment are not the install's: the
// line can change directory, source a file, set a variable that moves every user config, name a requirements file, go
// offline, or pass an option this reader does not know. On the exception path each of these is a hold no exception
// covers. The line is judged on the simple commands ParseLine's own walk visits (installread.Commands: after
// whichSubst, wrappers and their options, env -S, sh -c, pwsh -Command, cmd /c, eval), so there is one walk, not two;
// and a package manager's command may carry only the options plainFlags names for it — an abbreviation, a grouped
// short option or any other option is a hold, which closes the spellings this reader does not know at once.
//
// The shell's startup files (and direnv's .envrc, mise's [env], bun's .env, Yarn's .env.yarn) are read for the
// variables envVar judges: an assignment of a value this reader can know is judged as the environment's; another value
// or a mention that is not an assignment counts as moved. This is a heuristic over shell text (ADR-0174 round 8 lists
// what it does not see).

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/alalanet/alalanet-agent/internal/installread"
)

// flagSet: the options a plain install may carry: bare ones, and ones that take a value (the next word, or =value).
type flagSet struct{ bare, valued map[string]bool }

func flags(bare, valued string) flagSet {
	set := func(s string) map[string]bool {
		m := map[string]bool{}
		for _, f := range strings.Fields(s) {
			m[f] = true
		}
		return m
	}
	return flagSet{set(bare), set(valued)}
}

// plainFlags: per package manager, the options of a plain install (npm's, pnpm's, Yarn's, bun's, pip's, uv's and
// pipx's own docs). Not here, so a hold: another directory (--prefix, -C, --dir, --cwd, --directory, --project), a
// config file, offline mode or a cache, a requirements or constraints file, a registry or index (the server's reader
// holds these already), workspaces that read their own config (pnpm -r, --filter), npx -c.
var plainFlags = func() map[string]flagSet {
	const npmBare = "-D --save-dev -E --save-exact -S --save -O --save-optional -P --save-prod --save-peer -B " +
		"--save-bundle --no-save -g --global --legacy-peer-deps --strict-peer-deps --no-audit --no-fund --ignore-scripts " +
		"--no-package-lock --package-lock-only --silent -s --quiet -q --verbose -d --force -f --dry-run --prefer-online " +
		"--foreground-scripts --no-optional --production --json -y --yes --no-progress --"
	npm := flags(npmBare, "-w --workspace --loglevel --omit --include --install-strategy --save-prefix --location")
	npx := flags(npmBare, "-p --package -w --workspace --loglevel")
	pnpm := flags("-D --save-dev -P --save-prod -O --save-optional -E --save-exact --save-peer -g --global -w "+
		"--workspace-root --ignore-scripts --frozen-lockfile --no-frozen-lockfile --prefer-frozen-lockfile --silent -s "+
		"--no-optional --prod --dev --fix-lockfile --lockfile-only --strict-peer-dependencies --save-catalog --",
		"--reporter --loglevel --save-catalog-name")
	yarn := flags("-D --dev -P --peer -O --optional -E --exact -T --tilde --ignore-scripts --frozen-lockfile --immutable "+
		"--silent -s --no-progress --", "--mode")
	bun := flags("-d -D --dev --development --optional --peer -E --exact -g --global --frozen-lockfile --no-save "+
		"--ignore-scripts --silent --verbose --no-progress --trust --production -p --force --bun --", "")
	pip := flags("-U --upgrade -q --quiet -v --verbose --user --no-deps --pre --force-reinstall -I --ignore-installed "+
		"--no-cache-dir --break-system-packages --no-warn-script-location --disable-pip-version-check --no-input "+
		"--require-hashes --no-build-isolation --",
		"--upgrade-strategy --root-user-action --python -C --config-settings --config-setting --progress-bar -t "+
			"--target --prefix --root -e --editable")
	uv := flags("-q --quiet -v --verbose --dev -U --upgrade --system --break-system-packages --no-sync --frozen --locked "+
		"--no-cache --native-tls --editable --",
		"--python -p --group --optional --extra --prerelease --resolution -C --config-setting --upgrade-package -P")
	uvx := flags("-q --quiet -v --verbose --", "--from --with --python -p")
	pipx := flags("--force -f --include-deps -q --quiet -v --verbose --global --", "--python --suffix --spec")
	deno := flags("-D --dev -g --global --", "")
	return map[string]flagSet{"npm": npm, "npx": npx, "pnpm": pnpm, "pnpx": pnpm, "yarn": yarn, "bun": bun, "bunx": bun,
		"pip": pip, "pip3": pip, "uv": uv, "uvx": uvx, "pipx": pipx, "deno": deno}
}()

// subFlags: the options of a subcommand that has its own (uv run: docs.astral.sh/uv/reference/cli/#uv-run; uv tool
// run is uvx), by "program subcommand".
var subFlags = map[string]flagSet{
	"uv run": flags("--isolated --no-project --all-extras --no-dev --frozen --locked --no-sync --script -m --module "+
		"--active --no-editable", "--with --with-editable --extra --group --only-group --python -p"),
	"uv tool": flags("", "--from --with --with-editable --python -p"),
}

// runDone: the words after a run tool's package (or uv run's command) are that program's own, not the package
// manager's options (npx: "all flags and options must be set prior to any positional arguments"; uvx, bunx, pnpx,
// pnpm dlx, yarn dlx, bun x, pipx run, uv tool run, uv run alike). verbs: the positional words read so far.
func runDone(prog string, verbs []string) bool {
	n, first := len(verbs), ""
	if n > 0 {
		first = verbs[0]
	}
	switch prog {
	case "npx", "uvx", "bunx", "pnpx":
		return n >= 1
	case "pnpm", "yarn":
		return first == "dlx" && n >= 2
	case "bun":
		return first == "x" && n >= 2
	case "pipx":
		return first == "run" && n >= 2
	case "uv":
		return first == "run" && n >= 2 || first == "tool" && n >= 3 && verbs[1] == "run"
	}
	return false
}

// movedVars: variables that move every user config or the project, whatever their value, when the line sets them.
var movedVars = map[string]bool{"HOME": true, "XDG_CONFIG_HOME": true, "XDG_DATA_HOME": true, "XDG_CONFIG_DIRS": true,
	"APPDATA": true, "LOCALAPPDATA": true, "USERPROFILE": true, "PROGRAMDATA": true, "ZDOTDIR": true} // UV_PROJECT: envVar

// line judges the simple commands ParseLine visits in the line.
func (c *regCheck) line(command string) {
	const where = "the command line"
	for _, cmd := range installread.Commands(command) {
		if c.why != "" {
			return
		}
		for _, a := range cmd.Assigns {
			c.inlineVar(a)
		}
		for _, x := range cmd.Wrappers {
			c.wrapperWord(x)
		}
		prog := cmd.Prog
		c.progs[prog] = true
		if prog == "pnpm" && slices.Contains(cmd.Words[1:], "exec") {
			c.pnpmExec = true // pnpm exec, pn exec (Prog is the canonical name)
		}
		switch {
		case prog == "":
		// a program named by a variable ($C) and a sourced file are ParseLine's other (B5): a hold already. A virtual
		// environment's activate script is harmless to ParseLine, but it is the agent's file like any other: it is read
		// as a startup file (round 9, R2), and its prefix's site config is read too (pypiFiles).
		case prog == "source" || prog == ".":
			if len(cmd.Words) > 1 {
				c.sourced(cmd.Words[1])
			}
		case prog == "cd" || prog == "pushd" || prog == "popd" || prog == "chdir":
			c.moved(where, "changes directory ("+prog+"), so the install reads another folder's config")
		case prog == "export" || prog == "declare" || prog == "typeset" || prog == "local" || prog == "readonly" ||
			prog == "set" || prog == "setx":
			for _, a := range cmd.Words[1:] {
				if !strings.HasPrefix(a, "-") && strings.Contains(a, "=") {
					c.inlineVar(a)
				}
			}
		default:
			if fs, ok := plainFlags[prog]; ok { // the programs ParseLine reads installs of
				c.managerWords(prog, fs, cmd.Words[1:])
			}
		}
	}
}

// sourced: a file the line sources is accepted only when it is a virtual environment's own activate script, byte for
// byte one of the templates this reader knows (activateTemplate); any other counts as moved (round 11). Rounds 9 and 10
// read it as shell, and each re-review found a form the reading trusted and a script could turn (PATH, SCRIPT_PATH, a
// function named like a helper): the bytes of a known template are trusted, the reading of a script is not.
func (c *regCheck) sourced(p string) {
	switch {
	case strings.ContainsAny(p, "$`"):
		c.moved("the command line", "sources a file named by a variable")
		return
	case strings.HasPrefix(p, "~"):
		// R7-2 (round 13): ~+ is $PWD, ~- $OLDPWD, ~user another home; a ~/ the shell did not expand ("~/…", \~/…) is
		// the folder ~ in cwd, which this reading cannot tell from an expanded one — so only an unquoted-looking ~/ with
		// a known home and cwd, and no folder ~ in cwd, is read as the home's
		if !strings.HasPrefix(p, "~/") || c.home == "" || c.cwd == "" {
			c.moved("the command line", "sources a file by a ~ form this reader does not place")
			return
		}
		if _, err := os.Lstat(filepath.Join(c.cwd, "~")); err == nil {
			c.moved("the command line", "sources a file under ~ while the folder it runs in has a ~ of its own")
			return
		}
		p = filepath.Join(c.home, p[2:])
	case !filepath.IsAbs(p) && c.cwd != "":
		p = filepath.Join(c.cwd, p)
	}
	p = filepath.Clean(p)
	if b := c.read(p); b != nil {
		if activateTemplate(p, b) == "" {
			c.moved(p, "is sourced by the line and is no virtual environment's activate script this reader knows")
			return
		}
		// R7-1 (round 13): pip, run from the venv the script activates, reads that venv's site config
		c.site(filepath.Dir(filepath.Dir(p)))
	}
}

// inlineVar judges a VAR=value word of the line: a variable that moves every user config counts at once, any other is
// judged as the environment's (envVar).
func (c *regCheck) inlineVar(a string) {
	k, v, _ := strings.Cut(a, "=")
	if movedVars[strings.ToUpper(k)] {
		c.moved("the command line", "sets "+k+", which moves the config files the install reads")
		return
	}
	c.envVar("the command line", k, v)
}

// wrapperWord: a wrapper's option that changes directory — sudo's -D and --chdir, env's -C and --chdir — in any
// spelling getopt takes (-D /srv, -D/srv, a cluster such as -iC/srv).
func (c *regCheck) wrapperWord(x string) {
	switch {
	case strings.HasPrefix(x, "--"):
		if name, _, _ := strings.Cut(x, "="); name == "--chdir" || name == "--directory" {
			c.moved("the command line", "changes directory ("+name+")")
		}
	case strings.HasPrefix(x, "-") && strings.ContainsAny(x, "CD"):
		c.moved("the command line", "changes directory (a wrapper's "+x[:2]+")")
	}
}

// managerWords: a package manager's words after its name. An option must be one plainFlags names for it (a valued one
// takes the next word); a word with a variable in it, or Yarn's workspace commands (Yarn runs the command in the
// workspace's folder and reads that folder's .yarnrc.yml: plugin-essentials workspace.ts, cli.run with the
// workspace's cwd), count as moved.
func (c *regCheck) managerWords(prog string, fs flagSet, rest []string) {
	const where = "the command line"
	var verbs []string
	for i := 0; i < len(rest); i++ {
		x := rest[i]
		if runDone(prog, verbs) {
			return
		}
		if strings.Contains(x, "$") {
			c.moved(where, "passes "+prog+" a word built from a variable")
			return
		}
		if x == "--" {
			// the end of the options: npm exec -- pkg args (the rest is the package's), pip install -- x (positional;
			// a word with $ in it ParseLine holds already)
			return
		}
		if !strings.HasPrefix(x, "-") || x == "-" {
			if len(verbs) == 0 && prog == "yarn" && (x == "workspace" || x == "workspaces") {
				c.moved(where, "runs Yarn in a workspace's folder, whose config this reader does not read")
				return
			}
			verbs = append(verbs, x)
			continue
		}
		sub := flagSet{}
		if len(verbs) > 0 {
			sub = subFlags[prog+" "+verbs[0]]
		}
		name, _, hasVal := strings.Cut(x, "=")
		switch {
		case fs.valued[name] || sub.valued[name]:
			// the value is the next word, unless that is an option (npm's nopt then takes "" for a String option:
			// --save-prefix --prefix /srv sets prefix)
			if !hasVal && i+1 < len(rest) && !strings.HasPrefix(rest[i+1], "-") {
				i++
			}
		case fs.bare[x] || sub.bare[x]:
		default:
			c.moved(where, "passes "+prog+" an option a plain install does not take ("+name+")")
			return
		}
	}
}

// --- the shell's startup files, direnv, mise, .env ---

// listed: the files of a configuration folder (fish's conf.d, /etc/profile.d, environment.d) with the suffix, in
// order; a folder with more than maxListed counts as moved.
func (c *regCheck) listed(dir, suffix string) []string { return c.listedMax(dir, suffix, maxListed) }

// listedMax is listed with another bound; the folder is noted as enumerated (c.enumerated): a file of it that is gone
// is a change to the pin (startpin.go).
func (c *regCheck) listedMax(dir, suffix string, max int) []string {
	if c.enumerated != nil {
		c.enumerated[filepath.Clean(dir)] = true
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), suffix) && !e.IsDir() {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	if len(out) > max {
		c.moved(dir, "has more files than this reader reads")
		return nil
	}
	return out
}

// maxListed bounds the files read from one configuration folder (a variable for tests).
var maxListed = 128

// dotenvFiles: what bun install loads from the project root (bun.com/docs/runtime/env).
var dotenvFiles = []string{".env", ".env.production", ".env.development", ".env.test", ".env.local",
	".env.production.local", ".env.development.local", ".env.test.local"}

// projectEnvFiles reads, in every folder up, the files that set the install's environment: direnv's .envrc (and the
// .env its dotenv loads), mise's [env], and — for the tool that loads them — bun's .env files and Yarn's .env.yarn.
func (c *regCheck) projectEnvFiles(ups []string) {
	for _, d := range ups {
		p := filepath.Join(d, ".envrc")
		if b := c.read(p); b != nil {
			c.envrc(d, p, b)
		}
		names := []string{"mise.toml", ".mise.toml", "mise.local.toml", ".mise.local.toml", filepath.Join(".config", "mise.toml"),
			filepath.Join(".config", "mise", "config.toml"), filepath.Join("mise", "config.toml"), filepath.Join(".mise", "config.toml")}
		for _, e := range c.vals("MISE_ENV") { // mise.<env>.toml for each of MISE_ENV's environments
			for _, x := range strings.Split(e, ",") {
				if x = strings.TrimSpace(x); x != "" && !strings.ContainsAny(x, `/\`) {
					names = append(names, "mise."+x+".toml", ".mise."+x+".toml", "mise."+x+".local.toml", ".mise."+x+".local.toml")
				}
			}
		}
		for _, n := range names {
			c.mise(filepath.Join(d, n))
		}
		for _, f := range c.listed(filepath.Join(d, ".config", "mise", "conf.d"), ".toml") {
			c.mise(f)
		}
		c.toolVersions(filepath.Join(d, ".tool-versions"))
		if c.npm && (c.progs["bun"] || c.progs["bunx"]) {
			for _, n := range dotenvFiles {
				if b := c.read(filepath.Join(d, n)); b != nil {
					c.assignments(filepath.Join(d, n), b, false)
				}
			}
		}
		if c.npm && c.progs["yarn"] {
			if b := c.read(filepath.Join(d, ".env.yarn")); b != nil {
				c.assignments(filepath.Join(d, ".env.yarn"), b, false)
			}
		}
	}
	if c.home != "" {
		c.followLinks = true // the user's own file, which may be a link (round 9, F6)
		c.mise(filepath.Join(c.home, ".config", "mise", "config.toml"))
		for _, f := range c.listed(filepath.Join(c.home, ".config", "mise", "conf.d"), ".toml") {
			c.mise(f)
		}
		c.toolVersions(filepath.Join(c.home, ".tool-versions"))
		c.followLinks = false
	}
}

// envrc reads direnv's .envrc: its assignments as a startup file's; dotenv [file] reads that file the same way; a line
// that loads what this reader cannot see (source_env, source_up, source_url, layout python) counts as moved.
func (c *regCheck) envrc(dir, path string, b []byte) {
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		switch {
		case f[0] == "dotenv" || f[0] == "dotenv_if_exists":
			name := ".env"
			if len(f) > 1 {
				name = unquote(f[1])
			}
			if strings.ContainsAny(name, "$`") {
				c.moved(path, "loads an env file named by a variable")
				return
			}
			if !filepath.IsAbs(name) {
				name = filepath.Join(dir, name)
			}
			if eb := c.read(name); eb != nil {
				c.assignments(name, eb, false)
			}
		case strings.HasPrefix(f[0], "source_"), f[0] == "layout", f[0] == "use", f[0] == "load_prefix",
			f[0] == "PATH_add", f[0] == "path_add":
			// round 14 (R8-7): layout and use (node, python, nix, mise …) and PATH_add put other programs first
			c.moved(path, "loads an environment or puts programs first that this reader cannot see ("+f[0]+")")
			return
		}
	}
	c.assignments(path, b, false)
}

// mise reads a mise config's [env]: each variable envVar judges must be a string, and is judged as the environment's
// (a {{ template }} is no public registry, path or false word, so it counts as moved there); _.file and _.source load
// what it cannot see.
func (c *regCheck) mise(path string) {
	b := c.read(path)
	if b == nil {
		return
	}
	var m map[string]any
	if _, err := toml.Decode(string(b), &m); err != nil {
		c.moved(path, "could not be parsed, so the environment it sets is not known")
		return
	}
	// round 16 (R10-1): an allow-list, as with the activate templates — each round found another mise form that runs
	// code or puts another program first, so only what is known to be inert is read as such
	for _, k := range sortedKeys(m) {
		switch k {
		case "env", "vars", "tasks", "task_config", "task_templates", "min_version", "redactions", "_":
			// [env] is judged below; tasks run only with mise run; vars feed templates, which [env] judges as moved
		case "tool_config":
			if tc, ok := m[k].(map[string]any); !ok || len(tc) > 1 || (len(tc) == 1 && tc["locked"] == nil) {
				c.moved(path, "sets [tool_config] beyond locked, which this reader does not read as inert")
				return
			}
		case "tools":
			tools, ok := m[k].(map[string]any)
			if !ok {
				c.moved(path, "sets [tools] in a form this reader does not place")
				return
			}
			for _, name := range sortedKeys(tools) {
				if why := miseTool(name, tools[name]); why != "" {
					c.moved(path, why+" ([tools] "+name+")")
					return
				}
			}
		default:
			// [settings], [alias], [tool_alias], [plugins], [hooks], [shell_alias], [wrappers], [watch_files],
			// include, [secrets], [monorepo], env_file, dotenv, env_path and every other key
			c.moved(path, "sets "+k+", which this reader does not read as inert (mise)")
			return
		}
	}
	env, ok := m["env"].(map[string]any)
	if !ok {
		return
	}
	for _, k := range sortedKeys(env) {
		if k == "_" {
			// _.file, _.source, _.path (PATH), _.python.venv: each loads or puts first what this reader does not see
			if u, ok := env[k].(map[string]any); !ok || len(u) > 0 {
				c.moved(path, "loads or puts first an environment this reader cannot see (env._)")
			}
			continue
		}
		if codeVars[k] {
			c.moved(path, "sets "+k+", which changes the programs or the code the install runs")
			continue
		}
		if !c.envRelevant(k, true) {
			continue
		}
		v, ok := env[k].(string)
		if !ok {
			c.moved(path, "sets "+k+" to a value this reader cannot know")
			continue
		}
		c.envVar(path, k, v)
	}
}

var (
	shellWord = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)
	// an assignment: sh's NAME=value (export, declare -x, typeset -x, local, readonly before it), csh's setenv NAME
	// value, fish's set [-flags] NAME value
	shAssign   = regexp.MustCompile(`^(?:(?:export|declare|typeset|local|readonly)(?:\s+-[A-Za-z]+)*\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$`)
	wordAssign = regexp.MustCompile(`^(?:setenv|set(?:\s+-[A-Za-z]+)*)\s+([A-Za-z_][A-Za-z0-9_]*)\s+(.*)$`)
	unsetName  = regexp.MustCompile(`^(?:unset|unsetenv|set\s+-e)\s`)
	// a name built from a variable (npm_config_${R}) or an export of what a command prints (export $(cat f))
	builtName  = regexp.MustCompile(`(?i)\b(?:npm_config_|pnpm_config_|yarn_)[A-Za-z0-9_]*\$|\b(?:BUN_CONFIG_|PIP_|UV_)[A-Z0-9_]*\$`)
	exportExec = regexp.MustCompile(`^(?:export|declare\s+-x|typeset\s+-x)\s+["']?\$`)
	exportOnly = regexp.MustCompile(`^(?:export|declare\s+-x|typeset\s+-x)(?:\s+[A-Za-z_][A-Za-z0-9_]*)+\s*;?$`)
	// an alias (sh's alias NAME=value, any number; fish's alias NAME value) or a function (NAME () {, function NAME)
	aliasDef  = regexp.MustCompile(`^alias(?:\s+-[A-Za-z]+)*\s+(.*)$`)
	aliasPair = regexp.MustCompile(`(?:^|\s)([A-Za-z0-9_.+-]+)=('[^']*'|"[^"]*"|\S+)`)
	fishAlias = regexp.MustCompile(`^([A-Za-z0-9_.+-]+)\s+('[^']*'|"[^"]*"|\S+)`)
	funcDef   = regexp.MustCompile(`^(?:function\s+([A-Za-z0-9_.+-]+)|([A-Za-z0-9_.+-]+)\s*\(\s*\))`)
	// a value that is only a program's name or path (alias pip=pip3)
	plainProgram = regexp.MustCompile(`^[A-Za-z0-9_.+/][A-Za-z0-9_.+/-]*$`)
	// VIRTUAL_ENV=$(cygpath "…") in CPython's activate script (Cygwin and MSYS): the path inside is the value
	cygpath = regexp.MustCompile(`^\$\(cygpath(?:\s+-[uwm])?\s+["']?([^"'()$]+)["']?\)$`)
	// ${NAME:=…}, ${NAME=…}, ${NAME:?…}, ${NAME?…}
	expandSet = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*):?[=?]`)
	// zsh's aliases, galiases, saliases and functions arrays: aliases[npm]=…, functions+=(npm …)
	zshArray = regexp.MustCompile(`^(?:[gs]?aliases|functions)(?:\[|\+?=\()`)
	// an alias pair quoted whole: alias 'npm=…'
	quotedPair = regexp.MustCompile(`(?:^|\s)(?:'([A-Za-z0-9_.+-]+)=([^']*)'|"([A-Za-z0-9_.+-]+)=([^"]*)")`)
)

// codeVars: the variables that change which program runs or what code it loads, judged in a project's env files
// (.envrc, .env, mise's [env]) whatever their value (round 14, R8-7): a startup file's are pinned instead.
var codeVars = map[string]bool{"PATH": true, "NODE_OPTIONS": true, "NODE_PATH": true, "PYTHONPATH": true,
	"PYTHONHOME": true, "PYTHONUSERBASE": true, "PYTHONSTARTUP": true, "BASH_ENV": true, "ENV": true, "LD_PRELOAD": true,
	"LD_LIBRARY_PATH": true, "DYLD_INSERT_LIBRARIES": true, "DYLD_LIBRARY_PATH": true, "ZDOTDIR": true}

// miseToolName: a tool of mise's registry by its short name (node, python, terraform) or the core backend's; any
// other backend (github:, ubi:, aqua:, asdf:, vfox:, cargo:, npm:, pipx:, go:, http:, spm: …) fetches from a place
// the name chooses.
var miseToolName = regexp.MustCompile(`^(?:core:)?[a-z0-9][a-z0-9._-]*$`)

// miseVersion: a version request mise resolves in the tool's own releases: no path:, ref:, sub-…: or other prefix,
// no URL or path ("22", "3.12.4", "latest", "lts", "prefix:22" are; "path:/x" is not).
var miseVersion = regexp.MustCompile(`^(?:prefix:)?[A-Za-z0-9][A-Za-z0-9._+-]*$`)

// miseToolOptions: the per-tool options mise documents that do not change where the tool comes from or run anything
// (mise.jdx.dev/dev-tools, read 2026-11-15); install_env, postinstall, lazy, auto_update and backend options are not.
var miseToolOptions = map[string]bool{"version": true, "os": true, "depends": true, "minimum_release_age": true,
	"prerelease": true, "version_order": true}

// miseTool: why a [tools] entry is not inert ("" when it is): a registry name with a version string, a list of
// them, or a table of inert options.
func miseTool(name string, v any) string {
	if !miseToolName.MatchString(name) {
		return "names a tool by a backend that fetches from a place the name chooses"
	}
	versions := func(v any) bool {
		switch x := v.(type) {
		case string:
			return miseVersion.MatchString(strings.TrimSpace(x))
		case []any:
			for _, e := range x {
				if s, ok := e.(string); !ok || !miseVersion.MatchString(strings.TrimSpace(s)) {
					return false
				}
			}
			return len(x) > 0
		}
		return false
	}
	if t, ok := v.(map[string]any); ok {
		for _, k := range sortedKeys(t) {
			switch {
			case !miseToolOptions[k]:
				return "sets the tool option " + k + ", which may run code or change where the tool comes from"
			case k == "version" && !versions(t[k]):
				return "takes the tool from somewhere other than its releases"
			}
		}
		return ""
	}
	if !versions(v) {
		return "takes the tool from somewhere other than its releases"
	}
	return ""
}

// toolVersions reads asdf's and mise's .tool-versions: each line a registry name and version requests, as [tools].
func (c *regCheck) toolVersions(path string) {
	b := c.read(path)
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(codePart(strings.TrimSpace(line)))
		if len(f) == 0 {
			continue
		}
		vs := make([]any, 0, len(f)-1)
		for _, x := range f[1:] {
			vs = append(vs, x)
		}
		if why := miseTool(f[0], vs); why != "" {
			c.moved(path, why+" ("+f[0]+")")
			return
		}
	}
}

// pmNames: the programs an alias or a function must not stand in for (round 9, R5); pn and pnx are pnpm's and pnpx's
// own bins in pnpm 11 and 12 (ADR-0159 round 41).
var pmNames = map[string]bool{"npm": true, "npx": true, "pnpm": true, "pnpx": true, "pn": true, "pnx": true, "yarn": true, "bun": true,
	"bunx": true, "corepack": true, "pip": true, "pip3": true, "python": true, "python3": true, "uv": true,
	"uvx": true, "pipx": true, "deno": true}

// helperNames: the programs whose output this reader trusts in a startup file or a template (cygpath for VIRTUAL_ENV;
// dirname, realpath, basename, uname and command in the activate templates): any alias or function of one of these
// names counts as moved (round 11, T3).
var helperNames = map[string]bool{"cygpath": true, "dirname": true, "realpath": true, "basename": true, "uname": true,
	"command": true}

// tlsVars: the variables of a proxy and of a certificate authority (envVar's TLS block).
var tlsVars = map[string]bool{"HTTPS_PROXY": true, "HTTP_PROXY": true, "ALL_PROXY": true, "PIP_PROXY": true,
	"NODE_EXTRA_CA_CERTS": true, "SSL_CERT_FILE": true, "SSL_CERT_DIR": true, "REQUESTS_CA_BUNDLE": true, "PIP_CERT": true}

// pmShadow: the package manager a line's alias or function stands in for, "" when none — an alias whose value is
// only another program's name (alias pip=pip3) stands in for nothing this reader does not read.
func pmShadow(line string) string {
	if zshArray.MatchString(line) {
		for _, w := range shellWord.FindAllString(line, -1) {
			if pmNames[w] || helperNames[w] {
				return w
			}
		}
	}
	if m := funcDef.FindStringSubmatch(line); m != nil {
		if n := m[1] + m[2]; pmNames[n] || helperNames[n] {
			return n
		}
	}
	m := aliasDef.FindStringSubmatch(line)
	if m == nil {
		return ""
	}
	pairs := aliasPair.FindAllStringSubmatch(m[1], -1)
	for _, q := range quotedPair.FindAllStringSubmatch(m[1], -1) {
		pairs = append(pairs, []string{q[0], q[1] + q[3], q[2] + q[4]})
	}
	if len(pairs) == 0 {
		pairs = fishAlias.FindAllStringSubmatch(m[1], 1)
	}
	for _, p := range pairs {
		if helperNames[p[1]] || pmNames[p[1]] && !plainProgram.MatchString(unquote(p[2])) {
			return p[1]
		}
	}
	return ""
}

// codePart: a line without its comment (a # that starts a word, outside quotes).
func codePart(line string) string {
	q := byte(0)
	for i := 0; i < len(line); i++ {
		switch ch := line[i]; {
		case q != 0:
			if ch == q {
				q = 0
			}
		case ch == '\'' || ch == '"':
			q = ch
		case ch == '#' && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t'):
			return line[:i]
		}
	}
	return line
}

// assignments judges a startup file or an env file by the variables it names that envVar judges (envRelevant): an
// assignment of a value this reader can know — a literal, or one under $HOME or ~ — is judged as the environment's;
// any other value, a mention that is not an assignment (PREFIX counts only as an assignment), a name built from a
// variable, or an export of a command's output counts as moved. Lines ending in a backslash are joined first. shell:
// the file is a shell's (PREFIX is npm's there); an env file for one tool (.env, .env.yarn) sets no PREFIX npm reads.
func (c *regCheck) assignments(path string, b []byte, shell bool) {
	judged := map[string]bool{} // the names an assignment above set and envVar judged
	text := strings.ReplaceAll(strings.ReplaceAll(string(b), "\r\n", "\n"), "\\\n", "")
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(codePart(strings.TrimSpace(raw)))
		if line == "" {
			continue
		}
		if (c.npm && builtName.MatchString(line)) || exportExec.MatchString(line) {
			c.moved(path, "sets a variable this reader cannot name")
			return
		}
		if unsetName.MatchString(line) {
			continue
		}
		// ${NAME:=value}, ${NAME=value}, ${NAME:?…}: an assignment (or a check) by expansion (round 10, S4)
		for _, m := range expandSet.FindAllStringSubmatch(line, -1) {
			if c.envRelevant(m[1], shell) {
				c.moved(path, "sets "+m[1]+" by a parameter expansion")
				return
			}
		}
		if exportOnly.MatchString(line) {
			// export NAME: a value an assignment above set, and was judged there; else one this reader has not seen
			// (round 10, S5)
			for _, n := range strings.Fields(line)[1:] {
				if n != "-x" && c.envRelevant(n, shell) && !judged[n] {
					c.moved(path, "exports "+n+", set where this reader does not see")
					return
				}
			}
			continue
		}
		if shell {
			if name := pmShadow(line); name != "" {
				c.moved(path, "makes "+name+" run something else (an alias or a function)")
				return
			}
		}
		m := shAssign.FindStringSubmatch(line)
		if m == nil {
			m = wordAssign.FindStringSubmatch(line)
		}
		if !shell && m != nil && codeVars[m[1]] {
			// a project's env file (.envrc, .env): the startup files' PATH is pinned, a project's is not (round 14)
			c.moved(path, "sets "+m[1]+", which changes the programs or the code the install runs")
			return
		}
		// the names that are set or named here: $NAME and ${NAME} read a variable, which sets nothing
		var relevant []string
		for _, ix := range shellWord.FindAllStringIndex(line, -1) {
			n := line[ix[0]:ix[1]]
			if ix[0] > 0 && line[ix[0]-1] == '$' || ix[0] > 1 && line[ix[0]-2:ix[0]] == "${" {
				continue
			}
			if !c.envRelevant(n, shell) || n == "PREFIX" && (m == nil || m[1] != n) {
				continue
			}
			relevant = append(relevant, n)
		}
		if len(relevant) == 0 {
			continue
		}
		if m == nil || len(relevant) != 1 || relevant[0] != m[1] {
			c.moved(path, "names "+relevant[0]+" in a way this reader does not judge")
			return
		}
		value := strings.TrimSpace(m[2])
		if cm := cygpath.FindStringSubmatch(value); cm != nil && m[1] == "VIRTUAL_ENV" {
			value = cm[1] // $(cygpath "…") for VIRTUAL_ENV only; a function named cygpath counts as moved (pmShadow)
		}
		v, ok := c.literal(value)
		if !ok && tlsVars[strings.ToUpper(m[1])] {
			v, ok = "?", true // a proxy or a CA by a command: there is one, whatever it is
		}
		if !ok {
			c.moved(path, "sets "+m[1]+" to a value this reader cannot know")
			return
		}
		c.envVar(path, m[1], v)
		judged[m[1]] = true
	}
}

// literal: a shell value this reader can know — a single-quoted string, or a double-quoted or bare one whose only
// expansion is $HOME, ${HOME} or ~ at its start; a bare value ends at a space or a semicolon.
func (c *regCheck) literal(v string) (string, bool) {
	v = strings.TrimSpace(v)
	// a quoted value must end with its quote: 'a'$(cmd) or 'a'"b" is a value built further, which this reader does
	// not know (round 10)
	ends := func(rest string) bool { return rest == "" || strings.ContainsRune(" \t;", rune(rest[0])) }
	switch {
	case strings.HasPrefix(v, "'"):
		end := strings.IndexByte(v[1:], '\'')
		if end < 0 || !ends(v[end+2:]) {
			return "", false
		}
		return v[1 : end+1], true
	case strings.HasPrefix(v, `"`):
		end := strings.IndexByte(v[1:], '"')
		if end < 0 || !ends(v[end+2:]) {
			return "", false
		}
		v = v[1 : end+1]
	default:
		if i := strings.IndexAny(v, " \t;"); i >= 0 {
			v = v[:i]
		}
	}
	for _, h := range []string{"$HOME", "${HOME}", "~"} {
		if rest, ok := strings.CutPrefix(v, h); ok && c.home != "" && (rest == "" || rest[0] == '/') {
			v = c.home + rest
		}
	}
	if strings.ContainsAny(v, "$`\\") {
		return "", false
	}
	return v, true
}

// npmRelevant: the npm, pnpm, Yarn and bun settings envVar judges, by compact name (a cache or store alone does not
// count from the environment, so it is not here).
var npmRelevant = map[string]bool{"registry": true, "npmregistryserver": true, "registries": true, "npmscopes": true,
	"userconfig": true, "globalconfig": true, "prefix": true, "rcfilename": true, "offline": true, "preferoffline": true,
	"enableofflinemode": true, "yarnpath": true, "plugins": true, "pnpmfile": true, "globalpnpmfile": true, "cwd": true,
	"strictssl": true, "enablestrictssl": true, "cafile": true, "ca": true, "proxy": true, "httpsproxy": true,
	"httpproxy": true, "cafilepath": true, "httpscafilepath": true, "scriptshell": true, "nodeoptions": true, "git": true,
	"nodegyp": true, "shell": true, "npmpath": true}

var pypiRelevant = map[string]bool{"PIP_INDEX_URL": true, "PIP_EXTRA_INDEX_URL": true, "PIP_FIND_LINKS": true,
	"PIP_NO_INDEX": true, "PIP_CONFIG_FILE": true, "PIP_REQUIREMENT": true, "PIP_CONSTRAINT": true,
	"PIP_BUILD_CONSTRAINT": true, "PIP_PYTHON": true, "UV_INDEX_URL": true, "UV_DEFAULT_INDEX": true,
	"UV_EXTRA_INDEX_URL": true, "UV_INDEX": true, "UV_FIND_LINKS": true, "UV_NO_INDEX": true, "UV_CONFIG_FILE": true,
	"UV_OFFLINE": true, "UV_CONSTRAINT": true, "UV_OVERRIDE": true, "UV_BUILD_CONSTRAINT": true, "VIRTUAL_ENV": true,
	"CONDA_PREFIX": true, "UV_PROJECT_ENVIRONMENT": true, "UV_PROJECT": true, "PIP_TRUSTED_HOST": true,
	"UV_INSECURE_HOST": true, "PIP_KEYRING_PROVIDER": true, "UV_KEYRING_PROVIDER": true, "UV_PYTHON": true,
	"UV_PYTHON_SEARCH_PATH": true, "UV_ENV_FILE": true, "UV_ASTRAL_MIRROR_URL": true, "UV_PYTHON_INSTALL_MIRROR": true,
	"UV_PYPY_INSTALL_MIRROR": true, "UV_PYODIDE_INSTALL_MIRROR": true, "UV_GRAALPY_INSTALL_MIRROR": true,
	"UV_PYTHON_DOWNLOADS_JSON_URL": true, "UV_S3_ENDPOINT_URL": true, "UV_GCS_ENDPOINT_URL": true,
	"UV_AZURE_ENDPOINT_URL": true, "UV_TORCH_BACKEND": true, "UV_PYTHON_INSTALL_DIR": true, "UV_PYTHON_BIN_DIR": true,
	"UV_PYTHON_CACHE_DIR": true, "UV_TOOL_DIR": true, "UV_TOOL_BIN_DIR": true}

// envRelevant: a variable envVar judges for these targets, by the case the tools read it in: npm, pnpm and Yarn fold
// the case of their prefixes; bun's, PREFIX, corepack's and pip's and uv's names are exact on unix. shell: PREFIX
// counts (npm reads it from a shell's environment; a tool's env file sets none npm reads).
func (c *regCheck) envRelevant(name string, shell bool) bool {
	if tlsVars[strings.ToUpper(name)] { // a proxy (https_proxy too) or a certificate authority, for every tool
		return true
	}
	if c.npm {
		up := strings.ToUpper(name)
		if name == "PREFIX" && shell || name == "COREPACK_NPM_REGISTRY" || name == "NODE_TLS_REJECT_UNAUTHORIZED" {
			return true
		}
		for _, p := range []string{"NPM_CONFIG_", "PNPM_CONFIG_", "YARN_"} {
			if rest, ok := strings.CutPrefix(up, p); ok && npmRelevant[compact(rest)] {
				return true
			}
		}
		if rest, ok := strings.CutPrefix(name, "BUN_CONFIG_"); ok && npmRelevant[compact(rest)] {
			return true
		}
	}
	return c.pypi && pypiRelevant[name]
}
