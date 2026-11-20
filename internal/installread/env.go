package installread

import (
	"net/url"
	"regexp"
	"strings"
)

// Which environment variables, config keys and launcher flags are a reason (ADR-0131, eighth round).
//
// A name is a reason only when its tool documents it (or its source shows it) as a lever that makes
// alalanet's answer about the packages a line names wrong or incomplete:
//
//   - another source: a registry, an index, a mirror of the tool's own downloads;
//   - a config file alalanet cannot see;
//   - other code that runs: a shell, a git or ssh program, a preload, a plugin, an interpreter;
//   - a check switched off or a trust store swapped: TLS, hashes, signatures, host keys;
//   - a file that adds packages or variables: requirements, constraints, an env file.
//
// A family prefix is not a reason. Until the seventh review every NPM_CONFIG_*, UV_*, YARN_*, GIT_*,
// PYTHON*… name was one unless listed as safe; of that review's 203 agent commands production asked on
// 10 and the candidate on 52, most of them for names that only tune a tool (COREPACK_ENABLE_DOWNLOAD_PROMPT,
// YARN_IGNORE_ENGINES, UV_CACHE_DIR, a shell's own python_version). Not levers, by decision: where a
// tool keeps its caches, stores and binaries; proxies; script and build policy (ignore-scripts,
// enableScripts); what a project's own files can do as well (overrides, node --conditions, --prefix and
// the current folder); mirrors of third-party binaries (ELECTRON_MIRROR, PUPPETEER_*); the runtimes of
// other ecosystems beyond the names the production reader holds (JAVA_HOME, CARGO_*, GEM_*, Go's GOFLAGS
// and GOPROXY).
//
// Names are compared without case: Windows and npm read them that way, and a name a POSIX tool would
// not read in that case costs a question, not a miss. The sources per name are in
// docs/research/2026-11-11-package-manager-levers.md.

type lever uint8

const (
	lvNone       lever = iota
	lvAny              // set at all, to any value (an empty one too: git reads GIT_SSL_NO_VERIFY by presence)
	lvLoads            // loads code into what runs (the production reader's list and wording)
	lvSource           // a registry, an index or a mirror: a reason unless every address is a public registry over https
	lvMirror           // lvSource for Node's headers and binaries: nodejs.org and electronjs.org are theirs
	lvConfig           // a config file alalanet cannot see
	lvDirs             // a search path: a reason with a relative, temporary or current-folder entry
	lvPath             // a file or folder the tool reads: a reason in a relative or temporary folder
	lvVenv             // a virtualenv: as lvPath, but the project's own .venv is fine
	lvPython           // uv's or pip's interpreter: a path as lvPath (a virtualenv's is fine), a bare name that is no version (cwdFirst)
	lvInterp           // pipx's or node-gyp's interpreter, node-gyp's make: a name on PATH is fine, a path as lvPython
	lvProgram          // a program: a name on PATH or an absolute path is fine
	lvOff              // a check of npm, pnpm or Yarn: a reason when switched off, which is the word false
	lvOn               // a switch that removes a check: a reason when on
	lvNodeOpts         // NODE_OPTIONS: a reason with a flag that loads code or opens a debugger port
	lvBunOpts          // BUN_OPTIONS: also bun's own --config, --env-file, --registry, --cafile
	lvShellEnv         // ENV: a startup file for sh; ENV=production is an app setting
	lvSSH              // GIT_SSH_COMMAND: a reason unless it is ssh with options that pick a key, a port, a user
	lvTLS              // NODE_TLS_REJECT_UNAUTHORIZED: a reason for 0
	lvBreakpoint       // PYTHONBREAKPOINT: a callable; 0 switches breakpoints off
	lvWarnings         // PYTHONWARNINGS: a dotted category imports that module
	lvKeyring          // pip's keyring provider: subprocess runs a program, import a module, the line does not name
	lvKeyringUV        // uv's: subprocess alone (uv has no import provider and refuses the word)
	lvStrategy         // UV_INDEX_STRATEGY: unsafe-* lets any index answer for a name
	lvUnverified       // COREPACK_ON_UNVERIFIED_DOWNLOAD: anything but error or prompt accepts an unsigned download
	lvChecksum         // yarn's checksumBehavior: anything but throw accepts a changed archive
	lvHome             // where the package managers read their user config (HOME-CONFIG-ENV-1): a config file alalanet cannot see in a folder homeDirWhy or lvPath's reading holds
)

// envLevers: variables read under their own name, in upper case.
var envLevers = func() map[string]lever {
	m := map[string]lever{}
	set := func(lv lever, names string) {
		for _, n := range strings.Fields(names) {
			m[n] = lv
		}
	}
	for k := range codeLoadingEnv {
		m[k] = lvLoads
	}
	for k := range searchPathEnv {
		m[k] = lvDirs
	}
	set(lvDirs, "UV_PYTHON_SEARCH_PATH UV_TEST_PYTHON_PATH") // the second is the first's name before uv 0.11.8
	// shells: startup files and options that run a script (SHELLOPTS=xtrace with PS4='$(…)'); npm runs
	// scripts through ComSpec on Windows; glibc loads modules from GCONV_PATH and LOCPATH
	set(lvAny, "ZDOTDIR SHELLOPTS BASHOPTS PS4 PROMPT_COMMAND COMSPEC GCONV_PATH LOCPATH")
	set(lvShellEnv, "ENV")
	set(lvPath, "SHELL")
	// where tools look for their config: ~/.npmrc, ~/.config/uv/uv.toml, pip.conf, $PREFIX/etc/npmrc; the user config's
	// folders are lvHome (HOME-CONFIG-ENV-1)
	set(lvHome, "HOME USERPROFILE APPDATA XDG_CONFIG_HOME LOCALAPPDATA XDG_CONFIG_DIRS PREFIX") // round 2, P3-3: the last three
	set(lvPath, "DESTDIR")
	// trust stores
	set(lvTLS, "NODE_TLS_REJECT_UNAUTHORIZED")
	set(lvPath, "NODE_EXTRA_CA_CERTS SSL_CERT_FILE SSL_CERT_DIR REQUESTS_CA_BUNDLE CURL_CA_BUNDLE OPENSSL_CONF PIP_CERT DENO_CERT "+
		"GIT_SSL_CAINFO GIT_SSL_CAPATH")
	// Node, node-gyp
	// NODE_REPL_EXTERNAL_MODULE is not here: Node's REPL alone reads it, and no install starts one
	set(lvNodeOpts, "NODE_OPTIONS")
	set(lvPath, "NODE_COMPILE_CACHE")
	set(lvMirror, "NODEJS_ORG_MIRROR")
	set(lvInterp, "NODE_GYP_FORCE_PYTHON PYTHON MAKE")
	// Bun, Deno's JSR, Corepack
	set(lvBunOpts, "BUN_OPTIONS")
	set(lvAny, "BUN_INSPECT BUN_INSPECT_CONNECT_TO BUN_INSPECT_PRELOAD")
	set(lvSource, "BUN_CONFIG_REGISTRY JSR_URL JSR_NPM_URL COREPACK_NPM_REGISTRY")
	set(lvAny, "COREPACK_INTEGRITY_KEYS COREPACK_ENV_FILE")
	set(lvOn, "COREPACK_ENABLE_UNSAFE_CUSTOM_URLS")
	set(lvUnverified, "COREPACK_ON_UNVERIFIED_DOWNLOAD")
	set(lvPath, "COREPACK_HOME")
	// Python
	set(lvPath, "PYTHONUSERBASE PYTHONPYCACHEPREFIX")
	set(lvBreakpoint, "PYTHONBREAKPOINT")
	// PYTHON_PRESITE is not here: a release build of Python ignores it (debug builds alone import it)
	set(lvWarnings, "PYTHONWARNINGS")
	// pip
	// pip's and uv's index options through the environment, from their parsers (pyIndexEnv: PIP_INDEX_URL, its hidden
	// alias PIP_PYPI_URL, PIP_EXTRA_INDEX_URL, PIP_FIND_LINKS, UV_INDEX, UV_DEFAULT_INDEX, UV_INDEX_URL …; READER-VAR-OPT-1)
	for k := range pyIndexEnv {
		m[k] = lvSource
	}
	set(lvConfig, "PIP_CONFIG_FILE")
	set(lvAny, "PIP_TRUSTED_HOST PIP_REQUIREMENT PIP_CONSTRAINT PIP_BUILD_CONSTRAINT PIP_EDITABLE PIP_REQUIREMENTS_FROM_SCRIPT PIP_GROUP")
	set(lvPython, "PIP_PYTHON")
	set(lvKeyring, "PIP_KEYRING_PROVIDER")
	set(lvKeyringUV, "UV_KEYRING_PROVIDER")
	// uv
	set(lvSource, "UV_PYTHON_INSTALL_MIRROR "+
		"UV_PYPY_INSTALL_MIRROR UV_PYTHON_DOWNLOADS_JSON_URL UV_ASTRAL_MIRROR_URL UV_GRAALPY_INSTALL_MIRROR UV_PYODIDE_INSTALL_MIRROR "+
		"UV_INSTALLER_GITHUB_BASE_URL UV_INSTALLER_GHE_BASE_URL UV_DOWNLOAD_URL UV_S3_ENDPOINT_URL UV_GCS_ENDPOINT_URL "+
		"UV_AZURE_ENDPOINT_URL UV_MALWARE_CHECK_URL")
	set(lvConfig, "UV_CONFIG_FILE")
	set(lvAny, "UV_INSECURE_HOST UV_CONSTRAINT UV_BUILD_CONSTRAINT UV_OVERRIDE UV_ENV_FILE")
	set(lvPython, "UV_PYTHON")
	set(lvInterp, "PIPX_DEFAULT_PYTHON")
	set(lvStrategy, "UV_INDEX_STRATEGY")
	set(lvOn, "UV_NO_VERIFY_HASHES UV_INSECURE_NO_ZIP_VALIDATION UV_SKIP_WHEEL_FILENAME_CHECK")
	set(lvPath, "UV_PYTHON_INSTALL_DIR PIPX_HOME PIPX_GLOBAL_HOME PIPX_SHARED_LIBS")
	// the version managers' roots: eval "$(pyenv init -)" puts <PYENV_ROOT>/shims first on PATH (round 33)
	set(lvPath, "PYENV_ROOT RBENV_ROOT NODENV_ROOT GOENV_ROOT FNM_DIR CONDA_EXE CONDA_ROOT CONDA_PYTHON_EXE CONDA_ENVS_PATH "+
		"CONDA_ENVS_DIRS CONDA_PKGS_DIRS DIRENV_CONFIG XDG_DATA_HOME")
	set(lvVenv, "UV_PROJECT_ENVIRONMENT VIRTUAL_ENV CONDA_PREFIX")
	// Yarn 1's config file, pnpm's loader
	set(lvConfig, "YARN_CONFIG")
	set(lvAny, "PNPM_LOADER_MANIFEST")
	// git, which npm, pnpm, yarn, pip and uv run for git dependencies
	set(lvProgram, "GIT_SSH GIT_ASKPASS SSH_ASKPASS GIT_PROXY_COMMAND")
	set(lvSSH, "GIT_SSH_COMMAND")
	set(lvConfig, "GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM")
	set(lvPath, "GIT_EXEC_PATH GIT_TEMPLATE_DIR")
	set(lvAny, "GIT_SSL_NO_VERIFY GIT_ALLOW_PROTOCOL GIT_DIR GIT_COMMON_DIR GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_ATTR_SOURCE "+
		"GIT_CONFIG_PARAMETERS GIT_CONFIG_COUNT")
	// the JVM's options: JAVA_TOOL_OPTIONS (the production reader's) in its other spellings. Go's module
	// settings (GOFLAGS, GOPROXY) are not here: go run and go install are not read, and npm and pip do
	// not read them
	set(lvAny, "JDK_JAVA_OPTIONS _JAVA_OPTIONS")
	return m
}()

// pmCarriers: prefixes under which npm, pnpm and Yarn read any config key from the environment
// (npm_config_registry, PNPM_CONFIG_PNPMFILE, YARN_NPM_REGISTRY_SERVER; Yarn 1 reads YARN_REGISTRY).
var pmCarriers = []string{"NPM_CONFIG_", "PNPM_CONFIG_", "YARN_"}

// pmKeys: config keys of npm, pnpm and Yarn that are levers, by compact name (compactKey): the same
// key is script-shell in .npmrc, npm_config_script_shell in the environment, scriptShell in pnpm's
// yaml and --script-shell on a command line.
var pmKeys = func() map[string]lever {
	m := map[string]lever{}
	set := func(lv lever, names string) {
		for _, n := range strings.Fields(names) {
			m[n] = lv
		}
	}
	set(lvSource, "registry npmregistryserver")
	set(lvMirror, "disturl")
	set(lvAny, "registries namedregistries npmregistries npmscopes yarnofflinemirror nodedownloadmirrors tools pnprserver tarball nodedir")
	set(lvConfig, "userconfig globalconfig npmrcauthfile rcfilename npmrc useyarnrc")
	set(lvPath, "prefix cafile httpscafilepath")
	set(lvProgram, "scriptshell git nodegyp npmpath")
	set(lvNodeOpts, "nodeoptions")
	set(lvAny, "package call initmodule pnpmfile globalpnpmfile yarnpath plugins extensionfile")
	set(lvInterp, "python make")
	set(lvOff, "strictssl enablestrictssl verifystoreintegrity")
	set(lvAny, "ca unsafehttpwhitelist networksettings injectenvironmentfiles")
	set(lvChecksum, "checksumbehavior")
	return m
}()

var keyCompacter = strings.NewReplacer("-", "", "_", "")

// compactKey: a config key without case, dashes or underscores (strict-ssl, STRICT_SSL, strictSsl).
func compactKey(k string) string { return strings.ToLower(keyCompacter.Replace(k)) }

// pmKeyLever: the lever of a package manager's config key, however it is spelled.
func pmKeyLever(key string) lever {
	c := compactKey(key)
	if lv, ok := pmKeys[c]; ok {
		return lv
	}
	switch {
	case strings.HasSuffix(c, ":registry"): // @scope:registry
		return lvSource
	case strings.HasSuffix(c, ":cafile"): // //host/:cafile
		return lvPath
	case strings.HasSuffix(c, ":ca"), strings.HasSuffix(c, ":tokenhelper"), strings.HasPrefix(c, "nodemirror:"):
		return lvAny
	}
	return lvNone
}

// leverOf: the lever an environment variable is, if any.
func leverOf(k string) lever {
	uk := strings.ToUpper(k)
	if lv, ok := envLevers[uk]; ok {
		return lv
	}
	if strings.HasPrefix(uk, "GIT_CONFIG_KEY_") || strings.HasPrefix(uk, "GIT_CONFIG_VALUE_") {
		return lvAny // git config given through the environment (url.<base>.insteadOf, core.sshCommand)
	}
	for _, p := range pmCarriers {
		if strings.HasPrefix(uk, p) {
			return pmKeyLever(uk[len(p):])
		}
	}
	return lvNone
}

// riskyName: a name some value of which is a reason (a value the line does not show: read, printf -v,
// a number in a config file).
func riskyName(k string) bool { return leverOf(k) != lvNone }

// presentName: a name that is a reason whatever its value (export NAME, the value set elsewhere).
func presentName(k string) bool {
	lv := leverOf(k)
	return lv == lvAny || lv == lvLoads
}

// judgeEnv gives the reason, if any, for one variable and its value.
func (e *extraParse) judgeEnv(k, v string) {
	note := ""
	switch {
	case e.entryEnv && pathName(k) && leverOf(k) != lvHome:
		// an MCP entry's value reaches the server as written: a ~ element of a search path or a path lever is the folder
		// ./~ of its working folder, said as round 2 says it for HOME (entryHomeConfigWhy; round 8, D)
		if w, wrote := argTildeValue(k, strings.TrimSpace(v), pathListSep(v)); wrote != 0 {
			v, note = w, whyDirLiteral
		}
	case (e.win || e.argEnv) && pathName(k):
		// PowerShell and cmd never expand ~ in a value, nor zsh, dash or bash --posix in an MCP add's -e K=~ word (each
		// list element of it): the folder it names, and the reason says bash outside POSIX mode would use the home
		// (HOME-CONFIG-ENV-1 rounds 3–5); PowerShell's list is a ":" one where it has no ";" (round 8, E)
		sep := ":"
		if e.win {
			sep = winListSep(v, e.pwsh)
		}
		if w, wrote := argTildeValue(k, strings.TrimSpace(v), sep); wrote != 0 {
			v = w
			if !e.win && e.noShell == 0 && !e.argGlued {
				note = argTildeNote(wrote)
			}
		}
	}
	if why := e.leverWhy(leverOf(k), k, v); why != "" {
		if note != "" {
			why = withArgTildeNote(why, note)
		}
		e.envMiss(why)
	}
}

// envKey judges a variable whose value is not a string (a number, a boolean or a list in a config
// file: "NODE_TLS_REJECT_UNAUTHORIZED": 0). The name alone is the reason, unless only a folder, a
// program or an option string would be one ("UV_PYTHON": 3.12).
func (e *extraParse) envKey(k string) {
	switch leverOf(k) {
	case lvNone, lvDirs, lvPath, lvHome, lvVenv, lvPython, lvInterp, lvProgram, lvNodeOpts, lvBunOpts, lvShellEnv:
	default:
		e.envMiss(whyOverride + " (" + clip(k, 60) + ")")
	}
}

// leverWhy: the reason a lever set to v is one, or "" when that value is none.
func (e *extraParse) leverWhy(lv lever, k, v string) string {
	name := clip(k, 60)
	plain := whyOverride + " (" + name + ")"
	points := func(why string) string {
		if e.as != "" {
			return why + " (" + name + " points at " + shown(e.as) + ")" // as the line spells it: PowerShell's or cmd's, no ~name
		}
		if v == "" {
			return why + " (" + name + " is empty: the current folder)"
		}
		return why + " (" + name + " points at " + shown(v) + tildeWhy(v) + ")"
	}
	lv0 := strings.ToLower(strings.TrimSpace(v))
	switch lv {
	case lvDirs, lvPath, lvVenv, lvPython, lvInterp, lvProgram:
		// A value whose first element has a tilde-prefix — another user's home or a folder of the project (~name), the
		// current folder (~+, ~-, ~0) — is held whatever the lever, before its own test: the owner's rule, any ~name is
		// held (round 6), and a bare ~m$ for UV_PYTHON or PIP_PYTHON, a folder of the current one first, otherwise
		// passed cwdFirst (round 8, R1). The home (~, ~/…) keeps each lever's own rule.
		// uv's and pip's --python and UV_PYTHON take a version request, ~=3.12 among them (pyRequest): no folder
		if ds := strings.Split(v, pathListSep(v)); listTilde(ds, 0) && !(lv == lvPython && pyRequest.MatchString(lv0)) {
			why := whyOverride
			if lv == lvDirs {
				why = whyLoads
			}
			return points(why)
		}
	}
	switch lv {
	case lvAny:
		return plain
	case lvLoads:
		return whyLoads + " (" + name + ")"
	case lvSource, lvMirror:
		return sourceWhy(k, v, lv == lvMirror)
	case lvConfig:
		if v != "" && v != "/dev/null" && lv0 != "nul" {
			return "installs with a custom registry or config file alalanet cannot see (" + k + ")"
		}
	case lvDirs:
		// An empty value is the current folder for PATH alone: the loaders and runtimes take theirs for
		// unset (glibc, dyld, CPython, Node, Perl, Ruby, uv), though an empty entry of a list they do read.
		e.own = k
		if (v != "" || strings.EqualFold(k, "PATH")) && e.untrustedPathX(v, true) {
			return points(whyLoads)
		}
	case lvPath:
		if e.untrustedPathX(v, false) {
			return points(whyOverride)
		}
	case lvHome:
		// the line reader's rule (dirWhy; for an MCP entry's or a server's env, entryDirWhy: round 2, P2-1), and a value
		// past maxPathValue, which is not read folder by folder
		why := homeConfigWhy(k, v)
		if e.entryEnv {
			why = entryHomeConfigWhy(k, v)
		}
		if why == "" && len(v) > maxPathValue {
			why = homeReason(name, shown(v), "longer than alalanet reads a folder")
		}
		if why != "" {
			return why
		}
	case lvVenv:
		// .venv, $PWD/.venv, env: the project's own virtualenv
		own := venvDir.MatchString(v) && !tmpMarker(strings.ToLower(strings.ReplaceAll(v, `\`, "/")))
		if !own && e.untrustedPathX(v, false) {
			return points(whyOverride)
		}
	case lvPython:
		if cwdFirst(v) || strings.ContainsAny(v, `/\`) && e.untrustedInterpreter(v) {
			return points(whyOverride)
		}
	case lvInterp:
		if strings.ContainsAny(v, `/\`) && e.untrustedInterpreter(v) {
			return points(whyOverride)
		}
	case lvProgram:
		if strings.ContainsAny(v, `/\`) && e.untrustedPathX(v, false) {
			return points(whyOverride) // ./git, /tmp/sh; bash and /bin/bash are the user's own
		}
	case lvOff:
		// npm, pnpm and Yarn 1 switch a check off for the word false alone, trimmed and in lower case:
		// with 0, no, off or FALSE the check stays on. Yarn Berry's own key takes 0 as well.
		if t := strings.TrimSpace(v); t == "false" || t == "0" && strings.HasSuffix(compactKey(k), "enablestrictssl") {
			return plain
		}
	case lvOn:
		if lv0 != "" && !falseLike(lv0) {
			return plain
		}
	case lvNodeOpts:
		if strings.EqualFold(k, "NODE_OPTIONS") {
			name = "NODE_OPTIONS" // the production reader's wording
		}
		if nodeOptionsLoad(v) {
			return whyLoads + " (" + name + " " + shown(v) + ")"
		}
		if nodeDebug.MatchString(unquote(v)) {
			return whyDebug + " (" + name + " " + shown(v) + ")"
		}
	case lvBunOpts:
		if nodeOptionsLoad(v) || bunLoads.MatchString(unquote(v)) {
			return whyLoads + " (BUN_OPTIONS " + shown(v) + ")"
		}
		if nodeDebug.MatchString(unquote(v)) {
			return whyDebug + " (BUN_OPTIONS " + shown(v) + ")"
		}
	case lvShellEnv:
		if strings.ContainsAny(v, `/\.~$`) {
			return plain
		}
	case lvSSH:
		if !plainSSH(v) {
			return plain
		}
	case lvTLS:
		if lv0 == "0" {
			return plain
		}
	case lvBreakpoint:
		if lv0 != "" && lv0 != "0" {
			return plain
		}
	case lvWarnings:
		if warnsImport(v) {
			return whyLoads + " (PYTHONWARNINGS " + shown(v) + ")"
		}
	case lvKeyring:
		if v == "subprocess" || v == "import" { // pip refuses another case
			return plain
		}
	case lvKeyringUV:
		if v == "subprocess" {
			return plain
		}
	case lvStrategy:
		if strings.HasPrefix(lv0, "unsafe") {
			return plain
		}
	case lvUnverified:
		if lv0 != "" && lv0 != "error" && lv0 != "prompt" {
			return plain
		}
	case lvChecksum:
		if lv0 != "" && lv0 != "throw" {
			return plain
		}
	}
	if lv != lvNone && unread(v) {
		// A value the line does not show (read, printf -v) or one too long to expand, in which the
		// lever's own rule found nothing: a mark has no slash, no "0" and no flag in it, and what the
		// reader has not read it does not call harmless.
		return points(whyOverride)
	}
	return ""
}

// warnsImport: whether Python imports a module for a PYTHONWARNINGS value. Entries stand apart by
// commas, each action:message:category:module:lineno; a category with a dot in it is a class of the
// module before the last dot, which Python imports. A dot in the message or the module field imports
// nothing, and an entry of more than five fields is dropped whole.
func warnsImport(v string) bool {
	for _, entry := range strings.Split(v, ",") {
		if f := strings.Split(entry, ":"); len(f) >= 3 && len(f) <= 5 && strings.Contains(f[2], ".") {
			return true
		}
	}
	return false
}

// falseLike: how uv and Corepack spell "off" for a switch (a lower-case value).
func falseLike(lv string) bool {
	switch lv {
	case "0", "false", "no", "off", "n", "f", "null":
		return true
	}
	return false
}

// nodeMirrorHosts: where Node's and Electron's own headers and binaries come from.
var nodeMirrorHosts = map[string]bool{"nodejs.org": true, "electronjs.org": true, "www.electronjs.org": true}

// sourceWhy: a registry, index or mirror variable. Each address in the value (pip takes several,
// uv names them: corp=https://…) is read as the production reader reads one, so the same reason is not
// given twice: a public registry over https is none; plain http is one (the download can be changed in
// transit) except on this machine, where the registry itself is the reason (verdaccio on localhost).
func sourceWhy(k, v string, mirror bool) string {
	for _, f := range strings.Fields(v) {
		if i := strings.Index(f, "://"); i > 0 {
			if j := strings.LastIndexByte(f[:i], '='); j >= 0 {
				f = f[j+1:]
			}
		}
		host, scheme := f, ""
		if u, err := url.Parse(f); err == nil && u.Host != "" {
			host, scheme = u.Hostname(), u.Scheme // url.Parse gives the scheme in lower case
		}
		lh := strings.ToLower(host)
		custom := "installs from a custom registry or index (" + shown(host) + "): alalanet judges packages on the public registries only"
		switch {
		case lh == "localhost" || lh == "127.0.0.1" || lh == "::1":
			return custom
		case scheme == "http":
			return whyHTTP + " (" + clip(k, 60) + ")"
		case !defaultRegistries[lh] && !(mirror && nodeMirrorHosts[lh]):
			return custom
		}
	}
	return ""
}

// pyRequest: what uv reads as a version, a specifier list, an implementation or a download key (the
// formats its docs list), in lower case. All but the key it reads before it looks at the current folder
// (uv 0.9.0, crates/uv-python/src/discovery.rs: PythonRequest::parse, VersionRequest::from_str). A
// version is one to three numbers or a wheel tag (312), a pre-release only after two (3.14rc1, not
// 3rc1), then a variant (3.13t, 3.13+freethreaded). "python" needs a version: alone it is a name uv
// looks for in the folder first, like any other. Blanks are read as uv reads them and nowhere else: its
// version parser skips ASCII blanks around a version (uv-pep440 version.rs, parse_pattern), after the
// variant is cut off the end (so "3.13t " is no version); a specifier takes blanks around its operator
// and its version (version_specifier.rs, FromStr); a name takes none (" pypy" is a file name).
var pyRequest = func() *regexp.Regexp {
	num := `v?([0-9]+|([0-9]+\.[0-9]+(\.[0-9]+)?|[0-9]{2,})([-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?[0-9]+)?)`
	variant := `\+?(t|d|td|freethreaded|debug|freethreaded\+debug)`
	ver := num + `(` + variant + `)?`
	blank := `[ \t\n\f\r]*`
	spec := `\s*(~=|===?|!=|<=?|>=?)\s*[0-9]+(\.[0-9]+)*(\.\*)?\s*`
	impl := `(cpython|cp|pypy|pp|graalpy|gp|pyodide)`
	return regexp.MustCompile(`^(any|default|` + blank + num + `(` + variant + `|` + blank + `)|` + spec + `(,` + spec + `)*|python@?` + ver + `|` +
		impl + `(@?` + ver + `)?|` + impl + `-[0-9][0-9a-z.+_-]*)$`)
}()

// cwdFirst: a bare name uv and pip take for a folder or a file of the current folder before anything
// else (pip takes nothing else: identify_python_interpreter): not what uv reads first (pyRequest), not
// a variable, a placeholder or a range (the value is not on the line), not a folder named as a
// virtualenv (the project's own, as lvVenv). uvx --python py runs the repository's py when it has one.
// The value is read as given, in lower case as uv lowers it.
func cwdFirst(v string) bool {
	lv := strings.ToLower(v)
	return lv != "" && !strings.ContainsAny(lv, "/\\$%<>{}") && !pyRequest.MatchString(lv) && !venvDir.MatchString(lv)
}

// venvDir: a virtualenv folder by its usual names (.venv, venv, env, .venv-3.12), at any depth.
var venvDir = regexp.MustCompile(`(?i)(^|[/\\])\.?v?env[^/\\]*[/\\]?$`)

// nodeLoadsX: the production reader's NODE_OPTIONS flags and the others that run code
// (--openssl-config loads an engine; a snapshot or a package map decides what code a require gets).
// --conditions is not one: it picks among the package's own files.
var nodeLoadsX = regexp.MustCompile(`(^|\s)(-r|--require|--import|--loader|--experimental-loader|--preload|--openssl-config|--openssl-shared-config|--snapshot-blob|--experimental-package-map|--test-global-setup)(=|\s|$)`)

// nodeDebug: flags that open a debugger anyone who reaches the port can drive. --inspect-port is not
// one: it names a port and opens none.
var nodeDebug = regexp.MustCompile(`(^|\s)(--inspect|--inspect-brk|--inspect-wait)(=|\s|$)`)

// nodeReporter: --test-reporter names a module unless it is one of Node's own.
var nodeReporter = regexp.MustCompile(`(^|\s)--test-reporter(=|\s+)(\S+)`)

var nodeOwnReporters = map[string]bool{"spec": true, "tap": true, "dot": true, "junit": true, "lcov": true}

// bunLoads: bun's own options that BUN_OPTIONS can carry: a config file, an env file, a registry, a CA.
var bunLoads = regexp.MustCompile(`(^|\s)(-c|--config|--env-file|--registry|--cafile|--ca)(=|\s|$)`)

func nodeOptionsLoad(v string) bool {
	u := unquote(v)
	if nodeLoadsX.MatchString(u) {
		return true
	}
	for _, m := range nodeReporter.FindAllStringSubmatch(u, 8) {
		if !nodeOwnReporters[m[3]] {
			return true
		}
	}
	return false
}

// sshOptions: ssh -o keys that pick a key, a user or a port, or tune the connection. Not here, and so
// a reason: what runs a program (ProxyCommand, LocalCommand, KnownHostsCommand, PKCS11Provider), reads
// another config (Include), or moves the connection (HostName, ProxyJump, HostKeyAlias, ControlPath).
var sshOptions = func() map[string]bool {
	m := map[string]bool{}
	for _, k := range strings.Fields("stricthostkeychecking userknownhostsfile identitiesonly identityfile batchmode connecttimeout " +
		"serveraliveinterval serveralivecountmax loglevel port user addkeystoagent preferredauthentications pubkeyauthentication " +
		"passwordauthentication hostkeyalgorithms pubkeyacceptedalgorithms pubkeyacceptedkeytypes kexalgorithms ciphers macs " +
		"compression tcpkeepalive connectionattempts ipqos identityagent certificatefile") {
		m[k] = true
	}
	return m
}()

func sshOptionOK(kv string) bool {
	k, v, ok := strings.Cut(kv, "=")
	if !ok || !sshOptions[strings.ToLower(k)] {
		return false
	}
	switch lv := strings.ToLower(v); strings.ToLower(k) {
	case "stricthostkeychecking":
		return lv != "no" && lv != "off" // any host key is accepted
	case "userknownhostsfile":
		return lv != "/dev/null" && lv != "nul"
	}
	return true
}

// plainSSH: a GIT_SSH_COMMAND that is ssh itself with options that pick a key, a port or a user
// (GIT_SSH_COMMAND="ssh -i ~/.ssh/deploy -o IdentitiesOnly=yes", the usual way to use a deploy key).
// Git runs the value through a shell: another program, a shell operator, an option that runs a program
// or moves the connection, or a check switched off is a reason.
func plainSSH(v string) bool {
	if strings.ContainsAny(v, ";|&<>`(\n") {
		return false
	}
	w := strings.Fields(unquote(v))
	if len(w) == 0 {
		return true // unset in effect: git's own default
	}
	prog := strings.ToLower(strings.ReplaceAll(w[0], `\`, "/"))
	abs := strings.HasPrefix(prog, "/") || len(prog) > 2 && isASCIILetter(prog[0]) && prog[1] == ':' && prog[2] == '/'
	if prog != "ssh" && !(abs && (strings.HasSuffix(prog, "/ssh") || strings.HasSuffix(prog, "/ssh.exe")) && !tmpMarker(prog)) {
		return false
	}
	for i := 1; i < len(w); i++ {
		switch x := w[i]; {
		case x == "-i" || x == "-p" || x == "-l":
			i++ // a key file, a port, a user
		case strings.HasPrefix(x, "-i") || strings.HasPrefix(x, "-p") || strings.HasPrefix(x, "-l"): // -p2222
		case x == "-4" || x == "-6" || x == "-q" || x == "-T" || x == "-n" || x == "-a" || x == "-x" || x == "-C",
			len(x) > 1 && strings.Trim(x[1:], "v") == "" && x[0] == '-': // -v, -vv, -vvv
		case x == "-o":
			if i++; i >= len(w) || !sshOptionOK(w[i]) {
				return false
			}
		case strings.HasPrefix(x, "-o"):
			if !sshOptionOK(x[2:]) {
				return false
			}
		default:
			return false // -F, -J, -S, a forward, a host, a command
		}
	}
	return true
}

// Launcher flags.

// pmValueFlags: options of npm, pnpm, Yarn and pip that take their value as the next word (the
// production reader's valueFlags are the installers'): what follows them is not a subcommand, a key or
// a package.
var pmValueFlags = func() map[string]bool {
	m := map[string]bool{}
	for _, k := range strings.Fields("--location -L --userconfig --globalconfig -C --editor --loglevel --cache --otp --scope --tag " +
		"--dir --store-dir --npmrc-auth-file --env-file --https-proxy --http-proxy --proxy --no-proxy --noproxy --reporter --filter -F " +
		"--cwd --use-yarnrc --cache-folder --global-folder --modules-folder --link-folder --mutex --network-concurrency " +
		"--network-timeout --log --keyring-provider --retries --timeout --exists-action --trusted-host --cert --client-cert " +
		"--cache-dir --use-feature --use-deprecated --resume-retries --pnpmfile --global-pnpmfile --script-shell --node-options") {
		m[k] = true
	}
	return m
}()

// pmPositional: the index of the first word from i on that is not an option or an option's value
// (len(rest) when none; "--" counts).
func pmPositional(rest []string, i int) int {
	for j := i; j < len(rest); j++ {
		x := rest[j]
		if x == "--" {
			return j
		}
		if strings.HasPrefix(x, "-") && len(x) > 1 {
			if !strings.Contains(x, "=") && (valueFlags[x] || pmValueFlags[x]) {
				j++
			}
			continue
		}
		return j
	}
	return len(rest)
}

// pmVerbs: subcommands of npm, pnpm, Yarn and bun, after which the manager still reads its own
// options. Another first word is a script or a binary of the project (yarn babel src --plugins x, bun
// vite --config v.ts): what follows it is that program's argv.
var pmVerbs = func() map[string]bool {
	m := map[string]bool{}
	for _, k := range strings.Fields("install i add a ci clean-install install-test it cit install-ci-test update up upgrade remove rm " +
		"uninstall un unlink link ln rebuild rb dedupe prune audit outdated init create exec x dlx run run-script test t start stop " +
		"restart config c set get cache pack publish version view info show why list ls fetch import store patch global workspace " +
		"workspaces pm explore fund doctor ping query pkg deploy approve-builds self-update setup env npm plugin " +
		"upgrade-interactive bin root repo docs search dist-tag shrinkwrap login node") {
		m[k] = true
	}
	return m
}()

// ownOptionsEnd: where npm, pnpm, Yarn or bun stops reading its own options. npm reads them anywhere
// up to "--"; the others hand what follows a script's or a binary's name to it (pnpm run build --config
// x, yarn exec tsc --project p).
func ownOptionsEnd(cmd string, rest []string) int {
	p := pmPositional(rest, 0)
	if p >= len(rest) || rest[p] == "--" {
		return len(rest)
	}
	switch v := rest[p]; {
	case !pmVerbs[v]:
		return p
	case cmd != "npm" && (v == "run" || v == "run-script" || v == "exec" || v == "test" || v == "t" || v == "start" || v == "node"):
		return pmPositional(rest, p+1)
	}
	return len(rest)
}

// pmFlag judges an option of npm, pnpm, Yarn or bun: a config key given as --key is the lever the
// key is (--script-shell ./x, --pnpmfile, --no-strict-ssl), under the flag's reason.
func (e *extraParse) pmFlag(cmd, name, val string, hasVal bool, why string) {
	if key, ok := strings.CutPrefix(name, "--config."); ok {
		e.envBound("npm_config_"+key, val) // pnpm --config.script-shell=…; flag bound the value
		return
	}
	switch {
	case name == "--env-file" && (cmd == "pnpm" || cmd == "pnpx" || cmd == "bun" || cmd == "bunx"):
		// pnpm's and bun's option; npm, npx and Yarn have none (nopt reads an unknown --env-file as a switch)
		if val != "" {
			e.fromFile = append(e.fromFile, val) // a reason before a package the line names (reasons)
		}
		return
	case cmd == "bun" && (name == "--config" || name == "-c"):
		if val != "" {
			e.miss(why) // a bunfig.toml of the line's choosing: its registry and preloads
		}
		return
	case cmd == "npm" || cmd == "npx":
		// nopt reads -name as --name, and expands a shorthand, a cluster and a key's unambiguous prefix: each key the
		// word sets in any npm version is judged, the word's own name too (READER-NPM-ABBREV-1)
		if name = npmTwoDash(name); strings.HasPrefix(name, "--") {
			key, neg := strings.CutPrefix(name[2:], "no-")
			e.pmKey(key, neg, name, val, why)
			for _, k := range npmOptionKeys(name) {
				if k != key {
					e.pmKey(k, npmNegated(name[2:]), name, val, why)
				}
			}
		}
		return
	case !strings.HasPrefix(name, "--"):
		return
	}
	key, neg := strings.CutPrefix(name[2:], "no-")
	e.pmKey(key, neg, name, val, why)
}

// pmKey judges one config key an npm, pnpm, Yarn or bun option word sets (name: the word as written), negated by
// "no-" or set to val.
func (e *extraParse) pmKey(key string, neg bool, name, val, why string) {
	lv := pmKeyLever(key)
	switch c := compactKey(key); {
	case c == "prefix", c == "package", c == "call":
		// --prefix ./app installs a subfolder; -p/--package and -c/--call the production reader and npmCall
		// read. (A key that is no lever has no reason in leverWhy.)
	case neg:
		if lv == lvOff {
			e.miss(why) // --no-strict-ssl
		}
	case lv == lvOff:
		if val == "false" || unread(val) {
			// --strict-ssl=false, nopt's "--strict-ssl false", a value the line does not show. Any other
			// word (=0, =no, =FALSE) nopt leaves as an argument of its own, and the check stays on.
			e.miss(why)
		}
	case lv == lvSource || lv == lvMirror || lv == lvConfig:
		if w := e.leverWhy(lv, name, val); w != "" {
			e.miss(w) // a registry's or a config file's own reason, in the production reader's words
		}
	default:
		if e.leverWhy(lv, name, val) != "" {
			e.miss(why)
		}
	}
}

// Settings written with "config set".

// configSet reads "npm config set KEY VALUE" in the grammar each tool documents: the setting outlives
// the line, and later installs use it (sixth review: npm config set registry …). npm takes several
// pairs, as "key value" or "key=value"; pnpm one pair in either form; Yarn "name value", where the name
// may be a path (npmScopes.acme.npmRegistryServer); pip "section.option value". A key without a value
// removes the setting: no reason.
func (e *extraParse) configSet(cmd string, rest []string) {
	pip := cmd == "pip" || cmd == "pip3"
	if !pip && cmd != "npm" && cmd != "pnpm" && cmd != "yarn" {
		return
	}
	var pos []string
	for i := 0; i < len(rest); i++ {
		switch x := rest[i]; {
		case x == "--":
			pos = append(pos, rest[i+1:]...)
			i = len(rest)
		case strings.HasPrefix(x, "-") && len(x) > 1:
			if !strings.Contains(x, "=") && (valueFlags[x] || pmValueFlags[x]) {
				i++
			}
		default:
			pos = append(pos, x)
		}
	}
	switch {
	case len(pos) >= 2 && (pos[0] == "config" || pos[0] == "c" && (cmd == "npm" || cmd == "pnpm")) && pos[1] == "set":
		pos = pos[2:]
	case len(pos) >= 1 && pos[0] == "set" && (cmd == "npm" || cmd == "pnpm"):
		pos = pos[1:]
	default:
		return
	}
	for i := 0; i < len(pos); i++ {
		k, v := pos[i], ""
		switch {
		case cmd == "npm" || cmd == "pnpm":
			if a, b, ok := strings.Cut(k, "="); ok {
				k, v = a, b
			} else if i+1 < len(pos) {
				i++
				v = pos[i]
			}
		default: // yarn, pip: "name value", once
			if i+1 < len(pos) {
				v = pos[i+1]
			}
			i = len(pos)
		}
		if v == "" {
			continue
		}
		switch {
		case pip:
			if sec, after, ok := strings.Cut(k, "."); ok {
				// pip install reads the sections global and install, then the environment (cli/parser.py
				// _get_ordered_configuration_items: "global", the command's name, ":env:"); a key is the long option's name,
				// "_" as "-" (configuration.py _normalize_name): global.pypi-url and install.pypi_url are PIP_PYPI_URL
				if sec = strings.ToLower(sec); sec != "global" && sec != "install" {
					continue
				}
				k = after
			}
			e.env("PIP_"+strings.ToUpper(strings.ReplaceAll(k, "-", "_")), v)
		case cmd == "yarn":
			if k = yarnSetting(k, v); k != "" {
				e.env("YARN_"+snakeUpper(k), v) // npmRegistryServer -> YARN_NPM_REGISTRY_SERVER
			}
		default:
			e.env("npm_config_"+k, v)
		}
	}
}

// yarnSetting: the setting a Yarn config path sets: the last name of npmScopes.acme.npmRegistryServer
// when that is a lever; the first when a whole map is given as JSON (npmScopes '{…}'); nothing for a
// path that ends elsewhere (npmRegistries["//host"].npmAuthToken is a credential).
func yarnSetting(k, v string) string {
	i := strings.IndexAny(k, ".[")
	if i < 0 {
		return k
	}
	if j := strings.LastIndexAny(k, ".]"); j >= 0 && k[j] == '.' && pmKeyLever(k[j+1:]) != lvNone {
		return k[j+1:]
	}
	if strings.HasPrefix(v, "{") || strings.HasPrefix(v, "[") {
		return k[:i]
	}
	return ""
}

func snakeUpper(k string) string {
	var b strings.Builder
	for i, r := range k {
		if r >= 'A' && r <= 'Z' && i > 0 {
			b.WriteByte('_')
		}
		if r == '-' || r == '.' {
			r = '_'
		}
		b.WriteRune(r)
	}
	return strings.ToUpper(b.String())
}
