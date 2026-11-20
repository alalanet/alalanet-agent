package installread

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// The Claude Code install hook (ADR-0052). The alalanet-guard plugin declares HTTP PreToolUse
// hooks whose `if` rules (Bash(npm install *), Bash(npx *), Bash(pip install *) ...) make Claude
// Code send us only install commands. We read the install targets out of the command, run
// install_check on each and answer like a command hook: block -> deny, hold -> ask, allow -> nothing.
// The command line itself is never stored or logged; only the targets reach install_check.

// MaxHookTargets bounds the install_check calls one command can cause; more targets than this are a
// reason to ask, never a silent pass (deep review IMP-1).
const MaxHookTargets = 10

// valueFlags take the next word as their value, so that word is not a package.
var valueFlags = map[string]bool{
	"-r": true, "--requirement": true, "-c": true, "--constraint": true, "-e": true, "--editable": true,
	"-i": true, "--index-url": true, "--extra-index-url": true, "-f": true, "--find-links": true,
	"-t": true, "--target": true, "--prefix": true, "--registry": true, "-w": true, "--workspace": true,
	"--python": true, "-p": true, "--package": true, "--from": true, "--with": true, "--index": true, "--default-index": true,
	// pip's and uv's build settings (-C key=value, pip.pypa.io/en/stable/cli/pip_install, docs.astral.sh/uv/reference/cli):
	// the value is not a package (REPO-POL-NPMRC round 8)
	"-C": true, "--config-setting": true, "--config-settings": true,
}

var defaultRegistries = map[string]bool{"registry.npmjs.org": true, "registry.yarnpkg.com": true, "pypi.org": true,
	"pypi.python.org": true, "files.pythonhosted.org": true}

// The wrappers Claude Code itself strips before matching a command, plus the shell keywords that start
// a control-flow body: the install inside still runs.
var hookWrappers = map[string]bool{"sudo": true, "doas": true, "env": true, "time": true, "nice": true, "exec": true, "nohup": true, "eval": true,
	"command": true, "builtin": true, "noglob": true, "xargs": true, "corepack": true, "then": true, "do": true,
	"else": true, "elif": true, "if": true, "while": true, "until": true, "!": true, "stdbuf": true, "timeout": true,
	"busybox": true, "toybox": true, // busybox sh -c …: the applet is the command (READER-SHELLS)
	"arch": true, "nocorrect": true} // arch -x86_64 npm i x (Rosetta), zsh's nocorrect: a precommand modifier (round 6)

// wrapperValueFlags: the options of each wrapper that take a value word (env -u NAME, nice -n 10,
// xargs -n 1, timeout -s KILL, sudo -u root). Per wrapper: sudo -n, -S, -k and -s take none, and a
// shared table read "sudo -n npm i x" as -n's value npm (independent review of round 3, finding 9).
var wrapperValueFlags = map[string]map[string]bool{
	"sudo": {"-u": true, "-g": true, "-C": true, "-p": true, "-r": true, "-t": true, "-U": true, "-D": true, "-R": true, "-T": true,
		"--user": true, "--group": true, "--close-from": true, "--prompt": true, "--role": true, "--type": true, "--other-user": true,
		"--chdir": true, "--chroot": true, "--command-timeout": true},
	"env":     {"-u": true, "-C": true, "--unset": true, "--chdir": true, "-a": true, "--argv0": true, "-P": true, "-L": true, "-U": true, "--env0-from": true},
	"nice":    {"-n": true, "--adjustment": true},
	"xargs":   {"-a": true, "--arg-file": true, "-n": true, "-I": true, "-L": true, "-P": true, "-s": true, "-d": true, "-E": true, "--max-args": true, "--max-procs": true, "--delimiter": true, "--max-chars": true, "--max-lines": true, "--replace": true},
	"timeout": {"-s": true, "-k": true, "--signal": true, "--kill-after": true},
	"stdbuf":  {"-i": true, "-o": true, "-e": true},
	"time":    {"-f": true, "-o": true, "--format": true, "--output": true},
	"exec":    {"-a": true},
	"doas":    {"-u": true, "-C": true, "-a": true},
	"arch":    {"-arch": true, "-e": true, "-d": true}, // arch -arch NAME, -e VAR=val, -d VAR take a value; -x86_64 none
}

// wrapperName: the wrapper a command word runs, or "". /usr/bin/sudo and /usr/bin/doas (second
// review) and s\udo or \sudo, which bash runs as sudo (fourth review). A VAR=value word is never a
// wrapper and keeps its backslashes: npm reads https://evil.example\@registry.npmjs.org as
// evil.example (fifth review).
func wrapperName(x string) string {
	if strings.Contains(x, "=") {
		return ""
	}
	// s\udo and \sudo reach here as sudo: splitShell drops the backslash of a word that is not a Windows path
	// (READER-ESCAPE-1)
	if n := launchBase(x); hookWrappers[n] {
		return n
	}
	return ""
}

// looksWindowsPath: a word whose POSIX reading keeps its backslashes — a drive or UNC path (C:\…, \\server\…), or the
// value of a NAME=value word that begins as a Windows path other than a $ or ~ expansion (APPDATA=C:\…,
// PATH=%USERPROFILE%\bin). Every other word is the shell's POSIX argv, the backslash dropped (bash, dash and zsh read
// .\env as .env, ${X-}\-g as -g: the oracle shows it); a word PowerShell or cmd reads as another path is read a second
// time in that spelling (winSpelling), and the stricter decision wins (READER-ESCAPE-1, round 2).
func looksWindowsPath(raw string) bool {
	if k, v, ok := strings.Cut(raw, "="); ok && k != "" && !strings.ContainsAny(k, `\/:%$~ `) && windowsPathStart(v) &&
		v[0] != '$' && v[0] != '~' {
		// APPDATA=C:\Users\me\AppData\Roaming, PATH=C:\tools;%PATH%. A value that begins with a $ or ~ expansion is not kept:
		// the backslash after it is the POSIX shell's escape (NODE_OPTIONS=${X-}\-\-inspect=… is --inspect=…), and its
		// Windows spelling is the second reading (winSpelling)
		return true
	}
	// a whole word keeps its backslashes only when it is an unambiguous drive or UNC path. A $, ~ or %VAR% expansion
	// before a backslash is not kept (the backslash may be an escape the shell drops: ${ZZ-}\-g), and a Windows program
	// path (.\venv\Scripts\pip.exe, np\m.cmd) stays the POSIX word and is read a second time through the union
	// (winSpelling in flushWord), so its POSIX reading (np\m.cmd is npm.cmd) is not lost (READER-ESCAPE-1 round 2).
	return driveOrUNC(raw)
}

// driveOrUNC: C:\… or \\server\… with no slash — a Windows path no POSIX word is unquoted into. With a slash (C:/x\y,
// b:/py\thon) the word is POSIX-shaped and a backslash in it is the shell's escape, as windowsPathStart reads it.
func driveOrUNC(s string) bool {
	switch {
	case strings.Contains(s, "/"):
		return false
	case len(s) >= 3 && isASCIILetter(s[0]) && s[1] == ':' && s[2] == '\\':
		return true
	case strings.HasPrefix(s, `\\`) && len(s) > 2 && s[2] != '\\':
		return true
	}
	return false
}

// winExeName: a word ends in a Windows executable suffix (python3.12.exe), path or not.
func winExeName(w string) bool {
	low := strings.ToLower(w)
	if i := strings.LastIndexAny(low, `/\`); i >= 0 {
		low = low[i+1:]
	}
	return strings.HasSuffix(low, ".exe") || strings.HasSuffix(low, ".cmd") || strings.HasSuffix(low, ".bat") || strings.HasSuffix(low, ".ps1")
}

// winExePath: a Windows path to a program that PowerShell and cmd run — a relative one too (.\venv\Scripts\pip.exe,
// node_modules\.bin\npx.cmd, tools\uv.exe). The hook takes the PowerShell tool, so a word that POSIX turns into no
// program is read a second time as this path and the stricter decision wins (READER-ESCAPE-1 round 2, R2). It must
// end in a Windows executable suffix and hold a backslash the base kept (before an ordinary character).
func winExePath(raw string) bool {
	if !strings.Contains(raw, `\`) || strings.Contains(raw, "/") {
		return false
	}
	base := raw
	if i := strings.LastIndexByte(base, '\\'); i >= 0 {
		base = base[i+1:]
	}
	low := strings.ToLower(base)
	if strings.HasSuffix(low, ".exe") || strings.HasSuffix(low, ".cmd") || strings.HasSuffix(low, ".bat") ||
		strings.HasSuffix(low, ".ps1") { // not .com: it ends every domain name (sentry.example.com)
		return true
	}
	// a multi-component relative path with no extension (.\venv\Scripts\pip): PowerShell and cmd find pip.exe there.
	if (strings.HasPrefix(raw, `.\`) || strings.HasPrefix(raw, `..\`)) && strings.Count(raw, `\`) >= 2 {
		return true
	}
	return false
}

// winProgramPath: a relative Windows path with no suffix to a program the reader reads (venv\Scripts\pip,
// node_modules\.bin\npx, bin\npx), as a command's first word only: there PowerShell and cmd run it. Anywhere else a
// respelled argument (ds\py, --\python), an option (--use-\npm) or an assignment (PYTHON=\python3) is no path. A
// respelling of a program name makes one only from a name that ends in another (p\npm: pnpm, whose reading is npm's).
func winProgramPath(raw string) bool {
	b := launchBase(raw)
	return strings.Contains(raw, `\`) && !strings.ContainsAny(raw, "/=") && raw[0] != '\\' && raw[0] != '-' &&
		(winPrograms[b] || PythonLauncher(b)) // any Python launcher or pip by the pattern (PIP-VERSIONED-1 round 4)
}

// programSlot: the next word is where a command's program stands — the first word, or the first after wrappers and
// their options: sudo, env, time, nohup, exec, and cmd /c, start, call, Start-Process (-FilePath) that PowerShell and
// cmd run a program through (round 3, N3: sudo venv\Scripts\pip install x). The wrapper words are compared as the shell
// gives them; an option (a word starting with - or /) counts only after a wrapper.
func programSlot(words []string) bool {
	for i, w := range words {
		lw := strings.ToLower(w)
		switch {
		case hookWrappers[lw] || winWrappers[lw]:
		case i > 0 && (strings.HasPrefix(w, "-") || strings.HasPrefix(w, "/")) && !strings.Contains(w, "="):
		default:
			return false
		}
	}
	return true
}

// winWrappers: the words cmd and PowerShell run a program through.
var winWrappers = map[string]bool{"cmd": true, "cmd.exe": true, "start": true, "call": true, "start-process": true, "saps": true}

// winPrograms: the programs a Windows path to which is read a second time without a suffix (winProgramPath), beside
// every Python launcher and pip, which PythonLauncher takes by the pattern (python3.12, pypy3, pyw, pip3.12).
var winPrograms = map[string]bool{"npm": true, "npx": true, "pnpm": true, "pnpx": true, "yarn": true, "bun": true, "bunx": true,
	"uv": true, "uvx": true, "pipx": true, "deno": true}

// rawSpelling: the word with the dropped backslashes (at bs) put back — the Windows spelling, whether or not it is a
// path. "" when nothing was dropped.
func rawSpelling(w string, bs []int) string {
	if len(bs) == 0 {
		return ""
	}
	var b strings.Builder
	last := 0
	for _, p := range bs {
		b.WriteString(w[last:p])
		b.WriteByte('\\')
		last = p
	}
	b.WriteString(w[last:])
	return b.String()
}

var shellNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// windowsPathStart: a value that begins the way a Windows path does (a drive, a UNC share, ~ or %~, a $ expansion, a
// %NAME% then a backslash) and holds a backslash and no slash. It judges assignment values (looksWindowsPath) and the
// second, Windows reading of a word (winSpelling), never a whole word's POSIX reading.
func windowsPathStart(s string) bool {
	if !strings.Contains(s, `\`) {
		return false
	}
	switch {
	case strings.Contains(s, "/"):
		return false // C:/Program Files/… and b:/x are POSIX-shaped: a backslash there is the shell's escape
	case len(s) >= 3 && isASCIILetter(s[0]) && s[1] == ':' && s[2] == '\\':
		return true
	case strings.HasPrefix(s, `\\`) && len(s) > 2 && s[2] != '\\':
		return true
	case s[0] == '~' || strings.HasPrefix(s, "%~"): // %~dp0node_modules\.bin: a batch file's own folder
		return true
	case s[0] == '$': // an assignment value that is a $ expansion of a path (windowsPathStart judges only values now)
		return len(s) > 1 && (isASCIILetter(s[1]) || s[1] == '_' || s[1] == '{')
	case s[0] == '%':
		if e := strings.IndexByte(s[1:], '%'); e > 0 && shellNameRe.MatchString(s[1:e+1]) && strings.HasPrefix(s[e+2:], `\`) {
			return true
		}
	}
	return false
}

// windowsWord: the word w with the backslashes splitShell dropped before ordinary characters (at the offsets bs) put
// back, and its quoted parts' offsets moved to match (the escapes put back are no escapes there), when that raw
// spelling is a Windows path; ok false otherwise.
func windowsWord(w string, bs []int, segs [][3]int) (raw string, out [][3]int, ok bool) {
	if len(bs) == 0 {
		return "", nil, false
	}
	var b strings.Builder
	last := 0
	for _, p := range bs {
		b.WriteString(w[last:p])
		b.WriteByte('\\')
		last = p
	}
	b.WriteString(w[last:])
	raw = b.String()
	if !looksWindowsPath(raw) {
		return "", nil, false
	}
	// bs and the segments' starts both ascend as the word was read, so one pass of two counters moves every offset:
	// linear in the word, where a scan of bs per segment was quadratic on a long Windows path of escapes
	is, ie := 0, 0 // the backslashes put back before a segment's start, before its end
	for _, sg := range segs {
		for is < len(bs) && bs[is] < sg[0] {
			is++
		}
		if sg[2] == 3 && is < len(bs) && bs[is] == sg[0] {
			continue // an escape put back: a literal backslash there, no escape
		}
		if ie < is {
			ie = is
		}
		for ie < len(bs) && bs[ie] < sg[1] {
			ie++
		}
		out = append(out, [3]int{sg[0] + is, sg[1] + ie, sg[2]})
	}
	return raw, out, true
}

// hookTakesValue: an option that takes the next word, alone (sudo -u root) or last in a cluster of
// short options (sudo -nu root, doas -nu root: third review). As getopt reads it, the first option
// of a cluster that takes a value takes the rest of the word (sudo -uroot, -nuroot): then the next
// word is the command (fourth review).
func hookTakesValue(wrapper, flag string) bool {
	return takesNext(wrapperValueFlags[wrapper], flag)
}

// takesNext reports whether a short or long option word leaves its value to the next word.
func takesNext(values map[string]bool, flag string) bool {
	if values[flag] {
		return true
	}
	if len(flag) < 3 || flag[0] != '-' || flag[1] == '-' || strings.Contains(flag, "=") {
		return false
	}
	for i := 1; i < len(flag); i++ {
		if values["-"+flag[i:i+1]] {
			return i == len(flag)-1 // last letter: the next word; otherwise the rest is the value
		}
	}
	return false
}

// mcpClientPackages are the npm packages of the agent CLIs whose "mcp add NAME -- cmd" runs cmd.
var mcpClientPackages = map[string]bool{"@anthropic-ai/claude-code": true, "@openai/codex": true, "@google/gemini-cli": true}

// harmlessCommands change nothing an install check reads: "cd app && npm i x" is still an install line.
// Filters that only read the output piped into them count as well (npm i x 2>&1 | tail -5); sed and
// awk do not: they can run commands.
var harmlessCommands = map[string]bool{"cd": true, "pushd": true, "popd": true, "true": true, ":": true, "set": true,
	"export": true, "echo": true, "printf": true, "tail": true, "head": true, "grep": true, "egrep": true, "tee": true,
	"wc": true, "sort": true, "uniq": true, "cut": true, "less": true, "more": true, "cat": true, "column": true, "nl": true, "tr": true,
	"mkdir": true, "which": true, "type": true, "whereis": true, "hash": true, "declare": true, "typeset": true, "setx": true}

// substInstall: an install whose package words come from a command substitution the line does not
// show: `npm i $(cat f)`, `pip install `+"`cat r`"+`, or a runner whose package itself is substituted
// (`npx $(cat name)`). The words are not in the line, so they cannot be checked (round 3, R3-PLAN-02).
// pnpm's, Yarn's and bun's exec run what the project already has and fetch nothing (runnerVerbs): not here.
var substInstall = regexp.MustCompile("(?i)\\b(?:(?:npm|pip3?|uv|pipx)\\s+(?:install|i|add|dlx|exec|x)|(?:pnpm|pn|yarn|bun)\\s+(?:install|i|add|dlx|x))\\b[^;|&\\n]*(\\$\\([^(]|`|<\\()" +
	"|\\b(npx|bunx|pnpx|pnx|uvx)\\s+(-\\S+\\s+)*[\"']?(\\$\\([^(]|`)" +
	// go env -w with its pairs from a substitution: what it writes is not in the line (ECO-1 Go, round 3, P2-3)
	"|\\bgo(?:1[0-9a-z.]*|tip)?\\s+env\\s[^;|&\\n]*?-?-w\\b[^;|&\\n]*(\\$\\([^(]|`)")

var whichSubst = regexp.MustCompile("\\$\\((?:which|command -v|type -p)\\s+([A-Za-z0-9._-]+)\\)|`(?:which|command -v|type -p)\\s+([A-Za-z0-9._-]+)`")

var packageManagers = map[string]bool{"npm": true, "pnpm": true, "yarn": true, "bun": true, "npx": true, "bunx": true,
	"pnpx": true, "pip": true, "pip3": true, "uv": true, "uvx": true, "pipx": true, "deno": true}

var installVerbs = map[string]bool{"install": true, "i": true, "add": true, "dlx": true, "exec": true, "x": true}

// verbManagers: the package managers whose subcommand verbAfter finds (npm, pnpm, Yarn, bun).
var verbManagers = map[string]bool{"npm": true, "pnpm": true, "yarn": true, "bun": true}

// runnerVerbs: per package manager, the subcommands that fetch a package from the registry to run it — npm exec
// (alias x), pnpm dlx, Yarn dlx, bun x. pnpm's and Yarn's exec run a binary the project already has
// (node_modules/.bin) and bun's exec a shell script: they fetch nothing (pnpm.io/cli/exec, yarnpkg.com/cli/exec,
// bun's own help text, read 2026-11-14; RT-1 round 3).
var runnerVerbs = map[string][]string{"npm": {"exec", "x"}, "pnpm": {"dlx"}, "yarn": {"dlx"}, "bun": {"x"}}

// pmShortValueFlags: per package manager, the short options that take the next word as their value — npm's
// shorthands for --workspace, --prefix, --location, --call and --message (docs.npmjs.com/cli/v11/using-npm/config),
// pnpm's for --dir and --filter (pnpm.io/pnpm-cli, pnpm.io/filtering), bun's for --config and --filter
// (bun.sh/docs/cli/add); Yarn has none. A short option means different things to different managers: npm -w takes a
// workspace, pnpm -w none (RT-1 round 3).
var pmShortValueFlags = map[string]map[string]bool{
	"npm":  {"-w": true, "-C": true, "-L": true, "-c": true, "-m": true},
	"pnpm": {"-C": true, "-F": true},
	"bun":  {"-c": true, "-F": true},
	"bunx": {"-p": true},
}

// pmLongValueOptions: per package manager, the long options that take the next word as their value, and no other.
// An option a manager does not read with a value leaves the next word to be a package: npm reads any --name it does
// not know as a switch (nopt; with a warning) and installs the word after it (npm i --cwd x, npm i --index-url x), so
// another tool's options (pip's --index-url, Yarn's --cwd, pnpm's --filter) are not npm's. npm's are its config keys
// whose type takes a word in both npm 10.9 (Node 22) and npm 11 (npm/cli workspaces/config/lib/definitions at
// v10.9.2 and latest, read 2026-11-14 08:02 UTC; a key only npm 11 has is a switch to npm 10), with --enjoy-by, its
// alias of --before. pnpm validates all options (pnpm.io/pnpm-cli: an unknown one fails the command); its, Yarn's and
// bun's are the ones they document (pnpm.io/pnpm-cli, pnpm.io/cli/add, pnpm.io/filtering; classic.yarnpkg.com/en/docs/cli,
// yarnpkg.com/cli/add, yarnpkg.com/cli/dlx; bun.sh/docs/cli/add, bun.sh/docs/cli/install, and bunx's own few,
// bun.sh/docs/cli/bunx; read 2026-11-14). A registry option and its abbreviations are npmRegistryOption. RT-1 round 3.
var pmLongValueOptions = func() map[string]map[string]bool {
	m := map[string]map[string]bool{}
	for cmd, names := range map[string]string{
		"npm": "_auth access also audit-level auth-type before browser ca cache cache-max cache-min cafile call cert cidr " +
			"cpu depth diff diff-dst-prefix diff-src-prefix diff-unified editor expect-result-count fetch-retries " +
			"fetch-retry-factor fetch-retry-maxtimeout fetch-retry-mintimeout fetch-timeout git globalconfig heading " +
			"https-proxy include init-author-email init-author-name init-author-url init-license init-module init-version " +
			"init.author.email init.author.name init.author.url init.license init.module init.version install-strategy key " +
			"libc local-address location lockfile-version loglevel logs-dir logs-max maxsockets message node-options " +
			"noproxy omit only os otp pack-destination package prefix preid provenance-file proxy registry " +
			"replace-registry-host save-prefix sbom-format sbom-type scope script-shell searchexclude searchlimit " +
			"searchopts searchstaleness shell tag tag-version-prefix umask user-agent userconfig viewer which workspace " +
			"enjoy-by",
		"pnpm": "dir workspace-packages env-file save-prefix save-catalog-name allow-build lockfile-dir filter filter-prod " +
			"test-pattern changed-files-ignore-pattern registry cpu os libc reporter loglevel store-dir package " +
			// pnpm's value options GLOBAL_OPTIONS and dlx's and exec's own rc options have (color, prefix, use-node-version,
			// workspace-concurrency, resume-from; pnpm 12's clap reads the last two on dlx too): their word is no package
			// (pnpm dlx --color always x ran x in 10.34.9 and 11.28.12; ADR-0159 round 43, P2-2)
			"color use-node-version workspace-concurrency resume-from prefix",
		"yarn": "cwd mutex modules-folder cache-folder preferred-cache-folder global-folder link-folder proxy https-proxy " +
			"registry network-concurrency network-timeout otp use-yarnrc package mode",
		"bun": "omit catalog filter ca cafile registry network-concurrency backend concurrent-scripts cache-dir config cwd " +
			"env-file linker cpu os libc minimum-release-age minimum-release-age-excludes",
		"bunx": "package cwd env-file minimum-release-age",
	} {
		m[cmd] = map[string]bool{}
		for _, n := range strings.Fields(names) {
			m[cmd]["--"+n] = true
		}
	}
	return m
}()

// npmRegistryOption: --registry or an abbreviation of it from --reg on. npm expands a config name that resolves
// unambiguously to a known one, and registry is its only config key that begins with "reg"; --reg is its listed
// shorthand (docs.npmjs.com/cli/v11/using-npm/config, "Shorthands and Other CLI Niceties", read 2026-11-14).
func npmRegistryOption(x string) bool {
	x = npmTwoDash(x)
	return len(x) >= len("--reg") && strings.HasPrefix("--registry", x)
}

// npmTwoDash: npm's nopt reads a one-dash token longer than one letter as the long option of that name or its
// abbreviation (-registry, -reg, -userconfig, -@scope:registry: npm 10.8.2 config get, and an npm view that reached
// 127.0.0.1:9). It returns the "--" spelling for the registry and config matchers; a one-letter form and a two-dash
// option are returned unchanged. A one-dash word that is no such option (a cluster -Dg) still fails those matchers,
// so this only lifts the names they test.
func npmTwoDash(x string) string {
	if len(x) > 2 && x[0] == '-' && x[1] != '-' {
		return "-" + x
	}
	return x
}

// pmTakesValue: for npm, pnpm, Yarn or bun, whether option word opt leaves its value to the next word.
func pmTakesValue(cmd, opt string) bool {
	if cmd == "npm" { // nopt reads a one-dash long option; its value is the next word (-registry URL, -userconfig rc)
		if two := npmTwoDash(opt); two != opt {
			// -userc=/x carries its value: no next word (round 3; -userc=/x i pkg skipped the verb)
			return !strings.Contains(opt, "=") && (pmLongValueOptions[cmd][two] || npmRegistryOption(two) || npmConfigFileOption(two) ||
				npmValueOption(two))
		}
	}
	switch {
	case strings.HasPrefix(opt, "--"):
		// --prefix=x is neither; npm's unambiguous prefix of a key is that key (--loglev warn: --loglevel, READER-NPM-ABBREV-1)
		return pmLongValueOptions[cmd][opt] || npmRegistryOption(opt) || cmd == "npm" && npmValueOption(opt)
	case len(opt) == 2 && opt[0] == '-':
		return pmShortValueFlags[cmd][opt]
	}
	return false
}

// ownSwitch: whether an npm, pnpm, Yarn or bun command gives the switch name as an option of its own — not as another
// option's value (pnpm add x --filter --workspace: --filter takes it) and not after "--".
func ownSwitch(cmd string, rest []string, name string) bool {
	for i := 0; i < len(rest); i++ {
		switch x := rest[i]; {
		case x == "--":
			return false
		case x == name:
			return true
		case strings.HasPrefix(x, "-") && pmTakesValue(cmd, x):
			i++
		}
	}
	return false
}

// pmFirstPositional: the index of an npm, pnpm, Yarn or bun command's first word that is not an option or an
// option's value — its subcommand — or -1.
func pmFirstPositional(cmd string, rest []string) int {
	for i := 0; i < len(rest); i++ {
		x := rest[i]
		switch {
		case x == "--":
			if i+1 < len(rest) {
				return i + 1
			}
			return -1
		case strings.HasPrefix(x, "-") && len(x) > 1:
			if pmTakesValue(cmd, x) {
				i++
			}
		default:
			return i
		}
	}
	return -1
}

// parseInstallLineFull also reports whether the line runs something besides installs and harmless
// commands (curl … | bash && npx -y x), and whether it has a command substitution outside single
// quotes: install_check then cannot sign the install alone.
func parseInstallLineFull(line string) (targets, unread []string, other, subst bool) {
	p := &hookParse{seen: map[string]bool{}, shell: &shellFacts{}}
	if lineTooLong(line) { // round 23: past the cap, the line is not read and holds
		p.miss(fmt.Sprintf("a line of %d KiB, longer than alalanet reads (%d KiB)", len(line)>>10, MaxLineBytes>>10))
		return nil, p.unread, true, false
	}
	line = whichSubst.ReplaceAllString(line, "$1$2") // $(which npm) i x -> npm i x
	if substInstall.MatchString(line) {
		p.miss("install arguments come from a command substitution alalanet cannot see")
	}
	p.line(line, 0)
	// a line that installs and defines an alias or a function, of any name: what the install runs may be what the
	// line made it (READER-SHADOW-1, round 19)
	// PIPE-SCRIPT-1: a script the line downloads and runs is held for itself, whatever it defines or sets; these two
	// holds are for the other installs of the line (installs)
	installs := p.hits > p.scriptHits
	if p.defRaw(line); p.defined != "" && installs {
		p.miss(whyShadow + " (" + clip(p.defined, 40) + ")")
	}
	// round 29: every part of the line its own shell runs is on the allowlist (ownshell.go), or the line holds; also a
	// line that installs nothing when it has a group on a word, whose code may (ls *(e#npm i x#): lineGroup, rounds 37, 38)
	if p.shell.final(); p.shell.why != "" && (installs || lineGroup(line)) {
		p.miss(whyOwnShell + " (" + p.shell.why + ")")
	}
	// round 26: ${!ref:=…} assigns a variable by a name alalanet cannot place, on a line that installs
	if p.indirectAssign && installs {
		p.miss("installs with an environment an expansion sets by an indirect name (${!…:=…}, zsh's ${(P)…:=…}), which alalanet cannot place")
	}
	// PIPE-SCRIPT-1: sh -c "$(curl …)", bash <(curl …): a line whose every substitution is a download it runs as a
	// script shows what it runs — the script's address, a target
	if p.subst && len(p.ranSubsts) > 0 && substsAllRun(line, p.ranSubsts) {
		p.subst = false
	}
	// HOME-CONFIG-ENV-1: HOME, USERPROFILE, XDG_CONFIG_HOME or APPDATA moved to a folder the repository may hold, on a
	// line that installs: the package managers read their user config there
	if p.homeMoved != "" && (len(p.targets) > 0 || p.hits > 0) {
		p.miss(p.homeMoved)
	}
	p.noteArgTilde()
	if n := len(p.targets); n > MaxHookTargets {
		p.unread = append(p.unread, fmt.Sprintf("%d more install targets in this command (alalanet checks the first %d)", n-MaxHookTargets, MaxHookTargets))
		p.targets = p.targets[:MaxHookTargets]
	}
	return p.targets, p.unread, p.other, p.subst
}

type hookParse struct {
	targets, unread []string
	seen            map[string]bool
	hits            int  // installs found, unreadable installs and install forms with nothing to check
	other           bool // a command that is none of those and not harmless, or one that writes a file
	subst           bool // a command substitution outside single quotes
	// prog: the program of the simple command being read, past its wrappers (the first one command names
	// in it); firstOther: the program of the first command the line reads as "other". Bookkeeping for
	// OtherProgram (ECO-1, ADR-0159): nothing in the reader reads either.
	prog, firstOther string
	// visit, when set, is given every simple command the walk reads (Commands); nothing in the reader reads it.
	// winRead: the walk is reading a command's Windows spelling (Command.Win)
	visit   func(Command)
	winRead bool
	// reqs, when set, collects the requirements-format files the installs name (RequirementFiles, READER-REQFILE-1);
	// nothing in the reader reads it.
	reqs *[]string
	// defined: the first alias, function, hash entry, sourced input or table assignment the line makes (READER-SHADOW-1)
	defined string
	// srcs, when set, collects the files the line sources, as written (SourcedFiles, round 20); nothing in the reader
	// reads it.
	srcs *[]string
	// written: the files earlier commands of the line write by name (a redirection, cp, mv, curl -o …: writesFiles);
	// wrote: one of them writes files it does not name (tar, git, wget, curl -O …); venvs: the venv folders earlier
	// commands created (venvCreated) with nothing since that may write into them; acts, when set, collects the sources
	// of such a venv's bin/activate (VenvActivates). Round 21, P2-J.
	written map[string]bool
	wrote   bool
	venvs   []madeVenv
	created []string // every venv folder a command of the line creates (round 22)
	acts    *[]VenvActivate
	// homeMoved: the reason for the line's first HOME, USERPROFILE, XDG_CONFIG_HOME or APPDATA that points at a folder
	// the repository may hold (homeConfigWhy), a reason only on a line that installs (HOME-CONFIG-ENV-1)
	homeMoved string
	// entry: the values read are an MCP entry's, which no shell expands (EnvUnread; HOME-CONFIG-ENV-1 round 2, P2-1)
	entry bool
	// argTilde: the assignment being read is an argument word (after env or sudo, a cmd set), whose ~ no shell
	// expands in zsh, dash or bash --posix (HOME-CONFIG-ENV-1 round 3)
	argTilde bool
	// cmdSet: the assignment being read is cmd's set or setx, which never expands ~; argTildeVals: the values an
	// argument word's ~ was written in (configEnv), whose reasons get whyArgTildeNote (round 5, P3-1)
	cmdSet       bool
	argTildeVals [][2]string // the value and its note
	// quoted: the line's quoted words with a space or an operator and the value the shell assigns for each, taken
	// where an assignment stands (splitShell's shellLine.assigned, HOME-CONFIG-ENV-1 round 8, R2)
	quoted map[string]string
	// mayWrite: an earlier command of the line may write a file — any that is neither harmless nor an install the readers
	// read, other than a venv tool; unw, when set, collects the sources before any such command (SourcedUnwritten).
	mayWrite bool
	unw      *[]string
	// substLeft: the bytes of substitution bodies the whole reading may still walk (quotedSubsts, round 23)
	substLeft *int
	// indirectAssign: an expansion assigns a variable whose name the line does not show, ${!ref:=…} (round 26)
	indirectAssign bool
	// shell, when set (ParseLine), reads each POSIX script of the line by the allowlist of its own shell (round 29);
	// foreign: the walk is inside text no POSIX shell runs as a script — a PowerShell, cmd.exe, fish or csh script,
	// env -S's words, the walk's reading again of one word — which it does not judge by it
	shell   *shellFacts
	foreign int
	// ranSubsts: the substitutions the walk read as downloads the line runs as scripts, by their words (PIPE-SCRIPT-1):
	// a line whose every substitution is one shows all it runs (substsAllRun)
	ranSubsts map[string]bool
	// scriptHits: the hits that are such scripts, a target or the reason (remoteScript)
	scriptHits int
	// goEnv: the Go variables the line sets, in order (noteGoEnv), judged at a go install or go run it reads (ECO-1, Go)
	goEnv []goEnvSet
	// goWrites: the writes of earlier commands, and assigned: the values the line assigns to names (OUT=build), for the
	// Go reader's judgement of the line's writes at a go install or go run (ECO-1 Go, round 5)
	goWrites []goWrite
	assigned map[string]string
	// brewTapped: an earlier brew command named a third-party tap (tap, trust, an install of user/repo/name); the
	// installs by name after it are part of that install, not other commands (ECO-1-BREW round 2, brew.go)
	brewTapped bool
	// brewWhy: the reasons of the Homebrew variables the line sets, given when a brew command runs (brewFlush, round 3)
	brewWhy []string
	// brewAliases: the brew aliases the line defines (brew alias NAME=…), each the line its script runs (round 4)
	brewAliases map[string]string
	// goCwd, goOldCwd, goDirs, goLinks: the current folder the line has moved to ("" where it started, "?" unknown), the
	// one before it, pushd's stack and the symbolic links it made, for the Go reader's destinations (round 6)
	goCwd, goOldCwd string
	goDirs          []string
	goLinks         map[string]string
	// work: what the reading cost — the tokenizer's characters and copied bodies, and the bodies' readings; walked:
	// the bytes of bodies walked (round 24, P3-V; a test's count, nothing in the reader reads it)
	work, walked int
}

// line reads every simple command of a shell line (or of a script given to sh -c, eval, env -S).
func (p *hookParse) line(s string, depth int) {
	if p.shell != nil && p.foreign == 0 {
		p.shell.scan(s)
	}
	sl := splitShell(s)
	p.quoted = addAssigned(p.quoted, sl.assigned)
	p.work += sl.work
	arith, indirect := lineArith(s)
	for _, kv := range arith { // (( NAME = 1 )), $((NAME=1)), a[NAME=1]: as export NAME=1 (round 27)
		p.configEnv(kv[0], kv[1])
	}
	p.indirectAssign = p.indirectAssign || indirect // (( $n = 1 )): a name the line does not show (round 28)
	if sl.unclosed {
		p.miss("a quote the line does not close: alalanet cannot tell where its words end")
	}
	p.subst = p.subst || sl.subst
	wsegs := sl.winSegs()                       // the Windows reading, nil when the line has none (round 3, D1)
	run, ran := p.scriptRuns(s, sl.segs, wsegs) // a downloaded script the line runs: PIPE-SCRIPT-1, in both readings
	outer := p.prog                             // a script's line (sh -c …) is read inside its shell's command: that command's program stays
	for i, sg := range sl.segs {
		before := p.hits
		p.prog = ""
		// each consumer of the segment's words reads it in both readings, the Windows one too when a word has one
		// (round 3, D1); what they find is a union
		rds, rsegs := []shellSeg{sg}, [][]shellSeg{sl.segs}
		if wsegs != nil && sg.hasWin() {
			rds, rsegs = append(rds, wsegs[i]), append(rsegs, wsegs)
		}
		for _, rd := range rds {
			p.def(segDefines(rd)) // name() …, function name, source of its input (READER-SHADOW-1)
			if f := segSourced(rd); p.srcs != nil && f != "" && !slices.Contains(*p.srcs, f) {
				*p.srcs = append(*p.srcs, f) // source FILE, . FILE (round 20)
			}
			p.quotedSubsts(rd, depth) // the substitutions in its words run before it (round 22)
			// ${NAME:=word} in a word or a redirection's word, and an arithmetic assignment: as export NAME=word is
			// judged (rounds 26, 27)
			for _, kv := range segAssigns(rd) {
				p.configEnv(kv[0], kv[1])
			}
			p.indirectAssign = p.indirectAssign || segIndirect(rd)
			p.sourcedAfterWrite(rd) // a file the line may have written, then sources (round 21)
		}
		tb, ub := len(p.targets), len(p.unread)
		for _, segs := range rsegs {
			p.fed(segs, i, depth) // echo 'npm i x' | sh, bash <<< …, source <(echo …): READER-SHELLS
		}
		if r := run[i]; r != nil {
			p.remoteScript(r.urls, r.what)
		}
		p.command(sg.words, depth)
		if win := sg.winWords(); win != nil {
			// a word is also a Windows path (.\venv\Scripts\pip.exe, which PowerShell and cmd run): read the command
			// once more with that spelling, both readings count and the stricter wins — a launch target built from the
			// POSIX words (claude mcp add x -- .\node_modules\.bin\npx.cmd …) is read with its path too (round 2, R2)
			prog, read := p.prog, p.hits != before
			p.prog = ""
			wasWin := p.winRead
			p.winRead = true
			p.command(win, depth)
			p.winRead = wasWin
			if read {
				p.prog = prog // the POSIX reading already named the program counted (OtherProgram)
			}
		}
		if p.hits == before && !ran[i] && (sg.writes || !harmless(sg.words)) {
			p.other = true
			if p.firstOther == "" {
				p.firstOther = p.prog
			}
		}
		p.noteWrites(sg, len(p.targets) > tb || len(p.unread) > ub)
	}
	p.prog = outer
}

// foreignScript reads a script of a shell whose syntax the allowlist does not read (fish, csh, PowerShell, cmd.exe)
// the POSIX way. One that runs an install together with any other command holds: what the other commands set in that
// shell is not read (round 30, P2-Y). A script of installs alone is judged as before.
func (p *hookParse) foreignScript(script, what string, depth int) {
	before, hits := len(p.targets), p.hits
	p.foreign++
	p.line(script, depth+1)
	p.foreign--
	switch {
	case p.shell == nil || p.hits == hits:
	case len(p.targets) > before && !installsOnly(script):
		p.shell.hold("a " + what + " script that runs the install with other commands (" + clip(script, 60) + ")")
	case foreignParen(script):
		// fish runs a (…) substitution in the shell itself, PowerShell $( ) and ( ) in the same scope (round 31)
		p.shell.hold("a " + what + " script with a substitution that runs in its own shell (" + clip(script, 60) + ")")
	}
}

// foreignParen: a ( outside quotes, as fish, PowerShell and cmd.exe quote ('…', "…").
func foreignParen(s string) bool {
	q := byte(0)
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case q != 0 && c == q:
			q = 0
		case q == '"' && c == '\\':
			i++
		case q != 0:
		case c == '\'' || c == '"':
			q = c
		case c == '(':
			return true
		}
	}
	return false
}

// installsOnly: a script whose every command is a package manager's (npm, pip, uvx … or python -m pip).
func installsOnly(script string) bool {
	cs := Commands(script)
	if len(cs) == 0 {
		return false
	}
	only := func(c Command) bool {
		mod, _, isMod := pyModule(c.Prog, c.Words[1:])
		py := pythonInterp(c.Prog) && len(c.Words) > 1 && isMod && packageManagers[mod]
		return len(c.Assigns) == 0 && (packageManagers[c.Prog] || py || passOn[c.Prog] || judgedSet(c))
	}
	for i, c := range cs {
		if c.Win {
			continue // read with the command whose Windows spelling it is
		}
		// a command and its Windows reading are one command: an install in either is one (venv\Scripts\pip install x
		// is venvScriptspip to the POSIX shell; READER-ESCAPE-1 round 3, N3)
		if !only(c) && !(i+1 < len(cs) && cs[i+1].Win && only(cs[i+1])) {
			return false
		}
	}
	return true
}

// judgedSet: cmd.exe's set NAME=value (and setx), or PowerShell's $env:NAME = value — an environment the readers judge
// by its value (configEnv), as the line's own export.
func judgedSet(c Command) bool {
	if psEnvWord.MatchString(c.Prog) || len(c.Words) > 0 && psEnvWord.MatchString(c.Words[0]) {
		return true
	}
	if c.Prog != "set" && c.Prog != "setx" || len(c.Words) < 2 {
		return false
	}
	for _, w := range c.Words[1:] {
		if k, _, ok := strings.Cut(w, "="); !ok || !ownName(k) {
			return false
		}
	}
	return true
}

// passOn: commands that only run the command after them, which Commands visits next (cmd's call and start,
// PowerShell's iex), and fish's keywords, which only join commands.
var passOn = wordSet("call start iex invoke-expression and or not begin end if else while")

func (p *hookParse) add(t string) {
	p.hits++
	if !p.seen[t] {
		p.seen[t] = true
		p.targets = append(p.targets, t)
	}
}

func (p *hookParse) miss(why string) {
	p.hits++
	if !p.seen["?"+why] {
		p.seen["?"+why] = true
		p.unread = append(p.unread, why)
	}
}

// harmless: a directory change, an echo, an output filter, a virtualenv activation, or only VAR=value
// assignments. tee with a file writes it (… | tee .npmrc): not harmless.
func harmless(w []string) bool {
	for i, x := range w {
		if !strings.Contains(x, "=") || strings.HasPrefix(x, "-") {
			c := strings.ToLower(x)
			switch {
			case c == "tee":
				for _, a := range w[i+1:] {
					if !strings.HasPrefix(a, "-") && a != "/dev/null" && a != "/dev/stderr" {
						return false
					}
				}
				return true
			case c == "source" || c == ".":
				return len(w) == i+2 && strings.HasSuffix(w[i+1], "/bin/activate")
			case c == "sort" || c == "uniq":
				n := 0
				for _, a := range w[i+1:] {
					if a == "-o" || strings.HasPrefix(a, "--output") || strings.HasPrefix(a, "-o") && len(a) > 2 {
						return false // sort -o file writes it
					}
					if !strings.HasPrefix(a, "-") {
						n++
					}
				}
				return c == "sort" || n < 2 // uniq IN OUT writes OUT
			case launchBase(c) == "brew":
				return brewHarmless(w[i+1:]) // brew update, doctor, cleanup … (ECO-1-BREW round 3)
			case packageManagers[progName(c)] || c == "node" || strings.HasPrefix(c, "python"): // pn --version too
				return len(w) == i+2 && (w[i+1] == "-v" || w[i+1] == "--version" || w[i+1] == "-V" || w[i+1] == "version")
			}
			return harmlessCommands[c]
		}
	}
	return true
}

// shellSeg is one simple command: its words with the quotes removed, and whether it writes a file
// through a redirection (echo registry=… > .npmrc is not harmless; > /dev/null is). piped: its input is
// the previous command's output (a | before it); proc: its words end at a <( … ), whose command is the
// next segment; here: its here-strings' words (<<< word), its input (READER-SHELLS); doc: it has a here-document; def:
// the name its words define as a function — they end at an unquoted ( and the next character past blanks is ) —
// (READER-SHADOW-1).
type shellSeg struct {
	words       []string
	writes      bool
	piped, proc bool
	here        []string
	doc         bool
	def         string
	outs        []string // the files its output redirections name (round 21)
	redirs      []string // every redirection's word, which the shell expands as a command's words (round 27)
	// winOuts, winRedirs: outs and redirs spelled the Windows way, when a word of them has a second spelling (curl URL >
	// x\i.sh; sh .\x\i.sh: READER-ESCAPE-1 round 3), nil otherwise
	winOuts, winRedirs []string
	// qsubs: the command text of each substitution in its words the walk does not read as commands — inside double
	// quotes, ${ … } or $(( … )) — "?" when it does not close; cut: its words go on after a $( … ), backtick or <( … )
	// the walk reads as commands of their own (round 22)
	qsubs []string
	cut   bool
	// win: for a word POSIX left as no program, its Windows path spelling with the backslashes kept; the command is
	// read a second time with it, stricter wins (READER-ESCAPE-1 round 2, R2)
	win []string
}

// winWords: the command spelled the Windows way (sg.win in place of each word that has one), or nil when no word has.
// Every reader that reads a command reads this spelling a second time, and the stricter decision wins.
func (sg shellSeg) winWords() []string {
	if sg.win == nil {
		return nil
	}
	win := make([]string, len(sg.words))
	for j, w := range sg.words {
		if win[j] = w; j < len(sg.win) && sg.win[j] != "" {
			win[j] = sg.win[j]
		}
	}
	return win
}

// winSegs: the line's segments in their Windows reading — each segment's words spelled the Windows way where a word
// has a second spelling (winWords), everything else as it is — or nil when no word of the line has one. Every consumer
// of a line's words reads this reading too, and a decision in either counts (READER-ESCAPE-1 round 3, D1: PIPE-SCRIPT's
// "file written, then run" matcher read only the POSIX .i.ps1; TestReaderEscapeR3ConsumersReadBoth lists them).
func (sl shellLine) winSegs() []shellSeg {
	var out []shellSeg
	for i, sg := range sl.segs {
		if !sg.hasWin() {
			continue
		}
		if out == nil {
			out = slices.Clone(sl.segs)
		}
		if sg.win != nil {
			out[i].words = sg.winWords()
		}
		if sg.winRedirs != nil {
			out[i].outs, out[i].redirs = sg.winOuts, sg.winRedirs
		}
		out[i].win, out[i].winOuts, out[i].winRedirs = nil, nil, nil
	}
	return out
}

// hasWin: a word of the segment, or of its redirections, has a Windows spelling.
func (sg shellSeg) hasWin() bool { return sg.win != nil || sg.winRedirs != nil }

// winSpelling: a word whose raw spelling (backslashes kept) PowerShell or cmd reads as a Windows path the POSIX shell
// unquotes into another word — a program path (winExePath), a path from an expansion ($env:TEMP\python.exe,
// %TEMP%\r.txt, ~\x), or an option's or assignment's value that is one (--python=$env:TEMP\python.exe). PowerShell and
// cmd take a backslash as a path separator, never as an escape. The POSIX word stays the first reading and this
// spelling is the second; a decision in either counts (READER-ESCAPE-1 round 2, R2: a line that can be either shell's
// is read both ways, and the stricter decision wins). Any other escaped word (le\ft-pad) has no second reading: no
// Windows user writes it, and its POSIX word is what both readings would judge.
func winSpelling(raw string) bool {
	if winExePath(raw) || windowsPathStart(raw) || winScriptPath(raw) {
		return true
	}
	_, v, ok := strings.Cut(raw, "=")
	return ok && windowsPathStart(v)
}

// winScriptPath: a relative Windows path to a script file (x\i.sh, scripts\install.ps1, tools\setup.py), wherever it
// stands: a download's output (curl URL > x\i.sh, -OutFile scripts\i.ps1) and the file a shell runs (sh .\x\i.sh) are
// read in their Windows spelling too, as the base read them (READER-ESCAPE-1 round 3: the POSIX reading names xi.sh).
// A package name ends in no script suffix, so a respelled one (le\ft-pad) gets no second reading.
func winScriptPath(raw string) bool {
	if !strings.Contains(raw, `\`) || strings.ContainsAny(raw, "/=") || raw[0] == '\\' || raw[0] == '-' {
		return false
	}
	low := strings.ToLower(raw)
	for _, x := range winScriptSuffixes {
		if strings.HasSuffix(low, x) && len(low) > len(x) && low[len(low)-len(x)-1] != '\\' {
			return true
		}
	}
	return false
}

// winScriptSuffixes: the scripts a line downloads and runs (PIPE-SCRIPT-1's).
var winScriptSuffixes = []string{".sh", ".bash", ".zsh", ".ps1", ".psm1", ".bat", ".cmd", ".py", ".js", ".mjs", ".cjs", ".rb", ".pl"}

// shellLine is a line read the way a POSIX shell splits it, as far as an install check needs.
type shellLine struct {
	segs []shellSeg
	// assigned: a quoted word with a space or an operator whose name or "=" is quoted, and its value as the shell
	// assigns it (markTilde): what the readers take for it where an assignment stands (HOME-CONFIG-ENV-1 round 8, R2)
	assigned map[string]string
	unclosed bool // a quote left open: where the words end is unknown
	subst    bool // $( ), backticks or <( ) outside single quotes: words the line does not show
	// work: the characters the tokenizer visited (each once, and a here-document's lines again) and the bytes of the
	// substitution bodies it copied — what the reading of the line cost, counted (round 24, P3-V)
	work int
}

// splitShell splits a line into simple commands at the separators ; | & newline ( ) { } and backtick
// outside quotes, and each command into words with the quotes removed: a quoted string with spaces
// stays one word, so --from "x @ git+https://…" keeps its value (independent review of round 3,
// finding 6). It knows single and double quotes, $'…' and bash's $"…", backslash escapes (outside quotes the shell drops the
// backslash before any character; a Windows path keeps it, and has a second Windows reading — READER-ESCAPE-1), # comments,
// redirections (N>file, >>, 2>&1, &>, <file, <<<word: the file word is not an argument) and here-
// documents (the body is read as commands). A quote left open is reported, not guessed (second review
// pass, finding A).
func splitShell(line string) shellLine {
	var out shellLine
	var words []string
	var cur strings.Builder
	inWord, q := false, rune(0) // q: '\'', '"' or '$' for $'…'
	skipWord, redirOut, writes := false, false, false
	hereStr, piped, proc := false, false, false // the word skipped is a here-string's; a | before the command; a <( after it
	var here []string
	heredoc, heredocTabs := "", false
	doc, def := false, "" // the segment has a here-document; the name its words define as a function
	var outs []string     // the files the segment's output redirections name
	var redirs []string   // every redirection's word
	var qsubs []string    // the substitutions in its words the walk does not read (round 22)
	cut := false          // its words go on after a substitution read as commands of their own
	grp := 0              // zsh glob groups open on a word (a(|#), *(#q.)): a # inside starts no comment (round 37)
	var st substTrack     // the substitutions the walk does not read, followed in this one pass (round 23)
	// the other open parentheses, innermost last: 's' a subshell's (or a case pattern's), 'd' $( <( >(, 'a' an array's;
	// cmtAt: where a word starts after a subshell's ( or ), or after $(, so a # there is a comment; arrAt: right after an
	// array's ), where bash reads a # as part of a word and zsh as a comment; ambig: such a # is on this line (round 38)
	var parens []byte
	cmtAt, arrAt, ambig := -1, -1, false
	// qsegs: where the current word's quoted parts and escaped characters lie in it (byte offsets, end exclusive; an
	// empty pair of quotes is an empty part): whether its assignment's ~ is one the shell expands (markTilde,
	// HOME-CONFIG-ENV-1 round 3); qstart: the start of the open quote's part
	var qsegs [][3]int // start, end, and 1 for single quotes or $'…', 2 for double quotes, 3 for an escape
	qstart := -1
	// rawBS: where in the current word a backslash before an ordinary character was dropped (READER-ESCAPE-1). The
	// word is the shell's (POSIX) word; only a Windows path (looksWindowsPath of the word with them put back) keeps them.
	var rawBS []int
	var winw []string
	var winOuts, winRedirs []string // the Windows spellings of outs and redirs, parallel to them
	winRedir := false               // a redirection word of the segment has a Windows spelling
	flushWord := func() {
		if inWord {
			w, winAlt := cur.String(), ""
			switch {
			case skipWord:
				ww := w // the Windows spelling of a redirection's word, as a command's word gets one (round 3)
				if raw, _, ok := windowsWord(w, rawBS, qsegs); ok {
					ww = raw
				} else if r := rawSpelling(w, rawBS); r != "" && winSpelling(r) {
					ww = r
				}
				winRedir = winRedir || ww != w
				redirs, winRedirs = append(redirs, w), append(winRedirs, ww)
				if redirOut && w != "/dev/null" && w != "/dev/stderr" && w != "/dev/stdout" {
					writes = true
					outs, winOuts = append(outs, w), append(winOuts, ww)
				}
				if hereStr {
					here = append(here, w)
				}
				skipWord, redirOut, hereStr = false, false, false
			case heredoc == "\x00":
				heredoc = strings.ReplaceAll(w, "\\", "") // the delimiter of <<WORD, <<'WORD', <<\WORD
			default:
				src, srcSegs := w, qsegs
				if raw, segs, ok := windowsWord(w, rawBS, qsegs); ok {
					src, srcSegs = raw, segs
				} else if r := rawSpelling(w, rawBS); r != "" && (winSpelling(r) || programSlot(words) && winProgramPath(r)) {
					winAlt = r // POSIX kept this word, but it is also a Windows path: a second reading
				}
				mw, as := markTilde(src, srcSegs)
				words = append(words, mw)
				if as != "" && len(out.assigned) < 64 {
					if out.assigned == nil {
						out.assigned = map[string]string{}
					}
					out.assigned[mw] = as
				}
				winw = append(winw, winAlt)
			}
			cur.Reset()
			inWord = false
		}
		qsegs, qstart, rawBS = qsegs[:0], -1, rawBS[:0]
	}
	flushSeg := func() {
		flushWord()
		if n := len(words); n > 0 {
			if words[n-1] = strings.TrimSuffix(words[n-1], "$"); words[n-1] == "" {
				words = words[:n-1]
				winw = winw[:len(winw)-1]
			}
		}
		if len(words) > 0 || writes {
			seg := shellSeg{words: words, writes: writes, piped: piped, proc: proc, here: here, doc: doc, def: def,
				outs: outs, qsubs: qsubs, cut: cut, redirs: redirs}
			for _, x := range winw {
				if x != "" {
					seg.win = winw
					break
				}
			}
			if winRedir {
				seg.winOuts, seg.winRedirs = winOuts, winRedirs
			}
			out.segs = append(out.segs, seg)
			piped = false
		}
		words, winw, writes, here, proc, doc, def, outs, qsubs, cut, redirs = nil, nil, false, nil, false, false, "", nil, nil, false, nil
		winOuts, winRedirs, winRedir = nil, nil, false
	}
	rs := []rune(line)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		next := func() rune {
			if i+1 < len(rs) {
				return rs[i+1]
			}
			return 0
		}
		switch {
		case q == '\'':
			if r == '\'' {
				q = 0
				qsegs = append(qsegs, [3]int{qstart, cur.Len(), 1})
			} else {
				cur.WriteRune(r)
			}
		case q == '$': // $'…': backslash escapes the next character
			switch {
			case r == '\\' && i+1 < len(rs):
				i++
				// bash's ANSI-C escapes for blanks and controls; any other escaped character stands for
				// itself (env -S $'\n-i npm i x' gets a line break before -i, P1-X)
				// \xHH (one or two hex digits) and \NNN (one to three octal digits) give the byte they name
				switch c := map[rune]rune{'n': '\n', 't': '\t', 'v': '\v', 'f': '\f', 'r': '\r', 'a': '\a', 'b': '\b', 'e': 0x1b}[rs[i]]; {
				case c != 0:
					cur.WriteRune(c)
				case rs[i] == 'x' && i+1 < len(rs) && strings.ContainsRune("0123456789abcdefABCDEF", rs[i+1]):
					n, j := 0, i+1
					for ; j < len(rs) && j < i+3 && strings.ContainsRune("0123456789abcdefABCDEF", rs[j]); j++ {
						d := strings.IndexRune("0123456789abcdef", rs[j]|0x20)
						n = n*16 + d
					}
					cur.WriteRune(rune(n))
					i = j - 1
				case (rs[i] == 'u' || rs[i] == 'U') && i+1 < len(rs) && strings.ContainsRune("0123456789abcdefABCDEF", rs[i+1]):
					max := 4
					if rs[i] == 'U' {
						max = 8
					}
					n, j := 0, i+1
					for ; j < len(rs) && j <= i+max && strings.ContainsRune("0123456789abcdefABCDEF", rs[j]); j++ {
						n = n*16 + strings.IndexRune("0123456789abcdef", rs[j]|0x20)
					}
					cur.WriteRune(rune(n))
					i = j - 1
				case rs[i] >= '0' && rs[i] <= '7':
					n, j := 0, i
					for ; j < len(rs) && j < i+3 && rs[j] >= '0' && rs[j] <= '7'; j++ {
						n = n*8 + int(rs[j]-'0')
					}
					cur.WriteRune(rune(n & 0xff))
					i = j - 1
				default:
					cur.WriteRune(rs[i])
				}
			case r == '\'':
				q = 0
				qsegs = append(qsegs, [3]int{qstart, cur.Len(), 1})
			default:
				cur.WriteRune(r)
			}
		case q == '"':
			switch {
			case r == '"':
				q = 0
				qsegs = append(qsegs, [3]int{qstart, cur.Len(), 2})
				qsubs = st.end(rs, qsubs) // a substitution the closing quote leaves open (round 23)
			case r == '\\' && strings.ContainsRune("\"\\$`", next()):
				i++
				cur.WriteRune(rs[i])
			case r == '`':
				// a backtick substitution in double quotes: the backtick that closes it opens nothing (round 22); the
				// word is read as before, character by character
				out.subst = true
				qsubs = st.tick(rs, i, qsubs)
				cur.WriteRune(r)
			case r == '$' && next() == '(' && !(i+2 < len(rs) && rs[i+2] == '('): // $(( … )) is arithmetic
				out.subst = true
				qsubs = st.push(rs, i, qsubs)
				cur.WriteString("$(")
				i++
			default:
				if r == '$' && next() == '(' {
					out.subst = true
				}
				qsubs = st.char(rs, i, qsubs)
				cur.WriteRune(r)
			}
		case r == '\\' && next() == '\n' && ambig:
			// after a # that zsh reads as a comment: its \ continues nothing there, so the next line is a command of its own
			i++
			flushSeg()
			grp, ambig = 0, false
		case r == '\\' && next() == '\n': // a line continuation
			i++
		case r == '\\' && next() != 0:
			// a backslash outside quotes: the shell drops it before any character, so the next one stands for itself
			// (npm \i x is npm i x, in\stall is install: READER-ESCAPE-1); before an ordinary one it is remembered,
			// so a Windows path (C:\Users\npm.cmd) is put back together in flushWord
			i++
			// remember a dropped backslash only before an ordinary character, or as the leading \\ of a UNC path —
			// never before a special one (\', \;, \ ): there the base also dropped it, so a word looks like a Windows
			// path only where the base kept backslashes, and a -c/eval script is re-read without the escapes the shell
			// removed (READER-ESCAPE-1 round 2, R1)
			if !strings.ContainsRune(shellSpecial, rs[i]) || rs[i] == '\\' && cur.Len() == 0 {
				rawBS = append(rawBS, cur.Len())
			}
			qsegs = append(qsegs, [3]int{cur.Len(), cur.Len() + 1, 3})
			cur.WriteRune(rs[i])
			inWord = true
		case r == '$' && next() == '\'':
			i++
			q, inWord, qstart = '$', true, cur.Len()
		case r == '$' && next() == '"':
			// $"…": bash's locale translation of a string, which is the string itself where no catalogue translates it —
			// bash runs $"npm" i x as npm i x. dash and zsh read a literal $ before a quoted word (a program named $npm,
			// which no system has), so bash's reading is the one that installs, as with $'…' (READER-ESCAPE-1 round 3, N1)
			i++
			q, inWord, qstart = '"', true, cur.Len()
		case r == '\'' || r == '"':
			q, inWord, qstart = r, true, cur.Len()
		case r == '#' && !inWord && grp == 0 && (i == 0 || i == cmtAt || strings.ContainsRune(" \t\r\n;&|", rs[i-1])):
			// a comment to the end of the line: a # where a word starts — the line's start, after a blank, ;, & or |,
			// after a subshell's ( or ) or after $( (round 38), outside a group on a word. After { } and a group's ( ),
			// the shell's word goes on (x}#y, a{#,b}, zsh's *(#q.), a(|#), $(true)#c): the # is part of it (round 37)
			for i+1 < len(rs) && rs[i+1] != '\n' {
				i++
			}
		case r == '#' && i == arrAt: // a=(x)#…: a word to bash, a comment to zsh (round 38)
			cur.WriteRune(r)
			inWord, ambig = true, true
		case r == ' ' || r == '\t' || r == '\r':
			flushWord()
		case r == '\n' && heredoc != "":
			// a here-document: its lines go to the command's standard input up to the delimiter line;
			// for a shell they are a script (bash <<EOF … npm i x … EOF), for cat they are data
			flushSeg()
			if heredoc == "\x00" { // "<<" without a delimiter word
				heredoc = ""
				continue
			}
			var body []string
			for i++; i < len(rs); i++ {
				end := i
				for end < len(rs) && rs[end] != '\n' {
					end++
				}
				l := string(rs[i:end])
				if heredocTabs {
					l = strings.TrimLeft(l, "\t")
				}
				i = end
				if l == heredoc {
					break
				}
				body = append(body, l)
			}
			// Every body is read as commands, whoever reads it: a body piped on (bash <<EOF | tail),
			// written to a script run later (cat > s.sh <<EOF … ./s.sh) or code for python can carry an
			// install, and a false ask is safe where a skipped install is not (second review, H1–H4).
			// Line by line: a data body's apostrophe ("Don't forget") must not leave the line open.
			for _, l := range body {
				inner := splitShell(l)
				out.segs = append(out.segs, inner.segs...)
				for k, v := range inner.assigned {
					if out.assigned == nil {
						out.assigned = map[string]string{}
					}
					out.assigned[k] = v
				}
				out.subst = out.subst || inner.subst
				out.work += inner.work
			}
			heredoc, heredocTabs = "", false
		case r == '$' && (next() == '{' || next() == '(' && i+2 < len(rs) && rs[i+2] == '('):
			// ${VAR}, ${#VAR}, ${X:-y} and $((1+2)) belong to the word: "{", "(" and "#" inside are not
			// separators or a comment (third review pass, N1). A $( or backtick inside still counts.
			open, close := rs[i+1], '}'
			if open == '(' {
				close = ')'
			}
			depth, closed := 0, false
			for ; i < len(rs); i++ {
				c := rs[i]
				cur.WriteRune(c)
				if c == open {
					depth++
				} else if c == close {
					if depth--; depth == 0 {
						closed = true
						break
					}
				} else if c == '`' || c == '$' && i+1 < len(rs) && rs[i+1] == '(' && !(i+2 < len(rs) && rs[i+2] == '(') {
					out.subst = true
				}
				// the substitutions inside, followed in this pass (round 23): the loop's own count of its braces or
				// parentheses is unchanged
				switch {
				case c == '`':
					qsubs = st.tick(rs, i, qsubs)
				case c == '$' && i+1 < len(rs) && rs[i+1] == '(' && !(i+2 < len(rs) && rs[i+2] == '('):
					qsubs = st.push(rs, i, qsubs)
				case i > 0 && rs[i-1] == '$' && c == '(' && st.justPushed(i):
				default:
					qsubs = st.char(rs, i, qsubs)
				}
			}
			qsubs = st.end(rs, qsubs)
			if !closed {
				out.unclosed = true // "${A; npm i x": the rest of the line would vanish into the word
			}
			inWord = true
		case r == '<' && next() == '(':
			out.subst = true
			proc = true
			cut = len(words) > 0 || inWord
			flushSeg()
		case r == '$' && next() == '(':
			out.subst = true
			cut = len(words) > 0 || inWord
			flushSeg()
		case r == '>' || r == '<' || r == '&' && next() == '>':
			// a redirection: N>file, >>file, 2>&1, &>file, <file, <<WORD, <<<word
			if s := cur.String(); inWord && strings.Trim(s, "0123456789") == "" {
				cur.Reset() // the descriptor number
				rawBS = rawBS[:0]
				inWord = false
			}
			flushWord()
			out := r != '<'
			if r == '&' {
				i++ // &>
			}
			if r == '<' && next() == '<' {
				i++
				if next() == '<' { // <<< word: a here-string, data (the input of a shell: READER-SHELLS)
					i++
					skipWord, hereStr = true, true
					continue
				}
				if next() == '-' {
					i++
					heredocTabs = true
				}
				heredoc, doc = "\x00", true // the next word is the delimiter
				continue
			}
			for next() == '>' || next() == '|' {
				i++
			}
			if next() == '&' { // >&2, 2>&1, >&-: a descriptor, no file word
				i++
				for next() >= '0' && next() <= '9' || next() == '-' {
					i++
				}
				continue
			}
			skipWord, redirOut = true, out
		case r == '`':
			out.subst = true
			cut = len(words) > 0 || inWord
			flushSeg()
		case r == '{' && next() == '}':
			// "{}" is a word, never a brace group: xargs -I{} keeps its replacement string and find -exec … {}
			// its argument (RT-1 review, round 2)
			cur.WriteString("{}")
			i++
			inWord = true
		case strings.ContainsRune(";|&\n(){}", r):
			switch {
			case r == '(' && (grp > 0 || inWord && !strings.HasSuffix(cur.String(), "=")):
				grp++ // a group on a word (not NAME=( … ), an array)
			case r == '(':
				kind := byte('s')
				switch {
				case inWord:
					kind = 'a' // NAME=( … )
				case i > 0 && strings.ContainsRune("$<>", rs[i-1]):
					kind = 'd'
				}
				parens = append(parens, kind)
				cmtAt = i + 1
			case r == ')' && grp > 0:
				grp--
			case r == ')':
				kind := byte('s')
				if n := len(parens); n > 0 {
					kind, parens = parens[n-1], parens[:n-1]
				}
				switch kind {
				case 's':
					cmtAt = i + 1
				case 'a':
					arrAt = i + 1
				}
			case r == '\n':
				grp, ambig = 0, false
			}
			if r == '(' {
				// NAME () …: a function definition, whatever its body (a=() is an empty array)
				flushWord()
				j := i + 1
				for j < len(rs) && (rs[j] == ' ' || rs[j] == '\t') {
					j++
				}
				if n := len(words); n > 0 && j < len(rs) && rs[j] == ')' && !strings.HasSuffix(words[n-1], "=") {
					def = words[n-1]
				}
			}
			flushSeg()
			switch {
			case r == '|' && next() != '|' && (i == 0 || rs[i-1] != '|'):
				piped = true // a pipe; || is none, and |& is one
			case r == '|', r == ';', r == '&' && (i == 0 || rs[i-1] != '|'):
				piped = false
			}
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	out.unclosed = out.unclosed || q != 0
	flushSeg()
	out.work += len(rs) + st.copied // every character once (the inner loops advance i), and the bodies copied
	return out
}

// createPackage maps an npm initializer to the package npm runs: foo -> create-foo, @s -> @s/create,
// @s/foo -> @s/create-foo, keeping a version (vite@latest -> create-vite@latest). A path, URL or git
// source is not an npm package: "".
func createPackage(x string) string {
	if strings.ContainsAny(x, "/:") && !strings.HasPrefix(x, "@") || strings.Contains(x, "://") || strings.HasPrefix(x, ".") {
		return ""
	}
	name, ver := x, ""
	if i := strings.LastIndexByte(x, '@'); i > 0 {
		name, ver = x[:i], x[i:]
	}
	if scope, rest, ok := strings.Cut(name, "/"); ok && strings.HasPrefix(scope, "@") {
		return scope + "/create-" + rest + ver
	}
	if strings.HasPrefix(name, "@") {
		return name + "/create" + ver
	}
	return "create-" + name + ver
}

// configEnv reads a VAR=value prefix: a registry, index or package-manager config file set through the
// environment means the packages may not come from the public registries install_check reads.
func (p *hookParse) configEnv(k, v string) {
	win := p.cmdSet
	if len(k) > 5 && strings.EqualFold(k[:5], "$env:") { // PowerShell $env:NAME = value (N4)
		k, win = k[5:], true
	}
	// a ~ no shell expands in an argument word — after env or sudo, in what env -S splits (read again after an env), a
	// cmd set's or PowerShell's value — is the folder it names, as markTilde writes a quoted one, each list element too
	// (HOME-CONFIG-ENV-1 rounds 3–5; the value trimmed as the second reader's judgeEnv does). After env or sudo in a
	// line a POSIX shell runs, the reasons that name it say bash outside POSIX mode would use the home (round 5, P3-1)
	switch {
	case win:
		if w, wrote := argTildeValue(k, strings.TrimSpace(v), ";"); wrote != 0 {
			v = w
		}
	case p.entry && pathName(k) && !homeConfigEnv[strings.ToUpper(k)]:
		// an MCP entry's value, which no shell expands: its ~ elements are folders of the server's working folder, said
		// as round 2 says it (round 8, D); the config folders have entryHomeConfigWhy
		if w, wrote := argTildeValue(k, strings.TrimSpace(v), pathListSep(v)); wrote != 0 {
			v = w
			p.argTildeVals = append(p.argTildeVals, [2]string{w, whyDirLiteral})
		}
	case p.argTilde:
		w, wrote := argTildeValue(k, v, ":")
		if wrote != 0 && p.foreign == 0 { // env -S's words, a fish or csh script: no shell expands them
			p.argTildeVals = append(p.argTildeVals, [2]string{w, argTildeNote(wrote)})
		}
		v = w
	}
	lk := strings.ToLower(k)
	p.brewEnv(k, v) // Homebrew's source and tap-trust variables (ECO-1, brew.go)
	p.noteGoEnv(k, v)
	if p.assigned == nil {
		p.assigned = map[string]string{}
	}
	p.assigned[k] = v
	switch {
	case strings.Contains(lk, "registry") || strings.HasSuffix(lk, "index_url") || pyIndexEnv[strings.ToUpper(k)]:
		// pyIndexEnv: pip's and uv's index options through the environment, from their parsers (PIP_PYPI_URL, UV_INDEX)
		p.registryOverride(v)
	case strings.HasSuffix(lk, "userconfig") || strings.HasSuffix(lk, "globalconfig") || lk == "pip_config_file" || lk == "uv_config_file" ||
		lk == "npm_config_npmrc" || lk == "yarn_rc_filename" || lk == "bun_config_path":
		p.miss("installs with a custom registry or config file alalanet cannot see (" + k + ")")
	case codeLoadingEnv[strings.ToUpper(k)]:
		p.miss("runs with an environment that loads other code (" + k + ")")
	case lk == "node_options" && nodeLoads.MatchString(v):
		p.miss("runs with an environment that loads other code (NODE_OPTIONS " + clip(v, 60) + ")")
	case searchPathEnv[strings.ToUpper(k)] && untrustedPathIn(v, win):
		p.miss("runs with an environment that loads other code (" + k + " points at " + clip(v, 60) + tildeWhy(v) + ")")
	case homeConfigEnv[strings.ToUpper(k)] && p.homeMoved == "":
		// HOME-CONFIG-ENV-1: a reason only on a line that installs (parseInstallLineFull, EnvUnread); HOME=. make is none.
		// An MCP entry's value is passed as written (round 2, P2-1: no shell expands ~ or $HOME there)
		if p.entry {
			p.homeMoved = entryHomeConfigWhy(k, v)
		} else {
			p.homeMoved = homeConfigWhy(k, v)
		}
	}
}

// nodeLoads: NODE_OPTIONS that load a module before the program (--max-old-space-size does not).
var nodeLoads = regexp.MustCompile(`(^|\s)(-r|--require|--import|--loader|--experimental-loader)(=|\s|$)`)

// searchPathEnv: where a command, a library or a module is looked up; a hold only when it points at a
// relative or temporary folder (LD_LIBRARY_PATH=/usr/local/cuda/lib64 is how CUDA is used).
var searchPathEnv = map[string]bool{"PATH": true, "LD_LIBRARY_PATH": true, "DYLD_LIBRARY_PATH": true, "DYLD_FRAMEWORK_PATH": true,
	"NODE_PATH": true, "PYTHONPATH": true, "PYTHONHOME": true, "PERL5LIB": true, "RUBYLIB": true}

// windowsPath: C:\…, .\…, \\server\…, or a name with a Windows executable suffix.
func windowsPath(s string) bool {
	ls := strings.ToLower(s)
	return len(s) > 2 && s[1] == ':' || strings.HasPrefix(s, `.\`) || strings.HasPrefix(s, `\\`) ||
		strings.HasSuffix(ls, ".exe") || strings.HasSuffix(ls, ".cmd") || strings.HasSuffix(ls, ".bat") || strings.HasSuffix(ls, ".ps1")
}

// codeLoadingEnv: variables that make the interpreter or the dynamic loader run code the line does
// not name (second review pass, finding C).
var codeLoadingEnv = map[string]bool{"LD_PRELOAD": true, "LD_AUDIT": true, "DYLD_INSERT_LIBRARIES": true, "BASH_ENV": true,
	"PYTHONSTARTUP": true, "PERL5OPT": true, "RUBYOPT": true, "JAVA_TOOL_OPTIONS": true, "CLAUDE_CODE_SHELL_PREFIX": true}

// untrustedPath: a PATH with a relative entry or a world-writable temporary folder, where "npx" may be
// a file anyone put there. /usr/local/bin:/usr/bin (nvm users set PATH in MCP entries) is fine.
//
// win: the value is cmd's or PowerShell's; one that looks like a Windows list (windowsList: a ";" or a backslash, and
// every entry a drive, a share or %NAME%) is read as Windows' too, as the second reader's untrustedPathX reads it. A ":" list of a POSIX line otherwise names a %…%
// entry as the folder it is — no POSIX shell expands %P% — and has no cmd %NAME:~n,m% (HOME-CONFIG-ENV-1 round 8, G).
func untrustedPathIn(v string, win bool) bool {
	cmdish := win || windowsList(v) // a %P%\bin list is read as Windows', as untrustedPathX reads it
	ds := strings.Split(v, pathListSep(v))
	for i, d := range ds {
		ld := strings.ToLower(strings.ReplaceAll(d, `\`, "/"))
		switch {
		case d == "" || strings.HasPrefix(d, "$") || cmdish && strings.HasPrefix(d, "%") && !strings.HasPrefix(ld, "%temp%") && !strings.HasPrefix(ld, "%tmp%"):
		case strings.Contains(ld, "/tmp") || strings.Contains(ld, "/temp/") || strings.HasSuffix(ld, "/temp") || strings.HasPrefix(ld, "/var/tmp") ||
			strings.HasPrefix(ld, "/dev/shm") || strings.HasPrefix(ld, "%temp%") || strings.HasPrefix(ld, "%tmp%"):
			return true
		case listTilde(ds, i):
			// a search path trusts a ~ only for the home (~, ~/…): ~+, ~-, ~0 are the current folder, ~name another
			// user's home or a folder of the project (rounds 6–7, P2-A, P2-1, P2-2)
			return true
		case strings.HasPrefix(d, "/") || strings.HasPrefix(d, "~") || len(d) > 2 && d[1] == ':' || strings.HasPrefix(d, `\\`):
		default:
			return true // relative
		}
	}
	return false
}

// noteArgTilde: a reason that names an argument word's ./~ says the shell it holds for (round 5, P3-1), an MCP entry's
// that no shell reads it (round 8, D).
func (p *hookParse) noteArgTilde() {
	for i, r := range p.unread {
		for _, vn := range p.argTildeVals {
			if v := vn[0]; strings.Contains(r, v[:min(len(v), 40)]) {
				p.unread[i] = withArgTildeNote(r, vn[1])
				break
			}
		}
	}
}

// addAssigned adds the quoted assignment words of one more line read (shellLine.assigned) to those of the line.
func addAssigned(to, from map[string]string) map[string]string {
	for k, v := range from {
		if to == nil {
			to = map[string]string{}
		}
		if len(to) < 256 {
			to[k] = v
		}
	}
	return to
}

// assignedWord: x as the shell assigns it where an assignment stands — a quoted word with a space or an operator,
// written by markTilde (round 8, R2) — or x itself.
func assignedWord(assigned map[string]string, x string) string {
	if a, ok := assigned[x]; ok {
		return a
	}
	return x
}

// winListSep: the list separator of a value cmd or PowerShell (pwsh) reads — ";" for cmd; for PowerShell, which runs
// on Linux and macOS too, ";" only when the value has one, ":" otherwise, as untrustedPathX takes its entries
// ($env:PATH = "/usr/bin:~/bin": PowerShell keeps the ~, round 8, E).
func winListSep(v string, pwsh bool) string {
	if pwsh && !strings.Contains(v, ";") {
		return ":"
	}
	return ";"
}

// pathListSep: ";" for a Windows list (C:\Program Files\nodejs;C:\Windows), ":" otherwise.
func pathListSep(v string) string {
	if strings.Contains(v, ";") || len(v) > 2 && v[1] == ':' && (v[2] == '\\' || v[2] == '/') {
		return ";"
	}
	return ":"
}

// registryOverride notes a registry or index other than the public ones.
func (p *hookParse) registryOverride(v string) {
	host := v
	if u, err := url.Parse(v); err == nil && u.Host != "" {
		host = u.Hostname()
	}
	if !defaultRegistries[strings.ToLower(host)] {
		p.miss("installs from a custom registry or index (" + host + "): alalanet judges packages on the public registries only")
	}
}

func (p *hookParse) command(w []string, depth int) {
	if depth > 4 {
		p.miss("shell wrappers nested too deep to read")
		return
	}
	if s := stripEmptyExpansions(w); !slices.Equal(s, w) {
		// $@claude mcp add, npm install $@-g x, $@sudo …: at the top of the line an empty-by-default expansion in any
		// word vanishes, and the command is read as the shell runs it (READER-ESCAPE-1 round 2, R4). The line's own
		// words are read too, and both readings count: in a script given to sh -c with arguments, after set -- or in a
		// function, $1 and $@ are those arguments (sh -c 'npx -y $1' x evil-pkg runs npx -y evil-pkg), and that reading
		// holds the word as the base did.
		p.command(s, depth)
	}
	// Wrappers, their options, VAR=value prefixes (a registry set through the environment counts).
	viaXargs := false
	firstWrap := ""
	var assigns, wrappers []string // for visit
	for len(w) > 0 {
		x := w[0]
		if n := wrapperName(x); n != "" {
			x = n // /usr/bin/sudo, s\udo: only the wrapper's name; a VAR=value word is read as written
		}
		switch {
		case hookWrappers[x]:
			if firstWrap == "" {
				firstWrap = x
			}
			before := w
			w = w[1:]
			if x == "xargs" {
				viaXargs = true
			}
			if x == "timeout" {
				for len(w) > 0 && strings.HasPrefix(w[0], "-") && w[0] != "--" {
					if wrapperValueFlags[x][w[0]] && len(w) > 1 {
						w = w[1:]
					}
					w = w[1:]
				}
				if len(w) > 0 && w[0] == "--" {
					w = w[1:]
				}
				if len(w) > 0 {
					w = w[1:] // the duration
				}
			}
		flags:
			// sudo -E, env -i, nice -n 10, xargs -0. eval takes no options: zsh and dash run a leading -x word as
			// part of the line (eval '-x; npm i x' runs npm), bash refuses it and runs nothing (ADR-0159 round 4, F1).
			for x != "eval" && len(w) > 0 && strings.HasPrefix(w[0], "-") && w[0] != "--" {
				if x == "env" {
					// env -S 'npm i x' (and every spelling of it: --split-string, an abbreviation, a cluster
					// such as -iS): env splits the value into arguments and reads them as its own, options
					// first, then the words after it. The value is read again as env's arguments, so the
					// command behind any options is read (P1-X, ADR-0173).
					if v, rest, ok := envSplit(w); ok {
						if strings.HasPrefix(strings.TrimLeft(v, " \t"), "$") || strings.Contains(v, "${") {
							// $'…' or $VAR first, or ${NAME} anywhere (env -S expands it itself, even in single
							// quotes): what env gets is not in the line
							p.miss("runs env -S with a value alalanet cannot read (" + shown(v) + ")")
							return
						}
						line := envReread(v, rest)
						if viaXargs { // xargs env -S 'npm i' < list: the packages come from the input
							line = "xargs " + line
						}
						if p.visit != nil {
							p.visit(Command{Win: p.winRead, Assigns: assigns, Wrappers: append(wrappers, before...)})
						}
						p.foreign++ // env splits the value into words itself: no shell runs it as a script
						p.line(line, depth+1)
						p.foreign--
						return
					}
					n := envOptionWords(w[0])
					if n == 0 { // an option alalanet does not know may take the next word: never silent
						p.miss("runs env with an option alalanet does not read (" + shown(w[0]) + ")")
						n = 1
					}
					if n == 2 && len(w) > 1 {
						w = w[1:]
					}
					w = w[1:]
					continue flags
				}
				if hookTakesValue(x, w[0]) && len(w) > 1 {
					w = w[1:]
				}
				w = w[1:]
			}
			// sudo -- npm i x: the end of the wrapper's options; zsh's eval ends them at a lone - too
			if len(w) > 0 && (w[0] == "--" || x == "eval" && w[0] == "-") {
				w = w[1:]
			}
			if x == "eval" && len(w) > 0 {
				// eval joins its words with blanks and runs the result as a shell line, so the words are read
				// as that line, as sh -c reads its script: eval 'A=1 npx -y x' and eval 'npx -y' x run npx -y x.
				// Read word by word, a script with an "=" was one VAR=value word and a split one a program
				// named "npx -y" (READER-EQ-1, ADR-0159 round 4).
				line := strings.Join(w, " ")
				if viaXargs { // xargs eval 'npm i' < list: the packages come from the input
					line = "xargs " + line
				}
				if p.visit != nil {
					p.visit(Command{Win: p.winRead, Assigns: assigns, Wrappers: append(wrappers, before[:len(before)-len(w)]...)})
				}
				p.line(line, depth+1)
				return
			}
			wrappers = append(wrappers, before[:len(before)-len(w)]...)
		case strings.Contains(x, "=") && !strings.HasPrefix(x, "-"):
			if paramExpansionProgram(x) {
				goto body // ${X:=npm} i x, n${E:=p}m i x: a parameter expansion, not an assignment word (READER-SHELLS P2-3)
			}
			x = assignedWord(p.quoted, x) // export "PATH=~/a b:/usr/bin": the value the shell assigns (round 8, R2)
			assigns = append(assigns, x)
			k, v, _ := strings.Cut(x, "=")
			if unseenName.MatchString(k) {
				// env $K=… npm i x, an MCP add's -e "$E": a variable whose name the line does not show may move the
				// registry (ECO-1 Go, round 5, P2-2)
				p.miss(whyVarArgument + " (" + clip(x, 60) + ")")
			}
			// after env or sudo the assignment is an argument word: zsh, dash and bash --posix leave its ~ as it is
			// (HOME-CONFIG-ENV-1 round 3)
			p.argTilde = firstWrap != ""
			p.configEnv(k, v)
			p.argTilde = false
			w = w[1:]
		default:
			goto body
		}
	}
body:
	if len(w) == 0 {
		p.noteDefs("", nil, assigns, depth) // BASH_ALIASES[pip]=…, zsh's functions[pip]=… (READER-SHADOW-1)
	}
	if p.visit != nil && (len(w) == 0 || len(w) == 1 && strings.ContainsAny(w[0], " \t;|&")) {
		p.visit(Command{Win: p.winRead, Assigns: assigns, Wrappers: wrappers})
	}
	if len(w) == 0 {
		if p.prog == "" && (firstWrap == "busybox" || firstWrap == "toybox") {
			p.prog = firstWrap // busybox alone: ECO-1 counts it as before, not "" (round 6, P3-6)
		}
		return
	}
	if len(w) == 1 && strings.ContainsAny(w[0], " \t;|&") {
		if d := paramDefault(w[0]); d != "" {
			// a lone ${TEST_CMD:-npm test -- --watch=false}: the shell runs the default's value; read again whole, the
			// word would come back as one word until the depth runs out (round 8, R3-2)
			p.foreign++ // the walk's reading again of one word: no shell runs it as a script
			p.line(d, depth+1)
			p.foreign--
			return
		}
		p.foreign++
		p.line(w[0], depth+1) // a quoted script after a wrapper: sudo 'npm i x'
		p.foreign--
		return
	}
	cmd := w[0]
	// splitShell gives the shell's word: a backslash before an ordinary character is already gone (n\px -> npx), and
	// only a Windows-path word still holds backslashes (READER-ESCAPE-1).
	if i := strings.LastIndexAny(cmd, `/\`); i >= 0 { // /usr/bin/npm, ./node_modules/.bin/npx, C:\...\npm
		cmd = cmd[i+1:]
	}
	cmd = dropShim(strings.ToLower(cmd)) // npx.cmd, npx.exe, npx.ps1, npm.bat (round 43, P3-4)
	// pip3.12 is pip, npm isntall is npm install, bun a is bun add (READER-NPM-ALIAS-1)
	cmd, rest := canonCommand(cmd, w[1:])
	if cmd == "brew" {
		p.brewFlush() // the Homebrew variables set so far are brew's (ECO-1-BREW round 3)
	}
	p.noteDefs(cmd, rest, assigns, depth) // alias x=…, hash -p PATH pip, enable … (READER-SHADOW-1)
	if p.prog == "" {
		p.prog = cmd // the command's program; a command read inside it (python -m pip, npx … mcp add -- x) keeps it
	}
	if p.visit != nil {
		p.visit(Command{Win: p.winRead, Prog: cmd, Words: append(w[:1:1], rest...), Assigns: assigns, Wrappers: wrappers})
	}
	if p.runs(w, cmd, rest, depth) { // su -c, watch, trap, fish -c, iex, call, start, n${E}pm … (READER-SHELLS)
		return
	}
	if code := interpInline(cmd, rest); code != "" && p.inlineDownload(code) {
		return // python3 -c "$(curl …)", node -e, perl -e: the downloaded script is the program (PIPE-SCRIPT-1)
	}
	switch {
	case posixShells[cmd] && len(rest) > 0:
		if w, ok := cScriptWord(rest); ok && p.inlineDownload(w) {
			return // sh -c "$(curl …)" [name args…]: the downloaded script; the words after it are $0 and its arguments
		}
		if s, ok := shellScript(rest, false); ok { // bash -c "npm i x", bash -lc …, bash -c -- '…', sh -c -e '…'
			p.line(s, depth+1)
		}
		return
	case (cmd == "pwsh" || cmd == "powershell") && len(rest) > 0:
		for i, x := range rest {
			if lx := strings.ToLower(x); lx == "-command" || lx == "-c" {
				if i+1 == len(rest) {
					p.hits++ // pwsh -Command { … }: the block follows as its own commands
					return
				}
				if rest[i+1] == "-" {
					return // pwsh -Command -: the script is its input (a download it runs: PIPE-SCRIPT-1)
				}
				p.foreignScript(strings.Join(rest[i+1:], " "), "PowerShell", depth)
				return
			}
			if strings.HasPrefix(strings.ToLower(x), "-enc") {
				p.miss("an encoded PowerShell command alalanet cannot read")
				return
			}
		}
		return
	case cmd == "cmd" && len(rest) > 0:
		for i, x := range rest {
			if lx := strings.ToLower(x); lx == "/c" || lx == "/k" {
				p.foreignScript(strings.Join(rest[i+1:], " "), "cmd.exe", depth)
				return
			}
		}
		return
	case pythonInterp(cmd):
		if mod, margs, ok := pyModule(cmd, rest); ok && (mod == "pip" || mod == "pip3" || mod == "uv" || mod == "pipx") {
			p.command(append([]string{mod}, margs...), depth+1)
		} else if ok && mod == "venv" {
			p.hits++ // python3 -m venv .venv: the standard library, nothing installed
		}
		return
	}
	if cmd == "export" || cmd == "declare" || cmd == "typeset" || cmd == "setx" || cmd == "set" {
		// cmd.exe "set NAME=value" too (third review pass, N4)
		for _, x := range rest { // export NPM_CONFIG_REGISTRY=… && npx -y x (second review, finding B)
			if k, v, ok := strings.Cut(assignedWord(p.quoted, x), "="); ok && !strings.HasPrefix(k, "-") {
				p.cmdSet = cmd == "set" || cmd == "setx" // cmd.exe never expands ~ (HOME-CONFIG-ENV-1 round 3)
				p.configEnv(k, v)
				p.cmdSet = false
			}
		}
		return
	}
	// A word the line does not show where the tool reads an option or its subcommand: npm $P i x (READER-VAR-OPT-1).
	p.unseenLead(cmd, rest)
	// The subcommand of npm, pnpm, Yarn and bun is their first word that is not an option or an option's value
	// (npm -w web init vite, pnpm --dir web create vite: RT-1 round 3).
	sub := -1
	if verbManagers[cmd] {
		sub = pmFirstPositional(cmd, rest)
	}
	if sub >= 0 && (rest[sub] == "ci" || rest[sub] == "clean-install") {
		p.hits++ // the lockfile's packages: an install form with nothing named to check
		return
	}
	if sub >= 0 && (rest[sub] == "init" || rest[sub] == "create" || rest[sub] == "innit") {
		// npm init foo / npm create foo / yarn create foo run the package create-foo (npm docs, npm init);
		// a --registry or a value flag (-w ws) is read like any install's (third review pass, N5)
		p.hits++
		// npm reads options anywhere before "--" (nopt), so a hidden word after the initializer is one too (R4)
		p.unseenCommandWord(rest, sub+1, cmd == "npm", npmRunnerTakesValue(cmd), nil)
		for j := 0; j < len(rest); j++ {
			x := rest[j]
			if j == sub {
				continue
			}
			if k, v, ok := strings.Cut(x, "="); ok && npmRegistryOption(k) {
				p.registryOverride(v)
			} else if npmRegistryOption(x) && j+1 < len(rest) {
				p.registryOverride(rest[j+1])
			}
		}
		for j := sub + 1; j < len(rest); j++ {
			x := rest[j]
			if strings.HasPrefix(x, "-") {
				if pmTakesValue(cmd, x) || valueFlags[x] {
					j++
				}
				continue
			}
			if t := createPackage(x); t != "" {
				p.add("npm:" + t)
			} else {
				p.miss("runs an initializer alalanet cannot read (" + cmd + " " + rest[sub] + " " + x + ")")
			}
			break
		}
		return
	}
	// xargs appends words from standard input: with no subcommand on the line, xargs supplies the whole command,
	// install or not; with one, only an install form that takes its packages from its words does (npm i, pip
	// install, npx, pipx install), not npm view or pip show (RT-1 round 3). Decided on a throwaway reading of the
	// same words, so the reason keeps its place among the line's reasons.
	if viaXargs && (packageManagers[cmd] || cmd == "brew" || goCommand(cmd)) {
		noSubcommand := !slices.ContainsFunc(rest, func(x string) bool { return !strings.HasPrefix(x, "-") })
		if verbManagers[cmd] {
			noSubcommand = sub < 0
		}
		if _, _, names := (&hookParse{seen: map[string]bool{}}).commandTargets(cmd, rest); noSubcommand || names {
			p.miss("install arguments come from standard input (xargs) alalanet cannot see")
			if goCommand(cmd) && len(rest) > 0 && rest[0] == "env" {
				p.goEnv = append(p.goEnv, goEnvSet{"$", "xargs go env -w", true}) // pairs from stdin: any name (ECO-1 Go, round 3)
			}
		}
	}
	if len(rest) == 0 {
		return
	}
	// npm's scoped registry, --@scope:registry=URL (or a following word): the scope's packages come
	// from there, not from the public registry install_check reads (round 3, R3-PLAN-01/02).
	for i, x := range rest {
		if lx := strings.ToLower(npmTwoDash(x)); strings.HasPrefix(lx, "--@") && strings.Contains(lx, ":registry") {
			v := ""
			if _, after, ok := strings.Cut(x, "="); ok {
				v = after
			} else if i+1 < len(rest) {
				v = rest[i+1]
			}
			p.registryOverride(v)
		}
		// --userconfig / --globalconfig: a config file that can set any registry (also npm's --userc, --globalc …)
		if packageManagers[cmd] && npmConfigFileOption(x) {
			p.miss("installs with a custom registry or config file alalanet cannot see (" + x + ")")
		}
	}
	// "<agent CLI> mcp add NAME -- cmd" run through npx or a path: cmd is what the client will start
	// (npx -y @anthropic-ai/claude-code mcp add x -- npx -y pkg; independent review, finding 8), read by the one entry
	// point (findMCPAdd: the client's own grammar by its package or path, its root options, with or without "--")
	if clientOf(cmd) == "" {
		if m, ok := findMCPAdd(cmd, rest); ok {
			if m.why != "" {
				p.miss(m.why) // and the launch after "--", when it is known, is judged as well (round 2, P2-2)
			}
			switch {
			case m.url != "":
				p.add(m.url)
			case len(m.launch) > 0:
				p.command(append(mcpAddEnvFrom(m.env, m.launch, func(s string) string { return s }), m.launch...), depth+1)
			}
		}
	}
	targets, recognized, _ := p.commandTargets(cmd, rest)
	if recognized && packageManagers[cmd] {
		p.hits++ // an install form, even one with nothing to check (npm install, pip install -r r.txt)
	}
	for _, t := range targets {
		p.add(t)
	}
	// The program a package runner starts, with its words, is read as env's and sudo's is: pnpm exec sh -c '<line>',
	// npx -p x sh -c '<line>', yarn exec -- npx y (runnerProgram; ADR-0159 round 43, P2-1). A program named by a variable
	// that the runner's own reading already names as a variable argument (npx -y "$SHELL" -c …: the package word) is not
	// read again: that reading would only say the same in other words (round 45, P3-1).
	if i := runnerProgram(cmd, rest); i >= 0 && runnerReadsProgram(rest[i]) &&
		!(strings.Contains(rest[i], "$") && p.seen["?"+whyVarArgument+" ("+clip(rest[i], 60)+")"]) {
		p.command(rest[i:], depth+1)
	}
	// A package manager with an install verb that none of the forms above reads: ask, do not guess. Not for npm,
	// pnpm, Yarn and bun, whose subcommand verbAfter finds: a verb word it skipped is an option's value (npm --prefix
	// x run build) or another manager's runner (pnpm exec), not an install (RT-1 round 3).
	if !recognized && packageManagers[cmd] && !verbManagers[cmd] {
		for _, x := range rest {
			if installVerbs[x] {
				p.miss("an install command alalanet could not read (" + cmd + " " + x + ")")
				break
			}
		}
	}
}

// verbAfter: the index after the first of verbs in an npm, pnpm, Yarn or bun command's words, or -1. The words are
// read in order, as pmFirstPositional and pkgs read them: the word an option that takes a value takes is that value,
// not a verb — npm --prefix x install pkg (x is a folder), the short options each manager reads with a value (npm -w x
// install pkg; pnpm -F dlx add pkg: pmTakesValue, -w takes a value in npm and none in pnpm), and an option taken as
// another's value (npm -w --reg x pkg: x is npm's exec, not --reg's value). RT-1 round 3.
func verbAfter(cmd string, rest []string, verbs ...string) int {
	for i := 0; i < len(rest); i++ {
		switch x := rest[i]; {
		case strings.HasPrefix(x, "-") && pmTakesValue(cmd, x):
			i++
		case slices.Contains(verbs, x):
			return i + 1
		}
	}
	return -1
}

// commandTargets reads one package-manager command; recognized is true when it is a form alalanet knows, even one
// with nothing to check (npm install, pip install -r requirements.txt, pipx list); names is true when the form
// installs or runs the packages its own words name, so words xargs appends would be packages too.
func (p *hookParse) commandTargets(cmd string, rest []string) (targets []string, recognized, names bool) {
	if p.reqs != nil && pyTool(cmd) {
		p.reqFileWords(cmd, rest)
	}
	after := func(subs ...string) int {
		for i, x := range rest {
			for _, s := range subs {
				if x == s {
					return i + 1
				}
			}
		}
		return -1
	}
	// skillsAdd: when the package run is the skills CLI, the `skills add …` it runs, read from the
	// first add verb after the CLI word (from index from of rest on).
	skillsAdd := func(pkg string, from int) []string {
		if pkg != "skills" && !strings.HasPrefix(pkg, "skills@") {
			return nil
		}
		seen := false
		for j := max(from, 0); j < len(rest); j++ {
			x := rest[j]
			if !seen {
				seen = x == pkg
				continue
			}
			switch x {
			case "add", "install", "a", "i":
				if j+1 < len(rest) {
					return []string{"skills add " + strings.Join(rest[j+1:], " ")}
				}
				return nil
			}
		}
		return nil
	}
	// spec turns one package word into a target, or notes it as unreadable (git/URL/GitHub shorthand).
	spec := func(eco, x string) string {
		switch {
		case strings.Contains(x, "://"), strings.HasPrefix(x, "git+"), strings.HasPrefix(x, "github:"), strings.HasPrefix(x, "gitlab:"),
			strings.HasPrefix(x, "bitbucket:"), strings.HasPrefix(x, "git@"), strings.HasPrefix(x, "file:"):
			p.miss("installs a git or URL package (" + x + "): alalanet checks registry packages, not arbitrary sources")
			return ""
		case eco == "npm:" && !strings.HasPrefix(x, "@") && strings.Contains(x, "/"):
			p.miss("installs a GitHub shorthand (" + x + "): alalanet checks registry packages, not repositories")
			return ""
		case eco == "pypi:" && strings.Contains(x, " @ "):
			p.miss("installs a direct URL requirement (" + x + ")")
			return ""
		case strings.ContainsAny(x, "$\\"):
			// npx -y ${PKG}: the name comes from a variable the line does not show (third review, N2)
			p.miss(whyVarArgument + " (" + clip(x, 60) + ")")
			return ""
		}
		return eco + x
	}
	// pm: whose options this program reads — the manager's own, npm's for npx (npm exec), pnpm's for pnpx (pnpm dlx,
	// and pnpm validates them), bunx's own few for bunx (bun.sh/docs/cli/bunx).
	pm := map[string]string{"npm": "npm", "pnpm": "pnpm", "yarn": "yarn", "bun": "bun", "npx": "npm", "pnpx": "pnpm", "bunx": "bunx"}[cmd]
	// shortVal: the letters of this tool's short options that take a value, in this form (pyShortValue); indexShort:
	// those of its index options (pyIndexShort: -f is find-links in pip and uv, --force in pipx).
	pyT := pyTable(cmd, rest)
	pyIdx := pyIndexOptions[pyForm(cmd, rest)]
	shortVal := pyShortValue(cmd, rest)
	indexShort := pyIndexShort(cmd, pyIdx)
	// takesValue: whether an option word leaves its value to the next word, as this program reads its options. npm,
	// pnpm, Yarn and bun each read their own (npm i -f pkg forces, pnpm add -w pkg is the workspace root). pip, uv
	// and pipx read theirs per subcommand, from tables generated out of their own parsers (pyOptions, pyTakesValue):
	// no option's value is read as a package (pip install x --upgrade-strategy eager, uvx --torch-backend auto x) and
	// no switch takes the next word (uv run --script -f DIR: --script is a switch there, a path in uv add). RT-1 round
	// 3; READER-VAR-OPT-1 rounds 2 and 3.
	takesValue := func(x string) bool {
		switch {
		case pm != "":
			return pmTakesValue(pm, x)
		case pyTool(cmd):
			return pyTakesValue(pyT, cmd, x)
		}
		return valueFlags[x]
	}
	// isRegistry: an option naming another registry or index — for npm, pnpm, Yarn, bun and their runners only
	// --registry and its abbreviations (npmRegistryOption: npm i -f pkg forces; RT-1 round 3); for pip, pipx and uv
	// every option of the form whose parser destination is an index or a find-links location, by its full name or an
	// abbreviation the parser takes (pyIndexOption: pip install --pypi-url, --pyp, --in URL; not pipx's -f, --force).
	isRegistry := func(x string) bool {
		if pm != "" {
			return npmRegistryOption(x)
		}
		return pyIndexOption(cmd, pyT, pyIdx, x) // by the parser's dest, aliases included (READER-VAR-OPT-1 round 4)
	}
	// localFile: a word the program installs from a file on this machine. npm, pnpm, Yarn and bun read a bare name
	// ending in .tgz, .tar.gz or .tar as a file and any other bare word (x.txt, x.whl) as a registry package
	// (npm-package-arg); pip's requirement files and wheels end in .txt and .whl.
	localFile := func(x string) bool {
		lx := strings.ToLower(x)
		if pm != "" {
			return strings.HasSuffix(lx, ".tgz") || strings.HasSuffix(lx, ".tar.gz") || strings.HasSuffix(lx, ".tar")
		}
		return strings.HasSuffix(x, ".txt") || strings.HasSuffix(x, ".whl") || strings.HasSuffix(x, ".tgz") || strings.HasSuffix(x, ".tar.gz")
	}
	// pkgs: the non-flag words from i on, skipping flag values and local paths; registry flags noted.
	pkgs := func(i int) []string {
		var out []string
		for j := i; j < len(rest); j++ {
			x := rest[j]
			if k, v, ok := strings.Cut(x, "="); ok && isRegistry(k) {
				p.registryOverride(v)
				continue
			}
			switch {
			case x == "--":
				continue
			case unseenOption(x): // npm i x --$P, --re\gistry=URL: an option the line does not show (READER-VAR-OPT-1)
				p.miss(whyVarArgument + " (" + clip(x, 60) + ")")
			case isRegistry(x):
				if j+1 < len(rest) {
					p.registryOverride(rest[j+1])
				}
				j++
			case pyTool(cmd) && len(x) > 2 && x[0] == '-' && x[1] != '-':
				// pip install -ihttps://…, -Ui URL: a registry option in a cluster of short ones (READER-VAR-OPT-1)
				if v, next, ok := pyShortRegistry(x, shortVal, indexShort); ok && !next {
					p.registryOverride(v)
				} else if ok {
					if j+1 < len(rest) {
						p.registryOverride(rest[j+1])
					}
					j++
				}
			case takesValue(x):
				j++
			case strings.HasPrefix(x, "-"), x == "", strings.HasPrefix(x, "."), strings.HasPrefix(x, "/"), strings.HasPrefix(x, "~"),
				!strings.Contains(x, "://") && localFile(x):
				// a local file or folder; an archive at a URL (npm i https://host/p.tgz) is a URL package (spec)
			default:
				out = append(out, x)
			}
		}
		return out
	}
	// flagValues: every value of the given flags (-p x, --package x, --package=x).
	flagValues := func(names ...string) []string {
		var out []string
		for j, x := range rest {
			for _, n := range names {
				if x == n && j+1 < len(rest) {
					out = append(out, rest[j+1])
				} else if v, ok := strings.CutPrefix(x, n+"="); ok {
					out = append(out, v)
				}
			}
		}
		return out
	}
	addAll := func(eco string, xs []string) []string {
		var out []string
		for _, x := range xs {
			if t := spec(eco, x); t != "" {
				out = append(out, t)
			}
		}
		return out
	}
	if cmd != "go" && goCommand(cmd) { // go1.22.0, gotip: the go command of another version (ECO-1 Go, round 3)
		return p.goTargets(rest)
	}
	switch cmd {
	case "npx", "bunx", "pnpx":
		// npx -p PKG $P bin: $P is read as an option (R4); npx -c CMD carries the command (Q3)
		p.unseenCommandWord(rest, 0, false, npmRunnerTakesValue(pm), npmCommandOption)
		if pk := flagValues("-p", "--package"); len(pk) > 0 { // with --package the positional is a bin name, not a package
			pkgs(0) // registry flags still count
			return addAll("npm:", pk), true, true
		}
		ps := pkgs(0)
		if len(ps) == 0 {
			return nil, true, true
		}
		// npx skills add owner/repo (skills.sh's own instructions): the CLI and the skills it installs.
		return append(addAll("npm:", ps[:1]), skillsAdd(ps[0], 0)...), true, true
	case "npm", "pnpm", "yarn", "bun":
		// The subcommand is the first runner verb or install verb, and a later word equal to either is a
		// package: npm install left-pad x installs two (the runner verbs were looked for anywhere first, and
		// left-pad went unread: RT-1 review, round 2). The runner verbs are each manager's own (runnerVerbs:
		// pnpm exec and yarn exec fetch nothing; RT-1 round 3).
		run, inst := verbAfter(cmd, rest, runnerVerbs[cmd]...), verbAfter(cmd, rest, "i", "install", "add")
		// The manager's own options before the verb count too: npm --reg URL install x installs from URL (only the second
		// reader saw --registry there, and neither saw --reg; RT-1 round 3). Every registry option before the verb is
		// read, also one in a value's place: nopt takes an option-like word as the value of some options and not of
		// others (a String option leaves it to be read as an option), so npm --tag --registry URL exec x may install
		// from URL.
		verb := inst // the index after the subcommand's verb, or -1
		if run >= 0 && (inst < 0 || run < inst) {
			verb = run
		}
		for j := 0; j+1 < verb; j++ {
			if k, v, ok := strings.Cut(rest[j], "="); ok && npmRegistryOption(k) {
				p.registryOverride(v)
			} else if npmRegistryOption(rest[j]) && j+2 < verb {
				p.registryOverride(rest[j+1])
			}
		}
		if i := run; i >= 0 && (inst < 0 || run < inst) {
			// npm exec reads options anywhere before "--" (nopt); pnpm dlx, Yarn dlx and bun x stop at the command (R4)
			p.unseenCommandWord(rest, i, cmd == "npm", npmRunnerTakesValue(cmd), nil)
			if pk := flagValues("-p", "--package"); len(pk) > 0 {
				pkgs(i)
				return addAll("npm:", pk), true, true
			}
			if ps := pkgs(i); len(ps) > 0 {
				// pnpm dlx, yarn dlx, npm exec, bun x skills add …: the skills too (deep review IMP-55)
				return append(addAll("npm:", ps[:1]), skillsAdd(ps[0], i)...), true, true
			}
			return nil, true, true
		}
		if i := inst; i >= 0 {
			if ps := pkgs(i); cmd != "pnpm" || !ownSwitch(cmd, rest, "--workspace") {
				return addAll("npm:", ps), true, true
			}
			// pnpm add --workspace takes each package from the workspace and fails rather than fetch it from the
			// registry (pnpm.io/cli/add, read 2026-11-14): nothing install_check reads (RT-1 round 3)
			return nil, true, true
		}
	case "pip", "pip3":
		if i := after("install"); i >= 0 {
			for _, e := range flagValues("-e", "--editable") {
				if !strings.HasPrefix(e, ".") && !strings.HasPrefix(e, "/") {
					spec("pypi:", e)
				}
			}
			return addAll("pypi:", pkgs(i)), true, true
		}
	case "uv":
		if uvSubcommand(rest) == "python" {
			// uv python install <version> downloads a Python build (python-build-standalone), not a PyPI package
			// (docs.astral.sh/uv/reference/cli/#uv-python-install, read 2026-11-14): nothing install_check reads.
			return nil, true, false
		}
		switch {
		case len(rest) >= 2 && rest[0] == "tool" && (rest[1] == "run" || rest[1] == "install"):
			// tool run stops at the command; tool install takes one package, so a word after it is an option (R4)
			p.unseenCommandWord(rest, 2, rest[1] == "install", takesValue, nil)
			return p.uvx(2, spec, flagValues, pkgs), true, true
		case pyForm(cmd, rest) == "uv pip sync":
			// uv pip sync installs what its requirements files name, from the index its options name: the index is read
			// as an install's, the file words are no packages (READER-REQFILE-1)
			pkgs(0)
			return nil, true, false
		case len(rest) >= 1 && rest[0] == "run":
			p.unseenCommandWord(rest, 1, false, takesValue, uvRunCommandOption) // uv run --with PKG $P script.py: $P before the command (R4)
			out := addAll("pypi:", flagValues("--with"))
			pkgs(1)
			return out, true, false
		}
		if i := after("install", "add"); i >= 0 {
			return addAll("pypi:", pkgs(i)), true, true
		}
	case "uvx":
		p.unseenCommandWord(rest, 0, false, takesValue, nil) // uvx --from PKG $P bin: $P before the command (R4)
		return p.uvx(0, spec, flagValues, pkgs), true, true
	case "pipx":
		// pipx names what it fetches only in install (one or more package specs, and --preinstall), run (the app
		// or --spec, and --with extras), inject (the dependencies after the environment) and runpip (a pip
		// command run in an environment, read as pip's); list, upgrade, reinstall, uninstall, ensurepath,
		// environment and the rest name nothing to fetch (pipx.pypa.io/stable/reference/cli.html, read
		// 2026-11-14). An upgrade is not checked, as npm update is not (RT-1 round 3).
		pkgs(0) // a registry or index anywhere on the line is noted, as before
		for _, v := range pipxPipArgs(rest) {
			p.pipArgs(v) // what pipx gives pip install: --pip-args='--index-url=…' (READER-VAR-OPT-1)
		}
		sub := -1
		for j := 0; j < len(rest) && sub < 0; j++ {
			switch x := rest[j]; {
			case !strings.HasPrefix(x, "-"):
				sub = j
			case !strings.Contains(x, "=") && takesValue(x):
				j++ // the option's value, not the subcommand (pipx -w x run …)
			}
		}
		if sub < 0 {
			return nil, false, false
		}
		switch rest[sub] {
		case "install":
			out := addAll("pypi:", flagValues("--preinstall"))
			if sp := flagValues("--spec"); len(sp) > 0 { // older pipx: the package the app comes from
				pkgs(sub + 1)
				return append(out, addAll("pypi:", sp)...), true, true
			}
			return append(out, addAll("pypi:", pkgs(sub+1))...), true, true
		case "run":
			p.unseenCommandWord(rest, sub+1, false, takesValue, nil) // pipx run --spec PKG $P app: $P before the app (R4)
			out := addAll("pypi:", flagValues("--with"))
			if sp := flagValues("--spec"); len(sp) > 0 {
				pkgs(sub + 1)
				return append(addAll("pypi:", sp[:1]), out...), true, true
			}
			if ps := pkgs(sub + 1); len(ps) > 0 {
				return append(addAll("pypi:", ps[:1]), out...), true, true
			}
			return out, true, true
		case "inject":
			if ps := pkgs(sub + 1); len(ps) > 1 {
				return addAll("pypi:", ps[1:]), true, true // the first word is the environment
			}
			return nil, true, true
		case "runpip":
			if v := slices.IndexFunc(rest[sub+1:], func(x string) bool { return !strings.HasPrefix(x, "-") }); v >= 0 {
				t, _, n := p.commandTargets("pip", rest[sub+2+v:]) // after the environment: pip's own words
				return t, true, n
			}
			return nil, true, false
		case "install-all", "exec", "list", "upgrade", "upgrade-all", "upgrade-shared", "uninstall", "uninstall-all",
			"uninject", "reinstall", "reinstall-all", "repair", "manifest", "ensurepath", "environment", "completions",
			"interpreter", "pin", "unpin", "expose", "unexpose", "reset", "health", "cache", "help":
			return nil, true, false
		}
	case "brew": // Homebrew's third-party taps (ECO-1, brew.go)
		return p.brewTargets(rest)
	case "go": // go install and go run with a version (ECO-1, golang.go); also a golang.org/dl wrapper (goCommand)
		return p.goTargets(rest)
	case "deno":
		var out []string
		for _, x := range rest {
			if v, ok := strings.CutPrefix(x, "npm:"); ok {
				out = append(out, "npm:"+v)
			} else if strings.HasPrefix(x, "jsr:") || strings.HasPrefix(x, "https://") {
				p.miss("runs a deno module from " + x)
			}
		}
		return out, true, true
	case "claude", "codex", "gemini":
		// the server it adds, in the client's own grammar, its root options before "mcp" and "add" read, with or
		// without "--" (MCP-ADD-NO-DASH-1, mcpadd.go)
		m, ok := findMCPAdd(cmd, rest)
		if !ok {
			return nil, true, false
		}
		if m.why != "" {
			p.miss(m.why) // and the launch after "--", when it is known, is judged as well (round 2, P2-2)
		}
		switch {
		case m.url != "":
			return []string{m.url}, true, false
		case len(m.launch) > 0:
			// the server's -e/--env pairs that the Go reader judges go with its command (ECO-1 Go, round 3, P2-5)
			// the launch's words quoted, so that the target reads back as the client starts it (uvx --python ">=3.11,<3.14"
			// pkg: unquoted, the ">" and "<" were redirections; round 2): a word the line reads back otherwise — a space,
			// a redirection, a list or a quote in it — but not one with "$", "`", "<(" or ">(", which the shell expands
			// and the target must keep showing as such
			// A shell's -c script is quoted whole, its $ included: the nested sh -c reading reads it as the shell will
			// (round 3, P3-2: sh -c 'echo $HOME; go run x' read as a list named no module).
			words, script := mcpAddEnvFrom(m.env, m.launch, shellQuote), posixScriptAt(m.launch)
			for j, x := range m.launch {
				if j == script || strings.ContainsAny(x, " \t\n<>;|&()'\"\\") && !strings.ContainsAny(x, "$`") &&
					!strings.Contains(x, "<(") && !strings.Contains(x, ">(") {
					x = shellQuote(x)
				}
				words = append(words, x)
			}
			return []string{strings.Join(words, " ")}, true, false
		}
		return nil, true, false
	case "skills":
		if i := after("add", "install", "a", "i"); i >= 0 && i < len(rest) {
			return []string{"skills add " + strings.Join(rest[i:], " ")}, true, false
		}
	case "clawhub": // ClawHub skills (ADR-0066); its own parser reads --version
		if rest[0] == "install" {
			return []string{"clawhub " + strings.Join(rest, " ")}, true, false
		}
	case "openclaw":
		if len(rest) > 1 && rest[0] == "skills" && rest[1] == "install" {
			return []string{"clawhub " + strings.Join(rest[1:], " ")}, true, false
		}
	case "code", "code-insiders", "cursor", "windsurf", "codium", "vscodium", "positron", "kiro", "trae", "void": // IDE extensions (ADR-0070)
		var out []string
		for i, x := range rest {
			id := ""
			switch {
			case x == "--install-extension" && i+1 < len(rest):
				id = rest[i+1]
			case strings.HasPrefix(x, "--install-extension="):
				id = strings.TrimPrefix(x, "--install-extension=")
			}
			if id != "" && !strings.HasSuffix(id, ".vsix") { // a local .vsix file is not in a registry
				out = append(out, cmd+" --install-extension "+id)
			}
		}
		return out, true, false
	}
	return nil, false, false
}

// uvx: the package is --from's value if given (the positional is then a command), plus every --with.
func (p *hookParse) uvx(start int, spec func(string, string) string, flagValues func(...string) []string, pkgs func(int) []string) []string {
	var out []string
	add := func(x string) {
		if t := spec("pypi:", x); t != "" {
			out = append(out, t)
		}
	}
	from := flagValues("--from")
	for _, x := range from {
		add(x)
	}
	for _, x := range flagValues("--with", "--with-executables-from") { // uv tool install installs both (Q6)
		add(x)
	}
	ps := pkgs(start)
	if len(ps) >= 2 && (ps[1] == "@" || strings.HasPrefix(ps[1], "@ ")) {
		// "name @ git+https://…" (PEP 508): the tool comes from that URL, not from PyPI
		p.miss("installs a direct URL requirement (" + ps[0] + " @ " + clip(strings.Join(ps[2:], " "), 80) + ")")
		return out
	}
	if len(from) == 0 && len(ps) > 0 {
		add(ps[0])
	}
	return out
}

// uvValueFlags: uv's global options that take the next word as their value, besides valueFlags
// (docs.astral.sh/uv/reference/cli/, read 2026-11-14).
var uvValueFlags = map[string]bool{"--directory": true, "--project": true, "--config-file": true, "--cache-dir": true, "--color": true}

// uvSubcommand: uv's subcommand, its first word that is not an option or an option's value ("" when none).
func uvSubcommand(rest []string) string {
	for i := 0; i < len(rest); i++ {
		x := rest[i]
		if strings.HasPrefix(x, "-") {
			if !strings.Contains(x, "=") && (valueFlags[x] || uvValueFlags[x]) {
				i++
			}
			continue
		}
		return x
	}
	return ""
}

// envShortValue: env's short options that take a value (GNU coreutils 9 and the BSDs): -u NAME, -C DIR,
// -a ARG0 (GNU --argv0), -P PATH (BSD), -L CLASS and -U USER (FreeBSD). envShortKnown: every short
// option env has; a cluster such as -iu reads them in turn, as getopt does.
var envShortValue = map[byte]bool{'u': true, 'C': true, 'a': true, 'P': true, 'L': true, 'U': true}
var envShortKnown = map[byte]bool{'i': true, '0': true, 'v': true, 'u': true, 'C': true, 'S': true, 'a': true, 'P': true, 'L': true, 'U': true}

// envLongOptions: GNU env's long options and whether each takes a value; getopt_long takes any unique
// prefix (--split for --split-string).
var envLongOptions = map[string]bool{"argv0": true, "block-signal": false, "chdir": true, "debug": false,
	"default-signal": false, "env0-from": true, "ignore-environment": false, "ignore-signal": false,
	"list-signal-handling": false, "null": false, "split-string": true, "unset": true, "help": false, "version": false}

// envLong is the long option a word names, by its whole name or a unique prefix, or "".
func envLong(name string) string {
	if _, ok := envLongOptions[name]; ok {
		return name
	}
	found := ""
	for full := range envLongOptions {
		if strings.HasPrefix(full, name) {
			if found != "" {
				return ""
			}
			found = full
		}
	}
	return found
}

// envSplit finds env's split-string option in w[0] in any spelling: -S VALUE, -SVALUE, a cluster ending
// in it (-iS VALUE, -iSVALUE), --split-string VALUE, --split-string=VALUE and their unique prefixes. A
// value-taking short option earlier in a cluster takes the rest of the word instead (-uS is -u S).
func envSplit(w []string) (value string, rest []string, ok bool) {
	f := w[0]
	if strings.HasPrefix(f, "--") {
		name, val, eq := strings.Cut(f[2:], "=")
		if name == "" || envLong(name) != "split-string" {
			return "", nil, false
		}
		if eq {
			return val, w[1:], true
		}
		if len(w) > 1 {
			return w[1], w[2:], true
		}
		return "", nil, true
	}
	for i := 1; i < len(f); i++ {
		c := f[i]
		if c == 'S' {
			if i+1 < len(f) {
				return f[i+1:], w[1:], true
			}
			if len(w) > 1 {
				return w[1], w[2:], true
			}
			return "", nil, true
		}
		if envShortValue[c] || !envShortKnown[c] {
			return "", nil, false
		}
	}
	return "", nil, false
}

// envReread is the line env runs for a split string: env, the value split as env splits it (\_ is a
// separator, every blank and line break ends a word), then the words after the value.
func envReread(value string, rest []string) string {
	words := make([]string, 0, len(rest)+8)
	words = append(words, "env")
	for _, w := range envWords(value) {
		words = append(words, shellQuote(w))
	}
	for _, m := range rest {
		words = append(words, shellQuote(m))
	}
	return strings.Join(words, " ")
}

// envWords splits a split string as env -S does (GNU coreutils; the BSDs read the same forms): blanks, tabs and
// line breaks separate words; '…' is literal; "…" keeps its text with \" \\ \$ \_ escapes; outside quotes
// \_ separates, \t \n \v \f \r give their character inside the word, \# \$ \\ \' \" give themselves, \c ends
// the value; a # that begins a word ends the value (a comment). | & ; ( ) { } < > are ordinary characters to
// env, so each word is passed on quoted and the shell never reads them (P1-X round 5, ADR-0173).
func envWords(v string) []string {
	var out []string
	var cur strings.Builder
	in := false
	flush := func() {
		if in {
			out = append(out, cur.String())
		}
		cur.Reset()
		in = false
	}
	rs := []rune(v)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case r == ' ' || r == '\t' || r == '\n' || r == '\v' || r == '\f' || r == '\r':
			flush()
		case r == '#' && !in:
			return out
		case r == '\'':
			in = true
			for i++; i < len(rs) && rs[i] != '\''; i++ {
				if rs[i] == '\\' && i+1 < len(rs) && (rs[i+1] == '\'' || rs[i+1] == '\\') {
					i++ // \' and \\ are env's only escapes in single quotes: the quote goes on (round 6)
				}
				cur.WriteRune(rs[i])
			}
		case r == '"':
			in = true
			for i++; i < len(rs) && rs[i] != '"'; i++ {
				if rs[i] == '\\' && i+1 < len(rs) {
					i++
					switch rs[i] {
					case '_':
						cur.WriteRune(' ')
					case '"', '\\', '$', '#', '\'':
						cur.WriteRune(rs[i])
					case 't':
						cur.WriteRune('\t')
					case 'n':
						cur.WriteRune('\n')
					case 'v':
						cur.WriteRune('\v')
					case 'f':
						cur.WriteRune('\f')
					case 'r':
						cur.WriteRune('\r')
					default:
						cur.WriteRune('\\')
						cur.WriteRune(rs[i])
					}
					continue
				}
				cur.WriteRune(rs[i])
			}
		case r == '\\' && i+1 < len(rs):
			i++
			switch rs[i] {
			case '_':
				flush()
			case 'c':
				flush()
				return out
			case 't':
				in = true
				cur.WriteRune('\t')
			case 'n':
				in = true
				cur.WriteRune('\n')
			case 'v':
				in = true
				cur.WriteRune('\v')
			case 'f':
				in = true
				cur.WriteRune('\f')
			case 'r':
				in = true
				cur.WriteRune('\r')
			default:
				in = true
				cur.WriteRune(rs[i])
			}
		default:
			in = true
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

// envOptionWords: how many words an env option takes (1, or 2 when its value is the next word), or 0 for an
// option env does not have or alalanet does not know.
func envOptionWords(f string) int {
	if f == "-" {
		return 1 // the same as -i
	}
	if strings.HasPrefix(f, "--") {
		name, _, eq := strings.Cut(f[2:], "=")
		full := envLong(name)
		if full == "" {
			return 0
		}
		if envLongOptions[full] && !eq {
			return 2
		}
		return 1
	}
	for i := 1; i < len(f); i++ {
		c := f[i]
		if !envShortKnown[c] {
			return 0
		}
		if envShortValue[c] {
			if i == len(f)-1 {
				return 2
			}
			return 1 // the rest of the word is the value
		}
	}
	return 1
}
