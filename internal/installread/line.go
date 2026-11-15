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
}

// registryFlags point an install at another registry or index: the package would be judged on the
// public one while it comes from somewhere else (deep review SEC-4, IMP-2).
var registryFlags = map[string]bool{"--registry": true, "-i": true, "--index-url": true, "--extra-index-url": true,
	"-f": true, "--find-links": true, "--index": true, "--default-index": true}

var defaultRegistries = map[string]bool{"registry.npmjs.org": true, "registry.yarnpkg.com": true, "pypi.org": true,
	"pypi.python.org": true, "files.pythonhosted.org": true}

// The wrappers Claude Code itself strips before matching a command, plus the shell keywords that start
// a control-flow body: the install inside still runs.
var hookWrappers = map[string]bool{"sudo": true, "doas": true, "env": true, "time": true, "nice": true, "exec": true, "nohup": true, "eval": true,
	"command": true, "builtin": true, "noglob": true, "xargs": true, "corepack": true, "then": true, "do": true,
	"else": true, "elif": true, "if": true, "while": true, "until": true, "!": true, "stdbuf": true, "timeout": true}

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
}

// wrapperName: the wrapper a command word runs, or "". /usr/bin/sudo and /usr/bin/doas (second
// review) and s\udo or \sudo, which bash runs as sudo (fourth review). A VAR=value word is never a
// wrapper and keeps its backslashes: npm reads https://evil.example\@registry.npmjs.org as
// evil.example (fifth review).
func wrapperName(x string) string {
	if strings.Contains(x, "=") {
		return ""
	}
	n := x
	if strings.Contains(n, `\`) && !windowsPath(n) {
		n = strings.ReplaceAll(n, `\`, "")
	}
	if n = launchBase(n); hookWrappers[n] {
		return n
	}
	return ""
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
var substInstall = regexp.MustCompile("(?i)\\b(?:(?:npm|pip3?|uv|pipx)\\s+(?:install|i|add|dlx|exec|x)|(?:pnpm|yarn|bun)\\s+(?:install|i|add|dlx|x))\\b[^;|&\\n]*(\\$\\([^(]|`|<\\()" +
	"|\\b(npx|bunx|pnpx|uvx)\\s+(-\\S+\\s+)*[\"']?(\\$\\([^(]|`)")

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
			"test-pattern changed-files-ignore-pattern registry cpu os libc reporter loglevel store-dir package",
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
	return len(x) >= len("--reg") && strings.HasPrefix("--registry", x)
}

// pmTakesValue: for npm, pnpm, Yarn or bun, whether option word opt leaves its value to the next word.
func pmTakesValue(cmd, opt string) bool {
	switch {
	case strings.HasPrefix(opt, "--"):
		return pmLongValueOptions[cmd][opt] || npmRegistryOption(opt) // --prefix=x is neither
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

// pipxValueFlags: pipx's options that take the next word as their value, besides valueFlags
// (pipx.pypa.io/stable/reference/cli.html, read 2026-11-14).
var pipxValueFlags = map[string]bool{"--suffix": true, "--pip-args": true, "--app": true, "--fetch-python": true,
	"--lock": true, "--preinstall": true, "--spec": true}

// parseInstallLineFull also reports whether the line runs something besides installs and harmless
// commands (curl … | bash && npx -y x), and whether it has a command substitution outside single
// quotes: install_check then cannot sign the install alone.
func parseInstallLineFull(line string) (targets, unread []string, other, subst bool) {
	p := &hookParse{seen: map[string]bool{}}
	line = whichSubst.ReplaceAllString(line, "$1$2") // $(which npm) i x -> npm i x
	if substInstall.MatchString(line) {
		p.miss("install arguments come from a command substitution alalanet cannot see")
	}
	p.line(line, 0)
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
}

// line reads every simple command of a shell line (or of a script given to sh -c, eval, env -S).
func (p *hookParse) line(s string, depth int) {
	sl := splitShell(s)
	if sl.unclosed {
		p.miss("a quote the line does not close: alalanet cannot tell where its words end")
	}
	p.subst = p.subst || sl.subst
	outer := p.prog // a script's line (sh -c …) is read inside its shell's command: that command's program stays
	for _, sg := range sl.segs {
		before := p.hits
		p.prog = ""
		p.command(sg.words, depth)
		if p.hits == before && (sg.writes || !harmless(sg.words)) {
			p.other = true
			if p.firstOther == "" {
				p.firstOther = p.prog
			}
		}
	}
	p.prog = outer
}

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
			case packageManagers[c] || c == "node" || strings.HasPrefix(c, "python"):
				return len(w) == i+2 && (w[i+1] == "-v" || w[i+1] == "--version" || w[i+1] == "-V" || w[i+1] == "version")
			}
			return harmlessCommands[c]
		}
	}
	return true
}

// shellSeg is one simple command: its words with the quotes removed, and whether it writes a file
// through a redirection (echo registry=… > .npmrc is not harmless; > /dev/null is).
type shellSeg struct {
	words  []string
	writes bool
}

// shellLine is a line read the way a POSIX shell splits it, as far as an install check needs.
type shellLine struct {
	segs     []shellSeg
	unclosed bool // a quote left open: where the words end is unknown
	subst    bool // $( ), backticks or <( ) outside single quotes: words the line does not show
}

// splitShell splits a line into simple commands at the separators ; | & newline ( ) { } and backtick
// outside quotes, and each command into words with the quotes removed: a quoted string with spaces
// stays one word, so --from "x @ git+https://…" keeps its value (independent review of round 3,
// finding 6). It knows single and double quotes, $'…', backslash escapes (outside quotes only before a
// character the shell treats specially, so Windows paths like C:\Users\npm.cmd survive), # comments,
// redirections (N>file, >>, 2>&1, &>, <file, <<<word: the file word is not an argument) and here-
// documents (the body is read as commands). A quote left open is reported, not guessed (second review
// pass, finding A).
func splitShell(line string) shellLine {
	var out shellLine
	var words []string
	var cur strings.Builder
	inWord, q := false, rune(0) // q: '\'', '"' or '$' for $'…'
	skipWord, redirOut, writes := false, false, false
	heredoc, heredocTabs := "", false
	flushWord := func() {
		if inWord {
			w := cur.String()
			switch {
			case skipWord:
				if redirOut && w != "/dev/null" && w != "/dev/stderr" && w != "/dev/stdout" {
					writes = true
				}
				skipWord, redirOut = false, false
			case heredoc == "\x00":
				heredoc = strings.ReplaceAll(w, "\\", "") // the delimiter of <<WORD, <<'WORD', <<\WORD
			default:
				words = append(words, w)
			}
			cur.Reset()
			inWord = false
		}
	}
	flushSeg := func() {
		flushWord()
		if n := len(words); n > 0 {
			if words[n-1] = strings.TrimSuffix(words[n-1], "$"); words[n-1] == "" {
				words = words[:n-1]
			}
		}
		if len(words) > 0 || writes {
			out.segs = append(out.segs, shellSeg{words: words, writes: writes})
		}
		words, writes = nil, false
	}
	rs := []rune(line)
	special := "'\"\\ $`;|&#()<>{}\n\t*?[]~!"
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
			default:
				cur.WriteRune(r)
			}
		case q == '"':
			switch {
			case r == '"':
				q = 0
			case r == '\\' && strings.ContainsRune("\"\\$`", next()):
				i++
				cur.WriteRune(rs[i])
			case r == '$' && next() == '(' || r == '`':
				out.subst = true
				cur.WriteRune(r)
			default:
				cur.WriteRune(r)
			}
		case r == '\\' && next() == '\n': // a line continuation
			i++
		case r == '\\' && next() != 0 && strings.ContainsRune(special, next()):
			i++
			cur.WriteRune(rs[i])
			inWord = true
		case r == '$' && next() == '\'':
			i++
			q, inWord = '$', true
		case r == '\'' || r == '"':
			q, inWord = r, true
		case r == '#' && !inWord: // a comment to the end of the line
			for i+1 < len(rs) && rs[i+1] != '\n' {
				i++
			}
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
				out.subst = out.subst || inner.subst
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
			}
			if !closed {
				out.unclosed = true // "${A; npm i x": the rest of the line would vanish into the word
			}
			inWord = true
		case r == '<' && next() == '(':
			out.subst = true
			flushSeg()
		case r == '$' && next() == '(':
			out.subst = true
			flushSeg()
		case r == '>' || r == '<' || r == '&' && next() == '>':
			// a redirection: N>file, >>file, 2>&1, &>file, <file, <<WORD, <<<word
			if s := cur.String(); inWord && strings.Trim(s, "0123456789") == "" {
				cur.Reset() // the descriptor number
				inWord = false
			}
			flushWord()
			out := r != '<'
			if r == '&' {
				i++ // &>
			}
			if r == '<' && next() == '<' {
				i++
				if next() == '<' { // <<< word: a here-string, data
					i++
					skipWord = true
					continue
				}
				if next() == '-' {
					i++
					heredocTabs = true
				}
				heredoc = "\x00" // the next word is the delimiter
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
			flushSeg()
		case r == '{' && next() == '}':
			// "{}" is a word, never a brace group: xargs -I{} keeps its replacement string and find -exec … {}
			// its argument (RT-1 review, round 2)
			cur.WriteString("{}")
			i++
			inWord = true
		case strings.ContainsRune(";|&\n(){}", r):
			flushSeg()
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	out.unclosed = out.unclosed || q != 0
	flushSeg()
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
	if len(k) > 5 && strings.EqualFold(k[:5], "$env:") { // PowerShell $env:NAME = value (N4)
		k = k[5:]
	}
	lk := strings.ToLower(k)
	switch {
	case strings.Contains(lk, "registry") || strings.HasSuffix(lk, "index_url") || lk == "uv_index" || lk == "uv_default_index":
		p.registryOverride(v)
	case strings.HasSuffix(lk, "userconfig") || strings.HasSuffix(lk, "globalconfig") || lk == "pip_config_file" || lk == "uv_config_file" ||
		lk == "npm_config_npmrc" || lk == "yarn_rc_filename" || lk == "bun_config_path":
		p.miss("installs with a custom registry or config file alalanet cannot see (" + k + ")")
	case codeLoadingEnv[strings.ToUpper(k)]:
		p.miss("runs with an environment that loads other code (" + k + ")")
	case lk == "node_options" && nodeLoads.MatchString(v):
		p.miss("runs with an environment that loads other code (NODE_OPTIONS " + clip(v, 60) + ")")
	case searchPathEnv[strings.ToUpper(k)] && untrustedPath(v):
		p.miss("runs with an environment that loads other code (" + k + " points at " + clip(v, 60) + ")")
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
func untrustedPath(v string) bool {
	sep := ":"
	if strings.Contains(v, ";") || len(v) > 2 && v[1] == ':' && (v[2] == '\\' || v[2] == '/') {
		sep = ";" // a Windows list: C:\Program Files\nodejs;C:\Windows
	}
	for _, d := range strings.Split(v, sep) {
		ld := strings.ToLower(strings.ReplaceAll(d, `\`, "/"))
		switch {
		case d == "" || strings.HasPrefix(d, "$") || strings.HasPrefix(d, "%") && !strings.HasPrefix(ld, "%temp%") && !strings.HasPrefix(ld, "%tmp%"):
		case strings.Contains(ld, "/tmp") || strings.Contains(ld, "/temp/") || strings.HasSuffix(ld, "/temp") || strings.HasPrefix(ld, "/var/tmp") ||
			strings.HasPrefix(ld, "/dev/shm") || strings.HasPrefix(ld, "%temp%") || strings.HasPrefix(ld, "%tmp%"):
			return true
		case strings.HasPrefix(d, "/") || strings.HasPrefix(d, "~") || len(d) > 2 && d[1] == ':' || strings.HasPrefix(d, `\\`):
		default:
			return true // relative
		}
	}
	return false
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
	// Wrappers, their options, VAR=value prefixes (a registry set through the environment counts).
	viaXargs := false
	for len(w) > 0 {
		x := w[0]
		if n := wrapperName(x); n != "" {
			x = n // /usr/bin/sudo, s\udo: only the wrapper's name; a VAR=value word is read as written
		}
		switch {
		case hookWrappers[x]:
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
						if strings.Contains(v, "#") { // env's comment rules differ from the shell's in corner cases: ask as well
							p.miss("runs env -S with a # in its value, which env may read as a comment (" + shown(v) + ")")
						}
						line := envReread(v, rest)
						if viaXargs { // xargs env -S 'npm i' < list: the packages come from the input
							line = "xargs " + line
						}
						p.line(line, depth+1)
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
				p.line(line, depth+1)
				return
			}
		case strings.Contains(x, "=") && !strings.HasPrefix(x, "-"):
			k, v, _ := strings.Cut(x, "=")
			p.configEnv(k, v)
			w = w[1:]
		default:
			goto body
		}
	}
body:
	if len(w) == 0 {
		return
	}
	if len(w) == 1 && strings.ContainsAny(w[0], " \t;|&") {
		p.line(w[0], depth+1) // a quoted script after a wrapper: sudo 'npm i x'
		return
	}
	cmd := w[0]
	if strings.Contains(cmd, `\`) && !windowsPath(cmd) {
		cmd = strings.ReplaceAll(cmd, `\`, "") // n\px runs npx in bash (third review pass, N3)
	}
	if i := strings.LastIndexAny(cmd, `/\`); i >= 0 { // /usr/bin/npm, ./node_modules/.bin/npx, C:\...\npm
		cmd = cmd[i+1:]
	}
	cmd = strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(cmd), ".cmd"), ".exe")
	if p.prog == "" {
		p.prog = cmd // the command's program; a command read inside it (python -m pip, npx … mcp add -- x) keeps it
	}
	rest := w[1:]
	switch {
	case (cmd == "sh" || cmd == "bash" || cmd == "zsh" || cmd == "dash") && len(rest) > 0:
		for i, x := range rest { // bash -c "npm i x", bash -lc ...
			if strings.HasPrefix(x, "-") && strings.Contains(x, "c") && !strings.HasPrefix(x, "--") {
				p.line(strings.Join(rest[i+1:], " "), depth+1)
				return
			}
		}
		return
	case (cmd == "pwsh" || cmd == "powershell") && len(rest) > 0:
		for i, x := range rest {
			if lx := strings.ToLower(x); lx == "-command" || lx == "-c" {
				if i+1 == len(rest) {
					p.hits++ // pwsh -Command { … }: the block follows as its own commands
					return
				}
				p.line(strings.Join(rest[i+1:], " "), depth+1)
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
				p.line(strings.Join(rest[i+1:], " "), depth+1)
				return
			}
		}
		return
	case strings.HasPrefix(cmd, "python") || cmd == "py":
		if len(rest) >= 2 && rest[0] == "-m" && (rest[1] == "pip" || rest[1] == "pip3" || rest[1] == "uv" || rest[1] == "pipx") {
			p.command(append([]string{rest[1]}, rest[2:]...), depth+1)
		} else if len(rest) >= 2 && rest[0] == "-m" && rest[1] == "venv" {
			p.hits++ // python3 -m venv .venv: the standard library, nothing installed
		}
		return
	}
	if cmd == "export" || cmd == "declare" || cmd == "typeset" || cmd == "setx" || cmd == "set" {
		// cmd.exe "set NAME=value" too (third review pass, N4)
		for _, x := range rest { // export NPM_CONFIG_REGISTRY=… && npx -y x (second review, finding B)
			if k, v, ok := strings.Cut(x, "="); ok && !strings.HasPrefix(k, "-") {
				p.configEnv(k, v)
			}
		}
		return
	}
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
	if viaXargs && packageManagers[cmd] {
		noSubcommand := !slices.ContainsFunc(rest, func(x string) bool { return !strings.HasPrefix(x, "-") })
		if verbManagers[cmd] {
			noSubcommand = sub < 0
		}
		if _, _, names := (&hookParse{seen: map[string]bool{}}).commandTargets(cmd, rest); noSubcommand || names {
			p.miss("install arguments come from standard input (xargs) alalanet cannot see")
		}
	}
	if len(rest) == 0 {
		return
	}
	// npm's scoped registry, --@scope:registry=URL (or a following word): the scope's packages come
	// from there, not from the public registry install_check reads (round 3, R3-PLAN-01/02).
	for i, x := range rest {
		if lx := strings.ToLower(x); strings.HasPrefix(lx, "--@") && strings.Contains(lx, ":registry") {
			v := ""
			if _, after, ok := strings.Cut(x, "="); ok {
				v = after
			} else if i+1 < len(rest) {
				v = rest[i+1]
			}
			p.registryOverride(v)
		}
		// --userconfig / --globalconfig: a config file that can set any registry
		if lx := strings.ToLower(x); packageManagers[cmd] && (lx == "--userconfig" || lx == "--globalconfig" || strings.HasPrefix(lx, "--userconfig=") || strings.HasPrefix(lx, "--globalconfig=")) {
			p.miss("installs with a custom registry or config file alalanet cannot see (" + x + ")")
		}
	}
	// "<agent CLI> mcp add NAME -- cmd" run through npx or a path: cmd is what the client will start
	// (npx -y @anthropic-ai/claude-code mcp add x -- npx -y pkg; independent review, finding 8).
	if cmd != "claude" && cmd != "codex" && cmd != "gemini" {
		for i := 0; i+1 < len(rest); i++ {
			if rest[i] == "mcp" && rest[i+1] == "add" {
				for j := i + 2; j < len(rest); j++ {
					if rest[j] == "--" && j+1 < len(rest) {
						p.command(rest[j+1:], depth+1)
						break
					}
				}
				break
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
			p.miss("an install argument comes from a variable or an escape alalanet cannot see (" + clip(x, 60) + ")")
			return ""
		}
		return eco + x
	}
	// pm: whose options this program reads — the manager's own, npm's for npx (npm exec), pnpm's for pnpx (pnpm dlx,
	// and pnpm validates them), bunx's own few for bunx (bun.sh/docs/cli/bunx).
	pm := map[string]string{"npm": "npm", "pnpm": "pnpm", "yarn": "yarn", "bun": "bun", "npx": "npm", "pnpx": "pnpm", "bunx": "bunx"}[cmd]
	// takesValue: whether an option word leaves its value to the next word, as this program reads its options
	// (npm, pnpm, Yarn and bun each their own: npm i -f pkg forces, pnpm add -w pkg is the workspace root, npm i
	// --cwd pkg installs pkg — pip's -f, -w and --index-url take a value; RT-1 round 3).
	takesValue := func(x string) bool {
		switch {
		case pm != "":
			return pmTakesValue(pm, x)
		case cmd == "pipx":
			return valueFlags[x] || pipxValueFlags[x]
		}
		return valueFlags[x]
	}
	// isRegistry: an option naming another registry or index — for npm, pnpm, Yarn, bun and their runners only
	// --registry and its abbreviations (npmRegistryOption), where pip's -i and -f are an index and find-links (npm i
	// -f pkg forces; RT-1 round 3).
	isRegistry := func(x string) bool {
		if pm != "" {
			return npmRegistryOption(x)
		}
		return registryFlags[x]
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
			case isRegistry(x):
				if j+1 < len(rest) {
					p.registryOverride(rest[j+1])
				}
				j++
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
	switch cmd {
	case "npx", "bunx", "pnpx":
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
			return p.uvx(2, spec, flagValues, pkgs), true, true
		case len(rest) >= 1 && rest[0] == "run":
			out := addAll("pypi:", flagValues("--with"))
			pkgs(1)
			return out, true, false
		}
		if i := after("install", "add"); i >= 0 {
			return addAll("pypi:", pkgs(i)), true, true
		}
	case "uvx":
		return p.uvx(0, spec, flagValues, pkgs), true, true
	case "pipx":
		// pipx names what it fetches only in install (one or more package specs, and --preinstall), run (the app
		// or --spec, and --with extras), inject (the dependencies after the environment) and runpip (a pip
		// command run in an environment, read as pip's); list, upgrade, reinstall, uninstall, ensurepath,
		// environment and the rest name nothing to fetch (pipx.pypa.io/stable/reference/cli.html, read
		// 2026-11-14). An upgrade is not checked, as npm update is not (RT-1 round 3).
		pkgs(0) // a registry or index anywhere on the line is noted, as before
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
		if len(rest) < 3 || rest[0] != "mcp" || rest[1] != "add" {
			return nil, true, false
		}
		for i, x := range rest {
			if x == "--" && i+1 < len(rest) {
				return []string{strings.Join(rest[i+1:], " ")}, true, false
			}
		}
		for _, x := range rest[2:] {
			if u, err := url.Parse(x); err == nil && u.Scheme == "https" && u.Host != "" {
				return []string{x}, true, false
			}
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
	for _, x := range flagValues("--with") {
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
