package installread

import (
	"encoding/json/jsontext"
	"net/url"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// The second reader of a launch or install line (ADR-0131, rebuilt after its fifth review). Five
// rounds of changes inside the production reader each lost something it had caught, so the production
// reader (ParseInstallLine, ParseInstallTarget, judgeRepoServer) stays exactly as it was and this one
// runs beside it. It only adds reasons to ask or hold: it never adds or removes a target, a package
// the production reader blocks stays blocked, and a line it refuses stays refused. What it reads:
// environment variables that are levers (installenv.go: npm_config_package, UV_PYTHON, GIT_SSH…), the
// launcher flags that do the same (--script-shell, --pnpmfile, --node-options), assignments in the
// spellings shells and PowerShell accept, "mcp add -e", MCP entries given as JSON, command strings
// (npx -c), environments loaded from files, and installs run through wrappers the production reader
// does not know.

// Reasons this reader gives. extraCode maps them to the fixed codes install_check and the repository
// check sign; the hook shows them as written.
const (
	whyOverride   = "runs with an environment that changes what installs or runs"
	whyLoads      = "runs with an environment that loads other code" // the production reader's wording
	whyDebug      = "runs with an environment that opens a debugger port"
	whyFlag       = "runs with a launcher flag that changes what installs or runs"
	whyCall       = "runs a command string given to "
	whyFromFile   = "runs with an environment loaded from a file the line does not show"
	whyFromOutput = "runs with an environment set from the output of a command, which alalanet cannot see"
	whyVariant    = "an MCP entry with a key spelled in another case: clients differ on which one they read"
	whyJSON       = "an MCP server entry given as JSON (mcp add-json, --add-mcp): the hook does not check its package; check the entry with install_check first"
	whyThrough    = "runs an install through "
	whyGlued      = "an install inside or next to a command substitution, which alalanet does not check"
	whyManySubst  = "more command substitutions in one command than alalanet reads apart"
	whyHTTP       = "installs from a registry or index over plain http: the download can be changed in transit"
	whyCommand    = "runs a program named like an assignment, which alalanet does not check"
	whyTmpDir     = "runs a package manager in a temporary folder, whose .npmrc or pip.conf alalanet cannot see"
	whyUnknown    = "runs with an environment variable set from a value the line does not show"
	whyDeep       = "shell wrappers nested too deep to read" // the production reader's wording
)

func extraCode(msg string) string {
	switch {
	case strings.HasPrefix(msg, "an MCP entry with a key spelled"):
		return "case_variant_key"
	case strings.HasPrefix(msg, whyFromFile):
		return "env_file"
	case strings.HasPrefix(msg, whyFromOutput):
		return "env_from_command"
	case strings.HasPrefix(msg, whyFlag):
		return "launcher_flag_override"
	case strings.HasPrefix(msg, whyCall):
		return "command_string"
	case strings.HasPrefix(msg, "an MCP server entry given as JSON"):
		return "mcp_json_entry"
	case strings.HasPrefix(msg, whyThrough):
		return "install_through_wrapper"
	case strings.HasPrefix(msg, whyGlued), strings.HasPrefix(msg, whyManySubst):
		return "command_substitution"
	case strings.HasPrefix(msg, whyHTTP):
		return "custom_registry"
	case strings.HasPrefix(msg, whyCommand):
		return "command_not_assignment"
	case strings.HasPrefix(msg, whyTmpDir):
		return "temporary_folder"
	case strings.HasPrefix(msg, whyUnknown):
		return "environment_override"
	case strings.HasPrefix(msg, whyOverride), strings.HasPrefix(msg, whyDebug):
		return "environment_override"
	}
	return unreadCode(msg) // the production reader's wordings (loads other code, custom registry)
}

type extraParse struct {
	unread   []string
	gated    []bool // the reason counts only on a line that runs a package manager (see reasons)
	seen     map[string]bool
	assigned map[string]string   // NAME -> value set earlier on the line (PATH=$D after D=.), case-sensitive
	work     int                 // bytes left for expanding variables: what a crafted line can cost
	pm       int                 // package-manager and runner commands seen, and agent CLIs' mcp add
	fetch    int                 // commands that download a package they name (npx -y x, uvx x, pip install x)
	fromFile []string            // environments loaded from files; a reason only on a line that runs a package manager
	fromOut  bool                // an environment set from a command's output (export $(…), eval "$(…)", source <(…))
	apart    bool                // the line's command substitutions were taken apart: a mark stands for each
	literal  bool                // the line itself spells a mark (${_s}): a variable of that name, trusted as none
	own      string              // the search path being judged: its own $NAME entry is what the session had
	ps       map[string]string   // PowerShell: NAME -> an environment variable's value set on the line, $NAME a variable's
	win      bool                // the value being judged is one a Windows shell reads: %NAME% is a variable, ";" separates
	as       string              // that value as the line spells it, for the reason's text
	cmdRead  map[string][]string // cmd: NAME -> the values of set NAME=a;b read whole (cmdSets)
}

const extraWork = 1 << 20

func newExtraParse() *extraParse {
	return &extraParse{seen: map[string]bool{}, assigned: map[string]string{}, ps: map[string]string{}, work: extraWork}
}

func (e *extraParse) miss(why string) { e.add(why, false) }

// envMiss: a reason from the environment, which matters only to what the same line runs: the agent's
// shell does not keep variables between commands, so GIT_EDITOR=true git rebase or IFS=… read is not a
// reason, while the same assignment before npx is (fifth review's corpus: such lines asked without cause).
func (e *extraParse) envMiss(why string) { e.add(why, true) }

func (e *extraParse) add(why string, gated bool) {
	if !e.seen[why] {
		e.seen[why] = true
		e.unread = append(e.unread, why)
		e.gated = append(e.gated, gated)
	}
}

// reasons: what the line adds. Reasons from the environment count once the line runs a package
// manager, a runner or an agent CLI's mcp add. An environment from a file counts only before a package
// the line names (source .env && npx -y x), not before the project's own commands (source .env && uv run
// pytest, five times in one CLAUDE.md of the fifth review's corpus): what a planted .env could move there
// the repository's own files can move as well.
func (e *extraParse) reasons() []string {
	if e.fetch > 0 {
		if e.fromOut {
			e.miss(whyFromOutput)
		}
		for _, f := range e.fromFile {
			e.miss(whyFromFile + " (" + clip(f, 60) + ")")
		}
	}
	if e.pm > 0 {
		return e.unread
	}
	var out []string
	for i, r := range e.unread {
		if !e.gated[i] {
			out = append(out, r)
		}
	}
	return out
}

// hookExtra: the second reader's reasons for the hook, those the production reader did not give
// already. prodTargets, prodUnread and subst are the production reader's result for the same line.
func hookExtra(line string, prodTargets, prodUnread []string, subst bool) []string {
	e := newExtraParse()
	pieces := e.scan(line, subst)
	if pieces != nil {
		e.reread(pieces, prodTargets, prodUnread)
	}
	// Membership in a set: the filter was a scan of production's list for each reason, quadratic on a
	// line with many distinct reasons in both (seventh review: 1 MiB took 20 s against 0.13 s).
	prod := make(map[string]struct{}, len(prodUnread))
	for _, r := range prodUnread {
		prod[r] = struct{}{}
	}
	// What production names already in its two registry sentences is not said in other words (eighth
	// review, item 13: (--userconfig=/tmp/npmrc) and (--userconfig); ($R) and (evil.example)). By what
	// the sentence names, in a set: another registry or file on the same line is still said.
	said := map[string]struct{}{}
	for _, r := range prodUnread {
		kind, d := registryDetail(r)
		if kind == "" {
			continue
		}
		said[kind+d] = struct{}{}
		if kind == saidRegistry && strings.HasPrefix(d, "$") {
			said[kind+shown(registryHost(e.bind(d)))] = struct{}{} // R=https://evil.example; --registry $R
		}
	}
	var out []string
	more := 0
	for _, r := range e.reasons() {
		if _, ok := prod[r]; ok {
			continue
		}
		if kind, d := registryDetail(r); kind != "" {
			if _, ok := said[kind+d]; ok {
				continue
			}
		}
		if len(out) == maxExtraReasons {
			more++
			continue
		}
		out = append(out, r)
	}
	if more > 0 {
		out = append(out, "and "+strconv.Itoa(more)+" more reasons of these kinds")
	}
	if pieces != nil && !e.literal {
		for i, r := range out {
			out[i] = markText.Replace(r) // a reason shows the substitution, not the mark that stood for it
		}
	}
	return out
}

const (
	saidRegistry = "registry:"
	saidConfig   = "config:"
	registryHead = "installs from a custom registry or index ("
	registryTail = "): alalanet judges packages on the public registries only"
	configHead   = "installs with a custom registry or config file alalanet cannot see ("
)

// registryDetail: what one of the two registry sentences names. A registry by the host as printed; a
// config file by the flag or variable without its value, in lower case (--userconfig=/tmp/npmrc and
// --userconfig are one flag). kind is "" for any other reason.
func registryDetail(r string) (kind, detail string) {
	switch {
	case strings.HasPrefix(r, registryHead) && strings.HasSuffix(r, registryTail):
		return saidRegistry, r[len(registryHead) : len(r)-len(registryTail)]
	case strings.HasPrefix(r, configHead) && strings.HasSuffix(r, ")"):
		d, _, _ := strings.Cut(r[len(configHead):len(r)-1], "=")
		return saidConfig, strings.ToLower(d)
	}
	return "", ""
}

// registryHost: the host of a registry address, as the production reader takes it (registryOverride).
func registryHost(v string) string {
	if u, err := url.Parse(v); err == nil && u.Host != "" {
		return u.Hostname()
	}
	return v
}

// reread gives the pieces of a line with command substitutions to the production reader once more.
// FOO=$(true)x npx -y pkg: its splitter cuts the line at "$(" and loses the install; echo "$(npm i -g
// x)" runs one it does not read. An install it finds in the pieces and did not find in the line is one
// nothing checked: a reason that names it (the second reader still adds no target). What else it
// cannot read there (npx -y pkg@$(cat v)) is a reason when it had none of its own. $(npm -v), $(bun
// --version), VER=$(npx -y semver …) name nothing new: no reason, where the earlier rule asked for any
// install beside a substitution (seventh review: about fifteen blocks of its README corpus).
func (e *extraParse) reread(pieces, prodTargets, prodUnread []string) {
	p := &hookParse{seen: map[string]bool{}}
	for _, piece := range pieces {
		p.line(piece, 0)
	}
	cut := false // the production reader checks the first ten targets and asks for the rest itself
	for _, r := range prodUnread {
		cut = cut || strings.Contains(r, " more install targets in this command ")
	}
	if !cut {
		have := make(map[string]struct{}, len(prodTargets))
		for _, t := range prodTargets {
			have[t] = struct{}{}
			if strings.Contains(t, "$(") || strings.Contains(t, "`") || strings.Contains(t, "<(") {
				// A launch the production reader took with a substitution in an argument (claude mcp add
				// x -- serena … --project "$(pwd)"): the pieces spell the same launch with a mark where
				// the substitution stood. It is the launch production holds for the substitution itself,
				// not one nothing checked (eighth review). $(which NAME) is the name in both readers by
				// then, once for the whole line: what is left of a doubled one is a substitution.
				if ps, _ := unnest(t); len(ps) > 0 {
					have[ps[0]] = struct{}{}
				}
			}
		}
		for _, t := range p.targets {
			if _, ok := have[t]; !ok {
				e.miss(whyGlued + " (" + clip(t, 80) + ")")
			}
		}
	}
	if len(prodUnread) == 0 {
		for _, r := range p.unread {
			if !strings.HasPrefix(r, "a quote the line does not close") { // a piece is cut out of its quotes
				e.miss(r)
			}
		}
	}
}

// maxExtraReasons bounds what the second reader adds to the hook's answer: a crafted line with 50,000
// distinct reasons doubled a 4.5 MB answer. The decision is the same after the first reason.
const maxExtraReasons = 20

// launchExtra: the second reader's first reason, as a code, for an install_check target that is a
// launch line or an MCP entry; "" when it adds none or the target is a bare package.
func launchExtra(raw string) string {
	code, _ := launchExtraWhy(raw)
	return code
}

// launchExtraWhy: launchExtra, and the reason as the sentence the hook prints.
func launchExtraWhy(raw string) (code, why string) {
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > 2000 {
		return "", ""
	}
	e := newExtraParse()
	switch {
	case strings.HasPrefix(s, "{"):
		e.pm++ // an MCP entry is a launch
		e.entry(s, 0)
	case strings.ContainsAny(s, " \t\n"):
		e.scan(s, true)
	}
	if r := e.reasons(); len(r) > 0 {
		why = r[0]
		if e.apart && !e.literal {
			why = markText.Replace(why) // the substitution, not the mark that stood for it
		}
		return extraCode(r[0]), why
	}
	return "", ""
}

// scan reads a line. apart: its command substitutions are taken apart first (unnest) and each piece is
// read on its own, never joined again, so a piece left open cannot swallow the next. The pieces are
// returned; nil when the line has no substitution and was read whole.
func (e *extraParse) scan(line string, apart bool) []string {
	low := strings.ToLower(line)
	if strings.Contains(line, "`\"") && (strings.Contains(low, "add-json") || strings.Contains(low, "add-mcp")) {
		line = psJSON(line)
	}
	subst := strings.Contains(line, "$(") || strings.Contains(line, "`")
	if subst { // the regexes cost more than a 1 MiB line's split
		line = whichSubst.ReplaceAllString(line, "$1$2")
	}
	if strings.Contains(low, "setenvironmentvariable") {
		for _, m := range psSetEnv.FindAllStringSubmatch(line, -1) {
			e.psEnv(m[1], false, m[2]) // [Environment]::SetEnvironmentVariable('NAME', 'value'): the splitter cuts at "("
		}
	}
	if (strings.Contains(low, "set ") || strings.Contains(low, "set\t")) && strings.Contains(line, "%") && strings.Contains(line, ";") {
		e.cmdSets(line)
	}
	refresh := strings.Contains(low, "getenvironmentvariable")
	if apart && (subst || strings.Contains(line, "<(")) {
		if pieces, over := unnest(line); pieces != nil {
			if over {
				e.miss(whyManySubst)
			}
			e.apart = true
			e.literal = strings.Contains(line, markSubst) || strings.Contains(line, markInit) || strings.Contains(line, markProc)
			for _, p := range pieces {
				if (strings.Contains(p, markSubst) || strings.Contains(p, markProc)) && substEnv.MatchString(p) {
					// export $(cat .env | xargs), eval "$(…)", source <(…): said as what it is, not as a
					// file (eighth review: the reason named a file where the line shows a command)
					e.fromOut = true
				}
				e.line(refreshed(p, refresh), 0, "")
			}
			return pieces
		}
	}
	e.line(refreshed(line, refresh), 0, "")
	return nil
}

// refreshed: [Environment]::GetEnvironmentVariable("Path", "Machine") - the line installers print to
// reload PATH from the registry after an install - read as $env:Path: the machine's and the user's own
// value. Only for reading: the pieces a line is taken apart into stay as they were.
func refreshed(s string, on bool) string {
	if !on {
		return s
	}
	return psGetEnv.ReplaceAllString(s, "$$env:$1")
}

// line reads every simple command of a line. through names a wrapper the production reader does not
// read (cross-env, a PowerShell assignment): an install inside it is a reason.
func (e *extraParse) line(s string, depth int, through string) {
	if depth > 4 {
		e.miss(whyDeep) // six cross-env deep: production does not read through cross-env, so it does not ask
		return
	}
	for _, sg := range splitShell(s).segs {
		e.command(sg.words, depth, through)
	}
}

var (
	psSetEnv  = regexp.MustCompile(`(?i)SetEnvironmentVariable\(\s*['"]([^'"]{1,128})['"]\s*,\s*['"]([^'"]{0,512})['"]`)
	psEnvName = regexp.MustCompile(`(?i)^(\$env:[A-Za-z_][A-Za-z0-9_]*|\$\{env:[^}]{1,128}\})$`)
	psVar     = regexp.MustCompile(`^\$[A-Za-z_][A-Za-z0-9_]*$`)
	psGetEnv  = regexp.MustCompile(`(?i)\[(?:System\.)?Environment\]::GetEnvironmentVariable\(\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*(?:,\s*(?:['"](?:Machine|User|Process)['"]|\[(?:System\.)?EnvironmentVariableTarget\]::(?:Machine|User|Process))\s*)?\)`)
	// cmd's set NAME=value where a command starts: the value runs to the next operator, and ";" is a
	// character of it (a list's separator), where the splitter ends the word.
	cmdSet = regexp.MustCompile("(?im)(?:^|[&(\"']|/[ck][ \\t])[ \\t]*set[ \\t]+([A-Za-z_][A-Za-z0-9_]*)=([^\"'&|<>\\n`$]*;[^\"'&|<>\\n`$]*)")
	// an environment the line builds from a command's output, in a piece where a mark stands for the
	// substitution: export $(…), eval "$(…)", env $(…) cmd, source <(…). The output of a toolchain's
	// init command (eval "$(pyenv init -)") has a mark of its own and is none.
	substEnv = regexp.MustCompile(`(^|[\s;&|(])(export|declare\s+-x|typeset\s+-x|eval|env(\s+-\S+)*)\s+["']?\$\{_s\}|(^|[\s;&|(])(source|\.)\s+["']?\$\{_p\}`)
)

// shellKeywords: words of the shell's grammar after which a command starts with its own prefix.
var shellKeywords = map[string]bool{"time": true, "if": true, "then": true, "do": true, "else": true, "elif": true,
	"while": true, "until": true, "!": true, "eval": true}

// shellName: a name a shell takes as an assignment before a command (bash and zsh array elements too),
// or PowerShell's $env:NAME.
var shellName = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?|(?i)\$env:[A-Za-z_][A-Za-z0-9_]*\+?|(?i)\$\{env:[^}]{1,128}\}\+?)$`)

// envWrappers set variables, then run the rest of their words as a command (cross-env) or a script
// (cross-env-shell); env-cmd and dotenv read the variables from a file first.
var envWrappers = map[string]bool{"cross-env": true, "cross-env-shell": true}
var fileEnvWrappers = map[string]bool{"env-cmd": true, "dotenv": true, "dotenv-cli": true}

func (e *extraParse) command(w []string, depth int, through string) {
	if depth > 4 {
		e.miss(whyDeep)
		return
	}
	// Where a NAME=value word is an assignment: before the command a shell takes an identifier (A=1,
	// A[1]=1, A+=1); env and sudo take any NAME; after nice, nohup, exec, xargs, timeout… the word is
	// the program itself (env nice ./run=1 npx -y x runs ./run=1), which the production reader skips.
	mode := 0 // 0 the shell's prefix, 1 env or sudo, 2 a wrapper that runs the next word
	// statement: only assignments are left, no command follows them (PATH+=:/opt/bin; npx …). Asked at an
	// assignment word; the answer is the same at every later one, so the words are read once.
	stmt := 0
	statement := func() bool {
		if stmt == 0 {
			stmt = 1
			for _, y := range w[1:] {
				if k, _, ok := strings.Cut(y, "="); !ok || !shellName.MatchString(k) {
					stmt = 2
					break
				}
			}
		}
		return stmt == 1
	}
	for len(w) > 0 {
		x := w[0]
		if n := wrapperName(x); n != "" {
			x = n
		}
		switch {
		case strings.Trim(x, "=,;") == "" && x != "":
			w = w[1:] // cmd.exe skips =, "," and ";" before a command (cmd /c "= npx -y x")
		case hookWrappers[x]:
			w = w[1:]
			switch {
			case x == "env" || x == "sudo":
				mode = 1
			case shellKeywords[x]:
				mode = 0
			default:
				mode = 2
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
					w = w[1:]
				}
			}
			for x != "eval" && len(w) > 0 && strings.HasPrefix(w[0], "-") && w[0] != "--" { // eval takes no options (F1)
				if x == "env" {
					// the split string in any spelling, read again as env's own arguments, as the production
					// reader now reads it (P1-X, ADR-0173): what it reads, it checks, so no "not checked" reason
					if v, rest, ok := envSplit(w); ok {
						e.line(envReread(v, rest), depth+1, through) // joined once (sixth review)
						return
					}
				}
				if x == "env" { // env's own table: value options and unique long prefixes (P1-X round 4)
					if n := envOptionWords(w[0]); n == 2 && len(w) > 1 {
						w = w[1:]
					}
					w = w[1:]
					continue
				}
				if hookTakesValue(x, w[0]) && len(w) > 1 {
					w = w[1:]
				}
				w = w[1:]
			}
			if len(w) > 0 && (w[0] == "--" || x == "eval" && w[0] == "-") { // zsh's eval ends its options at - too
				w = w[1:]
			}
			if x == "eval" && len(w) > 0 {
				// eval runs its words joined as a shell line, and the production reader reads them so (READER-EQ-1,
				// ADR-0159 round 4): what it reads, it checks, so no "through eval" reason
				e.line(strings.Join(w, " "), depth+1, through)
				return
			}
		case mode == 1 && x == markSubst && e.apart && !e.literal:
			w = w[1:] // env $(cat .env | xargs) npx …: the output stands where env takes NAME=value words
		case len(w) == 1 && paramDefault(x) != "":
			goto body // ${X:=npx -y pkg} alone: an expansion the shell runs, not an assignment word
		case strings.Contains(x, "=") && !strings.HasPrefix(x, "-"):
			k, v, _ := strings.Cut(x, "=") // as the production reader takes it: NAME=, NAME+=, A[1]=, $env:NAME=
			if strings.ContainsAny(k, " \t\n;|&") {
				// A quoted command line with a = in one of its arguments (an MCP entry's command:
				// "npx -y mcp-remote https://host/mcp?key=…", seventh review): no shell takes it for an
				// assignment. Alone it is read as a line. Before other words it is a program, and a
				// reason only when those words are a launch the production reader judges in its place.
				if len(w) == 1 {
					goto body
				}
				pm := e.pm
				e.command(w[1:], depth+1, through)
				if e.pm > pm {
					e.miss(whyCommand + " (" + clip(x, 40) + ")")
				}
				return
			}
			if mode == 2 || mode == 0 && !shellName.MatchString(k) {
				e.envMiss(whyCommand + " (" + clip(x, 40) + ")") // a reason only before an install
			}
			switch name := strings.TrimSuffix(k, "+"); {
			case mode == 0 && psEnvName.MatchString(name):
				e.psEnv(name, name != k, v) // $env:NAME="value", $env:NAME+="value"
			case mode == 0 && name != k && statement():
				e.appendEnv(name, v)
			default:
				e.env(k, v)
			}
			w = w[1:]
		case psEnvName.MatchString(x) && len(w) >= 3 && (w[1] == "=" || w[1] == "+="):
			// $env:NAME = 'value', and a value joined of parts, once: $env:Path = "C:\tools;" + $env:Path
			parts := []string{w[2]}
			for n := 3; n+1 < len(w) && w[n] == "+"; n += 2 {
				parts = append(parts, w[n+1])
			}
			e.psEnv(x, w[1] == "+=", strings.Join(parts, ""))
			if len(w) > 3 { // also when the words read as a joined value: $env:X = npx + pkg runs npx
				e.command(w[2:], depth+1, "a PowerShell assignment") // $env:X = npm i x runs npm
			}
			return
		case psVar.MatchString(x) && len(w) >= 3 && w[1] == "=":
			un := "$" + strings.ToUpper(x[1:])
			e.ps[un] = unknownValue // $d = Get-Location, $x = npx -y pkg: what a command gives
			if len(w) == 3 {
				if v, ok := e.psValue(w[2]); ok {
					e.ps[un] = v // $d = "C:\tools"
				}
			}
			e.command(w[2:], depth+1, "a PowerShell assignment") // $x = npx -y pkg runs npx
			return
		case e.psSetsEnv(w):
			return
		case (x == "source" || x == ".") && len(w) > 1 && dotenvFile(w[1]):
			e.fromFile = append(e.fromFile, w[1])
			return
		default:
			goto body
		}
	}
body:
	if len(w) == 0 {
		return
	}
	if len(w) == 1 && strings.ContainsAny(w[0], " \t;|&") {
		segs := splitShell(w[0]).segs // eval "npm i x", a quoted script
		if len(segs) == 1 && len(segs[0].words) == 1 && segs[0].words[0] == w[0] {
			// The splitter gives the word back whole (${…} and $((…)) are one word to it): read again it
			// would be the same word until the depth ran out, and "nested too deep" on a line with no
			// wrapper in it (a GitHub Actions expression ${{ a && b }}: seven lines of the eighth
			// review's corpus). What a shell runs of such a word is the default of a parameter expansion
			// when the variable is unset; any other expansion is the session's own value. The default is
			// words by then, not a script: the first is the command, and an operator or NAME=value among
			// them is a word like any other (bash, dash: ${X:-A=1 npx -y x} runs a command named A=1).
			if def := paramDefault(w[0]); def != "" {
				if ds := splitShell(def).segs; len(ds) > 0 && len(ds[0].words) > 0 {
					if first := ds[0].words[0]; !strings.Contains(first, "=") || paramDefault(first) != "" {
						e.command(ds[0].words, depth+1, "a parameter default")
					}
				}
			}
			return
		}
		for _, sg := range segs { // past the depth each says "nested too deep", once: production does not read through cross-env
			e.command(sg.words, depth+1, through)
		}
		return
	}
	cmd := w[0]
	if strings.Contains(cmd, `\`) && !windowsPath(cmd) {
		cmd = strings.ReplaceAll(cmd, `\`, "")
	}
	cmd = launchBase(cmd)
	rest := w[1:]
	switch {
	case cmd == "sh" || cmd == "bash" || cmd == "zsh" || cmd == "dash" || cmd == "ksh" || cmd == "fish":
		for i, x := range rest {
			if strings.HasPrefix(x, "-") && strings.Contains(x, "c") && !strings.HasPrefix(x, "--") {
				e.line(strings.Join(rest[i+1:], " "), depth+1, through)
				return
			}
		}
		return
	case cmd == "pwsh" || cmd == "powershell":
		for i, x := range rest {
			if lx := strings.ToLower(x); lx == "-command" || lx == "-c" {
				e.line(strings.Join(rest[i+1:], " "), depth+1, through)
				return
			}
		}
		return
	case cmd == "cmd":
		for i, x := range rest {
			if lx := strings.ToLower(x); lx == "/c" || lx == "/k" {
				e.line(strings.Join(rest[i+1:], " "), depth+1, through)
				return
			}
		}
		return
	case strings.HasPrefix(cmd, "python") || cmd == "py":
		if len(rest) >= 2 && rest[0] == "-m" && (rest[1] == "pip" || rest[1] == "pip3" || rest[1] == "uv" || rest[1] == "pipx") {
			e.command(append([]string{rest[1]}, rest[2:]...), depth+1, through)
		}
		return
	case envWrappers[cmd]:
		e.command(rest, depth+1, cmd) // cross-env A=1 npm i x: the production reader does not read past cross-env
		return
	case fileEnvWrappers[cmd]:
		// The file's environment is the wrapped command's alone: a reason when that command fetches a
		// package it names (dotenv -e .env -- npx -y x), not for a command that fetches none or for the
		// line's later commands (dotenv -e .env -- npm start && npx -y x; eighth review).
		f := e.fetch
		e.command(afterOptions(rest), depth+1, cmd)
		if e.fetch > f {
			e.fromFile = append(e.fromFile, cmd)
		}
		return
	case cmd == "printf":
		for i, x := range rest { // printf -v NAME fmt …: sets NAME without an assignment word
			switch {
			case x == "-v" && i+1 < len(rest):
				e.unknownSet(rest[i+1])
			case strings.HasPrefix(x, "-v") && len(x) > 2:
				e.unknownSet(x[2:])
			}
		}
		return
	case cmd == "read" || cmd == "readarray" || cmd == "mapfile":
		for i := 0; i < len(rest); i++ { // read -r NAME …: the value comes from standard input
			x := rest[i]
			switch {
			case x == "-a" && i+1 < len(rest):
				i++
				e.unknownSet(rest[i])
			case len(x) == 2 && strings.Contains("dinNptuCcOs", x[1:]) && x[0] == '-' && i+1 < len(rest):
				i++ // an option's value
			case strings.HasPrefix(x, "-"):
			default:
				e.unknownSet(x)
			}
		}
		return
	case cmd == "code" || cmd == "code-insiders" || cmd == "cursor" || cmd == "windsurf" || cmd == "codium" || cmd == "vscodium":
		for i, x := range rest { // code --add-mcp '{…}': VS Code adds the server
			switch {
			case x == "--add-mcp" && i+1 < len(rest):
				e.pm++
				e.addJSON(rest[i+1], depth+1)
			case strings.HasPrefix(x, "--add-mcp="):
				e.pm++
				e.addJSON(strings.TrimPrefix(x, "--add-mcp="), depth+1)
			}
		}
		return
	case cmd == "export" || cmd == "declare" || cmd == "typeset" || cmd == "setx" || cmd == "set" || cmd == "local" || cmd == "readonly":
		if cmd == "set" {
			// fish: set [-g|-l|-U] -x NAME value…, in any order and clustered (-xg, -lx, --global --export)
			exported, i := false, 0
			for ; i < len(rest) && strings.HasPrefix(rest[i], "-") && rest[i] != "--"; i++ {
				if rest[i] == "--export" || !strings.HasPrefix(rest[i], "--") && strings.Contains(rest[i], "x") {
					exported = true
				}
			}
			if exported && i < len(rest) && !strings.Contains(rest[i], "=") {
				sep := " "
				if searchPathEnv[strings.ToUpper(rest[i])] {
					sep = ":"
				}
				e.env(rest[i], strings.Join(rest[i+1:], sep))
				return
			}
		}
		// cmd's set and setx: the value is Windows' own (set PATH=%PATH%)
		e.win = cmd == "set" || cmd == "setx"
		defer func() { e.win = false }()
		if cmd == "setx" && len(rest) >= 2 && !strings.Contains(rest[0], "=") {
			e.env(rest[0], rest[1]) // setx NAME value
			return
		}
		for _, x := range rest {
			k, v, ok := strings.Cut(x, "=")
			switch {
			case ok && !strings.HasPrefix(k, "-") && !e.win && strings.HasSuffix(k, "+"):
				e.appendEnv(strings.TrimSuffix(k, "+"), v) // export PATH+=":$HOME/bin": a statement
			case ok && !strings.HasPrefix(k, "-"):
				if cmd != "set" || !e.cmdWhole(k, v) {
					e.env(k, v)
				}
			case !ok && (cmd == "export" || cmd == "declare" || cmd == "typeset") && !strings.HasPrefix(x, "-"):
				if x == markSubst && e.apart && !e.literal {
					// export $(cat .env | xargs): the output's own reason, before a package the line
					// names (scan, reasons); before npm start it asked where source .env does not
					continue
				}
				if strings.HasPrefix(x, "$") || presentName(x) {
					// export npm_config_package after read or printf -v set it
					e.envMiss(whyOverride + " (" + clip(x, 40) + " exported)")
				}
			}
		}
		return
	}
	// "<agent CLI> mcp add [-e K=V…] NAME -- cmd", also run through npx; "mcp add-json NAME '{…}'"
	for i := 0; i+1 < len(rest); i++ {
		if rest[i] != "mcp" {
			continue
		}
		switch rest[i+1] {
		case "add":
			e.pm++ // the client launches the server: its environment counts
			e.mcpAddEnv(rest[i+2:])
			for j := i + 2; j < len(rest); j++ {
				if rest[j] == "--" && j+1 < len(rest) {
					e.command(rest[j+1:], depth+1, through)
					break
				}
			}
		case "add-json":
			e.pm++
			for _, a := range rest[i+2:] {
				if strings.HasPrefix(strings.TrimSpace(a), "{") {
					e.addJSON(a, depth+1)
					break
				}
			}
		}
		break
	}
	if packageManagers[cmd] {
		e.pm++
		e.launcher(cmd, rest, depth, through)
	}
}

// paramDefault: the text a shell puts in place of a word that is one parameter expansion with a default
// or an alternative (${X:-text}, ${X-text}, ${X:=text}, ${X=text}, ${X:+text}, ${X+text}; ${1:-text}
// too); "" for any other word (${X:?text} stops the shell, ${{ … }} is not a shell's).
func paramDefault(w string) string {
	if !strings.HasPrefix(w, "${") || !strings.HasSuffix(w, "}") {
		return ""
	}
	inner := w[2 : len(w)-1]
	j := 0
	for j < len(inner) && (inner[j] == '_' || isASCIILetter(inner[j]) || j > 0 && inner[j] >= '0' && inner[j] <= '9') {
		j++
	}
	if j == 0 {
		for j < len(inner) && inner[j] >= '0' && inner[j] <= '9' {
			j++ // a positional parameter
		}
	}
	if j == 0 {
		return ""
	}
	for _, op := range []string{":-", ":=", ":+", "-", "=", "+"} {
		if strings.HasPrefix(inner[j:], op) {
			return inner[j+len(op):]
		}
	}
	return ""
}

// afterOptions: the command after a wrapper's own options (env-cmd -f .env.x cmd, dotenv -e .env -- cmd).
func afterOptions(w []string) []string {
	for i := 0; i < len(w); i++ {
		switch x := w[i]; {
		case x == "--":
			return w[i+1:]
		case strings.HasPrefix(x, "-"):
			if !strings.Contains(x, "=") && i+1 < len(w) && (x == "-f" || x == "-e" || x == "-c" || x == "-r" || x == "-v" ||
				x == "--file" || x == "--environments" || x == "--rc-file") {
				i++
			}
		default:
			return w[i:]
		}
	}
	return nil
}

// addJSON reads "mcp add-json NAME '{…}'": the hook does not check the package of a command entry.
func (e *extraParse) addJSON(s string, depth int) {
	var ent struct {
		Type    string `json:"type"`
		Command string `json:"command"`
		URL     string `json:"url"`
	}
	if decodeExact([]byte(s), &ent) == nil && ent.URL != "" && (remoteType(ent.Type) || ent.Command == "") {
		return // a remote server, like "mcp add --transport http NAME URL"
	}
	e.miss(whyJSON)
	e.entry(s, depth)
}

func remoteType(t string) bool {
	return t == "http" || t == "sse" || t == "streamable-http" || t == "streamableHttp"
}

// entry reads an MCP config entry: keys in other cases, an envFile, its environment, its command line.
func (e *extraParse) entry(s string, depth int) {
	var keys map[string]jsontext.Value
	if decodeExact([]byte(s), &keys) != nil {
		return // the production reader refuses it
	}
	for k := range keys {
		switch lk := strings.ToLower(k); {
		case lk == "envfile" || lk == "env_file":
			e.miss(whyFromFile + " (" + clip(k, 20) + ")") // VS Code and Cursor load variables from that file
		case lk != k && (lk == "command" || lk == "args" || lk == "env" || lk == "url" || lk == "type"):
			e.miss(whyVariant)
		}
	}
	var ent struct {
		Type    string            `json:"type"`
		Command string            `json:"command"`
		Args    []string          `json:"args"`
		URL     string            `json:"url"`
		Env     map[string]string `json:"env"`
		Cwd     string            `json:"cwd"`
	}
	if decodeExact([]byte(s), &ent) != nil {
		return
	}
	if ent.URL != "" && (remoteType(ent.Type) || ent.Command == "") {
		return
	}
	if tmpDir(ent.Cwd) {
		e.miss(whyTmpDir + " (" + clip(ent.Cwd, 60) + ")")
	}
	names := make([]string, 0, len(ent.Env))
	for k := range ent.Env {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		e.env(k, ent.Env[k])
	}
	e.line(entryLine(ent.Command, ent.Args), depth, "")
	if raw := commandString(ent.Command, ent.Args); raw != "" {
		e.line(raw, depth, "")
	}
}

// entryLine: an MCP entry's command and arguments as the shell line a client that starts the program
// directly would be running: each one word.
func entryLine(command string, args []string) string {
	words := make([]string, 0, len(args)+1)
	words = append(words, shellQuote(command))
	for _, a := range args {
		words = append(words, shellQuote(a))
	}
	return strings.Join(words, " ")
}

// commandString: an entry whose command is a whole command line ("npx -y mcp-remote https://…"), as a
// client that hands it to a shell runs it and as the production reader reads a repository's server
// (launchLine): joined as written. "" for a command that is one word.
func commandString(command string, args []string) string {
	if !strings.ContainsAny(command, " \t\n") {
		return ""
	}
	return launchLine(command, args)
}

// mcpAddEnv reads -e/--env before "--" in "<client> mcp add": commander's -e is variadic (-e A=1 B=2),
// yargs takes -e=K=V; each K=V is the environment the server is launched with.
func (e *extraParse) mcpAddEnv(w []string) {
	for i := 0; i < len(w) && w[i] != "--"; i++ {
		x := w[i]
		var vals []string
		switch {
		case x == "-e" || x == "--env":
			for i+1 < len(w) && !strings.HasPrefix(w[i+1], "-") && strings.Contains(w[i+1], "=") {
				i++
				vals = append(vals, w[i])
			}
		case strings.HasPrefix(x, "--env="):
			vals = []string{x[len("--env="):]}
		case strings.HasPrefix(x, "-e") && len(x) > 2 && !strings.HasPrefix(x, "--"):
			vals = []string{strings.TrimPrefix(x[2:], "=")}
		}
		for _, kv := range vals {
			if k, v, ok := strings.Cut(kv, "="); ok && k != "" {
				e.env(k, v)
			}
		}
	}
}

// psSetsEnv: Set-Item env:NAME value sets a variable for what the line runs next.
func (e *extraParse) psSetsEnv(w []string) bool {
	lx := strings.ToLower(w[0])
	if (lx != "set-item" && lx != "si" && lx != "new-item" && lx != "ni" && lx != "set-content") || len(w) < 2 {
		return false
	}
	var name, val string
	for i := 1; i < len(w); i++ {
		lw := strings.ToLower(w[i])
		switch {
		case lw == "-path" || lw == "-value" || lw == "-force":
		case strings.HasPrefix(lw, "env:") && name == "":
			name = strings.TrimLeft(w[i][4:], `\/`) // Env:\NAME, Env:/NAME
		case name != "" && val == "":
			val = w[i]
		}
	}
	if name == "" {
		return false
	}
	e.psEnv(name, false, val)
	return true
}

// psKey: NAME of $env:NAME and ${env:NAME}; any other name as it is.
func psKey(k string) string {
	switch {
	case len(k) > 5 && strings.EqualFold(k[:5], "$env:"):
		return k[5:]
	case len(k) > 7 && strings.EqualFold(k[:6], "${env:") && strings.HasSuffix(k, "}"):
		return k[6 : len(k)-1]
	}
	return k
}

// psEnv judges an assignment PowerShell makes ($env:NAME = "…", +=, Set-Item env:NAME,
// [Environment]::SetEnvironmentVariable). The value is read as PowerShell expands it (psValue), and a
// folder or a program in it as Windows reads one: the production reader reads no such assignment, and
// read the POSIX way every one of them was a reason ($env:Path += ";C:\Program Files\nodejs": the
// entries were taken at ":"). += appends to what the variable held. Other levers, and a value psValue
// does not read, are judged as written, as before.
func (e *extraParse) psEnv(k string, plus bool, raw string) {
	name := psKey(k)
	un := strings.ToUpper(name)
	v, ok := e.psValue(raw)
	if !ok {
		e.ps[un] = unknownValue
		e.env(k, raw)
		return
	}
	if plus {
		old, set := e.ps[un]
		if !set {
			old = "%" + name + "%" // the session's own
		}
		if e.work -= len(old) + len(v); e.work < 0 || len(old)+len(v) > maxPathValue {
			v = tooLong
		} else {
			v = old + v
		}
	}
	e.ps[un] = v
	switch leverOf(name) {
	case lvDirs, lvPath, lvVenv, lvPython, lvInterp, lvProgram:
		e.win, e.as = true, raw
		e.judgeEnv(name, v)
		e.win, e.as = false, ""
	default:
		e.env(k, raw)
	}
}

// psValue reads a value as PowerShell expands a double-quoted string, in the spelling cmd gives the
// same thing: $env:NAME and ${env:NAME} are what the line set them to, or %NAME% - the session's own;
// a variable of PowerShell's ($d) is what the line set it to; $HOME, $PWD and the marks of a command's
// output stay as written, and any other is a value the line does not show ($PSScriptRoot: the
// script's folder). ok is false for what is not read that way - a literal %, a scope or a drive
// after the name, $( and the automatic variables: the caller reads the value as before. PowerShell
// 7.4.7: a ":" right after $env:NAME continues the name ("$env:PATH:/x" is "/x"); ".", "\", ";" and
// "-" end it.
func (e *extraParse) psValue(raw string) (v string, ok bool) {
	if len(raw) > maxPathValue || strings.ContainsAny(raw, "%\x00") {
		return "", false
	}
	if !strings.Contains(raw, "$") {
		return raw, true
	}
	var b strings.Builder
	for i := 0; i < len(raw); {
		if raw[i] != '$' {
			b.WriteByte(raw[i])
			i++
			continue
		}
		name, env, n := psRef(raw[i:])
		if n == 0 {
			return "", false
		}
		key := strings.ToUpper(name)
		if !env {
			key = "$" + key
		}
		val, set := e.ps[key]
		switch {
		case set:
			if e.work -= len(val); e.work < 0 {
				return tooLong, true
			}
		case env:
			val = "%" + name + "%"
		default:
			val = raw[i : i+n]
			if un := strings.ToUpper(name); un != "HOME" && un != "PWD" && val != markSubst && val != markInit && val != markProc {
				// a variable of PowerShell's that the line does not set, or sets in a way that is not
				// read ($d = Join-Path …): PowerShell has $HOME and $PWD of its own, and no other
				val = unknownValue
			}
		}
		b.WriteString(val)
		if b.Len() > maxPathValue {
			return tooLong, true
		}
		i += n
	}
	return b.String(), true
}

// psRef reads the variable s starts with: $NAME, ${NAME}, $env:NAME, ${env:NAME}. n is the length of
// the reference, 0 for anything else.
func psRef(s string) (name string, env bool, n int) {
	word := func(c byte) bool { return c == '_' || isASCIILetter(c) || c >= '0' && c <= '9' }
	if strings.HasPrefix(s, "${") {
		i := strings.IndexByte(s, '}')
		if i < 0 {
			return "", false, 0
		}
		name = s[2:i]
		if len(name) > 4 && strings.EqualFold(name[:4], "env:") {
			name, env = name[4:], true
		}
		for j := 0; j < len(name); j++ {
			if c := name[j]; !word(c) && !(env && (c == '(' || c == ')')) { // ${env:ProgramFiles(x86)}
				return "", false, 0
			}
		}
		if name == "" {
			return "", false, 0
		}
		return name, env, i + 1
	}
	i := 1
	for i < len(s) && word(s[i]) {
		i++
	}
	if i == 1 || s[1] >= '0' && s[1] <= '9' {
		return "", false, 0 // $$, $?, $(, $1, a lone $
	}
	name = s[1:i]
	if strings.EqualFold(name, "env") && i < len(s) && s[i] == ':' {
		j := i + 1
		for j < len(s) && word(s[j]) {
			j++
		}
		if j == i+1 {
			return "", false, 0
		}
		name, env, i = s[i+1:j], true, j
	}
	if i < len(s) && (s[i] == ':' || s[i] == '?') {
		return "", false, 0 // $env:PATH:/x, $global:x, $d:\bin: the name goes on
	}
	return name, env, i
}

// appendEnv: NAME+=value as a statement appends to what the variable held (bash 3.2 and 5.2, zsh):
// what the line set before, or the session's own for a search path (PATH+=:/opt/bin is $PATH:/opt/bin).
// Before a command the appended text is judged alone, as before: bash 3.2 - /bin/bash and /bin/sh of
// macOS - gives the command just that (PATH+=:/opt/bin tool runs ./tool).
func (e *extraParse) appendEnv(name, v string) {
	v = e.bind(v)
	old, set := e.assigned[name]
	if !set && leverOf(name) == lvDirs {
		old, set = "$"+name, true
	}
	if set {
		if e.work -= len(old) + len(v); e.work < 0 || len(old)+len(v) > maxPathValue {
			v = tooLong
		} else {
			v = old + v
		}
	}
	e.envBound(name, v)
}

// cmdSets reads cmd's set NAME=a;b where the splitter ends the word at ";": a search path is judged
// whole (set PATH=%PATH%;. && npx …). A ";" before a blank or at the end is another shell's end of a
// statement, and the value ends there. The word the splitter cuts off the same value is not judged
// again (cmdWhole): set PATH=%ProgramFiles(x86)%\nodejs;%PATH% is cut at "(", and what is left is no
// folder of the line's.
func (e *extraParse) cmdWhole(k, v string) bool {
	for _, whole := range e.cmdRead[strings.ToUpper(k)] {
		if strings.HasPrefix(whole, v) {
			return true
		}
	}
	return false
}

func (e *extraParse) cmdSets(line string) {
	for _, m := range cmdSet.FindAllStringSubmatch(line, -1) {
		if leverOf(m[1]) != lvDirs {
			continue
		}
		v := m[2]
		for i := 0; i < len(v); i++ {
			if v[i] == ';' && (i+1 == len(v) || v[i+1] == ' ' || v[i+1] == '\t') {
				v = v[:i]
				break
			}
		}
		if v = strings.TrimSpace(v); !strings.Contains(v, ";") {
			continue
		}
		if un := strings.ToUpper(m[1]); len(e.cmdRead[un]) < 8 { // a line sets a path once or twice
			if e.cmdRead == nil {
				e.cmdRead = map[string][]string{}
			}
			e.cmdRead[un] = append(e.cmdRead[un], v)
		}
		e.win, e.as = true, v
		e.judgeEnv(m[1], v)
		e.win, e.as = false, ""
	}
}

// psJSON spells an MCP entry quoted the PowerShell way ("{`"type`":`"http`"}": a backtick before each
// inner quote) the POSIX way ("{\"type\":\"http\"}"), so the entry is read as the one PowerShell
// passes on. A POSIX shell runs nothing of such a word: every backtick body starts with a quote that
// never closes (bash, dash, zsh: a syntax error). Only a word that is a JSON object from its first
// character to its last, with no backslash and no backtick of another kind; any other is left as it is.
func psJSON(line string) string {
	var b strings.Builder
	last := 0
	for i := 0; i < len(line); i++ {
		if line[i] != '"' || i > 0 && line[i-1] == '`' {
			continue
		}
		j := i + 1
		for j < len(line) && line[j] == ' ' {
			j++
		}
		if j == len(line) || line[j] != '{' {
			continue
		}
		end := -1
	body:
		for ; j < len(line); j++ {
			switch line[j] {
			case '`':
				if j+1 == len(line) || line[j+1] != '"' {
					break body
				}
				j++
			case '\\', '\n':
				break body
			case '"':
				end = j
				break body
			}
		}
		if end < 0 {
			continue // no plain quote lies between here and where the word stopped: the next start is past it
		}
		inner := line[i+1 : end]
		i = end
		var keys map[string]jsontext.Value
		if !strings.HasSuffix(strings.TrimRight(inner, " "), "}") || decodeExact([]byte(strings.ReplaceAll(inner, "`\"", `"`)), &keys) != nil {
			continue
		}
		b.WriteString(line[last : end-len(inner)])
		b.WriteString(strings.ReplaceAll(inner, "`\"", `\"`))
		last = end
	}
	if last == 0 {
		return line
	}
	b.WriteString(line[last:])
	return b.String()
}

// dotenvFile: a dotenv file (.env, .env.local, prod.env), not an activate script.
func dotenvFile(f string) bool {
	base := strings.ToLower(f[strings.LastIndexAny(f, `/\`)+1:])
	return base == ".env" || strings.HasPrefix(base, ".env.") || strings.HasSuffix(base, ".env")
}

// launcher reads a package manager's or runner's own options, where the tool reads them: an installer
// or npm exec anywhere up to "--", a runner only before its package (what follows is the package's own
// argv). Nothing is consumed: which word is the package is the production reader's business.
func (e *extraParse) launcher(cmd string, rest []string, depth int, through string) {
	e.configSet(cmd, rest)
	verb, runner := launcherRegion(cmd, rest)
	end := len(rest)
	switch {
	case runner:
		end = firstPositional(rest, verb)
	case npmFamily[cmd]:
		end = ownOptionsEnd(cmd, rest) // yarn babel src --plugins x: the script's own argv
	}
	for j := 0; j < end && rest[j] != "--"; j++ {
		if strings.HasPrefix(rest[j], "-") {
			e.flag(cmd, rest, j)
		}
	}
	callAt := -1
	switch cmd {
	case "npx", "pnpx":
		callAt = 0
	case "npm", "pnpm":
		for i, x := range rest {
			if x == "exec" || x == "x" || x == "dlx" {
				callAt = i + 1
				break
			}
			if !strings.HasPrefix(x, "-") {
				break
			}
		}
	}
	if callAt >= 0 && hasCall(rest, callAt) {
		e.miss(whyCall + cmd + " -c") // npx -c '<shell>': runs a command string
	}
	f := fetches(cmd, rest)
	if f {
		e.fetch++
	}
	if through != "" && f {
		e.miss(whyThrough + through + " that alalanet does not check (" + clip(cmd+" "+strings.Join(rest, " "), 60) + ")")
	}
	if runner {
		// npx -y cross-env A=1 npx -y x: the package itself runs a command the production reader does not read
		if p := firstPositional(rest, verb); p < len(rest) && rest[p] != "--" {
			if pkg := strings.ToLower(stripVersion(rest[p])); envWrappers[pkg] || fileEnvWrappers[pkg] {
				inner, f := rest[p+1:], e.fetch // after the runner's own fetch: what the wrapped command adds
				if fileEnvWrappers[pkg] {
					inner = afterOptions(inner) // npx dotenv -e .env -- npx jest: the wrapper's own options first
				}
				e.command(inner, depth+1, cmd+" "+pkg)
				if fileEnvWrappers[pkg] && e.fetch > f {
					e.fromFile = append(e.fromFile, pkg) // as for the wrapper run by its own name (command)
				}
			}
		}
	}
}

// fetches: the command downloads a package it names (npx x, npm i x, pip install x, uvx x).
func fetches(cmd string, rest []string) bool {
	verb, runner := launcherRegion(cmd, rest)
	if cmd == "uv" && len(rest) > 0 && rest[0] == "run" {
		return slices.ContainsFunc(rest, func(x string) bool { return x == "--with" || strings.HasPrefix(x, "--with=") })
	}
	if runner {
		p := firstPositional(rest, verb)
		if cmd == "uvx" || cmd == "uv" { // uv tool run: uv run returned above
			for _, x := range rest[verb:p] {
				if x == "--generate-shell-completion" || strings.HasPrefix(x, "--generate-shell-completion=") {
					// eval "$(uvx --generate-shell-completion bash)": before the tool's name the option
					// prints the shell's completion script and fetches nothing, whatever follows (uv 0.13.7)
					return false
				}
			}
		}
		if p < len(rest) && rest[p] == "--" {
			p++
		}
		return p < len(rest) || slices.ContainsFunc(rest, func(x string) bool {
			return x == "-p" || x == "--package" || x == "--from" || x == "--with" || strings.HasPrefix(x, "--package=")
		})
	}
	for i, x := range rest {
		// a runner word fetches only for the manager whose runner it is: pnpm exec and yarn exec run what the
		// project already has (runnerVerbs; RT-1 round 3)
		if installVerbs[x] && !(verbManagers[cmd] && (x == "exec" || x == "x" || x == "dlx") && !slices.Contains(runnerVerbs[cmd], x)) {
			p := firstPositional(rest, i+1)
			if p < len(rest) && rest[p] == "--" {
				p++
			}
			return p < len(rest) && !localSpec(rest[p])
		}
	}
	return false
}

// localSpec: a folder or a file, not a registry package (npm i ./pkg, pip install .).
func localSpec(s string) bool {
	ls := strings.ToLower(s)
	return strings.HasPrefix(s, ".") || strings.HasPrefix(s, "/") || strings.HasPrefix(s, "~") || strings.HasPrefix(s, `\`) ||
		len(s) > 1 && s[1] == ':' || strings.HasSuffix(ls, ".tgz") || strings.HasSuffix(ls, ".tar.gz") || strings.HasSuffix(ls, ".whl")
}

// launcherRegion: where a command's own options end. Runners (npx, bunx, pnpx, uvx, uv tool run,
// uv run, pipx run, pnpm/yarn dlx, bun x) stop reading options at the package.
func launcherRegion(cmd string, rest []string) (verb int, runner bool) {
	at := func(i int, s string) bool { return i < len(rest) && rest[i] == s }
	switch cmd {
	case "npx", "bunx", "pnpx", "uvx":
		return 0, true
	case "uv":
		switch {
		case at(0, "tool") && at(1, "run"):
			return 2, true
		case at(0, "run"):
			return 1, true
		}
	case "pipx":
		if at(0, "run") {
			return 1, true
		}
	case "pnpm", "yarn":
		if at(0, "dlx") {
			return 1, true
		}
	case "bun":
		if at(0, "x") {
			return 1, true
		}
	}
	return 0, false
}

// firstPositional: the index of the first word from i on that is not an option or an option's value,
// as the production reader skips them (len(rest) when none).
func firstPositional(rest []string, i int) int {
	for j := i; j < len(rest); j++ {
		x := rest[j]
		if x == "--" {
			return j
		}
		if strings.HasPrefix(x, "-") {
			if !strings.Contains(x, "=") && valueFlags[x] {
				j++
			}
			continue
		}
		return j
	}
	return len(rest)
}

// hasCall: -c / --call before the first positional from i on.
func hasCall(rest []string, i int) bool {
	if i > len(rest) {
		return false
	}
	end := firstPositional(rest, i)
	for _, x := range rest[i:end] {
		if x == "-c" || x == "--call" || strings.HasPrefix(x, "--call=") {
			return true
		}
	}
	return false
}

var npmFamily = map[string]bool{"npx": true, "bunx": true, "pnpx": true, "npm": true, "pnpm": true, "yarn": true, "bun": true}

// pyRiskFlags: options of uv, pip and pipx that are a reason with any value: a host taken without TLS,
// a config file alalanet cannot see.
var pyRiskFlags = map[string]bool{"--allow-insecure-host": true, "--trusted-host": true, "--config-file": true}

// venvPython: a project's own virtualenv interpreter (server/.venv/bin/python), the usual relative
// --python; a relative path elsewhere is held.
var venvPython = regexp.MustCompile(`(?i)(^|[/\\])\.?venv[^/\\]*[/\\](bin[/\\]python[0-9.]*|scripts[/\\]pythonw?(\.exe)?)$`)

// flag judges one option of a launcher. npm, pnpm, Yarn and bun take any config key as an option:
// the levers are the config keys' (pmFlag). An option of uv, pip or pipx is the lever its variable is
// (--python as UV_PYTHON, --cert as PIP_CERT, --keyring-provider, --index-strategy), under the flag's
// reason. A client certificate and its key (--client-cert, --key, npm's --cert) are credentials, not
// levers; --prefix, -C and --cache are not read: npm --prefix ./app install is how a subfolder is
// installed, and a cache is where downloads are kept.
func (e *extraParse) flag(cmd string, rest []string, j int) {
	name, val, hasVal := strings.Cut(rest[j], "=")
	if !hasVal && j+1 < len(rest) {
		val = rest[j+1] // a peek: the value may be the next word
	}
	val = e.bind(val) // D=. --cafile $D/ca.pem: what the line set before
	why := whyFlag + " (" + clip(name, 40) + ")"
	switch cmd {
	case "npx", "bunx", "pnpx", "npm", "pnpm", "yarn", "bun":
		e.pmFlag(cmd, name, val, hasVal, why)
	case "uvx", "uv", "pip", "pip3", "pipx":
		lv, win := lvNone, false
		if name == "--python" || name == "-p" || name == "--with-requirements" {
			// a file named the PowerShell way: uv run -p $env:LOCALAPPDATA\Python\…\python.exe
			if lval := strings.ToLower(val); strings.Contains(lval, "$env:") || strings.Contains(lval, "${env:") {
				if t, ok := e.psValue(val); ok {
					val, win = t, true
				}
			}
		}
		switch {
		case name == "--env-file" && (cmd == "uv" || cmd == "uvx"):
			// uv run's and uvx's option; pip and pipx have none, and fail on it before they install
			if val != "" {
				e.fromFile = append(e.fromFile, val) // a reason before a package the line names (reasons)
			}
		case pyRiskFlags[name]:
			lv = lvAny
		case name == "--with-requirements":
			// The project's own requirements file is what the project installs anyway, as pip install -r
			// requirements.txt is no reason (eighth review: uv run --with-requirements requirements.txt
			// server.py, four lines of its corpus). One fetched from a URL (uv does fetch it), kept in a
			// temporary folder anyone can write to, or named by a value the line does not show is one.
			if strings.Contains(val, "://") || unread(val) || tmpDir(val) {
				lv = lvAny
			}
		case name == "--python" || name == "-p" && cmd != "pip" && cmd != "pip3":
			if !hasVal && (cmd == "uv" || cmd == "uvx") && strings.HasPrefix(val, "-") {
				// uv run --python -V python: uv takes no word that starts with "-" for the value and
				// stops ("a value is required"); the next option is not an interpreter's name
				val = ""
			}
			// an interpreter in the current or a temporary folder; --python 3.12 is a version, and a bare
			// name that is none is a file of the current folder first for uv and pip (cwdFirst)
			lv = lvPython
			if cmd == "pipx" {
				lv = lvInterp // pipx looks a bare name up in PATH
			}
		case name == "--cert" && (cmd == "pip" || cmd == "pip3"):
			lv = lvPath // pip's CA bundle; /etc/ssl/… is the operator's own
		case name == "--keyring-provider":
			lv = lvKeyring
			if cmd == "uv" || cmd == "uvx" {
				lv = lvKeyringUV
			}
		case name == "--index-strategy":
			lv = lvStrategy
		}
		e.win = win
		held := e.leverWhy(lv, name, val) != ""
		e.win = false
		if held {
			e.miss(why)
		}
	}
}

func (e *extraParse) untrustedInterpreter(v string) bool {
	if (untrustedPath(v) || cwdRooted(v)) && venvPython.MatchString(v) && !tmpMarker(strings.ToLower(strings.ReplaceAll(v, `\`, "/"))) {
		return false // server/.venv/bin/python, $PWD/.venv/bin/python: the project's own virtualenv
	}
	return e.untrustedPathX(v, false)
}

// cwdRooted: a path spelled from the folder the line runs in ($PWD/…, ${workspaceFolder}/…, %CD%\…).
func cwdRooted(v string) bool {
	if lv := strings.ToLower(v); strings.HasPrefix(lv, `%cd%\`) || strings.HasPrefix(lv, "%cd%/") {
		return true
	}
	name, rest, op, ok := leadingVar(v)
	return ok && op == "" && (name == "PWD" || name == "workspaceFolder" || name == "workspaceRoot") &&
		(strings.HasPrefix(rest, "/") || strings.HasPrefix(rest, `\`))
}

// unquote drops the quotes node strips from NODE_OPTIONS ("--require" ./x.js, --re"quire").
func unquote(v string) string { return strings.NewReplacer(`"`, "", `'`, "").Replace(v) }

// env judges one assignment: a line's NAME=value in any spelling, an MCP entry's env, mcp add -e.
func (e *extraParse) env(k, v string) { e.envBound(k, e.bind(v)) }

// envBound: env for a value that is bound already (an option's: pnpm --config.script-shell=$D/x).
func (e *extraParse) envBound(k, v string) {
	k = strings.TrimSuffix(psKey(k), "+") // NAME+=value appends
	if i := strings.IndexByte(k, '['); i > 0 && strings.HasSuffix(k, "]") {
		k = k[:i] // NAME[0]=value: bash and zsh set an element; element 0 is $NAME
	}
	if k == "" {
		return
	}
	if strings.HasPrefix(k, "$") {
		// export "${upper}_REQUIRE_LIVE=1": the variable in front is the session's own, and no lever's
		// name ends with that tail. A value the line does not show, or a URL, stays a reason: pnpm
		// reads node-mirror:<channel> for any channel a line names, and its value is a URL.
		if name, tail, op, ok := leadingVar(k); ok && name != "" && op == "" && !strings.Contains(tail, "$") &&
			!leverTail(tail) && !strings.ContainsAny(v, "$\x00") && !strings.Contains(v, "://") {
			return
		}
		e.envMiss(whyOverride + " (a variable named by " + clip(k, 40) + ")") // export $X=evil
		return
	}
	defer func() { e.assigned[k] = v }()
	e.judgeEnv(k, v)
}

// leverTail: can the name of a lever end with tail (leverOf, read from the name's end)? An empty tail
// ends every name.
func leverTail(tail string) bool {
	ut := strings.ToUpper(tail)
	if strings.Contains(ut, ":") {
		return true // @scope:registry, //host/:cafile, node-mirror:release
	}
	for k := range envLevers {
		if strings.HasSuffix(k, ut) {
			return true
		}
	}
	// GIT_CONFIG_KEY_<n>, GIT_CONFIG_VALUE_<n>
	if letters := strings.TrimRight(ut, "0123456789"); strings.HasSuffix("GIT_CONFIG_KEY_", letters) || strings.HasSuffix("GIT_CONFIG_VALUE_", letters) {
		return true
	}
	c := compactKey(tail)
	for _, p := range pmCarriers {
		cp := compactKey(p)
		for key := range pmKeys {
			if strings.HasSuffix(cp+key, c) {
				return true
			}
		}
	}
	return false
}

// bind puts in what the line set before: a $NAME / ${NAME} that starts the value or an entry of a list
// (E=$D after D=., PATH=/b:$PATH after PATH=/a:$PATH, --cafile $D/ca.pem). A value is bound once, when
// it is set or given, as a shell binds it: a variable left in a bound value is the session's own. Read
// again later it would name the line's newer value, and PATH=/a:$PATH twice on a line would be a PATH
// made of itself. Values past maxPathValue, or expansions past the line's work budget, become one that
// every check holds.
func (e *extraParse) bind(v string) string {
	if len(e.assigned) == 0 || !strings.Contains(v, "$") {
		return v
	}
	entries := strings.Split(v, ":")
	bound := false
	for i, d := range entries {
		name, rest, op, ok := leadingVar(d)
		if !ok || op != "" {
			continue
		}
		val, set := e.assigned[name]
		if !set {
			continue
		}
		if e.work -= len(val) + len(rest); e.work < 0 || len(val)+len(rest) > maxPathValue {
			return tooLong
		}
		entries[i], bound = val+rest, true
	}
	if !bound {
		return v
	}
	return strings.Join(entries, ":")
}

// shown: a value as a reason prints it. The marks that stand for a value the line does not show, or
// for one too long to read, are spelled out.
func shown(v string) string {
	if unread(v) {
		v = strings.NewReplacer(unknownValue, "<not shown>", tooLong, "<too long>").Replace(v)
	}
	return clip(v, 60)
}

// tooLong stands for a value the reader does not expand: a relative entry, which every path check
// holds (the production reading too), printed as <too long>.
const tooLong = "\x00too-long"

// unread: a value with a mark in it (unknownValue, tooLong): text the reader has not read. Every lever
// is a reason for one (leverWhy).
func unread(v string) bool { return strings.IndexByte(v, 0) >= 0 }

const maxPathValue = 8 << 10

// sessionVars: variables the user's own session sets; an entry built on them is the user's.
var sessionVars = map[string]bool{"PATH": true, "HOME": true, "USERPROFILE": true, "APPDATA": true, "LOCALAPPDATA": true,
	"PROGRAMFILES": true, "SYSTEMROOT": true, "WINDIR": true, "NVM_BIN": true, "PNPM_HOME": true, "BUN_INSTALL": true, "CARGO_HOME": true}

var procCwd = regexp.MustCompile(`^/proc/[^/]+/(cwd|root)(/|$)`)

// untrustedPathX: the production reader's untrustedPath, and what it does not see: empty entries
// (PATH=:$PATH), the current folder spelled $PWD, ~+ or /proc/self/cwd, an operator alalanet does not
// evaluate (${D:-.}), an unset variable's whole entry, /run/lock. v comes bound (bind): what the line
// set earlier is in it (D=. --cafile $D/ca.pem), and a variable still there is the session's. list: a
// search path, where an empty entry is the current folder.
func (e *extraParse) untrustedPathX(v string, list bool) bool {
	if untrustedPath(v) {
		return true // the production reading first: what it holds stays held
	}
	if len(v) > maxPathValue {
		return true // not read entry by entry: the hook takes lines up to 1 MiB
	}
	// A Windows list only when it looks like one: a ";" or a backslash, and every entry a drive, UNC or
	// %VAR% path. Otherwise POSIX: ".:/usr/bin" and "b:/usr/bin" are "." (or "b") and /usr/bin, which
	// the production reading takes for a drive.
	// A value PowerShell or cmd reads (e.win) is Windows' own whatever it looks like. Without a ";"
	// the entries of either are still taken at ":" (PowerShell on macOS and Linux; %A%\x:%CD% in a
	// POSIX shell), a lone drive path apart.
	windows := e.win || windowsList(v)
	sep := ":"
	if windows && (strings.Contains(v, ";") || driveEntry(v)) {
		sep = ";"
	}
	entries := strings.Split(v, sep)
	for _, d := range entries {
		ld := strings.ToLower(strings.ReplaceAll(d, `\`, "/"))
		if windows && strings.HasPrefix(d, "%") {
			if cmdVarHeld(ld) {
				return true
			}
			continue
		}
		if name, rest, op, ok := leadingVar(d); ok {
			if op != "" {
				return true // ${HOME+.}, ${D-.}, ${PWD%/}
			}
			un := strings.ToUpper(name)
			switch {
			case un == "PWD" || un == "OLDPWD":
				return true
			case strings.EqualFold(name, "workspaceFolder") || strings.EqualFold(name, "workspaceRoot") || strings.EqualFold(name, "fileDirname"):
				return true // the repository the editor opened
			}
			if sessionVars[un] {
				if lr := strings.ToLower(strings.ReplaceAll(rest, `\`, "/")); strings.Contains(lr, "/..") || tmpMarker(lr) {
					return true // $HOME/../../tmp, $HOME\..\x
				}
				continue
			}
			if rest == "" && list && name != e.own && !(d == markSubst && e.apart && !e.literal) {
				// an unset variable's whole entry expands to "": the current folder. The variable's own
				// name is what the session had (PYTHONPATH=$PYTHONPATH:/opt/lib appends, as PATH=$PATH:…
				// does). A command's output ($(dirname "$(command -v corepack)")) is a folder the line
				// does not show, as $X/bin is.
				return true
			}
			continue // $SOMETHING/bin: the user's own environment
		}
		switch {
		case d == "":
			if list {
				return true // an empty entry is the current folder (PATH=:$PATH, a::b, a trailing ":", PATH=)
			}
		case strings.HasPrefix(d, "~+") || strings.HasPrefix(d, "~-"):
			return true // the current or previous folder
		case strings.HasPrefix(ld, "%cd%") || tmpMarker(ld):
			return true
		case strings.HasPrefix(ld, "/"):
			if c := path.Clean(ld); procCwd.MatchString(c) || tmpMarker(c) {
				return true // //proc/./self/cwd, /usr/../tmp
			}
		case strings.HasPrefix(d, "~"): // ~/bin, ~user/bin: a home folder
		case windows && driveEntry(d): // a share (\\server\x) starts with "/" above, as any rooted path
		default:
			return true // relative: the current folder decides what runs
		}
	}
	return false
}

// windowsList: a value with a ";" or a backslash whose every ";" entry is a drive, UNC or %VAR% path.
func windowsList(v string) bool {
	if !strings.ContainsAny(v, `;\`) {
		return false
	}
	for _, d := range strings.Split(v, ";") {
		if d != "" && !driveEntry(d) && !strings.HasPrefix(d, `\\`) && !strings.HasPrefix(d, "%") {
			return false
		}
	}
	return true
}

// cmdVarHeld: an entry of a Windows list that starts with %NAME% (ld: in lower case, with "/") and is
// not the session's own folder: the current folder (%CD%, %__CD__%) or a temporary one, a name cmd
// does not expand as written (%PATH:~0,3%, %~dp0: the script's folder), text glued to a variable the
// session may not have (%X%bin), or a path that leaves the folder or goes into a temporary one
// (%USERPROFILE%\..\x, %LOCALAPPDATA%\Temp\x). %NAME% alone and %NAME%\folder are the session's, as
// $NAME/folder is.
func cmdVarHeld(ld string) bool {
	i := strings.IndexByte(ld[1:], '%')
	if i <= 0 {
		return true // %evil, %%
	}
	name, rest := ld[1:1+i], ld[2+i:]
	for j := 0; j < len(name); j++ {
		if c := name[j]; !(c == '_' || c == '(' || c == ')' || isASCIILetter(c) || c >= '0' && c <= '9') {
			return true
		}
	}
	switch name {
	case "cd", "__cd__", "pwd", "oldpwd", "temp", "tmp", "tmpdir":
		return true
	}
	if rest == "" {
		return false
	}
	if rest[0] != '/' && !sessionVars[strings.ToUpper(name)] {
		return true // %X%bin; %ProgramFiles%(x86) is a folder next to the session's own
	}
	return strings.Contains(rest, "/..") || strings.Contains(rest, "/tmp") || strings.Contains(rest, "/temp/") || strings.HasSuffix(rest, "/temp")
}

// driveEntry: C:\…, C:/…, or a bare C:.
func driveEntry(d string) bool {
	return len(d) >= 2 && isASCIILetter(d[0]) && d[1] == ':' && (len(d) == 2 || d[2] == '\\' || d[2] == '/')
}

// tmpMarker: a temporary or lock folder anyone can write to (in addition to the production checks).
func tmpMarker(ld string) bool {
	return strings.Contains(ld, "/tmp") || strings.HasPrefix(ld, "/var/tmp") || strings.HasPrefix(ld, "/dev/shm") ||
		strings.HasPrefix(ld, "/run/lock") || strings.HasPrefix(ld, "/var/lock") || strings.HasPrefix(ld, "/dev/mqueue")
}

func isASCIILetter(c byte) bool { return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' }

// leadingVar splits an entry that starts with $NAME or ${NAME<op>…} into the name, the rest after the
// variable, and the operator text inside the braces (%/, :-x …), if any.
func leadingVar(d string) (name, rest, op string, ok bool) {
	switch {
	case strings.HasPrefix(d, "${"):
		i := strings.IndexByte(d, '}')
		if i < 3 {
			return "", "", "", false
		}
		inner := d[2:i]
		j := 0
		for j < len(inner) && (inner[j] == '_' || isASCIILetter(inner[j]) || j > 0 && inner[j] >= '0' && inner[j] <= '9') {
			j++
		}
		if j == 0 {
			return "", "", "", false
		}
		return inner[:j], d[i+1:], inner[j:], true
	case strings.HasPrefix(d, "$"):
		i := 1
		for i < len(d) && (d[i] == '_' || isASCIILetter(d[i]) || i > 1 && d[i] >= '0' && d[i] <= '9') {
			i++
		}
		if i > 1 {
			return d[1:i], d[i:], "", true
		}
		if len(d) > 1 && d[1] >= '0' && d[1] <= '9' { // $1: a positional parameter, unset here
			return d[1:2], d[2:], "", true
		}
	}
	return "", "", "", false
}

// unknownValue stands for a value set by printf -v or read: the line does not show it.
const unknownValue = "\x00unknown"

// unknownSet: printf -v NAME or read NAME set a variable whose value the line does not show; a name any
// check could hold for some value is a reason (printf -v PATH needs no export).
func (e *extraParse) unknownSet(k string) {
	if i := strings.IndexByte(k, '['); i > 0 {
		k = k[:i]
	}
	e.assigned[k] = unknownValue
	if riskyName(k) {
		e.envMiss(whyUnknown + " (" + clip(k, 40) + ")")
	}
}

// tmpDir: a temporary folder anyone can write to, spelled as a path, a variable or mktemp. ~/tmp is the
// user's own (it asked in the corpus without cause). It is held as an MCP entry's "cwd", where a client
// starts the server every time: the folder's .npmrc, pip.conf or uv.toml is one anyone could have put
// there. On a command line it is no reason (seventh review: cd /tmp && npx create-next-app, cd
// "$(mktemp -d)" && npm init asked, all nine forms it tried, while a dozen other spellings of the same
// folder passed): a scratch folder is where agents and READMEs try a package, and the spellings a line
// can give a folder are more than a reader of one line can know.
func tmpDir(d string) bool {
	if d == "" {
		return false
	}
	ld := strings.ToLower(strings.ReplaceAll(d, `\`, "/"))
	if name, _, _, ok := leadingVar(d); ok {
		switch strings.ToUpper(name) {
		case "TMPDIR", "TMP", "TEMP", "RUNNER_TEMP":
			return true
		}
	}
	if strings.Contains(ld, "mktemp") || strings.HasPrefix(ld, "%temp%") || strings.HasPrefix(ld, "%tmp%") {
		return true
	}
	if strings.HasPrefix(ld, "/") {
		for _, c := range []string{ld, path.Clean(ld)} {
			for _, p := range []string{"/tmp", "/var/tmp", "/dev/shm", "/run/lock", "/var/lock", "/private/tmp", "/private/var/tmp"} {
				if c == p || strings.HasPrefix(c, p+"/") {
					return true
				}
			}
		}
	}
	return driveEntry(d) && (strings.Contains(ld, "/temp/") || strings.HasSuffix(ld, "/temp"))
}
