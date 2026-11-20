// Package installread reads a shell line the way alalanet's install-time check reads it: which install targets the
// line names, what about it cannot be read, and the second reader's reasons to hold (ADR-0052, ADR-0131). The
// server's hook (internal/app InstallHook, POST /v1/hooks/claude-code) and install_check use it, and so does
// alalanet-agent's hook adapter for the runtimes other than Claude Code (RT-1, ADR-0150): the adapter sends a line to
// the server exactly when the server would act on it (a target from ParseLine, a reason from ParseLine or HookExtra),
// or when it has a command substitution. It has no state, no store and no network; its only imports are the standard
// library.
//
// The reader moved here from internal/app unchanged in RT-1's second round; internal/app keeps the names it always
// called it by (internal/app/installread.go).
package installread

import (
	"slices"
	"sort"
)

// MaxLineBytes: the longest line the readers read (the server's hook endpoint takes 1 MiB of body). ParseLine holds a
// longer one, and the other readers give nothing for it (ADR-0159 round 23: what a line built to cost may spend).
const MaxLineBytes = 1 << 20

// lineTooLong: a line past MaxLineBytes.
func lineTooLong(line string) bool { return len(line) > MaxLineBytes }

// ParseLine is the reader the hook acts on: the install targets in a shell line (at most MaxHookTargets; more is a
// reason in unread), what it could not read (unread: each a reason to hold), whether the line runs anything besides
// installs and harmless commands (other), and whether it has a command substitution outside single quotes (subst).
func ParseLine(line string) (targets, unread []string, other, subst bool) {
	return parseInstallLineFull(line)
}

// OtherProgram is the program of the first command in a line that ParseLine reads as neither an install it reads
// nor a harmless command — past VAR=value words, wrappers and their options that take a value (WrapperValueFlags),
// into sh -c, eval, env -S, pwsh -Command and cmd /c scripts, past harmless commands before && or ; — as a lower-case
// name without directory, .exe or .cmd; "" when the line runs no such command. ParseLine reads the line the same
// way and gives the same answer with or without this call. ECO-1 counts the program, by a fixed list of words, for
// a line install_check could not read (ADR-0159).
func OtherProgram(line string) string {
	if lineTooLong(line) {
		return ""
	}
	p := &hookParse{seen: map[string]bool{}}
	p.line(whichSubst.ReplaceAllString(line, "$1$2"), 0)
	return p.firstOther
}

// Command is one simple command ParseLine's walk reads: its program as the walk names it (no directory, lower case, no
// .exe or .cmd, a backslash removed as bash removes it), its words from the program on, the VAR=value words before it,
// and the wrappers before it with their options and values (sudo -u me -D /srv, env -C/srv, timeout 5). A command of
// only VAR=value words, or the script word of eval or env -S, has no program.
type Command struct {
	Prog     string
	Words    []string
	Assigns  []string
	Wrappers []string
	// Win: the Windows reading of the command visited just before (its words as PowerShell and cmd read them, a
	// backslash a path separator: READER-ESCAPE-1 round 2–3); a consumer judges both
	Win bool
}

// Commands is every simple command ParseLine's own walk visits in a line — after whichSubst, through wrappers and their
// options, env -S, sh/bash/zsh/dash -c, pwsh -Command, cmd /c, eval, python -m pip — in the order it visits them.
// alalanet-agent's hook judges these for what moves an install's source beyond the registry it names (REPO-POL-NPMRC,
// ADR-0174 round 8): one walk, not a second one of its own.
func Commands(line string) []Command {
	if lineTooLong(line) {
		return nil
	}
	var out []Command
	p := &hookParse{seen: map[string]bool{}, visit: func(c Command) {
		out = append(out, Command{Prog: c.Prog, Words: slices.Clone(c.Words), Assigns: slices.Clone(c.Assigns), Wrappers: slices.Clone(c.Wrappers), Win: c.Win})
	}}
	p.line(whichSubst.ReplaceAllString(line, "$1$2"), 0)
	return out
}

// HookExtra is the second reader's reasons for the hook that the first one (ParseLine's targets and unread for the
// same line) did not give already.
func HookExtra(line string, targets, unread []string, subst bool) []string {
	if lineTooLong(line) {
		return nil // ParseLine holds it
	}
	return hookExtra(line, targets, unread, subst)
}

// LaunchExtraWhy is the second reader's first reason for an install_check target that is a launch line or an MCP
// entry: its code, and the sentence the hook prints; "" when it adds none.
func LaunchExtraWhy(raw string) (code, why string) { return launchExtraWhy(raw) }

// ExtraCode maps one of the second reader's reasons to the fixed code install_check and the repository check sign.
func ExtraCode(msg string) string { return extraCode(msg) }

// UnreadCode maps what ParseLine could not read to a fixed reason code.
func UnreadCode(msg string) string { return unreadCode(msg) }

// EnvUnread reads an MCP entry's environment as the line reader reads VAR=value prefixes: what in it moves the
// registry, a package manager's config or loads other code, each a reason (in the order of the sorted names).
func EnvUnread(env map[string]string) []string {
	p := &hookParse{seen: map[string]bool{}, entry: true}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p.configEnv(k, env[k])
	}
	if p.homeMoved != "" { // an entry is a launch: the folder alone decides (HOME-CONFIG-ENV-1)
		p.miss(p.homeMoved)
	}
	p.noteArgTilde()
	return p.unread
}

// ServerExtraCodes is the second reader's reasons for a repository config's command server — its command, args and
// environment (string values in envVals; names whose value is not a string in envKeys) — as codes, each once, in
// order. The caller (internal/app serverExtraCodes) answers an entry without a command, or with a reason from its
// keys, before it reads anything here.
func ServerExtraCodes(command string, args []string, envVals map[string]string, envKeys []string) []string {
	e := newExtraParse()
	e.pm++ // a server's command is a launch
	keys := make([]string, 0, len(envVals))
	for k := range envVals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		e.entryEnv = true // a server's env reaches it as written (HOME-CONFIG-ENV-1 round 2, P2-1)
		e.env(k, envVals[k])
		e.entryEnv = false
	}
	for _, k := range envKeys {
		if _, ok := envVals[k]; !ok {
			e.envKey(k) // a value that is not a string: the name alone
		}
	}
	e.scan(entryLine(command, args), true)
	if raw := commandString(command, args); raw != "" {
		e.scan(raw, true)
	}
	var codes []string
	for _, r := range e.reasons() {
		if c := extraCode(r); !slices.Contains(codes, c) { // a few dozen codes at most
			codes = append(codes, c)
		}
	}
	return codes
}

// The reader's helpers and tables the rest of the server uses as well.

// DecodeExact decodes JSON (with comments and trailing commas removed) as the clients read it: member names match
// exactly; duplicate names and invalid UTF-8 are errors.
func DecodeExact(b []byte, v any) error { return decodeExact(b, v) }

// LaunchLine joins a launch command and its arguments into a shell line for ParseLine.
func LaunchLine(command string, args []string) string { return launchLine(command, args) }

// ShellFields are the words of the first simple command in a shell line, as the shell hands them to the program —
// quotes and a backslash removed, a Windows path kept (splitShell). install_check reads a launch line's program and
// the "mcp add" grammar from these, not from a raw strings.Fields, so a quoted or escaped program ('npx', np\x,
// claude mcp \add) is read as the shell runs it (READER-ESCAPE-1); an empty-by-default expansion is read away
// (READER-ESCAPE-1 round 2, R4). An empty word (a lone "") is dropped: it is no program, verb or "--".
func ShellFields(line string) []string {
	sl := splitShell(line)
	if len(sl.segs) == 0 {
		return nil
	}
	out := make([]string, 0, len(sl.segs[0].words))
	for _, w := range stripEmptyExpansions(sl.segs[0].words) { // claude ${9}mcp add, "$@"\-\-: as the shell passes them
		if w != "" {
			out = append(out, w)
		}
	}
	return out
}

// LaunchBase is a command word's program name: no directory, lower case, no .cmd or .exe.
func LaunchBase(w string) string { return launchBase(w) }

// WinExePath reports whether a first word is a Windows path to a program PowerShell and cmd run (.\venv\Scripts\pip.exe,
// venv\Scripts\pip):
// install_check routes such a line to the shared reader, which reads it a second time as that path (READER-ESCAPE-1 r2).
func WinExePath(w string) bool { return winExePath(w) || winProgramPath(w) }

// WinExeName reports whether a word ends in a Windows executable suffix (python3.12.exe, pip3.12.cmd); install_check
// routes such a program to the shared reader, which reads it as the hook does (READER-ESCAPE-1 round 2).
func WinExeName(w string) bool { return winExeName(w) }

// EmptyExpansionProgram reports whether a word is a program with an empty-by-default expansion before it ($@claude,
// $*npm), which the shell drops; install_check routes such a line to the shared reader (READER-ESCAPE-1 round 2).
func EmptyExpansionProgram(w string) bool { return emptyExpansionRemainder(w) != "" }

// ProgramName is a command word's program as the reader reads it: LaunchBase's name, with pip's versioned console
// scripts (pip3.12, pip2) as pip (READER-NPM-ALIAS-1). install_check looks a launch line's first word up by it.
func ProgramName(w string) string { return progName(launchBase(w)) }

// StripVersion:"@scope/name@1.2.3" -> "@scope/name", "name@1" -> "name".
func StripVersion(name string) string { return stripVersion(name) }

// ShellQuote quotes a word so that a line read by ParseLine keeps it one word.
func ShellQuote(w string) string { return shellQuote(w) }

// TakesNext reports whether a short or long option word leaves its value to the next word.
func TakesNext(values map[string]bool, flag string) bool { return takesNext(values, flag) }

// TmpDir: a temporary folder (a package manager run there reads an .npmrc or pip.conf the line does not show).
func TmpDir(d string) bool { return tmpDir(d) }

var (
	// PosixShells: the shells whose -c script the reader reads as a POSIX line (ksh, mksh, ash …).
	PosixShells = posixShells
	// ForeignShells: shells with a syntax of their own (fish, csh, tcsh, nu …).
	ForeignShells = foreignShells
	// ScriptRunners: the commands, other than shells, that run a script or command from their words (READER-SHELLS).
	ScriptRunners = map[string]bool{"busybox": true, "toybox": true, "su": true, "runuser": true, "script": true, "flock": true,
		"watch": true, "trap": true, "call": true, "start": true, "iex": true, "invoke-expression": true,
		"arch": true, "nocorrect": true}
	// WrapperValueFlags: per wrapper (sudo, env, timeout …), the options that take a value word.
	WrapperValueFlags = wrapperValueFlags
	// DefaultRegistries: the public registries and indexes install_check reads.
	DefaultRegistries = defaultRegistries
	// IndexEnv: the environment variables that set pip's and uv's index options (pyIndexEnv, generated from the
	// tools' parsers: PIP_INDEX_URL, its hidden alias PIP_PYPI_URL, UV_INDEX …).
	IndexEnv = pyIndexEnv
	// MCPClientPackages: the npm packages of the agent CLIs whose "mcp add NAME -- cmd" runs cmd.
	MCPClientPackages = mcpClientPackages
)
