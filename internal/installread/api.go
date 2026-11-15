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
	p := &hookParse{seen: map[string]bool{}}
	p.line(whichSubst.ReplaceAllString(line, "$1$2"), 0)
	return p.firstOther
}

// HookExtra is the second reader's reasons for the hook that the first one (ParseLine's targets and unread for the
// same line) did not give already.
func HookExtra(line string, targets, unread []string, subst bool) []string {
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
	p := &hookParse{seen: map[string]bool{}}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p.configEnv(k, env[k])
	}
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
		e.env(k, envVals[k])
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

// LaunchBase is a command word's program name: no directory, lower case, no .cmd or .exe.
func LaunchBase(w string) string { return launchBase(w) }

// StripVersion: "@scope/name@1.2.3" -> "@scope/name", "name@1" -> "name".
func StripVersion(name string) string { return stripVersion(name) }

// ShellQuote quotes a word so that a line read by ParseLine keeps it one word.
func ShellQuote(w string) string { return shellQuote(w) }

// TakesNext reports whether a short or long option word leaves its value to the next word.
func TakesNext(values map[string]bool, flag string) bool { return takesNext(values, flag) }

// TmpDir: a temporary folder (a package manager run there reads an .npmrc or pip.conf the line does not show).
func TmpDir(d string) bool { return tmpDir(d) }

var (
	// WrapperValueFlags: per wrapper (sudo, env, timeout …), the options that take a value word.
	WrapperValueFlags = wrapperValueFlags
	// DefaultRegistries: the public registries and indexes install_check reads.
	DefaultRegistries = defaultRegistries
	// MCPClientPackages: the npm packages of the agent CLIs whose "mcp add NAME -- cmd" runs cmd.
	MCPClientPackages = mcpClientPackages
)
