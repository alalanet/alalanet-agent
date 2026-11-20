package installread

import (
	"maps"
	"regexp"
	"slices"
	"strings"
)

// Commands that run other commands the way a shell does (READER-SHELLS, ADR-0159 round 5). Both readers read what a
// shell's rules make certain: the -c script of a POSIX-like shell, su -c, script, flock, watch, trap, cmd's call and
// start, busybox's applets — each as sh -c's script is read. What they cannot read is a reason, never silence: a
// shell with a syntax of its own (fish, csh), PowerShell's Invoke-Expression, a script fed to a shell's input or given
// as a <(…) file, a command whose name comes from a command substitution or a variable. A line that shows no install
// (eval "$X", . ./x.sh, curl … | sh, a toolchain's init output) stays silent, as before.

const (
	whyScript       = "runs a script alalanet cannot read"
	whyVarCommand   = "runs a command whose name comes from a variable alalanet cannot see"
	whySubstCommand = "runs a command whose name comes from a command substitution alalanet cannot see"
)

// posixShells: shells whose -c script is a POSIX shell line, read as sh -c's is (ksh, mksh, ash, yash …).
var posixShells = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "ksh93": true, "mksh": true,
	"lksh": true, "pdksh": true, "oksh": true, "loksh": true, "ash": true, "hush": true, "yash": true, "posh": true, "rbash": true,
	"osh": true}

// foreignShells: shells with a syntax of their own — fish's (cmd) substitutions and quotes, csh's and tcsh's, nushell,
// xonsh, elvish. alalanet does not read their scripts: one that runs anything but harmless commands is a reason.
var foreignShells = map[string]bool{"fish": true, "csh": true, "tcsh": true, "nu": true, "xonsh": true, "elvish": true}

// How a command runs the command it is given (runsWhat).
const (
	runNone    = iota
	runLine    // a script, read as sh -c's: su -c, script -c, flock -c, watch, trap
	runWords   // a command given as words: flock FILE cmd …, script FILE cmd …, watch -x, call, start
	runForeign // a script in a syntax alalanet does not read: fish -c, csh -c, Invoke-Expression
)

// runsWhat: what cmd (lower case, no folder) runs of its words rest, and how. sh, bash, zsh, dash and the other POSIX
// shells are each reader's own case. A foreign script (fish, csh, iex) that holds none of the characters where those
// shells differ from a POSIX shell is read as POSIX (a target, or silent on other commands), not given a reason:
// fish -c 'npm test' is quiet and fish -c 'npm i x' is a checked target (P3-3).
func runsWhat(cmd string, rest []string) (how int, script string, words []string) {
	how, script, words = runsWhatRaw(cmd, rest)
	if how == runForeign && posixSafe(script) {
		how = runLine
		if cmd != "iex" && cmd != "invoke-expression" {
			script = stripForeignKeywords(script) // fish -c 'cd app; and npm i x' runs npm (round 7, R2-1)
		}
	}
	return how, script, words
}

// stripForeignKeywords: a POSIX-safe fish or csh script without the words that, where a command starts, run the
// command after them — fish's and, or, not and begin, tcsh's repeat N — so that the POSIX reading reads that command, as
// the foreign shell runs it. fish's if, while and else take a command right after them too: they are kept (the POSIX
// reader knows them) and a command still starts after them, so "if not npm i x" reads npm (round 8, R3-1). The script has no quote or bracket (posixSafe): its words end at blanks and at ; | & and new
// lines.
func stripForeignKeywords(s string) string {
	var b strings.Builder
	start, count := true, false
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case strings.IndexByte(";|&\n", c) >= 0:
			b.WriteByte(c)
			start, count = true, false
			i++
			continue
		case c == ' ' || c == '\t' || c == '\r':
			b.WriteByte(c)
			i++
			continue
		}
		j := i
		for j < len(s) && strings.IndexByte(";|&\n \t\r", s[j]) < 0 {
			j++
		}
		switch w := s[i:j]; {
		case count:
			count = false // repeat's count
		case start && (w == "and" || w == "or" || w == "not" || w == "begin"):
		case start && (w == "if" || w == "while" || w == "else" || w == "time"): // fish's time takes a job too (R4-3)
			b.WriteString(w) // a header: the command follows it
		case start && w == "repeat":
			count = true
		default:
			b.WriteString(w)
			start = false
		}
		i = j
	}
	return b.String()
}

// posixSafe: a script with none of the characters where fish or PowerShell parse unlike a POSIX shell, so reading it
// as POSIX gives what the foreign shell runs.
func posixSafe(s string) bool {
	return !strings.ContainsAny(s, "(){}[]$\\'\"`@%")
}

// paramExpansionProgram: a word that is a program named by a parameter expansion whose "=" is an assigning default
// inside the braces (${X:=npm}, ${X=npm}, n${E:=p}m), not an assignment word. The shell runs the expanded value, so
// both readers read it through varCommand, not as VAR=value. A word whose first "=" is outside any ${…} (FOO=1,
// ${p}:x=1 after env) is a real assignment and stays one (round 6, P2-3).
func paramExpansionProgram(x string) bool {
	if !strings.Contains(x, "${") || !strings.Contains(x, "=") {
		return false
	}
	var open []int // where each ${ that is still open starts
	for i := 0; i < len(x); i++ {
		switch {
		case x[i] == '$' && i+1 < len(x) && x[i+1] == '{':
			open = append(open, i+2)
			i++
		case x[i] == '}' && len(open) > 0:
			open = open[:len(open)-1]
		case x[i] == '=':
			// the first "=": outside the braces it is an assignment; inside it is a program only in the shape
			// ${NAME:=…}, ${NAME=…}, ${NAME:-…}, ${NAME-…} — a GitHub Actions ${{ a == b }} is neither (round 7, R2-4)
			return len(open) > 0 && defaultShape.MatchString(x[open[len(open)-1]:])
		}
	}
	return false
}

// remoteFetch: a PowerShell download inside a subexpression or a group: $(irm …), (iwr …), $(Invoke-RestMethod …).
var remoteFetch = regexp.MustCompile(`(?i)\(\s*(irm|iwr|invoke-restmethod|invoke-webrequest)\b`)

// defaultShape: the start of a parameter expansion with a default or an assigning default.
var defaultShape = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(:=|=|:-|-|:\+|\+)`) // and the alternates (round 8, R3-3)

func runsWhatRaw(cmd string, rest []string) (how int, script string, words []string) {
	switch cmd {
	case "iex", "invoke-expression":
		if a := psCommandArgs(rest); len(a) > 0 {
			return runForeign, strings.Join(a, " "), nil
		}
		return runNone, "", nil // its input: a script the line shows is read where it is fed (fed)
	case "su":
		return suScript(rest)
	case "runuser":
		// util-linux runuser: su's options (-c, -l, -s …), or -u USER [--] COMMAND…, run with no shell (ADR-0159 round 14)
		if how, s, w := suScript(rest); how != runNone {
			return how, s, w
		}
		return runuserCommand(rest)
	case "script":
		return scriptCommand(rest)
	case "flock":
		return flockCommand(rest)
	case "watch":
		return watchCommand(rest)
	case "brew":
		// brew exec|x, sandbox-exec, bundle exec, sh -c, ruby, benchmark --exec, a shell alias, and the wrappers that run
		// a brew command (ECO-1-BREW rounds 2–3, brewRuns)
		return brewRuns(rest)
	case "trap":
		// trap [--] ACTION CONDITION…: ACTION is a script; "-", "" and a number (trap 1 2) reset, one word is a condition
		if len(rest) > 0 && rest[0] == "--" {
			rest = rest[1:]
		}
		if len(rest) < 2 || rest[0] == "" || strings.HasPrefix(rest[0], "-") || strings.Trim(rest[0], "0123456789") == "" {
			return runNone, "", nil
		}
		return runLine, rest[0], nil
	case "call":
		// cmd's call: the rest is a command, or :label, a subroutine of the batch file (not on the line)
		if len(rest) == 0 || strings.HasPrefix(rest[0], ":") {
			return runNone, "", nil
		}
		return runWords, "", rest
	case "start":
		return startCommand(rest)
	}
	if foreignShells[cmd] {
		if s, ok := shellScript(rest, true); ok {
			return runForeign, s, nil
		}
	}
	return runNone, "", nil
}

// shellScript: the script a shell's words give it with -c. POSIX: sh -c [options…] command_string [name [args]].
// bash, dash, ksh and busybox sh take more options and an end of options "--" after -c, and the command_string is the
// first word that is not an option (bash -c -- '…', sh -c -e '…', bash -c -o pipefail '…'). foreign: also fish's -C
// and --command, --commands and --init-command, alone or with "=".
func shellScript(rest []string, foreign bool) (string, bool) {
	for i, x := range rest {
		switch {
		case strings.HasPrefix(x, "--"):
			if !foreign {
				continue
			}
			name, v, eq := strings.Cut(x, "=")
			if name != "--command" && name != "--commands" && name != "--init-command" {
				continue
			}
			if eq {
				return strings.Join(append([]string{v}, rest[i+1:]...), " "), true
			}
			return scriptAfterC(rest[i+1:])
		case strings.HasPrefix(x, "-") && (strings.Contains(x, "c") || foreign && strings.Contains(x, "C")):
			return scriptAfterC(rest[i+1:])
		}
	}
	return "", false
}

// cScriptWord: the command_string word of a POSIX shell's -c alone, as shellScript finds it (without the words after it).
func cScriptWord(rest []string) (string, bool) {
	for i, x := range rest {
		if !strings.HasPrefix(x, "--") && strings.HasPrefix(x, "-") && strings.Contains(x, "c") {
			if j := scriptAfterCAt(rest[i+1:]); j >= 0 {
				return rest[i+1+j], true
			}
			return "", false
		}
	}
	return "", false
}

// scriptAfterC: the command_string among the words after -c, joined with the rest. The shell's options come first
// (-e, -x, -l, +x, -o errexit and clusters), then one "--", then the command_string; its own positional parameters
// follow it, harmlessly joined on. "" when every word is an option.
func scriptAfterC(after []string) (string, bool) {
	if i := scriptAfterCAt(after); i >= 0 {
		return strings.Join(after[i:], " "), true
	}
	return "", false
}

// scriptAfterCAt is scriptAfterC's command_string as an index into after; -1 for none.
func scriptAfterCAt(after []string) int {
	for i := 0; i < len(after); i++ {
		x := after[i]
		switch {
		case x == "--" || x == "-": // bash and dash end the options at a lone "-" too (round 7, R2-2)
			if i+1 < len(after) {
				return i + 1
			}
			return -1
		case (x == "-o" || x == "+o" || x == "-O" || x == "+O") && i+1 < len(after):
			i++ // the option's value word (set -o errexit)
		case len(x) > 1 && (x[0] == '-' || x[0] == '+') && !strings.ContainsAny(x, " \t"):
			// a shell option word, alone or clustered; a lone "-", and a word with a blank (the whole
			// command_string, quoted), are not options
		default:
			return i
		}
	}
	return -1
}

// posixScriptAt: the index in words (a command and its arguments) of a POSIX-like shell's -c command_string, as
// shellScript finds it; -1 for none (MCP-ADD-NO-DASH-1 round 3, P3-2: an MCP add launch's sh -c script is quoted
// whole in its target, its $ included).
func posixScriptAt(words []string) int {
	if len(words) < 2 || !posixShells[launchBase(words[0])] {
		return -1
	}
	for k, x := range words[1:] {
		if strings.HasPrefix(x, "-") && !strings.HasPrefix(x, "--") && strings.Contains(x, "c") {
			if i := scriptAfterCAt(words[k+2:]); i >= 0 {
				return k + 2 + i
			}
			return -1
		}
	}
	return -1
}

// shellReadsStdin: a POSIX or foreign shell cmd given rest runs its input as its script (no -c script, readsStdin).
func shellReadsStdin(cmd string, rest []string) bool {
	if !posixShells[cmd] && !foreignShells[cmd] {
		return false
	}
	_, ok := shellScript(rest, foreignShells[cmd])
	return !ok && readsStdin(rest)
}

// readsStdin: a shell given these words reads its script from its input: no script operand (bash, sh -s, bash -s --
// args) or /dev/stdin as the operand. The -c case is shellScript's.
func readsStdin(rest []string) bool {
	for i := 0; i < len(rest); i++ {
		switch x := rest[i]; {
		case x == "-" || x == "--":
			return i+1 == len(rest) || stdinFile(rest[i+1])
		case x == "-o" || x == "+o" || x == "-O" || x == "+O" || x == "--rcfile" || x == "--init-file":
			i++ // an option's value
		case strings.HasPrefix(x, "--"):
		case strings.HasPrefix(x, "-"):
			if strings.Contains(x, "s") {
				return true // -s: the script is the input, the words after it its arguments
			}
		case strings.HasPrefix(x, "+"):
		default:
			return stdinFile(x)
		}
	}
	return true
}

// stdinFile: a file name that is the input itself.
func stdinFile(x string) bool {
	return x == "/dev/stdin" || x == "/dev/fd/0" || x == "/proc/self/fd/0"
}

// psCommandArgs: Invoke-Expression's words without its -Command parameter name (any prefix of it, PowerShell's own
// rule; -Command:value too).
func psCommandArgs(rest []string) []string {
	var out []string
	for _, x := range rest {
		lx := strings.ToLower(x)
		if name, _, ok := strings.Cut(lx, ":"); ok && len(name) > 1 && strings.HasPrefix("-command", name) {
			out = append(out, x[len(name)+1:])
			continue
		}
		if len(lx) > 1 && strings.HasPrefix("-command", lx) {
			continue
		}
		out = append(out, x)
	}
	return out
}

// runuserCommand: runuser -u USER [options] [--] COMMAND [ARG…] runs COMMAND as USER with no shell (util-linux
// runuser(1)); without -u it runs a shell, which suScript reads.
func runuserCommand(rest []string) (int, string, []string) {
	user := false
	for i := 0; i < len(rest); i++ {
		name, _, eq := strings.Cut(rest[i], "=")
		switch x := rest[i]; {
		case x == "--":
			if user && i+1 < len(rest) {
				return runWords, "", rest[i+1:]
			}
			return runNone, "", nil
		case x == "-u" || x == "--user":
			user = true
			i++
		case eq && name == "--user":
			user = true
		case x == "-g" || x == "--group" || x == "-G" || x == "--supp-group" || x == "-w" || x == "--whitelist-environment" ||
			x == "-s" || x == "--shell":
			i++
		case strings.HasPrefix(x, "-"):
		default:
			if user {
				return runWords, "", rest[i:]
			}
			return runNone, "", nil
		}
	}
	return runNone, "", nil
}

// suScript: su -c SCRIPT (also --command, --session-command, a cluster such as -lc, and BSD's su USER -c, where the
// words after the user go to the shell): the user's shell runs SCRIPT with -c. A shell given with -s that has a syntax
// of its own makes it a script alalanet does not read.
func suScript(rest []string) (int, string, []string) {
	script, shell, found := "", "", false
	for i := 0; i < len(rest); i++ {
		x := rest[i]
		next := func() string {
			if i+1 < len(rest) {
				i++
				return rest[i]
			}
			return ""
		}
		name, v, eq := strings.Cut(x, "=")
		switch {
		case x == "-c" || x == "--command" || x == "--session-command":
			if s := next(); !found {
				script, found = s, true
			}
		case eq && (name == "--command" || name == "--session-command"):
			if !found {
				script, found = v, true
			}
		case x == "-s" || x == "--shell":
			shell = next()
		case eq && name == "--shell":
			shell = v
		case x == "-g" || x == "--group" || x == "-G" || x == "--supp-group" || x == "-w" || x == "--whitelist-environment":
			next()
		case len(x) > 2 && x[0] == '-' && x[1] != '-':
			// a cluster of flags before c: -lc SCRIPT, -mcSCRIPT
			if k := strings.IndexByte(x, 'c'); k > 0 && strings.Trim(x[1:k], "lmpfP") == "" {
				s := x[k+1:]
				if k == len(x)-1 {
					s = next()
				}
				if !found {
					script, found = s, true
				}
			}
		}
	}
	switch {
	case !found:
		return runNone, "", nil
	case foreignShells[launchBase(shell)]:
		return runForeign, script, nil
	}
	return runLine, script, nil
}

// scriptCommand: util-linux script -c COMMAND [FILE]; macOS and BSD script [options] FILE COMMAND … (the words after the
// file are the command).
func scriptCommand(rest []string) (int, string, []string) {
	const values = "EIOBTmot" // util-linux -E -I -O -B -T -m -o, BSD -t and -T take a value
	for i := 0; i < len(rest); i++ {
		x := rest[i]
		name, v, eq := strings.Cut(x, "=")
		switch {
		case x == "-c" || x == "--command":
			if i+1 < len(rest) {
				return runLine, rest[i+1], nil
			}
			return runNone, "", nil
		case eq && name == "--command":
			return runLine, v, nil
		case x == "--":
			if i+2 < len(rest) {
				return runWords, "", rest[i+2:]
			}
			return runNone, "", nil
		case strings.HasPrefix(x, "--"):
			switch name {
			case "--echo", "--log-in", "--log-out", "--log-io", "--log-timing", "--logging-format", "--output-limit":
				if !eq {
					i++
				}
			}
		case strings.HasPrefix(x, "-") && len(x) > 1:
		cluster:
			for k := 1; k < len(x); k++ {
				switch {
				case x[k] == 'c':
					if k < len(x)-1 {
						return runLine, x[k+1:], nil
					}
					if i+1 < len(rest) {
						return runLine, rest[i+1], nil
					}
					return runNone, "", nil
				case strings.IndexByte(values, x[k]) >= 0:
					if k == len(x)-1 {
						i++ // the value is the next word
					}
					break cluster
				}
			}
		default:
			// util-linux permutes options past the file (getopt, no "+"): script -a log -c CMD, script log --command=CMD
			// run CMD. BSD and macOS: script [options] FILE command …, the words after the file are the command.
			for j := i + 1; j < len(rest); j++ {
				switch y := rest[j]; {
				case y == "-c" || y == "--command":
					if j+1 < len(rest) {
						return runLine, rest[j+1], nil
					}
					return runNone, "", nil
				case strings.HasPrefix(y, "--command="):
					return runLine, strings.TrimPrefix(y, "--command="), nil
				}
			}
			if i+1 < len(rest) {
				return runWords, "", rest[i+1:]
			}
			return runNone, "", nil
		}
	}
	return runNone, "", nil
}

var flockValues = map[string]bool{"-w": true, "--wait": true, "--timeout": true, "-E": true, "--conflict-exit-code": true}

// flockCommand: flock [options] FILE -c COMMAND, or flock [options] FILE COMMAND …; flock N (a descriptor) runs nothing.
func flockCommand(rest []string) (int, string, []string) {
	for i := 0; i < len(rest); i++ {
		x := rest[i]
		switch {
		case x == "-c" || x == "--command":
			if i+1 < len(rest) {
				return runLine, rest[i+1], nil // before the file flock refuses it; read all the same
			}
			return runNone, "", nil
		case x == "--":
			continue
		case strings.HasPrefix(x, "-") && len(x) > 1:
			if takesNext(flockValues, x) {
				i++
			}
			continue
		}
		after := rest[i+1:] // x is the lock file
		switch {
		case len(after) >= 2 && (after[0] == "-c" || after[0] == "--command"):
			return runLine, after[1], nil
		case len(after) >= 1 && strings.HasPrefix(after[0], "--command="):
			return runLine, strings.TrimPrefix(after[0], "--command="), nil
		case len(after) > 0:
			return runWords, "", after
		}
		return runNone, "", nil
	}
	return runNone, "", nil
}

var watchValues = map[string]bool{"-n": true, "--interval": true, "-q": true, "--equexit": true}

// watchCommand: procps watch [options] COMMAND …: the words are joined and run by sh -c, or with -x (--exec) run as
// they are.
func watchCommand(rest []string) (int, string, []string) {
	exec, i := false, 0
options:
	for ; i < len(rest); i++ {
		x := rest[i]
		switch {
		case x == "--":
			i++
			break options
		case x == "--exec":
			exec = true
		case strings.HasPrefix(x, "--"):
			if takesNext(watchValues, x) {
				i++
			}
		case strings.HasPrefix(x, "-") && len(x) > 1:
			if strings.Contains(x, "x") && strings.Trim(x[1:], "bcdeghprtwx") == "" {
				exec = true
			}
			if takesNext(watchValues, x) {
				i++
			}
		default:
			break options
		}
	}
	switch {
	case i >= len(rest):
		return runNone, "", nil
	case exec:
		return runWords, "", rest[i:]
	}
	return runLine, strings.Join(rest[i:], " "), nil
}

// startCommand: cmd's start [title] [/options] command …: a first word that is empty or has a blank is the window's
// title (start "" npx …); /D, /NODE, /AFFINITY and /MACHINE take a value, /Dfolder has it attached.
func startCommand(rest []string) (int, string, []string) {
	option := func(x string) bool {
		u := strings.ToUpper(x)
		switch {
		case len(u) < 2 || u[0] != '/':
			return false
		case strings.HasPrefix(u, "/D") && strings.ContainsAny(u, `:\`):
			return true
		}
		return strings.Trim(u[1:], "ABCDEFGHIJKLMNOPQRSTUVWXYZ") == ""
	}
	i := 0
	options := func() {
		for i < len(rest) && option(rest[i]) {
			switch strings.ToUpper(rest[i]) {
			case "/D", "/NODE", "/AFFINITY", "/MACHINE":
				i++
			}
			i++
		}
	}
	options()
	if i < len(rest) && (rest[i] == "" || strings.ContainsAny(rest[i], " \t")) {
		i++
		options()
	}
	if i >= len(rest) {
		return runNone, "", nil
	}
	return runWords, "", rest[i:]
}

// unwrapped: a simple command's program (lower case, no folder) and its words, past wrappers and VAR=value words.
func unwrapped(w []string) (string, []string) {
	for len(w) > 0 {
		x := w[0]
		if n := wrapperName(x); n != "" {
			w = w[1:]
			for len(w) > 0 && strings.HasPrefix(w[0], "-") && w[0] != "--" {
				if hookTakesValue(n, w[0]) && len(w) > 1 {
					w = w[1:]
				}
				w = w[1:]
			}
			if len(w) > 0 && w[0] == "--" {
				w = w[1:]
			}
			if n == "timeout" && len(w) > 0 {
				w = w[1:] // the duration
			}
			continue
		}
		if strings.Contains(x, "=") && !strings.HasPrefix(x, "-") {
			w = w[1:]
			continue
		}
		return launchBase(strings.ReplaceAll(x, `\`, "")), w[1:]
	}
	return "", nil
}

// printed: what a command that prints its words prints, when the line shows it — echo, printf, PowerShell's
// Write-Output, or a quoted string alone (PowerShell prints it).
func printed(w []string) (string, bool) {
	if len(w) == 1 && strings.ContainsAny(w[0], " \t") {
		return w[0], true
	}
	cmd, rest := unwrapped(w)
	switch cmd {
	case "echo", "print":
		for len(rest) > 0 && len(rest[0]) > 1 && rest[0][0] == '-' && strings.Trim(rest[0][1:], "neE") == "" {
			rest = rest[1:]
		}
		return strings.Join(rest, " "), true
	case "printf":
		if len(rest) > 0 && strings.HasPrefix(rest[0], "-v") {
			return "", false // printf -v NAME: into a variable
		}
		return strings.Join(rest, " "), true
	case "write-output", "write-host":
		return strings.Join(rest, " "), true
	}
	return "", false
}

// passesInput: a command that passes its input on unchanged (tee, cat with no file).
func passesInput(w []string) bool {
	cmd, rest := unwrapped(w)
	return cmd == "tee" || cmd == "cat" && !strings.ContainsFunc(strings.Join(rest, ""), func(r rune) bool { return r != '-' })
}

// shownInput: the text a command reads as its input or as a <(…) file, when the line shows it: a here-string, the
// words of echo or printf piped into it (through tee or cat), the words of echo in the <(…) that follows it.
func shownInput(segs []shellSeg, i int) string {
	sg := segs[i]
	if len(sg.here) > 0 {
		return strings.Join(sg.here, "\n")
	}
	if sg.proc && i+1 < len(segs) {
		s, _ := printed(segs[i+1].words)
		return s
	}
	for j := i; j > 0 && segs[j].piped; j-- {
		prev := segs[j-1]
		if len(prev.here) > 0 && passesInput(prev.words) {
			return strings.Join(prev.here, "\n")
		}
		if s, ok := printed(prev.words); ok {
			return s
		}
		if !passesInput(prev.words) {
			return ""
		}
	}
	return ""
}

// fed: a shell, source or Invoke-Expression that reads a script from its input or a <(…) file whose text the line
// shows (echo 'npm i x' | sh, bash <<< 'npm i x', source <(echo npm i x)): a reason when that script runs an install.
func (p *hookParse) fed(segs []shellSeg, i, depth int) {
	cmd, rest := unwrapped(segs[i].words)
	foreign := foreignShells[cmd] || cmd == "iex" || cmd == "invoke-expression"
	switch {
	case posixShells[cmd] || foreignShells[cmd]:
		if !shellReadsStdin(cmd, rest) {
			return
		}
	case cmd == "brew":
		// brew sh, brew bundle sh, brew x bash, sandbox-exec P -- sh -s …: a shell that reads the input (ECO-1-BREW round 4)
		if !brewStdinShell(rest) {
			return
		}
	case cmd == "source" || cmd == ".":
		if len(rest) > 0 && !stdinFile(rest[0]) || len(rest) == 0 && !segs[i].proc {
			return
		}
	case cmd == "iex" || cmd == "invoke-expression":
		if len(psCommandArgs(rest)) > 0 {
			return
		}
	case implicitStdinShell(segs[i].words):
		// su with no -c, sudo -s / -i / doas -s with no command: the user's shell reads the input
	default:
		return
	}
	if cmd == "" {
		cmd = "a shell"
	}
	if s := shownInput(segs, i); s != "" {
		if _, _, ok := downloadCommand(substBody(s)); ok {
			return // bash <<< "$(curl …)", echo "$(curl …)" | sh: the download's script, read by scriptRuns (PIPE-SCRIPT-1 round 2)
		}
		// the segment's own VAR=value words reach the script's commands (HOMEBREW_API_DOMAIN=… bash <<< 'brew install
		// wget'); read before it, as the command reads them after (reasons are said once: ECO-1-BREW round 3)
		for _, w := range segs[i].words {
			if launchBase(w) == cmd {
				break
			}
			if k, v, ok := strings.Cut(w, "="); ok && shellName.MatchString(k) {
				p.configEnv(k, v)
			}
		}
		p.unreadScript("the input of "+cmd, s, depth, foreign)
	}
}

// implicitStdinShell: words that start the user's shell with no command, so it reads its script from the input —
// su with no -c (su, su root, su -), and sudo or doas run with -s / -i / --shell / --login and no command (sudo -s,
// sudo -i, doas -s). The started shell reads what is piped or given as a here-string (P3-1).
func implicitStdinShell(words []string) bool {
	login := false
	for len(words) > 0 {
		n := wrapperName(words[0])
		if n != "sudo" && n != "doas" {
			break
		}
		words = words[1:]
		for len(words) > 0 && strings.HasPrefix(words[0], "-") && words[0] != "--" {
			if x := words[0]; x == "-s" || x == "--shell" || x == "-i" || x == "--login" {
				login = true
			}
			if hookTakesValue(n, words[0]) && len(words) > 1 {
				words = words[1:]
			}
			words = words[1:]
		}
		if len(words) > 0 && words[0] == "--" {
			words = words[1:]
		}
		if login {
			return len(words) == 0 // sudo -s cmd runs cmd, not a login shell
		}
	}
	if len(words) > 0 && launchBase(strings.ReplaceAll(words[0], `\`, "")) == "su" {
		how, _, _ := suScript(words[1:])
		return how == runNone // su with a -c runs that script, read by runsWhat; without one it reads the input
	}
	return false
}

// unreadScript: a script alalanet does not read as the shell does, read the POSIX way for a decision only. A reason when
// it installs, or reads as anything but harmless commands in a syntax of its own (foreign: fish's n(echo p)m is npm).
func (p *hookParse) unreadScript(what, s string, depth int, foreign bool) {
	// the Homebrew variables set so far and the line's assignments go in: brew in the script is theirs (round 3)
	q := &hookParse{seen: map[string]bool{}, brewWhy: slices.Clone(p.brewWhy), assigned: maps.Clone(p.assigned)}
	q.line(s, depth+1)
	p.work += q.work
	p.def(q.defined) // source /dev/stdin <<< 'pip() { … }': the definition is made in this shell (READER-SHADOW-1)
	install := len(q.targets)+len(q.unread) > 0
	if foreign && p.shell != nil && q.hits > 0 && foreignParen(s) {
		// fish runs a (…) substitution in the shell itself, before the install it feeds (round 31)
		p.miss(whyOwnShell + " (" + what + " with a substitution that runs in its own shell: " + clip(s, 60) + ")")
	}
	// A foreign script that shows a command alalanet cannot read: a reason. One that is only a variable (iex $cmd,
	// iex $profile) shows no command, as eval "$X" does, and stays silent by design (P3-3).
	if install || foreign && q.other && showsCommand(s) {
		p.miss(whyScript + " (" + what + ": " + clip(s, 60) + ")")
	}
}

// showsCommand: a script whose first word, in some segment, is a program the line spells — not only a variable
// expansion. iex $cmd and iex "$x" show none; iex 'n(echo p)m i x' shows one.
func showsCommand(s string) bool {
	for _, sg := range splitShell(s).segs {
		if len(sg.words) == 0 {
			continue
		}
		if w := sg.words[0]; !strings.Contains(w, "$") || expandUnset(w, false, 0) != "" || expandUnset(w, true, 0) != "" {
			return true
		}
	}
	return false
}

// runs reads a command that runs other commands (runsWhat), and one whose name comes from a variable; true when it read
// the command, and the caller reads nothing more of it.
func (p *hookParse) runs(w []string, cmd string, rest []string, depth int) bool {
	if cmd == "brew" {
		// brew alias NAME=… && brew NAME ARGS: the alias's script with ARGS, a command the line made (ECO-1-BREW round 4)
		if line, name, ok := p.brewAliasUse(rest); ok {
			p.miss(whyShadow + " (brew alias " + clip(name, 40) + ")")
			p.prog = ""
			p.line(line, depth+1)
			return true
		}
	}
	switch how, script, words := runsWhat(cmd, rest); how {
	case runLine:
		if foreignShells[cmd] || cmd == "iex" || cmd == "invoke-expression" {
			p.foreignScript(script, cmd, depth) // fish, csh, PowerShell: not by the POSIX allowlist (rounds 29, 30)
			return true
		}
		if cmd == "brew" {
			p.brewTargets(rest) // brew sh, benchmark, alias: their option words' reasons, the alias's name (round 4)
		}
		p.line(script, depth+1)
		return true
	case runWords:
		if cmd == "brew" { // brew exec --formulae=u/r/x: the taps it installs before the command (ECO-1-BREW round 2)
			targets, _, _ := p.brewTargets(rest)
			for _, t := range targets {
				p.add(t)
			}
		}
		p.prog = "" // the program is the one it runs (ECO-1)
		p.command(words, depth+1)
		return true
	case runForeign:
		what := cmd + " -c"
		switch cmd {
		case "iex", "invoke-expression":
			what = "Invoke-Expression"
		case "su":
			what = "su -s -c"
		}
		// iex "& { $(irm https://…) }": the script iex runs is downloaded, as in irm … | iex, which stays silent by the
		// owner's decision — only an install the line itself shows is a reason (round 8, R3-6). Read again in the
		// second reader's pieces the download is a mark: the same (what a mark-named command runs is substRuns').
		// A local file's text ($(Get-Content x.ps1), R4-4) likewise, but only when what is left once the $(…)
		// subexpressions are taken out reads the same in PowerShell and POSIX and holds no & (PowerShell's call
		// operator) and no other iex: "& $(Get-Command npm) i x" and "$(x) | iex" keep their reason (round 10, R5-2).
		foreign := !((cmd == "iex" || cmd == "invoke-expression") &&
			(remoteFetch.MatchString(script) || strings.Contains(script, markSubst) || plainAroundSubexpr(script)))
		p.unreadScript(what, script, depth, foreign)
		return true
	}
	return p.varCommand(w, depth)
}

// varCommand: a command word whose program name holds a parameter expansion (n${E}pm, ${NPX:-npx}, $E npm …). Read with
// every variable unset (its default where it has one; a session's own variables such as $PATH stay set), with the
// alternatives of ${X:+…} taken, as a shell (a shell in a variable: $SHELL -c) and as python (-m pip): a reason when
// any of these readings installs. $CMD i x stays silent: the line does not show the program. Not for the marks of
// substitutions read apart (the second reader's, substRuns) or a PowerShell assignment ($x = …, its own reading).
func (p *hookParse) varCommand(w []string, depth int) bool {
	if len(w) == 0 || !strings.Contains(w[0], "$") || strings.Contains(w[0], markSubst) || strings.Contains(w[0], markInit) ||
		strings.Contains(w[0], markProc) || len(w) > 1 && (w[1] == "=" || w[1] == "+=") {
		return false
	}
	base := launchBase(w[0])
	var cands [][]string
	unset, alt := expandUnset(w[0], false, 0), expandUnset(w[0], true, 0)
	if launchBase(unset) != base {
		cands = append(cands, append(strings.Fields(unset), w[1:]...))
	}
	if alt != unset && launchBase(alt) != base {
		cands = append(cands, append(strings.Fields(alt), w[1:]...))
	}
	if strings.Contains(base, "$") {
		cands = append(cands, append([]string{"sh"}, w[1:]...))
		if len(w) > 2 && w[1] == "-m" {
			cands = append(cands, append([]string{"python"}, w[1:]...))
		}
	}
	for _, c := range cands {
		if len(c) == 0 {
			continue
		}
		// the Homebrew variables set so far and the line's assignments: ${BREW:-brew} install wget after
		// HOMEBREW_API_DOMAIN=… is brew's (ECO-1-BREW round 3, brewFlush and brewHome)
		q := &hookParse{seen: map[string]bool{}, brewWhy: slices.Clone(p.brewWhy), assigned: maps.Clone(p.assigned)}
		// a target or an unreadable install, not q.hits: an install form with nothing to check (${NPM:-npm} ci,
		// ${PYTHON:-python3} -m venv) is as quiet as npm ci and python3 -m venv (P3-2)
		if q.command(c, depth+1); len(q.targets)+len(q.unread) > 0 {
			p.miss(whyVarCommand + " (" + clip(strings.Join(w, " "), 60) + ")")
			return true
		}
	}
	return false
}

// setVars: variables every session has; $PATH npx … runs a program named by PATH's value, not npx.
var setVars = map[string]bool{"PATH": true, "HOME": true, "PWD": true, "USER": true, "LOGNAME": true, "SHELL": true}

// expandUnset: a word as a shell expands it with every variable unset — $NAME, ${NAME}, $1, $@ … empty, ${X:-w} and
// ${X=w} the word w, ${X:+w} empty, or w when alt (the variable set). setVars and a ${ left open stay as written.
func expandUnset(s string, alt bool, depth int) string {
	if depth > 8 || !strings.Contains(s, "$") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '$' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		switch n := s[i+1]; {
		case n == '{':
			j, open := i+1, 0
			for ; j < len(s); j++ {
				if s[j] == '{' {
					open++
				} else if s[j] == '}' {
					if open--; open == 0 {
						break
					}
				}
			}
			if j >= len(s) {
				b.WriteString(s[i:])
				return b.String()
			}
			if setVars[s[i+2:j]] {
				b.WriteString(s[i : j+1])
			} else {
				b.WriteString(expansionUnset(s[i+2:j], alt, depth))
			}
			i = j
		case n == '_' || isASCIILetter(n):
			j := i + 1
			for j < len(s) && (s[j] == '_' || isASCIILetter(s[j]) || s[j] >= '0' && s[j] <= '9') {
				j++
			}
			if strings.EqualFold(s[i+1:j], "env") && j < len(s) && s[j] == ':' {
				// PowerShell's $env:NAME is one variable (round 7, R2-5)
				for j++; j < len(s) && (s[j] == '_' || isASCIILetter(s[j]) || s[j] >= '0' && s[j] <= '9'); j++ {
				}
			}
			if setVars[s[i+1:j]] {
				b.WriteString(s[i:j])
			}
			i = j - 1
		case n >= '0' && n <= '9' || strings.IndexByte("@*#?$!-", n) >= 0:
			i++
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// expansionUnset: the value of ${inner} with its variable unset (expandUnset).
func expansionUnset(inner string, alt bool, depth int) string {
	if strings.HasPrefix(inner, "#") {
		return "" // ${#X}: a length
	}
	j := 0
	for j < len(inner) && (inner[j] == '_' || isASCIILetter(inner[j]) || j > 0 && inner[j] >= '0' && inner[j] <= '9') {
		j++
	}
	if j == 0 {
		for j < len(inner) && inner[j] >= '0' && inner[j] <= '9' {
			j++
		}
	}
	if j == 0 && len(inner) > 0 && strings.IndexByte("@*?$!-", inner[0]) >= 0 {
		j = 1
	}
	for _, op := range []string{":-", ":=", ":+", "-", "=", "+"} {
		if w, ok := strings.CutPrefix(inner[j:], op); ok {
			if strings.HasSuffix(op, "+") && !alt {
				return ""
			}
			// the shell removes the quotes of the default: ${NPX:-"npx"} runs npx (READER-SHELLS P2-3)
			return expandUnset(unquote(w), alt, depth+1)
		}
	}
	return ""
}

// substFacts: the texts a line's command substitutions could put in place of a mark, read once per line: a name a
// lookup prints (pyenv which python, type -P npm, which -a npx), and what those that print their words (echo npx)
// print. Each is capped at maxPrinted bytes, and every reading of one is charged to e.work (substRuns): a crafted
// line must not make the reading quadratic (P2-4), and past the budget the answer is the reason (R2-3, R4-1).
type substFacts struct {
	texts []string
}

// maxPrinted bounds a printed or looked-up text put in a mark's place: an install command's program word is short.
const maxPrinted = 1 << 10

// lookupWords: a command that prints where a program is (which, where, pyenv which, command -v, type -P).
var lookupWords = map[string]bool{"which": true, "where": true, "whence": true, "whereis": true, "type": true, "-v": true}

func (e *extraParse) substFacts() *substFacts {
	if e.facts != nil {
		return e.facts
	}
	e.facts = &substFacts{}
	add := func(s string) {
		f := strings.Fields(s)
		switch {
		case len(f) == 0:
		default:
			// no count cap: every text is tried, and the e.work budget bounds the readings — a spent budget is the
			// reason (round 9, R4-1); blanks collapsed first, so they cannot push the program past the 1 KiB clip (R2-6)
			e.facts.texts = append(e.facts.texts, clip(strings.Join(f, " "), maxPrinted))
		}
	}
	for _, s := range e.substs {
		for _, sg := range splitShell(s).segs {
			lookup, name := false, ""
			for _, x := range sg.words {
				b := launchBase(strings.ReplaceAll(x, `\`, ""))
				if lookup && !strings.HasPrefix(x, "-") {
					name = b // the program a lookup prints the path of: $(type -P npm) -> npm
				}
				lookup = lookup || lookupWords[b]
			}
			if name != "" {
				add(name)
			}
			if out, ok := printed(sg.words); ok {
				add(out)
			}
		}
	}
	return e.facts
}

// substRuns: a command word whose program name holds a command substitution's mark could run an install: a text one
// of the line's substitutions supplies (a looked-up name or printed words) put in the mark's place gives a command
// that installs. $(pyenv which python) -m pytest reads as python -m pytest (quiet), $(echo npx) -y pkg as npx -y pkg
// (a target). $(xcrun -f clang) x.c names none, and $(npm i x) is read where it stands, not here.
func (e *extraParse) substRuns(w []string) bool {
	f := e.substFacts()
	for _, out := range f.texts {
		c := append(strings.Fields(strings.ReplaceAll(w[0], markSubst, out)), w[1:]...)
		// charged by what it reads: its bytes, and a reading for each command of a printed script (sh -c 'a;a;…'
		// is ~500 commands for its KiB), so the budget bounds the commands read, not only the bytes (round 10, R5-1)
		if e.work -= len(out) + 16 + 512*separators(out); e.work < 0 {
			return true // past the budget the answer is the reason, never silence (round 7, R2-3)
		}
		q := &hookParse{seen: map[string]bool{}}
		if q.command(c, 1); len(q.targets)+len(q.unread) > 0 {
			return true
		}
	}
	return false
}

// runs: the second reader's reading of what runsWhat finds (the scripts the first reader reads, and those it gives a
// reason for, read the POSIX way as fish's always were here), and of a command named by a substitution. True when it
// read the command.
func (e *extraParse) runs(w []string, cmd string, rest []string, depth int, through string) bool {
	if e.apart && !e.literal && strings.Contains(launchBase(w[0]), markSubst) && e.substRuns(w) {
		e.miss(whySubstCommand + " (" + clip(strings.Join(w, " "), 60) + ")")
		return true
	}
	switch how, script, words := runsWhat(cmd, rest); how {
	case runLine, runForeign:
		// fish's, csh's, Invoke-Expression's script, even one read the POSIX way: no POSIX shell expands an argument
		// word's ~ there (HOME-CONFIG-ENV-1 round 5)
		foreign := how == runForeign || foreignShells[cmd] || cmd == "iex" || cmd == "invoke-expression"
		if foreign {
			e.noShell++
		}
		e.line(script, depth+1, through)
		if foreign {
			e.noShell--
		}
	case runWords:
		e.command(words, depth+1, through)
	default:
		return false
	}
	return true
}

// separators: the command separators of a printed text (; | & and new lines), each the start of a command a reading
// reads (substRuns' charge, R5-1).
func separators(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ';', '|', '&', '\n':
			n++
		}
	}
	return n
}

// plainAroundSubexpr: an Invoke-Expression script that holds a $(…) subexpression and, once they are taken out, holds only what reads the same in PowerShell and POSIX (posixSafe), no &
// and no other Invoke-Expression: what it runs is the subexpression's output, as for iex $cmd (R4-4, R5-2).
func plainAroundSubexpr(s string) bool {
	if !strings.Contains(s, "$(") {
		return false
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '$' && i+1 < len(s) && s[i+1] == '(' {
			depth := 0
			j := i + 1
			for ; j < len(s); j++ {
				if s[j] == '(' {
					depth++
				} else if s[j] == ')' {
					if depth--; depth == 0 {
						break
					}
				}
			}
			if j >= len(s) {
				return false // a subexpression left open: not plain
			}
			b.WriteByte(' ')
			i = j
			continue
		}
		b.WriteByte(s[i])
	}
	rest := b.String()
	if !posixSafe(rest) || strings.Contains(rest, "&") {
		return false
	}
	for _, w := range strings.Fields(strings.NewReplacer(";", " ", "|", " ").Replace(rest)) {
		if lw := strings.ToLower(w); lw == "iex" || lw == "invoke-expression" {
			return false
		}
	}
	return true
}
