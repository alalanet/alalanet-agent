package installread

import (
	"strings"
	"testing"
)

// Re-review of READER-SHELLS round 6 (ea5eef1). Placeholders zz-review-pkg only; the shell behaviour of R2-2 was
// checked in golang:1.27.4-bookworm (bash 5.2, dash) with echo in place of the install.

// R2-1 (P2). posixSafe reads a fish or tcsh script with no special character as a POSIX line, but fish's and, or and
// not and tcsh's repeat N run the command that follows: read as POSIX they are programs named "and", "not", "repeat".
// Round 5 gave a reason here (a foreign script with an unread command); round 6 is silent.
func TestReaderShellsReview2ForeignKeywords(t *testing.T) {
	for _, line := range []string{
		"fish -c 'true; and npm i zz-review-pkg'",
		"fish -c 'cd app; and npm i zz-review-pkg'",
		"fish -c 'false; or npm i zz-review-pkg'",
		"fish -c 'not npm i zz-review-pkg'",
		"echo 'true; and npm i zz-review-pkg' | fish",
		"tcsh -c 'repeat 1 npm i zz-review-pkg'",
	} {
		if silentOn(line) {
			t.Errorf("%q: silent on an install", line)
		}
	}
}

// R2-2 (P2). bash and dash end their options at a lone "-" after -c as at "--": bash -c - 'cmd' runs cmd.
// scriptAfterC takes the lone "-" for the command_string.
func TestReaderShellsReview2LoneDashAfterC(t *testing.T) {
	for _, line := range []string{
		"bash -c - 'npm i zz-review-pkg'",
		"dash -c - 'npx -y zz-review-pkg'",
		"sh -c -e - 'npm i zz-review-pkg'",
	} {
		if silentOn(line) {
			t.Errorf("%q: silent on an install", line)
		}
	}
}

// R2-3 (P2). substRuns returns false once e.work is spent: a line that first spends the budget on commands named by
// a mark (seven 1 KB printed texts, 150 commands) then runs $(echo npx) -y pkg is silent. Elsewhere a spent budget is a
// reason (tooLong), never silence: past the budget the answer must be the reason.
func TestReaderShellsReview2SpentBudgetAsks(t *testing.T) {
	pad := ""
	for i := 0; i < 7; i++ {
		pad += "$(echo " + strings.Repeat(string(rune('a'+i)), 1000) + "); "
	}
	for _, k := range []int{150, 400} {
		line := pad + strings.Repeat("$(:) --version; ", k) + "$(echo npx) -y zz-review-pkg"
		if silentOn(line) {
			t.Errorf("%d commands before the install (%d bytes): silent on an install", k, len(line))
		}
	}
}

// R2-4 (P3, a regression against 7b53831). paramExpansionProgram takes a GitHub Actions expression with == inside
// ${{ … }} for a program named by a parameter expansion; read again as a line it comes back whole until the depth runs
// out: "shell wrappers nested too deep to read". The eighth review's corpus fixed this shape in the second reader;
// 7b53831 is silent on these lines.
func TestReaderShellsReview2ActionsExpressionNoReason(t *testing.T) {
	for _, line := range []string{
		"${{ matrix.os == 'windows-latest' && '--test-concurrency=1' || '' }}",
		"${{ github.event_name == 'merge_group' && '--retry' || '' }}",
		"cargo build\n${{ github.event_name == 'merge_group' && '--retry' || '' }}\nnpm ci",
	} {
		if !silentOn(line) {
			tg, un, _, s := ParseLine(line)
			t.Errorf("%q: asks without an install: targets %q, unread %q, extra %q", line, tg, un, HookExtra(line, tg, un, s))
		}
	}
}

// R2-5 (P3). iex $cmd is silent as eval "$X" is (round 6), but iex $env:CMD asks: showsCommand expands $env as an
// unset variable and keeps ":CMD", a program the line seems to spell.
func TestReaderShellsReview2IexEnvVariable(t *testing.T) {
	for _, line := range []string{"iex $env:CMD", `iex "$env:CMD"`, "Invoke-Expression $env:ZZ_SCRIPT"} {
		if !silentOn(line) {
			tg, un, _, s := ParseLine(line)
			t.Errorf("%q: asks without an install shown: unread %q, extra %q", line, un, HookExtra(line, tg, un, s))
		}
	}
}

// R2-6 (P3). The 1 KiB cap clips a printed text from its start: blanks before the program push it past the cap, and
// $(echo "<blanks>npx") -y pkg runs npx -y pkg silently. Collapse blanks (strings.Fields) before clipping.
func TestReaderShellsReview2PrintedTextBlanks(t *testing.T) {
	line := `$(echo "` + strings.Repeat(" ", 1100) + `npx") -y zz-review-pkg`
	if silentOn(line) {
		t.Errorf("printed text with %d leading blanks: silent on an install", 1100)
	}
}
