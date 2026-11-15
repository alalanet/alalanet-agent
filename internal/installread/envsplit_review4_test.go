package installread

import "testing"

// Review round 4 of reader-env-opts (d1a2bac), untracked. env passes | & ; ( ) { } < > in a split string through as
// characters of a word; the reader re-reads the value with the shell's rules, where they end a command. GNU env 9.12
// and macOS env run npm (or pip) with zz-review-evil for each line (checked with a stand-in npm); npm takes 1||2 as a
// range and pip takes name(>=1) (PEP 508). The hook must name zz-review-evil or give a reason.
func TestZZReviewR4ShellCharsInSplitString(t *testing.T) {
	for _, line := range []string{
		`env -S 'npm i zz-review-ok@1||2' zz-review-evil`,
		`env -S 'npm i zz-review-ok@1||2 zz-review-evil'`,
		`env -S 'pip install zz-review-ok(>=1)' zz-review-evil`,
		`env -S '-i pip install zz-review-ok(>=1) zz-review-evil'`,
	} {
		tg, un, _, s := ParseLine(line)
		x := HookExtra(line, tg, un, s)
		evil := false
		for _, t := range tg {
			evil = evil || t == "npm:zz-review-evil" || t == "pypi:zz-review-evil"
		}
		if !evil && len(un) == 0 && len(x) == 0 {
			t.Errorf("%q: targets %q, no reason: zz-review-evil is never checked", line, tg)
		}
	}
	// \U takes eight hex digits (bash, zsh): the mutant "four" leaves this silent
	line := "env -S $'\\U0000002di npm i zz-review-evil'"
	if tg, _, _, _ := ParseLine(line); len(tg) != 1 || tg[0] != "npm:zz-review-evil" {
		t.Errorf("%q: targets %q", line, tg)
	}
}
