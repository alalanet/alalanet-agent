package installread

import "testing"

// Re-review of READER-SHELLS round 8 (1ddfec2). Placeholders zz-review-pkg only. R4-2's shell behaviour was checked in
// golang:1.27.4-bookworm (bash 5.2) with echo in place of the install.

// R4-1 (P2, the rule of R2-3 and R3-5). launchDropped looks at a dropped text's own first word, but a mark inside a
// program word joins the text to the letters around it: n$(echo p)m runs npm. Eight harmless $(echo …) before
// n$(echo p)m i pkg make it silent; alone it gives the reason. Honest marked words past the cap must stay quiet.
func TestReaderShellsReview4DroppedFragment(t *testing.T) {
	pad := ""
	for i := 0; i < 8; i++ {
		pad += "echo $(echo zz" + string(rune('a'+i)) + "); "
	}
	for _, line := range []string{
		pad + "n$(echo p)m i zz-review-pkg",
		pad + "$(echo np)x -y zz-review-pkg",
	} {
		if silentOn(line) {
			t.Errorf("%q: silent on an install", line)
		}
	}
	for _, line := range []string{
		pad + "./bin/tool-$(echo x) run",
		pad + "$(echo zzi)/bin/x --version",
	} {
		if !silentOn(line) {
			tg, un, _, s := ParseLine(line)
			t.Errorf("%q: asks without an install: unread %q, extra %q", line, un, HookExtra(line, tg, un, s))
		}
	}
}

// R4-2 (P3, the mutant is still not equivalent after :+). paramExpansionProgram by the outermost brace takes
// ${A/x/${B:=npm} i pkg} and ${A%${B:=npm} i pkg} for assignments (A/x/ and A% are no default shape) and is silent; the
// innermost brace gives a reason. bash: A=x; ${A/x/${B:=echo} hi} runs echo.
func TestReaderShellsReview4OuterOperatorNotEquivalent(t *testing.T) {
	for _, line := range []string{
		"${A/x/${B:=npm} i zz-review-pkg}",
		"${A%${B:=npm} i zz-review-pkg}",
	} {
		if silentOn(line) {
			t.Errorf("%q: silent on an install", line)
		}
	}
}

// R4-3 (P3). fish's time is a keyword that takes a job: time not npm i x runs npm, but stripForeignKeywords keeps
// start false after time, so not reaches the POSIX reading as a program.
func TestReaderShellsReview4FishTimeNot(t *testing.T) {
	if line := "fish -c 'time not npm i zz-review-pkg'"; silentOn(line) {
		t.Errorf("%q: silent on an install", line)
	}
}

// R4-4 (P3). iex of a local file's text asks, while eval "$(cat x.sh)" and iex (Get-Content x.ps1 -Raw) are quiet.
func TestReaderShellsReview4IexLocalFileQuiet(t *testing.T) {
	for _, line := range []string{
		`iex "$(Get-Content x.ps1)"`,
		"iex (Get-Content x.ps1 -Raw)",
		`eval "$(cat x.sh)"`,
	} {
		if !silentOn(line) {
			tg, un, _, s := ParseLine(line)
			t.Errorf("%q: asks without an install shown: unread %q, extra %q", line, un, HookExtra(line, tg, un, s))
		}
	}
}
