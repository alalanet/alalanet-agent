package installread

import (
	"strings"
	"testing"
)

// Re-review of READER-SHELLS round 7 (8db039b). Placeholders zz-review-pkg only. The shell behaviour of R3-2 and R3-4
// was checked in golang:1.27.4-bookworm (bash 5.2) with echo in place of the install; fish's grammar from its parser
// (if, while and else if take a job, begin needs no ";" after it).

// R3-1 (P2). stripForeignKeywords drops and, or and not only where a command starts, but fish's if, while and else if
// and its begin are followed by a command too: "if not npm i x" reads as a program named "not" (silent), and so does
// "begin npm i x; end" (a program named "begin").
func TestReaderShellsReview3ForeignKeywordsAfterHeaders(t *testing.T) {
	for _, line := range []string{
		"fish -c 'if not npm i zz-review-pkg; echo failed; end'",
		"fish -c 'while not npm i zz-review-pkg; sleep 1; end'",
		"fish -c 'if true; else if not npm i zz-review-pkg; end; end'",
		"fish -c 'if not npx -y zz-review-pkg; end'",
		"fish -c 'begin npm i zz-review-pkg; end'",
	} {
		if silentOn(line) {
			t.Errorf("%q: silent on an install", line)
		}
	}
	for _, line := range []string{
		"fish -c 'if not test -d node_modules; npm ci; end'",
		"fish -c 'while not curl -sf localhost:3000; sleep 1; end'",
		"fish -c 'begin; npm test; end'",
	} {
		if !silentOn(line) {
			tg, un, _, s := ParseLine(line)
			t.Errorf("%q: asks without an install: unread %q, extra %q", line, un, HookExtra(line, tg, un, s))
		}
	}
}

// R3-2 (P2, new false holds against 7b53831). A lone ${NAME:-…} word whose default has a blank and an "=" (the "run
// $TEST_CMD or this" idiom) is now a program (paramExpansionProgram), and the first reader reads the whole word again
// as a line: the splitter gives it back whole until the depth runs out, "shell wrappers nested too deep to read".
// 7b53831 took these words for assignments and was silent. The same loop already holds on 7b53831 for a default with
// no "=" (${CMD:-make test}); reading the default's value instead of the word ends both.
func TestReaderShellsReview3LoneDefaultNoHold(t *testing.T) {
	for _, line := range []string{
		"${RUN:-make test V=1}",
		"${PYTEST:-pytest --cov=src}",
		"${TEST_CMD:-npm test -- --watch=false}",
		"${BUILD_CMD:-make build GOOS=linux}",
		"${LINT:-golangci-lint run --timeout=5m}",
		"cd app && ${TEST_CMD:-go test ./... -run=TestX}",
		"set -e\n${TEST:-npm test -- --ci=true}\n",
		"sh -c '${RUN:-make test V=1}'",
	} {
		if !silentOn(line) {
			tg, un, _, s := ParseLine(line)
			t.Errorf("%q: asks without an install: unread %q, extra %q", line, un, HookExtra(line, tg, un, s))
		}
	}
	for _, line := range []string{"${X:-npm i zz-review-pkg --save=true}", "${X:=npx -y zz-review-pkg --a=1}"} {
		if silentOn(line) {
			t.Errorf("%q: silent on an install", line)
		}
	}
}

// R3-3 (P3, silent against ea5eef1; silent on 7b53831). defaultShape knows :=, =, :- and - but not :+ and +, which
// paramDefault and expandUnset read (${X:+npx} -y pkg is whyVarCommand): with an "=" in the alternate value the word is
// taken for an assignment and skipped. bash: X=1; ${X:+echo --a=1} hi runs echo.
func TestReaderShellsReview3AlternateWithEquals(t *testing.T) {
	for _, line := range []string{
		"${X:+npm --zz=1} i zz-review-pkg",
		"${X+npm --zz=1} i zz-review-pkg",
	} {
		if silentOn(line) {
			t.Errorf("%q: silent on an install", line)
		}
	}
}

// R3-4 (P3, the "equivalent" mutant is not). paramExpansionProgram by the outermost brace instead of the innermost
// survives the suite, yet it differs: ${A:+${B:=npm}} expands to npm when A is set (bash: A=1; ${A:+${B:=echo}} hi runs
// echo). The innermost brace (the code) gives the reason; the outermost takes the word for an assignment: silent.
func TestReaderShellsReview3InnermostBrace(t *testing.T) {
	for _, line := range []string{
		"${A:+${B:=npm}} i zz-review-pkg",
		"${A:+${B=npm}} i zz-review-pkg",
	} {
		if silentOn(line) {
			t.Errorf("%q: silent on an install", line)
		}
	}
}

// R3-5 (P2, the rule of R2-3). substFacts keeps eight printed texts: a ninth, dropped for the count, is silence, not
// a reason. Eight harmless $(echo …) before $(echo npx) -y pkg make it silent; alone it gives the reason. A fix must not
// make honest lines with many printed texts ask: the second half stays quiet.
func TestReaderShellsReview3PrintedTextCount(t *testing.T) {
	pad := ""
	for i := 0; i < 8; i++ {
		pad += "echo $(echo zz" + string(rune('a'+i)) + "); "
	}
	if line := pad + "$(echo npx) -y zz-review-pkg"; silentOn(line) {
		t.Errorf("%q: silent on an install", line)
	}
	for _, line := range []string{
		pad + "$(which python3) -m pytest",
		pad + strings.Repeat("$(command -v node) --version; ", 3),
	} {
		if !silentOn(line) {
			tg, un, _, s := ParseLine(line)
			t.Errorf("%q: asks without an install: unread %q, extra %q", line, un, HookExtra(line, tg, un, s))
		}
	}
}
