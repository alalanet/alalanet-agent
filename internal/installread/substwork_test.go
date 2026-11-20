package installread

import (
	"strings"
	"testing"
)

// lineWork reads a line as ParseLine and SourcedFiles do (hookParse.line) and gives what it cost: the characters the
// tokenizer visited and the bodies it copied, and the bodies' readings (work), and the bytes of bodies walked.
func lineWork(line string) (work, walked int) {
	p := &hookParse{seen: map[string]bool{}}
	p.line(whichSubst.ReplaceAllString(line, "$1$2"), 0)
	return p.work, p.walked
}

// ADR-0159 round 24 (P3-V): the substitution walk's cost, counted, not timed — so the bound runs under -race too, in
// make ci and the pipeline. For lines of about 230 KiB built to cost (round 22's quadratic shapes and more), the work
// is at most workFactor × the line plus (1 + maxSubstDepth) × the bytes of bodies walked, and those are at most
// maxSubstWalk, shared by every nested reading. HookExtra's second reader and the command steps are not counted: their
// wall time is TestReview10SubstCost's log (round 25, P3-W). Round 22's walk scanned each body to its end: its count on these shapes
// is quadratic. The wall time is round 23's TestReview10SubstCost, a log only.
func TestSubstWorkBound(t *testing.T) {
	const workFactor = 10 // the line once, and nested bodies copied up to maxSubstDepth deep
	shapes := map[string]func(n int) string{
		"quoted $( unclosed": func(n int) string { return `echo "` + strings.Repeat("$(", n) + `"; pip install zz-pkg` },
		"quoted $( nested": func(n int) string {
			return `echo "` + strings.Repeat("$(", n) + strings.Repeat(")", n) + `"; pip install zz-pkg`
		},
		"quoted $( flat":      func(n int) string { return `echo "` + strings.Repeat("$(true) ", n/3) + `"; pip install zz-pkg` },
		"backticks quoted":    func(n int) string { return `echo "` + strings.Repeat("`", n) + `"; pip install zz-pkg` },
		"${ with $( unclosed": func(n int) string { return `echo ${X:-` + strings.Repeat("$(", n) + `}; pip install zz-pkg` },
		"${ with $( nested": func(n int) string {
			return `echo ${X:-` + strings.Repeat("$(", n) + strings.Repeat(")", n) + `}; pip install zz-pkg`
		},
		"unquoted $( unclosed": func(n int) string { return `echo ` + strings.Repeat("$(", n) + `; pip install zz-pkg` },
		"quoted ${ nested": func(n int) string {
			return `echo "` + strings.Repeat("${X:-", n/4) + strings.Repeat("}", n/4) + `"; pip install zz-pkg`
		},
		"quoted $( with quotes": func(n int) string { return `echo "` + strings.Repeat("$(echo ')' ", n/8) + `"; pip install zz-pkg` },
		"quoted $( heredocs": func(n int) string {
			return `echo "` + strings.Repeat("$(cat <<E\n)\nE\n", n/8) + `"; pip install zz-pkg`
		},
		"quoted $( depth 8": func(n int) string {
			return `echo "` + strings.Repeat(strings.Repeat("$(echo ", 8)+"x"+strings.Repeat(")", 8)+" ", n/80) + `"; pip install zz-pkg`
		},
		"quoted bodies flat": func(n int) string {
			return `echo "` + strings.Repeat("$(echo "+strings.Repeat("a", n/64)+") ", 64) + `"; pip install zz-pkg`
		},
	}
	for name, shape := range shapes {
		for _, n := range []int{20000, 80000} {
			line := shape(n)
			work, walked := lineWork(line)
			t.Logf("%-22s %4d KiB: work %8d (%.1f× the line), walked %6d", name, len(line)>>10, work,
				float64(work)/float64(len(line)), walked)
			// round 25 (P3-W): the walk's allowance scales with what was walked, not a fixed 640 KiB, so the small sizes
			// tell too: a walked body costs its own characters and copies (1 + maxSubstDepth)
			if limit := workFactor*len(line) + (1+maxSubstDepth)*walked; work > limit {
				t.Errorf("%s, %d KiB: work %d, want at most %d", name, len(line)>>10, work, limit)
			}
			if walked > maxSubstWalk {
				t.Errorf("%s, %d KiB: walked %d bytes of bodies, want at most %d", name, len(line)>>10, walked, maxSubstWalk)
			}
		}
	}
	// nested bodies the walk reads again inside a body (${ … } in a quoted $( … )): one budget for every reading
	line := `echo "$(echo ${X:-$(echo ${Y:-$(echo ` + strings.Repeat("a", 21000) + `)})})"; pip install zz-pkg`
	if _, walked := lineWork(line); walked > maxSubstWalk {
		t.Errorf("nested readings: walked %d bytes of bodies, want at most %d", walked, maxSubstWalk)
	}
}
