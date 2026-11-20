package installread

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

// READER-ESCAPE-1: the unquoting (a backslash dropped before any character, the Windows path put back, the shell's
// words for install_check) stays linear. Each shape is read by both readers, as the hook reads a line, at a quarter
// of the size and at the full size (just under MaxLineBytes, the hook's cap; a sixteenth of that under the race detector), and the full
// size may cost at most twice the quarter size's ratio of 4, plus 50 ms for a busy host. The least of five interleaved
// rounds is taken.
func TestReaderEscapeCostLinear(t *testing.T) {
	full := MaxLineBytes - 1024 // just under the hook's cap: a longer line is refused before it is read
	if raceDetector {
		full = 64 << 10
	}
	fill := func(head, unit, tail string, n int) string {
		var b strings.Builder
		b.WriteString(head)
		for b.Len() < n-len(tail) {
			b.WriteString(unit)
		}
		b.WriteString(tail)
		return b.String()
	}
	shapes := map[string]func(n int) string{
		"one word of escapes":         func(n int) string { return fill(`npm i `, `\a`, ``, n) },
		"many escaped words":          func(n int) string { return fill(`npm i `, `\l\e\f\t-\p\a\d `, ``, n) },
		"a Windows path of escapes":   func(n int) string { return fill(`C:\`, `x\`, ` install left-pad`, n) },
		"escaped assignments":         func(n int) string { return fill(``, `\P\A\T\H=./bin `, `npm i x`, n) },
		"quotes and empty quotes":     func(n int) string { return fill(`npm i `, `l''e""f't'"-"pad `, ``, n) },
		"continuations in a word":     func(n int) string { return fill(`npm i left`, "\\\n-", `pad`, n) },
		"an escaped verb, many times": func(n int) string { return fill(``, `npm \i x; `, `true`, n) },
		"a value of escapes":          func(n int) string { return fill(`APPDATA=C:\`, `a\`, ` pip install x`, n) },
	}
	read := func(line string) func() {
		return func() {
			tg, un, _, s := ParseLine(line)
			_ = HookExtra(line, tg, un, s)
		}
	}
	for name, shape := range shapes {
		small, big := shape(full/4), shape(full)
		var ts, tb time.Duration
		for r := 0; r < 5; r++ {
			for i, f := range []func(){read(small), read(big)} {
				runtime.GC()
				start := time.Now()
				f()
				d := time.Since(start)
				if p := &ts; i == 1 {
					p = &tb
					if r == 0 || d < *p {
						*p = d
					}
				} else if r == 0 || d < *p {
					*p = d
				}
			}
		}
		if limit := 2*4*ts + 50*time.Millisecond; tb > limit {
			t.Errorf("%s: %d bytes in %v, %d bytes in %v (limit %v): not linear", name, len(small), ts, len(big), tb, limit)
		}
		t.Logf("%-30s %8d B %10v   %8d B %10v", name, len(small), ts, len(big), tb)
	}
}
