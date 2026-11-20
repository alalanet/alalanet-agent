package installread

import (
	"strings"
	"testing"

	"github.com/alalanet/alalanet-agent/internal/costtest"
)

// READER-ESCAPE-1: the unquoting (a backslash dropped before any character, the Windows path put back, the shell's
// words for install_check) stays linear. Each shape is read by both readers, as the hook reads a line, at the full
// size (just under MaxLineBytes, the hook's cap; a sixteenth of that under the race detector) against the same shape at
// a 64th of it read 64 times (costtest.Linear, COST-WALLCLOCK-1): at most costtest.Bound times, which a linear reading
// stays under however loaded the host is (both sides slowed alike) and a quadratic one passes 64-fold. It was a quarter
// of the size read once against twice the size ratio plus 50 ms, which make ci at load ~30 failed.
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
		small, big := shape(full/costtest.Scale), shape(full)
		ratio, tb, ts := costtest.Linear(5, costtest.Scale, read(big), read(small))
		if ratio > costtest.Bound {
			t.Errorf("%s: %d bytes in %v, %d bytes read %d times in %v (x%.1f, bound x%d): not linear", name, len(big), tb, len(small), costtest.Scale, ts, ratio, costtest.Bound)
		}
		t.Logf("%-30s %8d B %10v   %8d B x%d %10v (x%.2f)", name, len(big), tb, len(small), costtest.Scale, ts, ratio)
	}
}
