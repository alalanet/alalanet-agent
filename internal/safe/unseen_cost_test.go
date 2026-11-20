package safe

// The cost of Unseen (ADR-0167 round 6): the scanners of an MCP server's texts and of a repository's
// instruction files call it on every text they read. ASCII only.

import (
	"strings"
	"testing"
	"time"

	"github.com/alalanet/alalanet-agent/internal/costtest"
)

// unseenWorst: the shapes that make Unseen's rules work, besides TextCount's (zzWorst).
func unseenWorst(size int) map[string]string {
	rep := func(unit string) string { return strings.Repeat(unit, size/len(unit)) }
	shy, rlm, alm, acute := string(rune(0x00AD)), string(rune(0x200F)), string(rune(0x061C)), string(rune(0x0301))
	return map[string]string{
		"soft hyphen after each letter":     rep("a" + shy),
		"soft hyphens, two in a row":        rep("ab" + shy + shy),
		"one long word, soft hyphens apart": rep(strings.Repeat("a", 61) + shy),
		"letters with marks, soft hyphen":   rep("a" + acute + acute + acute + shy),
		"directional marks among digits":    rep("1" + rlm + alm + "2"),
		"digits with marks and a mark":      rep("1" + acute + rlm),
		"marks before an Arabic letter":     rep(rlm + acute + acute + string(rune(0x0644))),
		"Mongolian separators":              rep(string(rune(0x1820)) + string(rune(0x180E))),
		"Mongolian before a final a":        rep(string(rune(0x182D)) + string(rune(0x180E)) + string(rune(0x1820)) + " "),
		"joiners between symbols":           rep(string(rune(0x2605)) + string(rune(0x200D))),
		"ZWNJ after f":                      rep("f" + string(rune(0x200C))),
		"invisible operators as bits":       rep(string(rune(0x2062)) + string(rune(0x2064))),
		"later emoji with selectors":        rep(string(rune(0x1FAFA)) + string(rune(0xFE0F)) + string(rune(0x200D))),
		"isolate pairs in Hebrew":           rep(string(rune(0x05D0)) + string(rune(0x2068)) + "a" + string(rune(0x2069))),
		"isolates opened, never closed":     rep(string(rune(0x05D0)) + string(rune(0x2068))),
		"Arabic dates":                      rep(string(rune(0x0627)) + "15" + string(rune(0x200F)) + "/11" + string(rune(0x200F)) + "/2026 "),
		"marks beside signs":                rep(string(rune(0x05D0)) + string(rune(0x200F)) + string(rune(0x200E)) + "-1" + string(rune(0x00A0)) + string(rune(0x200F)) + "$"),
	}
}

// Each shape at 64 KiB, 256 KiB and 1 MiB, the best of five (round 7, R6-COST-1: the best of three at
// 64 KiB and 1 MiB came within a quarter of the limit at a load of 25-40): failed past one second for
// 64 KiB, and when a byte of 1 MiB costs more than twice a byte of 256 KiB plus 20 ms in all (a
// quadratic count costs four times). The shapes of the isolate pairs and the number formats are
// in it (round 7). Logged with TextCount's shapes too (zzWorst), which Unseen runs first. Measured
// without the race detector, as the prober's cost bounds are.
func TestUnseenCost(t *testing.T) {
	if testing.Short() || raceDetector {
		t.Skip("cost bounds are measured without the race detector")
	}
	sizes := []int{64 << 10, 256 << 10, 1 << 20}
	shapes := make([]map[string]string, len(sizes))
	for i, n := range sizes {
		shapes[i] = unseenWorst(n)
		for name, s := range zzWorst(n) {
			shapes[i]["text: "+name] = s
		}
	}
	for name, s := range shapes[0] {
		// The least of five, the three sizes in the same rounds, each its thread's CPU time (costtest, COST-TEST-LOAD-1:
		// at load ~30 make ci measured them one size after the other and found 1 MiB "not linear" five times).
		d, _ := costtest.Best(5, func() { Measure(s) }, func() { Measure(shapes[1][name]) }, func() { Measure(shapes[2][name]) })
		d64, d256, d1m := d[0], d[1], d[2]
		perByte := func(d time.Duration, n int) float64 { return float64(d.Nanoseconds()) / float64(n) }
		t.Logf("%-44s 64 KiB %10v, 256 KiB %10v (%5.1f ns/B), 1 MiB %10v (%5.1f ns/B), %d hidden units", name, d64, d256,
			perByte(d256, len(shapes[1][name])), d1m, perByte(d1m, len(shapes[2][name])), Unseen(s))
		if d64 > time.Second {
			t.Errorf("%s: %v for 64 KiB", name, d64)
		}
		if d1m > 2*4*d256+20*time.Millisecond {
			t.Errorf("%s: 1 MiB %v against 256 KiB %v: not linear", name, d1m, d256)
		}
	}
}

// HonestMarks counts the honest marks in place, and Selectors.Marks bounds them per source.
func TestHonestMarks(t *testing.T) {
	shy, rlm, mvs := string(rune(0x00AD)), string(rune(0x200F)), string(rune(0x180E))
	hebrew := string([]rune{0x05E9, 0x05DC, 0x05D5, 0x05DD})
	for _, c := range []struct {
		name string
		s    string
		want int
	}{
		{"none", "Plain text.", 0},
		{"two soft hyphens inside a word", "Bundes" + shy + "verfassungs" + shy + "gericht", 2},
		{"a soft hyphen at a word's end (misplaced)", "Haus" + shy + " Hof", 0},
		{"an RLM Hebrew needs", hebrew + " " + rlm + "(2)", 1},
		{"an RLM in Latin text (misplaced)", "Run " + rlm + "(2)", 0},
		{"a Mongolian separator before a final a", string([]rune{0x182D}) + mvs + string([]rune{0x1820}), 1},
		{"one in place, one misplaced", "Bundes" + shy + "gericht Haus" + shy + " Hof", 1},
		// Judged as Unseen judges s, its variation selectors aside: the ALM beside the digit (an emoji
		// with VS16) is in place there, and on the raw text it would be neither in place nor misplaced.
		{"an ALM after a digit with its emoji selector", "1" + string(rune(0xFE0F)) + string(rune(0x061C)) + string(rune(0x0644)), 1},
	} {
		if got := HonestMarks(c.s); got != c.want {
			t.Errorf("%s: HonestMarks %d, want %d", c.name, got, c.want)
		}
	}
	var sel Selectors
	word := "Bundes" + shy + "verfassungs" + shy + "gericht" // two in place
	for i, want := range []int{0, 0, 0, 0, 2, 2} {
		if got := sel.Marks(word); got != want {
			t.Errorf("text %d: Marks %d, want %d", i+1, got, want)
		}
	}
	if MaxHonestMarks != 8 {
		t.Errorf("MaxHonestMarks %d", MaxHonestMarks)
	}
}
