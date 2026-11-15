package safe

// Review of a1-p2-checks on the merge with origin/develop. ASCII only.

import (
	"strings"
	"testing"
	"time"
	"unicode"
)

// UTS #37: an ideographic variation sequence is a unified ideograph followed by one of VS17-VS256;
// the IVD registers only such pairs. Every unified ideograph is Ideographic, so every IVD sequence
// (one per base, up to the bound) is kept by StraySelectors.
func TestA1ReviewIVDBasesAreIdeographic(t *testing.T) {
	bases, missing := 0, 0
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if !unicode.Is(unicode.Unified_Ideograph, r) {
			continue
		}
		bases++
		if !unicode.Is(unicode.Ideographic, r) {
			missing++
			if missing < 5 {
				t.Errorf("U+%04X is a unified ideograph but not Ideographic", r)
			}
			continue
		}
		if r%97 == 0 { // a sample of the 240 selectors per base, every one of them across the bases
			sel := 0xE0100 + (r % 240)
			if n, _ := StraySelectors(string(r) + string(sel)); n != 0 {
				t.Errorf("U+%04X U+%05X: %d stray", r, sel, n)
			}
		}
	}
	t.Logf("%d unified ideographs (Unicode %s), %d not Ideographic", bases, unicode.Version, missing)
}

func TestA1ReviewStraySelectorsThroughput(t *testing.T) {
	for _, c := range []struct{ name, unit string }{
		{"all selectors", "\U0000FE0F"},
		{"emoji runs", "\U0001F600\U0000FE0F\U0000FE0F"},
		{"IVS", "\U0000845B\U000E0100"},
		{"ASCII", "abcd"},
	} {
		s := strings.Repeat(c.unit, (256<<10)/len(c.unit))
		start := time.Now()
		for i := 0; i < 8; i++ {
			StraySelectors(s)
		}
		t.Logf("%-12s 2 MiB in %v", c.name, time.Since(start))
	}
}
