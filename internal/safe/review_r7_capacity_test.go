package safe

// Review of ADR-0167 round 7 (kept proof): the covert-channel capacity the per-source bound leaves in
// honest-looking right-to-left text (Q1), that LRM/RLM/ALM are not decoded into model-readable bytes,
// and that a lone CR still counts (Q3). ASCII only.

import (
	"math"
	"testing"
)

func hebrewWords(n int, place func(i int) rune) string {
	word := []rune{0x05D0, 0x05DC, 0x05D5, 0x05DD}
	rs := []rune{}
	for i := 0; i < n; i++ {
		if i > 0 {
			rs = append(rs, ' ')
			if m := place(i); m != 0 {
				rs = append(rs, m)
			}
		}
		rs = append(rs, word...)
	}
	return string(rs)
}

// The bound is the channel: within it, directional marks pass with zero hidden units, and the bound
// grows with the right-to-left letters a person sees. 640 RTL letters (about 160 words, a few
// sentences) already carry ~20 bytes with no flag; this matches the rate ADR round 7 discloses.
func TestReviewR7Capacity(t *testing.T) {
	for _, words := range []int{160, 400} {
		rtl := words * 4
		bound := MaxHonestMarks + rtl/RTLLettersPerMark
		gaps := words - 1
		s := hebrewWords(words, func(i int) rune {
			if i <= bound {
				return 0x200F
			}
			return 0
		})
		c := Measure(s)
		var sel Selectors
		_, units := sel.Judge(s)
		bits := lchoose(gaps, bound) + float64(bound)*math.Log2(3)
		t.Logf("%d words (%d RTL letters): bound %d, Directional %d, units %d; channel ~%.0f bits = %.1f bytes, 0 units",
			words, rtl, bound, c.Directional, units, bits, bits/8)
		if units != 0 {
			t.Errorf("%d words: %d units within the bound, want 0", words, units)
		}
	}
}

func lchoose(n, k int) float64 {
	if k < 0 || k > n {
		return 0
	}
	l := 0.0
	for i := 0; i < k; i++ {
		l += math.Log2(float64(n-i)) - math.Log2(float64(i+1))
	}
	return l
}

// LRM/RLM/ALM are format controls, not an encoding Hidden decodes: a run spells nothing, so the
// directional channel cannot carry a prompt injection the way tag characters or variation selectors
// do. If this ever changes the risk changes, and this test fails.
func TestReviewR7MarksNotDecoded(t *testing.T) {
	marks := string([]rune{0x200F, 0x200E, 0x061C, 0x200F, 0x200E, 0x061C, 0x200F, 0x200E})
	if h := Hidden("word " + marks + " word"); h != "" {
		t.Errorf("Hidden decoded directional marks into %q; they must spell nothing", h)
	}
}

// Q3: a lone CR (a classic-Mac line end) still counts as a hidden unit, unlike CRLF. Two of them flag.
// A plan row only (recommendation): fold a bare CR to a line feed as CRLF is folded.
func TestReviewR7LoneCR(t *testing.T) {
	if Unseen("a\r\nb") != 0 {
		t.Errorf("CRLF counted")
	}
	if Unseen("a\rb\rc") != 2 {
		t.Errorf("two lone CRs: want 2, got %d", Unseen("a\rb\rc"))
	}
}
