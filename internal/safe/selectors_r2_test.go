package safe

import (
	"strings"
	"testing"
)

// A1-VS-1 round 2 (P3-1): the ideographic bound is the source's. Eight ideographic selectors in one
// text and a ninth in the next make the ninth stray, wherever the texts break; a stray one does not
// count toward the bound (P3-5, R3), and StraySelectors is one source of one text.
func TestSelectorsShareTheBound(t *testing.T) {
	place := "\U0000845B\U000E0100\U000098FE" // Katsushika, with the ideographic variant of its first ideograph
	var c Selectors
	if n, first := c.Stray(strings.Repeat(place, 8)); n != 0 || first != -1 {
		t.Fatalf("eight in the first text: %d stray, the first at %d", n, first)
	}
	if n, first := c.Stray("\U00008FBB\U000E0100 and \U00008FBB\U000E0101"); n != 2 || first != len("\U00008FBB") {
		t.Errorf("the ninth and tenth in the next text: %d stray, the first at %d", n, first)
	}
	if n, _ := c.Stray("\U00002764\U0000FE0F \U00008279\U0000FE00"); n != 0 {
		t.Errorf("selectors of the BMP do not count toward the ideographic bound: %d stray", n)
	}
	var fresh Selectors
	if n, _ := fresh.Stray(place); n != 0 {
		t.Errorf("another source starts at zero: %d stray", n)
	}
	// A stray VS17 (after a Latin letter) before eight valid ones: one stray, not two (R3).
	if n, first := StraySelectors("a\U000E0100" + strings.Repeat(place, 8)); n != 1 || first != 1 {
		t.Errorf("a stray VS17 before eight valid ones: %d stray, the first at %d", n, first)
	}
	if n, _ := StraySelectors(strings.Repeat(place, 8)); n != 0 {
		t.Errorf("StraySelectors keeps no count between calls: %d stray", n)
	}
}

// P3-5 (R1, R2): an ideographic variation selector selects a glyph only after an ideograph. The Han
// radicals and strokes, the iteration mark U+3005 and the letters of the scripts that take VS1-VS3
// (Myanmar, Phags-pa, Manichaean, Egyptian hieroglyphs) are no ideographs.
func TestIdeographicSelectorsOnlyAfterIdeographs(t *testing.T) {
	for name, base := range map[string]rune{
		"a Kangxi radical (U+2F00)":        0x2F00,
		"a CJK radical (U+2E80)":           0x2E80,
		"a CJK stroke (U+31C0)":            0x31C0,
		"the iteration mark (U+3005)":      0x3005,
		"a Myanmar letter (U+1000)":        0x1000,
		"a Phags-pa letter (U+A840)":       0xA840,
		"a Manichaean letter (U+10AC0)":    0x10AC0,
		"an Egyptian hieroglyph (U+13000)": 0x13000,
		"a hiragana letter (U+3042)":       0x3042,
	} {
		if n, first := StraySelectors(string(base) + "\U000E0100"); n != 1 || first != len(string(base)) {
			t.Errorf("%s + VS17: %d stray, the first at %d", name, n, first)
		}
	}
	for name, base := range map[string]rune{
		"a unified ideograph (U+4E00)":          0x4E00,
		"a compatibility ideograph (U+F900)":    0xF900,
		"the ideographic number zero (U+3007)":  0x3007,
		"an ideograph of extension B (U+20000)": 0x20000,
	} {
		if n, _ := StraySelectors(string(base) + "\U000E0100"); n != 0 {
			t.Errorf("%s + VS17: %d stray", name, n)
		}
	}
}
