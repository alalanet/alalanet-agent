package safe

// Independent review of a1-p2-checks (0916145), A1-VS-1, adopted byte for byte in round 2 (names
// without zz; lines marked "round 2" assert what the review logged). ASCII only: every non-ASCII rune is an
// 8-digit escape or computed. Payloads are neutral bytes, never instructions.

import (
	"bufio"
	"math/rand"
	"os"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

const a1rPayload = "neutral-review-bytes-0123456789" // 31 bytes, nothing a model would act on

// Honest text from Unicode's own data and common writing: no stray selector.
func TestA1ReviewHonestSequences(t *testing.T) {
	for _, c := range []struct{ name, in string }{
		{"health worker (ZWJ + VS16 after a sign)", "\U0001F469\U0000200D\U00002695\U0000FE0F"},
		{"pirate flag", "\U0001F3F4\U0000200D\U00002620\U0000FE0F"},
		{"transgender flag", "\U0001F3F3\U0000FE0F\U0000200D\U000026A7\U0000FE0F"},
		{"heart on fire", "\U00002764\U0000FE0F\U0000200D\U0001F525"},
		{"detective, woman, skin tone", "\U0001F575\U0001F3FD\U0000200D\U00002640\U0000FE0F"},
		{"detective, woman, VS16 then ZWJ", "\U0001F575\U0000FE0F\U0000200D\U00002640\U0000FE0F"},
		{"England flag (tag sequence)", "\U0001F3F4\U000E0067\U000E0062\U000E0065\U000E006E\U000E0067\U000E007F"},
		{"Japan flag (regional indicators)", "\U0001F1EF\U0001F1F5"},
		{"all twelve keycaps", "#\U0000FE0F\U000020E3*\U0000FE0F\U000020E30\U0000FE0F\U000020E31\U0000FE0F\U000020E39\U0000FE0F\U000020E3"},
		{"text-style keycap", "1\U0000FE0E\U000020E3"},
		{"victory hand, VS16 then skin tone (keyboards)", "\U0000270C\U0000FE0F\U0001F3FD"},
		{"text presentation of telephone and envelope", "\U0000260E\U0000FE0E \U00002709\U0000FE0E"},
		{"emoji that need no VS, with VS16 anyway", "\U0001F389\U0000FE0F\U0001F680\U0000FE0F"},
		{"trade mark, info, double exclamation", "\U00002122\U0000FE0F \U00002139\U0000FE0F \U0000203C\U0000FE0F"},
		{"IVD Adobe-Japan1 / Hanyo-Denshi style", "\U0000908A\U000E0100\U00008FBB\U000E0101\U0000845B\U000E0102"},
		{"CJK compatibility SVS (StandardizedVariants)", "\U00008C48\U0000FE00\U000066F4\U0000FE00"},
		{"Mongolian word with FVS1 and FVS2 inside", "\U00001820\U0000180B\U00001828\U00001822\U0000180C\U00001833"},
		{"Myanmar dotted form", "\U00001000\U0000FE00"},
		{"Egyptian hieroglyph rotated", "\U00013000\U0000FE03"},
		{"math variant: not equal with stroke", "\U00002268\U0000FE00"},
		{"slashed zero", "0\U0000FE00"},
		{"quotation mark, non-fullwidth form", "\U0000201C\U0000FE00x\U0000201D\U0000FE00"},
		{"fullwidth comma, centred", "\U0000FF0C\U0000FE01"},
	} {
		if n, first := StraySelectors(c.in); n != 0 {
			t.Errorf("%s: %d stray, the first at %d (%+q)", c.name, n, first, c.in)
		}
	}
}

// What honest editing leaves behind, and how StraySelectors judges it (logged, not asserted as
// right or wrong: a hold, not a block, is the policy for these).
func TestA1ReviewEditingLeftovers(t *testing.T) {
	for _, c := range []struct{ name, in string }{
		{"orphan VS16 after a space (emoji deleted, selector left)", "Done \U0000FE0F next"},
		{"VS16 doubled by two emoji converters", "\U00002764\U0000FE0F\U0000FE0F"},
		{"VS16 after a check mark that is no emoji (U+2713)", "\U00002713\U0000FE0F done"},
		{"VS16 after a black star that is no emoji (U+2605)", "\U00002605\U0000FE0F"},
		{"VS16 after a right arrow that is no emoji (U+2192)", "a \U00002192\U0000FE0F b"},
		{"VS16 after a skin tone modifier", "\U0001F44D\U0001F3FD\U0000FE0F"},
		{"VS16 after a keycap's enclosing mark", "1\U000020E3\U0000FE0F"},
		{"space between warning sign and VS16", "\U000026A0 \U0000FE0F Warning"},
	} {
		n, first := StraySelectors(c.in)
		t.Logf("%-58s stray=%d first=%d", c.name, n, first)
		if n > 1 { // round 2: an editing leftover is one stray selector at most
			t.Errorf("%s: %d stray", c.name, n)
		}
	}
}

// Selector encodings the rule must hold, wherever the run stands.
func TestA1ReviewHeldEncodings(t *testing.T) {
	run := func(b []byte) string { // one selector per byte, the published encoding
		var s strings.Builder
		for _, c := range b {
			if c < 16 {
				s.WriteRune(0xFE00 + rune(c))
			} else {
				s.WriteRune(0xE0100 + rune(c) - 16)
			}
		}
		return s.String()
	}
	p := []byte(a1rPayload)
	for _, c := range []struct {
		name string
		in   string
		min  int
	}{
		{"after an emoji", "\U0001F600" + run(p), len(p)},
		{"after a keycap base", "#" + run(p), len(p)},
		{"after an ideograph", "\U00006F22" + run(p), len(p) - 1},
		{"after ZWJ", "\U0001F600\U0000200D" + run(p), len(p)},
		{"after a tag run", "\U0001F3F4\U000E0067\U000E007F" + run(p), len(p)},
		{"after a combining acute", "e\U00000301" + run(p), len(p)},
		{"after the BOM", "\U0000FEFF" + run(p), len(p)},
		{"after an invalid byte", "\xff" + run(p), len(p)},
		{"after a regional indicator", "\U0001F1EF" + run(p), len(p)},
		{"after a skin tone", "\U0001F44D\U0001F3FD" + run(p), len(p)},
		{"one per Latin letter", strings.Join(strings.Split("abcdefghij", ""), "\U0000FE00"), 9},
		{"one VS17+ per Hangul syllable", "\U0000AC00\U000E0100\U0000AC01\U000E0101\U0000AC02\U000E0102", 3},
		{"one VS17+ per kana", "\U00003042\U000E0100\U00003044\U000E0101", 2},
		{"VS8-VS14 after emoji, one each", "\U00002764\U0000FE07\U00002764\U0000FE0D", 2},
		{"FVS after a Latin letter", "a\U0000180B", 1},
		{"FVS4 after a Mongolian digit", "\U00001810\U0000180F", 1},
	} {
		if n, _ := StraySelectors(c.in); n < c.min {
			t.Errorf("%s: %d stray, want at least %d", c.name, n, c.min)
		}
	}
}

// The selectors the rule keeps (one per fitting base, eight ideographic ones) still form a channel:
// capacity per visible carrier, measured with a neutral payload (no stray selector). ADR-0167 names the
// ideograph and emoji channels; the quotation marks and the keycap bases (# * 0-9) carry the same in
// ordinary English Markdown.
func TestA1ReviewResidualCapacity(t *testing.T) {
	bits := func(b []byte, width int) []int { // payload as base-2^width digits
		var out []int
		for _, c := range b {
			for sh := 8 - width; sh >= 0; sh -= width {
				out = append(out, int(c>>uint(sh))&(1<<uint(width)-1))
			}
		}
		return out
	}
	p := []byte(a1rPayload)
	// 2 bits per ideograph: none, VS1, VS2, VS3.
	{
		var s strings.Builder
		for i, d := range bits(p, 2) {
			s.WriteRune(0x4E00 + rune(i%500))
			if d > 0 {
				s.WriteRune(0xFE00 + rune(d-1))
			}
		}
		n, _ := StraySelectors(s.String())
		out, changed := Text(s.String())
		t.Logf("ideographs, 2 bits each: %d carriers for %d bytes, stray=%d, Text changes it=%v (kept as is: %v)", len(bits(p, 2)), len(p), n, changed, out == s.String())
		if n != 0 {
			t.Errorf("expected the documented residual channel, got %d stray", n)
		}
	}
	// 2 bits per curly quote: none, VS1, VS2, VS3.
	{
		var s strings.Builder
		for _, d := range bits(p, 2) {
			s.WriteString("say \U0000201C")
			if d > 0 {
				s.WriteRune(0xFE00 + rune(d-1))
			}
			s.WriteString("x\U0000201D ")
		}
		n, _ := StraySelectors(s.String())
		t.Logf("curly quotes, 2 bits each (not named in ADR-0167): stray=%d", n)
	}
	// 1 bit per keycap base (# * 0-9) with VS15 or VS16, no U+20E3 after it.
	{
		var s strings.Builder
		for i, d := range bits(p, 1) {
			s.WriteString([]string{"#", "*", "1", "2"}[i%4])
			s.WriteRune(0xFE0E + rune(d))
			s.WriteByte(' ')
		}
		n, _ := StraySelectors(s.String())
		t.Logf("keycap bases in Markdown, 1 bit each (not named in ADR-0167): stray=%d", n)
	}
	// 8 bits per ideograph, eight per text.
	{
		var s strings.Builder
		for i := 0; i < 8; i++ {
			s.WriteRune(0x4E00 + rune(i))
			s.WriteRune(0xE0100 + rune(p[i]))
		}
		n, _ := StraySelectors(s.String())
		t.Logf("eight ideographic selectors, 8 bytes per text: stray=%d", n)
	}
}

// Differential: on text without the characters Text drops wherever they stand, StraySelectors counts
// exactly the BMP selectors Text's joined removes (same rule, same tables), and VS17+ past the bound.
func TestA1ReviewStrayMatchesText(t *testing.T) {
	alphabet := []rune{'a', 'f', '#', '1', '0', ' ', '\n', 0x2764, 0x1F600, 0x26A0, 0x1F3FD, 0x200D, 0x20E3, 0x0301,
		0x4E00, 0x845B, 0x1820, 0x1828, 0x1000, 0x13000, 0x201C, 0xFF0C, 0x2268, 0x3042,
		0xFE00, 0xFE01, 0xFE02, 0xFE03, 0xFE07, 0xFE0E, 0xFE0F, 0x180B, 0x180C, 0x180D, 0x180F}
	rng := rand.New(rand.NewSource(1114))
	bmp := func(s string) int {
		n := 0
		for _, r := range s {
			if selector(r) {
				n++
			}
		}
		return n
	}
	joiners := func(s string) int { return strings.Count(s, "\U0000200D") }
	stricter := 0
	for i := 0; i < 200000; i++ {
		var b strings.Builder
		for j := rng.Intn(12); j >= 0; j-- {
			b.WriteRune(alphabet[rng.Intn(len(alphabet))])
		}
		s := b.String()
		out, _ := Text(s)
		n, first := StraySelectors(s)
		want := bmp(s) - bmp(out)
		switch {
		case n < want:
			t.Fatalf("%+q: StraySelectors %d < Text's %d: a selector Text drops is not counted", s, n, want)
		case n > want:
			// Text judges a selector by the last character it kept: after a dropped joiner or a dropped
			// run it keeps one that fits the base before them; StraySelectors judges the raw neighbour.
			stricter++
			if joiners(out) == joiners(s) && stricter <= 3 {
				t.Logf("stricter without a dropped joiner: %+q (%d vs %d)", s, n, want)
			}
		}
		if (n > 0) != (first >= 0) || first >= len(s) || (first >= 0 && !utf8.RuneStart(s[first])) {
			t.Fatalf("%+q: first %d", s, first)
		}
	}
	t.Logf("StraySelectors stricter than Text (a dropped joiner before the selector): %d of 200000", stricter)
}

// Honest corpus: every file listed in A1_CORPUS (one path a line). Logs each file with a stray
// selector, escaped, with its line.
func TestA1ReviewCorpus(t *testing.T) {
	list := os.Getenv("A1_CORPUS")
	if list == "" {
		t.Skip("A1_CORPUS not set")
	}
	f, err := os.Open(list)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	files, withSel, hits := 0, 0, 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		b, err := os.ReadFile(sc.Text())
		if err != nil || len(b) > 400<<10 {
			continue
		}
		files++
		s := string(b)
		any := false
		for _, r := range s {
			if selector(r) || (r >= 0xE0100 && r <= 0xE01EF) {
				any = true
				break
			}
		}
		if any {
			withSel++
		}
		if n, first := StraySelectors(s); n > 0 {
			hits++
			lo, hi := max(0, first-24), min(len(s), first+24)
			for lo > 0 && !utf8.RuneStart(s[lo]) {
				lo--
			}
			for hi < len(s) && !utf8.RuneStart(s[hi]) {
				hi++
			}
			t.Logf("HIT %s: %d stray, line %d: %+q", sc.Text(), n, 1+strings.Count(s[:first], "\n"), s[lo:hi])
		}
	}
	t.Logf("corpus: %d files read, %d with any selector, %d with a stray one", files, withSel, hits)
	_ = unicode.Version
}
