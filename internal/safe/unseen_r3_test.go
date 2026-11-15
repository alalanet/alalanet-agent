package safe

import (
	"math/rand"
	"strings"
	"testing"
	"unicode"
)

// sparseRound2 is Sparse as round 2 left it (an early return at the first mark out of place): the
// oracle of the counting core round 3 put under it (misplacedMarks).
func sparseRound2(s string) bool {
	rs := []rune(s)
	honest := func(i int) bool {
		switch r := rs[i]; {
		case r == 0x200E, r == 0x200F, r == 0x061C, r == 0x00AD, r == 0x180E:
			return true
		case r >= 0xE0100 && r <= 0xE01EF:
			return i > 0 && unicode.Is(unicode.Ideographic, rs[i-1])
		}
		return false
	}
	// segment counts the letters from rs[i] on, one way, to the word's edge or a soft hyphen, and says
	// whether a soft hyphen ended it.
	segment := func(i, step int) (n int, shy bool) {
		for ; i >= 0 && i < len(rs) && (unicode.IsLetter(rs[i]) || unicode.IsMark(rs[i])); i += step {
			if unicode.IsLetter(rs[i]) {
				n++
			}
		}
		return n, i >= 0 && i < len(rs) && rs[i] == 0x00AD
	}
	syllable := func(n int, shy bool) bool { return n >= 2 || shy && n >= 1 } // two letters at a word's edge, one inside
	mongolian := func(i int) bool {
		return i >= 0 && i < len(rs) && unicode.IsLetter(rs[i]) && unicode.Is(unicode.Mongolian, rs[i])
	}
	rtl, ivs, ideographs := false, 0, 0
	for i, r := range rs {
		switch {
		case i > 0 && honest(i) && honest(i-1):
			return false
		case r == 0x00AD && (!syllable(segment(i-1, -1)) || !syllable(segment(i+1, 1))):
			return false
		case r == 0x180E && !(mongolian(i-1) && i+1 < len(rs) && (rs[i+1] == 0x1820 || rs[i+1] == 0x1821) && !mongolian(i+2)):
			return false
		case r >= 0xE0100 && r <= 0xE01EF:
			ivs++
		case unicode.Is(unicode.Ideographic, r):
			ideographs++
		}
		rtl = rtl || unicode.IsLetter(r) && rightToLeft(r)
	}
	if ivs > min(ideographs, MaxIdeographicSelectors) {
		return false
	}
	// The directional marks, run by run of characters that are no letters (nor their marks).
	dir := func(r rune) int {
		if rightToLeft(r) {
			return 2
		}
		return 1
	}
	last := 0 // the direction of the last letter before the run; 0 at the text's start
	for i := 0; i < len(rs); {
		if unicode.IsLetter(rs[i]) || unicode.IsMark(rs[i]) {
			if unicode.IsLetter(rs[i]) {
				last = dir(rs[i])
			}
			i++
			continue
		}
		j, marks, others, edge := i, 0, 0, i == 0
		firstMark, lastMark, firstDigit, lastDigit := -1, -1, -1, -1
		for ; j < len(rs) && !unicode.IsLetter(rs[j]) && !unicode.IsMark(rs[j]); j++ {
			switch r := rs[j]; {
			case r == 0x200E, r == 0x200F, r == 0x061C:
				if marks++; firstMark < 0 {
					firstMark = j
				}
				lastMark = j
				continue
			case unicode.IsNumber(r):
				if firstDigit < 0 {
					firstDigit = j
				}
				lastDigit = j
			case r == '\n':
				edge = true
			}
			others++
		}
		digit := firstDigit >= 0
		wrapped := marks == 2 && digit && firstMark < firstDigit && lastMark > lastDigit // a number set off on both sides
		next := 0
		for k := j; k < len(rs); k++ {
			if unicode.IsLetter(rs[k]) {
				next = dir(rs[k])
				break
			}
			if !unicode.IsMark(rs[k]) {
				break
			}
		}
		edge = edge || j == len(rs)
		if marks > 0 && (!rtl || marks > 1 && !wrapped || !(digit || edge || last != next && others > 0)) {
			return false
		}
		i = j
	}
	return true
}

// A1 round 3: Sparse is unchanged by its counting core. Random texts over the marks and their
// neighbours: Sparse agrees with round 2's, and MisplacedMarks counts none exactly when no mark is out
// of place (the ideographic bound aside).
func TestSparseKeepsItsAnswers(t *testing.T) {
	alphabet := []rune{'a', 'b', 'f', 'Z', '1', '(', ')', '$', ' ', '\n', ',',
		0x05D0, 0x05D1, 0x0627, 0x0644, 0x0661, 0x1820, 0x1821, 0x1828, 0x845B, 0x98FE, 0x0308,
		0x200E, 0x200F, 0x061C, 0x00AD, 0x180E, 0xE0100, 0xE0101}
	rng := rand.New(rand.NewSource(1114))
	for i := 0; i < 300000; i++ {
		var b strings.Builder
		for j := rng.Intn(14); j >= 0; j-- {
			b.WriteRune(alphabet[rng.Intn(len(alphabet))])
		}
		s := b.String()
		if got, want := Sparse(s), sparseRound2(s); got != want {
			t.Fatalf("Sparse(%+q) = %v, round 2's %v", s, got, want)
		}
		ivs := strings.ContainsFunc(s, func(r rune) bool { return r >= 0xE0100 && r <= 0xE01EF })
		if n := MisplacedMarks(s); !ivs && (n == 0) != sparseRound2(s) { // the ideographic bound is not MisplacedMarks'
			t.Fatalf("MisplacedMarks(%+q) = %d, Sparse %v", s, n, Sparse(s))
		}
	}
}

// A1 round 3 (PE-6, R2-P3-3): Unseen counts what no one sees beyond honest text: the invisible
// characters Text removes, the honest marks out of place, and the joiners kept by the Latin
// allowances alone; selectors, a line's CRLF and bytes that are not UTF-8 are not its.
func TestUnseen(t *testing.T) {
	bits := func(zero, one rune) string { // "neutral" as bits, one character a bit
		var b strings.Builder
		for _, c := range []byte("neutral") {
			for k := 7; k >= 0; k-- {
				if c>>uint(k)&1 == 1 {
					b.WriteRune(one)
				} else {
					b.WriteRune(zero)
				}
			}
		}
		return b.String()
	}
	for _, c := range []struct {
		name string
		in   string
		n    int
	}{
		{"plain ASCII", "Use pnpm; run the tests.", 0},
		{"Windows line ends", "line one\r\nline two\r\n", 0},
		{"a carriage return alone", "visible\rhidden", 1},
		{"bytes that are not UTF-8", "caf\xe9 au lait", 0},
		{"variation selectors are not Unseen's", "\U0001F600\U0000FE00\U0000FE01 a\U0000FE0F", 0},
		{"a soft hyphen inside a word", "Fu\U000000DF\U000000ADball\U000000ADwelt", 0},
		{"a soft hyphen at a word's end", "Haus\U000000AD und Hof", 1},
		{"an RLM that Hebrew needs before a number", "\U000005E9\U000005DC\U000005D5\U000005DD \U0000200F(2)", 0},
		{"an RLM in text without right-to-left letters", "price \U0000200F123", 1},
		{"the Mongolian vowel separator before a final a", "\U00001828\U0000180E\U00001820", 0},
		{"the Mongolian vowel separator after a Latin letter", "a\U0000180E\U00001820", 1},
		{"an emoji ZWJ sequence", "\U0001F468\U0000200D\U0001F4BB \U0001F3F3\U0000FE0F\U0000200D\U0001F308", 0},
		{"Persian with ZWNJ", "\U00000645\U000006CC\U0000200C\U00000634\U000006A9\U00000646\U00000645", 0},
		{"Hindi conjunct with ZWJ after the virama", "\U00000915\U0000094D\U0000200D\U00000937", 0},
		{"the flag of England", "\U0001F3F4\U000E0067\U000E0062\U000E0065\U000E006E\U000E0067\U000E007F", 0},
		{"a ZWNJ after f before a Latin letter (Latin allowance)", "Auf\U0000200Clage", 1},
		{"a joiner between two ASCII symbols (symbol allowance)", "a =\U0000200D> b", 1},
		{"a joiner between an emoji and an ASCII symbol", "\U0001F600\U0000200D=", 1},
		{"a zero-width space", "Get\U0000200B the weather.", 1},
		{"a ZWJ between Latin letters", "Ge\U0000200Dt", 1},
		{"a byte order mark", "\U0000FEFFWeather", 1},
		{"a right-to-left override", "a\U0000202Eb", 1},
		{"tags beyond a flag", "x\U000E0072\U000E0075\U000E006E", 3},
		{"the invisible operators U+2062/U+2064 as bits", bits(0x2062, 0x2064), 56},
		{"U+2061/U+2063 as bits", bits(0x2061, 0x2063), 56},
		{"U+206A/U+206B as bits", bits(0x206A, 0x206B), 56},
		{"the Hangul fillers U+3164/U+FFA0 as bits", bits(0x3164, 0xFFA0), 56},
		{"a word joiner", "a\U00002060b", 1},
		{"CGJ", "a\U0000034Fb", 1},
		{"an interlinear annotation", "a\U0000FFF9b\U0000FFFAc\U0000FFFB", 3},
		{"a musical format control", "a\U0001D173b", 1},
		{"an ALM where no right-to-left text needs it", "price\U0000061C 5", 1},
	} {
		if got := Unseen(c.in); got != c.n {
			t.Errorf("%s: Unseen = %d, want %d (%+q)", c.name, got, c.n, c.in)
		}
	}
	// MisplacedMarks leaves the ideographic bound to Selectors; Sparse keeps it (signed text).
	nine := strings.Repeat("\U0000845B\U000E0100\U000098FE", 9)
	if MisplacedMarks(nine) != 0 || Sparse(nine) {
		t.Errorf("nine ideographic variants: MisplacedMarks %d, Sparse %v", MisplacedMarks(nine), Sparse(nine))
	}
	// The soft hyphen and CGJ as bits: the hyphens out of place and every CGJ.
	if n := Unseen("Be concise." + bits(0x00AD, 0x034F)); n < 56 {
		t.Errorf("U+00AD/U+034F as bits: Unseen = %d", n)
	}
}

// Round 4 (R3 P3): a code point Go's tables leave unassigned in the emoji blocks may be an emoji a
// later Unicode version added: Unseen counts it as one, its presentation selector is not stray, its
// joiners join as an emoji's. Unassigned code points elsewhere still count.
func TestUnseenLaterEmoji(t *testing.T) {
	later := rune(-1)
	for r := rune(0x1FA70); r <= 0x1FAFF && later < 0; r++ {
		if laterEmoji(r) {
			later = r
		}
	}
	if later < 0 {
		t.Skip("no unassigned code point left in U+1FA70-1FAFF: pick another for this test")
	}
	e := string(later)
	if laterEmoji(0x1F600) || laterEmoji(0x1FFFE) || laterEmoji(0x50000) || laterEmoji(0x2FFFF) || laterEmoji(0x0378) || laterEmoji(0x1EFFF) {
		t.Error("laterEmoji: an assigned code point or one outside the emoji blocks")
	}
	for _, c := range []struct {
		name string
		in   string
		n    int
	}{
		{"two later emoji", "New: " + e + e + ".", 0},
		{"a later emoji in a ZWJ sequence", "\U0001F600\U0000200D" + e, 0},
		{"a later emoji with its presentation selector", e + "\U0000FE0F", 0},
		{"a ZWSP beside a later emoji", e + "\U0000200B" + e, 1},
		{"an unassigned code point outside the emoji blocks", "a\U00050000b", 1},
		{"a noncharacter", "a\U0001FFFEb", 1},
	} {
		if got := Unseen(c.in); got != c.n {
			t.Errorf("%s: Unseen = %d, want %d (%+q)", c.name, got, c.n, c.in)
		}
	}
	for _, c := range []struct {
		in string
		n  int
	}{
		{e + "\U0000FE0F", 0},
		{e + "\U0000FE0E", 0},
		{e + "\U0000FE0F\U0000FE0F", 1},
		{e + "\U0000FE00", 1},
		{"\U00050000\U0000FE0F", 1},
	} {
		if n, _ := StraySelectors(c.in); n != c.n {
			t.Errorf("%+q: StraySelectors = %d, want %d", c.in, n, c.n)
		}
	}
	if out, _ := Text(e); out != "" {
		t.Errorf("Text keeps the unassigned %U", later)
	}
}

// Round 5 (the re-review's P3): LaterEmoji counts what Unseen takes for emoji; the re-review's capacity
// proof (TestZZR4LaterEmojiCapacity, adopted): a 20-byte payload in later emoji is no unseen character
// and no stray selector, Text removes all of it, and LaterEmoji counts it for the server's bound.
func TestLaterEmojiCapacity(t *testing.T) {
	var pts []rune
	for r := rune(0x1F000); r <= 0x1FAFF; r++ {
		if laterEmoji(r) {
			pts = append(pts, r)
		}
	}
	if len(pts) == 0 {
		t.Skip("no unassigned code point left in U+1F000-1FAFF")
	}
	var b strings.Builder
	for i, c := range []byte("neutral-review-bytes") {
		b.WriteRune(pts[(int(c)+i*7)%len(pts)])
	}
	s := "Weather " + b.String()
	n, _ := StraySelectors(s)
	_, removed := TextCount(s)
	if Unseen(s) != 0 || n != 0 || removed != 20 || LaterEmoji(s) != 20 {
		t.Errorf("20 later emoji: Unseen %d, stray %d, Text removes %d, LaterEmoji %d", Unseen(s), n, removed, LaterEmoji(s))
	}
	if LaterEmoji("Weather \U0001F600 \U00050000") != 0 {
		t.Error("LaterEmoji counts an assigned emoji or an unassigned code point outside the emoji blocks")
	}
}
