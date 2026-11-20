package safe

// Independent review of SEC9-AGENT (ADR-0166): TextCount against an oracle of the reviewer's own, on
// every code point, every two-byte sequence, random texts and the fuzzer; and its worst-case cost.
// Untracked review file: not part of the branch.

import (
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/alalanet/alalanet-agent/internal/costtest"
)

// zzNonblank counts the characters of s that are not blanks (U+0020, the other Zs, U+2800), each byte
// that is not UTF-8 as one. Text never removes a blank (a run of them becomes one space at most) and
// never writes a character that is not a blank of its own, so what it removed is exactly
// zzNonblank(s) - zzNonblank(out). The oracle does not run Text on another input.
func zzNonblank(s string) int {
	n := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if (r == utf8.RuneError && size == 1) || !(r == 0x2800 || unicode.Is(unicode.Zs, r)) {
			n++
		}
		i += size
	}
	return n
}

func zzOracle(s, out string) int { return zzNonblank(s) - zzNonblank(out) }

// zzInvisible is the reviewer's own list of what SEC-9 (ADR-0137) says a person does not see: Cc but
// newline and tab, Cf but the prepended concatenation marks, surrogates, unassigned code points
// (noncharacters too), Other_Default_Ignorable_Code_Point, every Variation_Selector and Join_Control.
func zzInvisible(r rune) bool {
	switch {
	case r == '\n' || r == '\t':
		return false
	case unicode.Is(unicode.Prepended_Concatenation_Mark, r):
		return false
	case unicode.Is(unicode.Cc, r), unicode.Is(unicode.Cf, r), unicode.Is(unicode.Cs, r),
		unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r), unicode.Is(unicode.Variation_Selector, r),
		unicode.Is(unicode.Join_Control, r):
		return true
	}
	for _, cat := range []string{"L", "M", "N", "P", "S", "Z", "Co"} {
		if unicode.Is(unicode.Categories[cat], r) {
			return false
		}
	}
	return true // Cn
}

func zzBlank(r rune) bool { return r == 0x2800 || unicode.Is(unicode.Zs, r) }

// zzCheck: the properties every call must have, by the oracle; returns TextCount's result.
func zzCheck(t *testing.T, s string) (string, int) {
	t.Helper()
	out, n := TextCount(s)
	if text, changed := Text(s); text != out || changed != (n > 0) {
		t.Fatalf("Text(%+q) = %+q, %v; TextCount %+q, %d", s, text, changed, out, n)
	}
	if o := zzOracle(s, out); o != n {
		t.Fatalf("TextCount(%+q) = %+q, %d; the reviewer's oracle counts %d", s, out, n, o)
	}
	if again, n2 := TextCount(out); again != out || n2 != 0 {
		t.Fatalf("TextCount not idempotent on %+q: %+q, %d", out, again, n2)
	}
	if !utf8.ValidString(out) || len(out) > len(s) || n > len(s) {
		t.Fatalf("TextCount(%+q) = %+q, %d: invalid, longer or over-counted", s, out, n)
	}
	return out, n
}

// Every code point (surrogates have no UTF-8 form) in five contexts: what is invisible by the
// reviewer's list is removed and counted once, but for the joiners and selectors a context keeps;
// everything else is kept, uncounted (a blank may become one space).
func TestZZReviewSEC9AgentCountEveryCodePoint(t *testing.T) {
	type ctx struct {
		name, before, after string
		kept                func(r rune) bool // invisible characters this context keeps
	}
	none := func(rune) bool { return false }
	ctxs := []ctx{
		{"between Latin letters", "a", "b", none},
		{"between two emoji", "\U0001F600", "\U0001F600", func(r rune) bool {
			return r == 0x200D || r == 0x200C || r == 0xFE0E || r == 0xFE0F
		}},
		{"between Arabic letters", "\U00000644", "\U00000627", func(r rune) bool { return r == 0x200D || r == 0x200C }},
		{"after a Devanagari virama", "\U00000915\U0000094D", "\U00000937", func(r rune) bool { return r == 0x200D || r == 0x200C }},
		{"inside a run of spaces", "x ", " y", none},
	}
	var removedAt, keptInvisible, countedVisible int
	for _, c := range ctxs {
		for r := rune(0); r <= unicode.MaxRune; r++ {
			if r >= 0xD800 && r <= 0xDFFF {
				continue
			}
			s := c.before + string(r) + c.after
			out, n := zzCheck(t, s)
			switch {
			case zzInvisible(r) && !c.kept(r):
				if n != 1 || out != c.before+c.after {
					t.Errorf("%s: U+%04X (invisible) gives %+q, %d; want %+q, 1", c.name, r, out, n, c.before+c.after)
				}
				removedAt++
			case zzInvisible(r):
				if n != 0 || out != s {
					t.Errorf("%s: U+%04X (kept here) gives %+q, %d", c.name, r, out, n)
				}
				keptInvisible++
			case zzBlank(r):
				if n != 0 {
					t.Errorf("%s: blank U+%04X counted %d", c.name, r, n)
				}
			default:
				if n != 0 || out != s {
					t.Errorf("%s: visible U+%04X gives %+q, %d", c.name, r, out, n)
					countedVisible++
				}
			}
		}
	}
	t.Logf("removed and counted once: %d (code point, context) pairs; kept invisible where the context allows: %d; visible miscounted: %d",
		removedAt, keptInvisible, countedVisible)
}

// Every sequence of two bytes after "a" and before "b": a byte that is not UTF-8 counts one each.
func TestZZReviewSEC9AgentCountEveryTwoBytes(t *testing.T) {
	for b1 := 0; b1 < 256; b1++ {
		for b2 := 0; b2 < 256; b2++ {
			zzCheck(t, "a"+string([]byte{byte(b1), byte(b2)})+"b")
		}
	}
	for _, s := range []string{"\xed\xa0\x80", "\xed\xbf\xbf", "\xc0\x80", "\xe0\x80\xaf", "\xf4\x90\x80\x80", "\xf8\x88\x80\x80\x80",
		"\xe2\x80", "\xf3\xa0\x81", "\xef\xbf\xbd", "\xff\xfe\xfd", "\xf3\xa0\x81\xa1\xf3\xa0\x81"} {
		out, n := zzCheck(t, "a"+s+"b")
		t.Logf("a %+q b -> %+q, %d", s, out, n)
	}
}

// zzPool: pieces whose fate depends on their neighbours, and every class.
var zzPool = []string{
	"a", "f", "b", "Z", "0", "1", "#", "*", " ", "  ", "\n", "\t", "\r", "\r\n",
	"\U0000200B", "\U0000200C", "\U0000200D", "\U00002060", "\U0000202E", "\U0000202C", "\U00002066", "\U00002069", "\U0000FEFF",
	"\U000000AD", "\U0000200E", "\U0000200F", "\U0000061C", "\U0000180E", "\U00002061", "\U00002064", "\U0000206A",
	"\U0000FE0F", "\U0000FE0E", "\U0000FE00", "\U0000FE01", "\U0000FE02", "\U0000FE07", "\U0000FE0D",
	"\U000E0100", "\U000E0131", "\U000E01EF", "\U000E0001", "\U000E0020", "\U000E0041", "\U000E007E", "\U000E007F",
	"\U000E0067", "\U000E0062", "\U000E0065", "\U000E006E", "\U000E0073", "\U000E0063", "\U000E0074", "\U000E0077", "\U000E006C",
	"\U0001F3F4", "\U0001F3F4\U000E0067\U000E0062\U000E0065\U000E006E\U000E0067\U000E007F",
	"\U0001F3F4\U000E0067\U000E0062\U000E0073\U000E0063\U000E0074\U000E007F",
	"\U0001F3F4\U000E0075\U000E0073\U000E0074\U000E0078\U000E007F",
	"\U0001F600", "\U00002764", "\U0001F3FD", "\U000020E3", "\U00000644", "\U00000627", "\U00000647",
	"\U000009B0", "\U000009CD", "\U000009AF", "\U00000915", "\U0000094D", "\U00000DC1", "\U00000DCA", "\U00000DBB",
	"\U00001780", "\U000017D2", "\U000017C9", "\U000017B6", "\U000017B4", "\U00001000", "\U00001031", "\U0000103A",
	"\U00002D5C", "\U00002D7F", "\U00001820", "\U0000180B", "\U0000180F", "\U00004E00", "\U0000845B", "\U00003001",
	"\U00003000", "\U00002003", "\U000000A0", "\U00002800", "\U0000202F", "\U00000301", "\U0000034F", "\U00003164",
	"\U0000115F", "\U00001160", "\U0000FFA0", "\U0001D173", "\U0001BCA0", "\U00000600", "\U000110BD", "\U0000FFF9",
	"\U00013430", "\U0000E000", "\U000F0000", "\U00000378", "\U0000FDD0", "\U0000FFFE", "\U0010FFFF", "\U000E0080",
	"\U0001F1FA", "\U0001F1E6", "\U00002028", "\U00002029", "\U0000FFFD",
	"\xff", "\xc3", "\xe2\x80", "\xed\xa0\x80", "\xc0\x80", "\x00", "\x1b", "\x7f", "\U00000085", "\U0000009B",
}

func zzRandom(rng *rand.Rand, max int) string {
	var b strings.Builder
	for j := rng.Intn(max + 1); j > 0; j-- {
		b.WriteString(zzPool[rng.Intn(len(zzPool))])
	}
	return b.String()
}

// Random texts: the count equals the reviewer's oracle and the branch's own countOracle.
func TestZZReviewSEC9AgentCountRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(20261114))
	for i := 0; i < 300000; i++ {
		s := zzRandom(rng, 24)
		_, n := zzCheck(t, s)
		if o := countOracle(s); o != n {
			t.Fatalf("the branch's countOracle(%+q) = %d, TextCount %d", s, o, n)
		}
	}
}

func FuzzZZReviewSEC9AgentTextCount(f *testing.F) {
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 64; i++ {
		f.Add(zzRandom(rng, 16))
	}
	f.Fuzz(func(t *testing.T, s string) {
		zzCheck(t, s)
	})
}

// zzWorst: texts that make TextCount, Hidden and IdeographicSelectors do the most per byte.
func zzWorst(size int) map[string]string {
	rep := func(unit string) string { return strings.Repeat(unit, size/len(unit)) }
	return map[string]string{
		"ZWJ only":                      rep("\U0000200D"),
		"Latin letter + ZWJ":            rep("a\U0000200D"),
		"Arabic letter + ZWJ":           rep("\U00000644\U0000200D"),
		"Arabic letter + ZWJ + ZWNJ":    rep("\U00000644\U0000200D\U0000200C"),
		"virama + ZWJ":                  rep("\U00000915\U0000094D\U0000200D"),
		"black flag only":               rep("\U0001F3F4"),
		"black flag + 5 tags, no end":   rep("\U0001F3F4\U000E0067\U000E0062\U000E0065\U000E006E\U000E0067"),
		"England flags":                 rep("\U0001F3F4\U000E0067\U000E0062\U000E0065\U000E006E\U000E0067\U000E007F"),
		"space + ZWSP":                  rep(" \U0000200B"),
		"space + letter":                rep(" a\U000000E9"),
		"em space + ZWSP":               rep("\U00002003\U0000200B"),
		"tag characters":                rep("\U000E0041"),
		"tag, letter alternating":       rep("\U000E0041a"),
		"emoji + VS16 + VS16":           rep("\U00002764\U0000FE0F\U0000FE0F"),
		"VS1 run":                       rep("\U0000FE01"),
		"IVS run":                       rep("\U000E0131"),
		"ideograph + IVS":               rep("\U00004E00\U000E0131"),
		"ideograph + IVS + ZWSP":        rep("\U00004E00\U000E0131\U0000200B"),
		"bytes not UTF-8":               rep("\xff"),
		"cut tag sequences":             rep("\xf3\xa0\x81"),
		"Mongolian letter + FVS + FVS":  rep("\U00001820\U0000180B\U0000180C"),
		"Khmer + ZWNJ + shifter":        rep("\U00001780\U0000200C\U000017C9"),
		"unassigned":                    rep("\U00000378"),
		"CJK text (honest)":             rep("\U00005929\U00006C14\U00003000"),
		"selector run, tag run, letter": rep("\U0000FE01\U0000FE02\U000E0041\U000E0042x"),
	}
}

// The cost: ns per byte and allocations for each worst text at 64 KiB (the largest gift wrap the
// server keeps holds less) and the slowest at 4 MiB (all agentkit reads of one response). Logged, and
// failed only past one second for 64 KiB or 30 s for 4 MiB, far beyond any finding; the Mac is shared.
func TestZZReviewSEC9AgentCountCost(t *testing.T) {
	if testing.Short() {
		t.Skip("cost")
	}
	var lines []string
	worstName, worstNs := "", 0.0
	for name, s := range zzWorst(64 << 10) {
		var n int
		d := costtest.One(costtest.Rounds, func() { // the least of three, thread CPU (COST-TEST-LOAD-1)
			_, n = TextCount(s)
			_ = Hidden(s)
			_ = IdeographicSelectors(s)
		})
		allocs := testing.AllocsPerRun(3, func() { TextCount(s) })
		res := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				TextCount(s)
			}
		})
		nsb := float64(res.NsPerOp()) / float64(len(s))
		if nsb > worstNs {
			worstName, worstNs = name, nsb
		}
		lines = append(lines, fmt.Sprintf("%-32s %6d B  removed %6d  TextCount %8.1f us (%5.1f ns/B, %d B/op, %.0f allocs)  with Hidden+IVS %v (least of 3)",
			name, len(s), n, float64(res.NsPerOp())/1e3, nsb, res.AllocedBytesPerOp(), allocs, d))
		if d > time.Second {
			t.Errorf("%s: %v for 64 KiB", name, d)
		}
	}
	big := zzWorst(4 << 20)[worstName]
	var n int
	d := costtest.One(costtest.Rounds, func() { _, n = TextCount(big) }) // the least of three, thread CPU (COST-TEST-LOAD-1)
	lines = append(lines, fmt.Sprintf("4 MiB of the slowest (%s): TextCount %v, removed %d", worstName, d, n))
	if d > 30*time.Second {
		t.Errorf("4 MiB: %v", d)
	}
	for _, l := range lines {
		t.Log(l)
	}
	if out := os.Getenv("ZZ_REVIEW_OUT"); out != "" {
		_ = os.WriteFile(out, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
	}
}
