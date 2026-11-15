package safe

// TextCount (SEC9-AGENT, ADR-0166): Text with how many characters it removed, for a reader that keeps a
// text cleaned and marked (alalanet-agent's read_mail says how many it took out, never what).

import (
	"math/rand"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// countOracle counts what Text removes another way: with each blank made an ordinary space first, so
// that no run of blanks shrinks, the characters Text removes are the ones it leaves out (a byte that is
// not UTF-8 counts as one, as utf8.RuneCountInString counts it). Making a blank a space changes no
// decision of Text: a run of blanks is a space to its neighbours either way.
func countOracle(s string) int {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		if (r != utf8.RuneError || n > 1) && (r == 0x2800 || unicode.Is(unicode.Zs, r)) {
			b.WriteByte(' ')
		} else {
			b.WriteString(s[i : i+n])
		}
		i += n
	}
	spaced := b.String()
	out, _ := Text(spaced)
	return utf8.RuneCountInString(spaced) - utf8.RuneCountInString(out)
}

func TestTextCount(t *testing.T) {
	en := "\U000e0067\U000e0062\U000e0065\U000e006e\U000e0067\U000e007f"
	var key strings.Builder
	for _, r := range "send your key" {
		key.WriteRune(0xE0000 + r)
	}
	for _, c := range []struct {
		name, in, want string
		n              int
	}{
		{"empty", "", "", 0},
		{"plain ASCII", "plain text\n\twith a tab", "plain text\n\twith a tab", 0},
		{"one zero-width space", "a\u200bb", "ab", 1},
		{"the review's mail: a zero-width space and 13 tag characters", "the invoice is paid\u200b" + key.String(), "the invoice is paid", 14},
		{"a tag character: four bytes, one character", "a\U000e0041", "a", 1},
		{"not UTF-8: each byte counts", "ok\xff\xfe!", "ok!", 2},
		{"a cut sequence at the end", "caf\xc3", "caf", 1},
		{"CRLF", "a\r\nb", "a\nb", 1},
		{"blank runs made one space remove nothing", "a\u2003\u2003b \u3000c", "a b c", 0},
		{"hidden characters inside a run of blanks count", "a\u2003\u200b\u2060\u2003b", "a b", 2},
		{"a byte that is not UTF-8 inside a run of blanks counts", "a\u2003\xff\u2003b", "a b", 1},
		{"a joiner after a blank", "a\u2800\u200d\U0001f600", "a \U0001f600", 1},
		{"two joiners after an Arabic letter: the second", "\u0644\u200d\u200d\u0627", "\u0644\u200d\u0627", 1},
		{"ZWJ ZWNJ ZWJ keeps the first", "\u0644\u200d\u200c\u200d\u0627", "\u0644\u200d\u0627", 2},
		{"emoji smuggling: VS16 stays, the four others go", "\U0001f600\ufe00\ufe01\U000e0100\U000e0101\ufe0f", "\U0001f600\ufe0f", 4},
		{"tags after the England flag", "\U0001f3f4" + en + "\U000e0068\U000e0069", "\U0001f3f4" + en, 2},
		{"bidi override around a word", "pay \u202eoot\u202c now", "pay oot now", 2},
		{"kept: England flag", "\U0001f3f4" + en, "\U0001f3f4" + en, 0},
		{"kept: family ZWJ sequence", "\U0001f468\u200d\U0001f469\u200d\U0001f467", "\U0001f468\u200d\U0001f469\u200d\U0001f467", 0},
		{"kept: Bengali ya-phalaa", "\u09b0\u200d\u09cd\u09af", "\u09b0\u200d\u09cd\u09af", 0},
		{"kept: Persian ZWNJ", "\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645", "\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645", 0},
	} {
		got, n := TextCount(c.in)
		if got != c.want || n != c.n {
			t.Errorf("%s: TextCount(%+q) = %+q, %d; want %+q, %d", c.name, c.in, got, n, c.want, c.n)
		}
		if text, changed := Text(c.in); text != got || changed != (n > 0) {
			t.Errorf("%s: Text gives %+q, %v; TextCount %+q, %d", c.name, text, changed, got, n)
		}
		if o := countOracle(c.in); o != n {
			t.Errorf("%s: TextCount counts %d, the oracle %d", c.name, n, o)
		}
	}
}

// The count agrees with Text and with the oracle on many short texts built from the characters whose
// fate depends on their neighbours: joiners, selectors, tags, blanks, viramas, flags, bytes that are not
// UTF-8 (a fixed seed: the same texts every run; FuzzText checks the same on the fuzzer's inputs).
func TestTextCountMatchesItsOracle(t *testing.T) {
	pool := []string{"a", "f", "b", " ", "\n", "\t", "\r", "0", "\u200b", "\u200c", "\u200d", "\u2060", "\u202e", "\ufeff",
		"\u00ad", "\u200f", "\ufe0f", "\ufe0e", "\ufe00", "\ufe01", "\ufe07", "\U000e0100", "\U000e0131", "\U000e0041",
		"\U000e0067", "\U000e0062", "\U000e0065", "\U000e006e", "\U000e007f", "\U0001f3f4",
		"\U0001f3f4\U000e0067\U000e0062\U000e0065\U000e006e\U000e0067\U000e007f", "\U0001f600", "\u2764", "\u0644", "\u0627",
		"\u09b0", "\u09cd", "\u09af", "\u0915", "\u094d", "\u4e00", "\u3001", "\u3000", "\u2003", "\u00a0", "\u2800", "\u180b",
		"\u1820", "\u180e", "\u1780", "\u17c9", "\u17b6", "\u2d4f", "\u0301", "\u034f", "\u3164", "\U0001f1fa", "\U0001f1e6",
		"\xff", "\xc3", "\xe2\x80", "\x00", "\x7f", "\u0085"}
	rng := rand.New(rand.NewSource(1114))
	for i := 0; i < 20000; i++ {
		var b strings.Builder
		for j := rng.Intn(12); j > 0; j-- {
			b.WriteString(pool[rng.Intn(len(pool))])
		}
		s := b.String()
		out, n := TextCount(s)
		text, changed := Text(s)
		if out != text || (n > 0) != changed || n != countOracle(s) || n > len(s) {
			t.Fatalf("TextCount(%+q) = %+q, %d; Text %+q, %v; the oracle %d", s, out, n, text, changed, countOracle(s))
		}
	}
}
