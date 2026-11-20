package safe

// ADR-0167 round 7: what honest right-to-left text writes (CLDR number and date formats, Apple's
// isolate pairs) is in place, and the directional marks' bound grows with the right-to-left letters
// of the source. ASCII only: the characters are escapes.

import (
	"strings"
	"testing"
	"unicode"
)

// icuFormats: the distinct outputs with directional marks of Intl.DateTimeFormat, NumberFormat
// (decimal, percent, currency, unit, compact), RelativeTimeFormat and ListFormat for 17 right-to-left
// locales, from Node's ICU 78.3 (CLDR 48) on 2026-11-15.
var icuFormats = []struct{ locale, s string }{
	{"ar", "15\u200f/11\u200f/2026"},
	{"ar", "15\u200f/11\u200f/2026\u060c 5:05 \u0645"},
	{"ar", "15\u200f/11\u200f/2026\u060c 5:05:09 \u0645"},
	{"ar", "\u200e-1,234,567.891"},
	{"ar", "50\u200e%\u200e"},
	{"ar", "\u200e-13\u200e%\u200e"},
	{"ar", "\u200f\u200e-1,234.50\u00a0US$"},
	{"ar", "\u200f1,234.50\u00a0\u20ac"},
	{"ar", "\u200f99.00\u00a0\u20aa"},
	{"ar", "\u200e-1,234.5"},
	{"ar-EG", "\u0661\u0665\u200f/\u0661\u0661\u200f/\u0662\u0660\u0662\u0666"},
	{"ar-EG", "\u0661\u0665\u200f/\u0661\u0661\u200f/\u0662\u0660\u0662\u0666\u060c \u0665:\u0660\u0665 \u0645"},
	{"ar-EG", "\u0661\u0665\u200f/\u0661\u0661\u200f/\u0662\u0660\u0662\u0666\u060c \u0665:\u0660\u0665:\u0660\u0669 \u0645"},
	{"ar-EG", "\u061c-\u0661\u066c\u0662\u0663\u0664\u066c\u0665\u0666\u0667\u066b\u0668\u0669\u0661"},
	{"ar-EG", "\u0665\u0660\u066a\u061c"},
	{"ar-EG", "\u061c-\u0661\u0663\u066a\u061c"},
	{"ar-EG", "\u061c-\u200f\u0661\u066c\u0662\u0663\u0664\u066b\u0665\u0660\u00a0US$"},
	{"ar-EG", "\u200f\u0661\u066c\u0662\u0663\u0664\u066b\u0665\u0660\u00a0\u20ac"},
	{"ar-EG", "\u200f\u0669\u0669\u066b\u0660\u0660\u00a0\u20aa"},
	{"ar-MA", "15\u200f/11\u200f/2026\u060c 17:05"},
	{"ar-MA", "15\u200f/11\u200f/2026\u060c 17:05:09"},
	{"ar-MA", "\u200e-1.234.567,891"},
	{"ar-MA", "\u200f\u200e-1.234,50\u00a0US$"},
	{"ar-MA", "\u200f1.234,50\u00a0\u20ac"},
	{"ar-MA", "\u200f99,00\u00a0\u20aa"},
	{"ar-MA", "\u200e-1.234,5"},
	{"he", "\u200e-13%"},
	{"he", "\u200f\u200e-1,234.50\u00a0\u200f$"},
	{"he", "\u200f1,234.50\u00a0\u200f\u20ac"},
	{"he", "\u200f99.00\u00a0\u200f\u20aa"},
	{"he", "12M\u200f"},
	{"fa", "\u200e\u2212\u06f1\u066c\u06f2\u06f3\u06f4\u066c\u06f5\u06f6\u06f7\u066b\u06f8\u06f9\u06f1"},
	{"fa", "\u200e\u2212\u06f1\u06f3\u066a"},
	{"fa", "\u200e\u2212\u200e$\u06f1\u066c\u06f2\u06f3\u06f4\u066b\u06f5\u06f0"},
	{"fa", "\u200e\u20ac\u06f1\u066c\u06f2\u06f3\u06f4\u066b\u06f5\u06f0"},
	{"fa", "\u200e\u20aa\u06f9\u06f9\u066b\u06f0\u06f0"},
	{"fa", "\u06f8\u06f8\u200e km/h"},
	{"fa", "\u200e\u22121,234.5"},
	{"fa", "A\u060c\u200f B\u060c \u0648 C"},
	{"ur", "\u200e-$1,234.50"},
	{"ps", "\u200e-\u200e\u06f1\u066c\u06f2\u06f3\u06f4\u066c\u06f5\u06f6\u06f7\u066b\u06f8\u06f9\u06f1"},
	{"ps", "\u200e-\u200e\u06f1\u06f3\u066a"},
	{"ps", "\u200e-\u200e$\u00a0\u06f1\u066c\u06f2\u06f3\u06f4\u066b\u06f5\u06f0"},
	{"ps", "\u200e\u22121.234,5"},
	{"ckb", "\u200f-\u0661\u066c\u0662\u0663\u0664\u066c\u0665\u0666\u0667\u066b\u0668\u0669\u0661"},
	{"ckb", "\u200f-\u0661\u0663\u00a0\u066a"},
	{"ckb", "\u200f-\u0661\u066c\u0662\u0663\u0664\u066b\u0665\u0660\u00a0US$"},
	{"sd", "\u061c-\u0661\u066c\u0662\u0663\u0664\u066c\u0665\u0666\u0667.\u0668\u0669\u0661"},
	{"sd", "\u061c-\u0661\u066c\u0662\u0663\u0664.\u0665\u0660\u00a0US$"},
}

// rtlWord: a word of the locale's script.
func rtlWord(locale string) string {
	if strings.HasPrefix(locale, "he") || locale == "yi" {
		return "\U000005D4\U000005EA\U000005D0\U000005E8\U000005D9\U000005DA" // "the date"
	}
	return "\U00000627\U00000644\U0000062A\U00000627\U00000631\U0000064A\U0000062E"
}

// PRE-1: each format, in a sentence of its locale's script, is in place: no unit, no reordering.
func TestCLDRFormatsInPlace(t *testing.T) {
	for _, c := range icuFormats {
		s := rtlWord(c.locale) + " " + c.s + " " + rtlWord(c.locale) + "."
		if u, m := Unseen(s), MisplacedMarks(unseenText(s)); u != 0 || m != 0 || Reorders(s) {
			t.Errorf("%s %+q: Unseen %d, misplaced %d, Reorders %v", c.locale, c.s, u, m, Reorders(s))
		}
		if h := HonestMarks(s); h == 0 {
			t.Errorf("%s %+q: no mark in place counted toward the bound", c.locale, c.s)
		}
	}
	// Without a right-to-left letter the marks are still out of place.
	for _, s := range []string{"price \U0000200F99.00\U000000A0\U000020AA", "15\U0000200F/11\U0000200F/2026", "50\U0000200E%\U0000200E"} {
		if Unseen(s) == 0 {
			t.Errorf("%+q without right-to-left letters: Unseen 0", s)
		}
	}
	// What the detectors' rule does not take in right-to-left text: two alike side by side, three in a
	// row.
	he := "\U000005E9\U000005DC\U000005D5\U000005DD "
	for _, s := range []string{he + "15\U0000200F\U0000200F/11", he + "\U0000200F\U0000200E\U0000200F-1"} {
		if Unseen(s) == 0 {
			t.Errorf("%+q: Unseen 0", s)
		}
	}
}

// PRE-1: Apple's isolate pairs around inserted names in right-to-left text are honest and count as
// directional marks in place, one a pair; other isolates still reorder.
func TestIsolatePairs(t *testing.T) {
	he := "\U000005D4\U000005E2\U000005D3\U000005DB\U000005E0\U000005D9 \U000005D0\U000005EA "
	for _, c := range []struct {
		name     string
		s        string
		reorders bool
		marks    int
	}{
		{"FSI and PDI around a name in Hebrew", he + "\U00002068Apple Inc.\U00002069.", false, 1},
		{"two pairs and an RLM", "\U0000200FAirDrop " + he + "\U00002068A\U00002069 \U00002067B\U00002069", false, 3},
		{"nested pairs", he + "\U00002068x \U00002066y\U00002069\U00002069", false, 2},
		{"a pair in English", "Updated \U00002068Apple Inc.\U00002069.", true, 0},
		{"an initiator alone", he + "\U00002068Apple Inc.", true, 0},
		{"a PDI alone", he + "Apple Inc.\U00002069", true, 0},
		{"an empty pair", he + "\U00002068\U00002069x", true, 0},
		{"a pair around a mark alone", he + "\U00002068\U0000200F\U00002069x", true, 0},
		{"a pair across lines", he + "\U00002068Apple\nInc.\U00002069", true, 0},
		{"an override inside a pair", he + "\U00002068a\U0000202Eb\U00002069", true, 0},
		{"an embedding pair around an address", he + "\U0000202A@example.org\U0000202C, \U0000200F\U0000202A%2$@\U0000202C", false, 3},
		{"an override pair", he + "\U0000202Eabc\U0000202C", true, 0},
		{"an embedding alone", he + "\U0000202Babc", true, 0},
	} {
		if got := Reorders(c.s); got != c.reorders {
			t.Errorf("%s: Reorders %v", c.name, got)
		}
		if u, h := Unseen(c.s), HonestMarks(c.s); !c.reorders && (u != 0 || h != c.marks) {
			t.Errorf("%s: Unseen %d, HonestMarks %d, want 0 and %d", c.name, u, h, c.marks)
		} else if c.reorders && u == 0 {
			t.Errorf("%s: reorders, and Unseen counts none of it", c.name)
		}
	}
	if s := StripReorders(he + "\U00002068A\U00002069 \U00002066B \U0000202EC"); s != he+"\U00002068A\U00002069 B C" {
		t.Errorf("StripReorders: %+q", s)
	}
}

// R6-FP-1: the directional marks' bound is MaxHonestMarks plus one for each RTLLettersPerMark right-
// to-left letters of the source; the soft hyphens' stays MaxHonestMarks, shared with the marks past
// their allowance; a unit once given is never taken back.
func TestJudgeRTLAllowance(t *testing.T) {
	lines := func(n int) string { // n RLM in place at lines' ends, one Hebrew letter
		return "\U000005D0\n" + strings.Repeat("Keep it short\U0000200F\n", n)
	}
	letters := func(n int) string { return strings.Repeat("\U000005D0", n) + "." }
	var a Selectors
	if _, m := a.Judge(lines(10)); m != 2 {
		t.Errorf("ten RLM, one Hebrew letter: %d units, want 2", m)
	}
	if _, m := a.Judge(letters(399)); m != 0 { // 400 letters: allowance 28, but the 2 stay given
		t.Errorf("then 399 Hebrew letters: %d units, want 0", m)
	}
	if _, m := a.Judge(lines(30)); m != 10 { // 40 marks, 401 letters: 20 past the allowance, 12 past 8, 2 given before
		t.Errorf("then thirty RLM more: %d units, want 10", m)
	}
	var b Selectors
	if _, m := b.Judge(letters(200) + lines(18)); m != 0 { // 201 letters: 8 + 10
		t.Errorf("eighteen RLM, 201 Hebrew letters: %d units", m)
	}
	if _, m := b.Judge(lines(1)); m != 1 {
		t.Errorf("one RLM more: %d units, want 1", m)
	}
	var c Selectors
	shy := "Bundes\U000000ADverfassungs\U000000ADgericht "
	if _, m := c.Judge(letters(400) + strings.Repeat(shy, 5)); m != 2 { // ten soft hyphens: their bound is 8 whatever the letters
		t.Errorf("ten soft hyphens beside 400 Hebrew letters: %d units, want 2", m)
	}
}

// rightToLeft's fast path: no letter of a right-to-left script stands below U+0590 (round 7: the
// detectors call it for every letter).
func TestRightToLeftBelowHebrew(t *testing.T) {
	for r := rune(0); r < 0x0590; r++ {
		if unicode.In(r, rightToLeftScripts...) {
			t.Fatalf("U+%04X is in a right-to-left script", r)
		}
	}
}
