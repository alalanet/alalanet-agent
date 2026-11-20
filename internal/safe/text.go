package safe

import (
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// tables.go holds the Unicode tables Text needs that Go's unicode package lacks, written by gentables.go
// from the Unicode Character Database files vendored in testdata/ucd (package ucd).
//
//go:generate go run gentables.go

// Text returns s without the characters a person does not see but a model reads, and whether it
// removed any (A2:SEC-9). alalanet relays third-party text to agents (catalogue names and
// descriptions, profiles, board labels); such characters can carry instructions that the people who
// look at the same text never see.
//
// The classes are those of the Unicode tables Go ships (unicode.Version, 17.0.0 in Go 1.27):
//
//   - Cc, the C0 and C1 controls, except \n and \t;
//   - Cf, the format characters: the soft hyphen U+00AD, the Arabic letter mark U+061C, the Mongolian
//     vowel separator U+180E, the zero-width space, joiners and directional marks U+200B–200F, the
//     directional embeddings and overrides U+202A–202E, the word joiner and invisible operators
//     U+2060–2064, the directional isolates U+2066–2069, the deprecated format characters
//     U+206A–206F, the byte order mark U+FEFF, the interlinear annotation characters U+FFF9–FFFB, the
//     Egyptian, shorthand and musical format controls, the language tag U+E0001 and the tag
//     characters U+E0020–E007F. Kept: the Prepended_Concatenation_Mark signs (U+0600–0605, 06DD,
//     070F, 0890–0891, 08E2, 110BD, 110CD), which are Cf but visible (Unicode leaves them out of
//     Default_Ignorable_Code_Point); ZWNJ U+200C and ZWJ U+200D where they join (below); and the tags
//     of the three RGI subdivision flags (below);
//   - Other_Default_Ignorable_Code_Point, characters Unicode itself says to render as nothing: the
//     combining grapheme joiner U+034F, the Hangul fillers U+115F, U+1160, U+3164 and U+FFA0 (the
//     classic blank "names") and the Khmer inherent vowels U+17B4–17B5;
//   - the variation selectors VS17–VS256 (U+E0100–E01EF), always; VS1–VS16 (U+FE00–FE0F) and the
//     Mongolian free variation selectors (U+180B–180D, U+180F) beyond one, and after a base that no
//     registered sequence of theirs has (below): one selects a glyph (the red heart emoji is U+2764
//     U+FE0F), a run of them carries bytes ("emoji smuggling", one byte per selector);
//   - unassigned code points (Cn), noncharacters included (U+FDD0–FDEF, U+xFFFE–xFFFF): nothing is
//     drawn for them, and a code point Unicode assigns later is unassigned here until Go's tables
//     move (TestTextUnicodeVersion);
//   - bytes that are not UTF-8.
//
// ZWNJ and ZWJ stay where the standard uses them (The Unicode Standard, 23.2 Layout Controls):
//
//   - after a letter of a cursive script (cursiveScripts), directly or after its marks, whatever
//     comes next: between letters they control joining (the Persian ZWNJ), and after an Arabic letter
//     at a word's end a ZWJ asks for its joining form (9.2 Arabic);
//   - after a letter, beside a virama (viramas), where they ask for a conjunct form or keep one from
//     forming (12.1 Devanagari; Bengali ra + ZWJ + virama + ya is the ya-phalaa, 12.2 Bengali; a ZWJ
//     after a virama at a word's end gives the chillu of older Malayalam text, 12.9 Malayalam);
//   - a ZWNJ after f, or the long s, before another Latin letter: it keeps a ligature from forming
//     across the parts of a word (Auf + ZWNJ + lage, 23.2);
//   - in Khmer, a ZWNJ after a letter before the consonant shifter U+17C9 or U+17CA, which keeps the
//     shifter from moving below (16.4 Khmer, Consonant Shifters: the standard's 'beer' and 'urgent,
//     too busy'), and a joiner after a letter, its marks or a subscript consonant before a dependent
//     vowel U+17B6–17C5 (the syllable structure of 16.4);
//   - a ZWJ between two Tifinagh letters, which asks for their bi-consonant (19.3 Tifinagh);
//   - between two symbols: a ZWJ joins the elements of an emoji ZWJ sequence (UTS #51, 2.5: woman
//     U+200D laptop, the families, the rainbow flag U+1F3F3 U+FE0F U+200D U+1F308).
//
// Anywhere else a joiner is dropped, and so is a second one in a row: a joiner after each letter, or a
// run of them, would carry bits, so the ligature-control sequence ZWJ ZWNJ ZWJ (23.2) keeps only its
// first ZWJ.
//
// A variation selector stays directly after a base its registered sequences have
// (StandardizedVariants.txt, emoji-variation-sequences.txt), one at most (fits): VS15 and VS16, text
// and emoji presentation, after a character with the Emoji property (emojiCharacters); VS1 after one
// of the 25 mathematical symbols that have a variant or a zero that has a slashed form
// (mathVariants), the Myanmar vowel sign E, an ideograph (the compatibility ideographs) or a letter of
// Myanmar, Phags-pa, Manichaean or the Egyptian hieroglyphs; VS1 and VS2 after the East Asian
// punctuation and the mathematical script capitals that have them; VS1-VS3 after the quotation marks
// U+2018, U+2019, U+201C and U+201D, an ideograph or a letter of those scripts; VS4-VS7 after an
// Egyptian hieroglyph (its rotations); a Mongolian free variation selector after a Mongolian letter.
// VS8-VS14 stay nowhere: no sequence uses them. The tag characters of England, Scotland and Wales
// (U+1F3F4, five tag letters, U+E007F; the only tag sequences in Unicode's RGI emoji list) stay after
// their black flag.
// Private-use characters stay: they are drawn (a box or a vendor's glyph).
//
// Blanks are normalized: a run of the space separators (Zs) and the braille blank U+2800 that holds
// any other than U+0020 becomes one ordinary space. They look alike, so the choice among them could
// carry bits; and a name of blanks looks empty. That is no removal of a hidden character: the bool
// Text returns stays false for it (honest CJK text has the ideographic space U+3000).
//
// The result is never longer, is valid UTF-8, and cleaning it again changes nothing. Callers choose
// the policy: author-supplied text with hidden characters is refused (Author), imported text is kept
// cleaned and marked.
func Text(s string) (string, bool) {
	out, n := TextCount(s)
	return out, n > 0
}

// TextCount is Text with how many characters it removed: code points, and each byte that is not
// UTF-8. A run of blanks written as one space removes none (Text). A reader that keeps a text cleaned
// and marked says by it how much was taken out, never what (alalanet-agent's read_mail, SEC9-AGENT).
func TextCount(s string) (string, int) {
	if plain(s) {
		return s, 0
	}
	t, removed := dropped(s)
	out, removedToo := joined(t)
	return out, removed + removedToo
}

// blank: a space separator or the braille blank.
func blank(r rune) bool { return r == 0x2800 || unicode.Is(unicode.Zs, r) }

// plain: printable ASCII, newlines and tabs only, which Text leaves as they are.
func plain(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 0x20 && c != '\n' && c != '\t') || c >= 0x7f {
			return false
		}
	}
	return true
}

// hidden reports the invisible characters: the two invisible classes inside the categories of text
// (Other_Default_Ignorable_Code_Point, VS17–VS256), and everything outside those categories
// (letters, marks, numbers, punctuation, symbols, separators, private use), that is the controls
// (Cc), the format characters (Cf), surrogates and unassigned code points, but for newline, tab and
// the visible prepended concatenation marks. Text drops them wherever they stand, but for the two
// joiners (Cf), which joined keeps or drops by their neighbours.
func hidden(r rune) bool {
	switch {
	case r == '\n', r == '\t', unicode.Is(unicode.Prepended_Concatenation_Mark, r):
		return false
	case unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r), r >= 0xE0100 && r <= 0xE01EF: // VS17–VS256
		return true
	}
	return !unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S, unicode.Z, unicode.Co)
}

// joiner: ZWNJ and ZWJ (Join_Control), kept where the standard uses them (joined).
func joiner(r rune) bool { return r == 0x200C || r == 0x200D }

// cursiveScripts are the scripts whose letters join (a Joining_Type in ArabicShaping.txt, Unicode 17).
var cursiveScripts = []*unicode.RangeTable{
	unicode.Adlam, unicode.Arabic, unicode.Chorasmian, unicode.Hanifi_Rohingya, unicode.Mandaic, unicode.Manichaean,
	unicode.Mongolian, unicode.Nko, unicode.Old_Uyghur, unicode.Phags_Pa, unicode.Psalter_Pahlavi, unicode.Sogdian,
	unicode.Syriac,
}

// joins reports whether joiner r may stand after base, its last character (a mark of base, a virama)
// and before next: where the standard uses it (Text).
func joins(r, base, last, next rune) bool {
	switch {
	case base < 0:
		return false
	case unicode.IsLetter(base):
		return unicode.In(base, cursiveScripts...) || // a cursive script: joining forms
			unicode.Is(viramas, last) || unicode.Is(viramas, next) || // a conjunct, asked for or kept from forming
			r == 0x200C && (base == 'f' || base == 0x017F) && unicode.IsLetter(next) && unicode.Is(unicode.Latin, next) || // a ligature kept from forming
			unicode.Is(unicode.Khmer, base) && r == 0x200C && (next == 0x17C9 || next == 0x17CA) || // a consonant shifter kept in place
			unicode.Is(unicode.Khmer, base) && next >= 0x17B6 && next <= 0x17C5 || // before a dependent vowel
			r == 0x200D && unicode.Is(unicode.Tifinagh, base) && unicode.IsLetter(next) && unicode.Is(unicode.Tifinagh, next) // a bi-consonant
	}
	return unicode.IsSymbol(base) && unicode.IsSymbol(next) // an emoji ZWJ sequence
}

// selector: a variation selector of the BMP, kept only directly after a base that fits it.
func selector(r rune) bool {
	return (r >= 0xFE00 && r <= 0xFE0F) || (r >= 0x180B && r <= 0x180D) || r == 0x180F
}

// fits reports whether selector sel may follow base: a base its registered sequences have, by class
// where a class holds them and by code point where none does (StandardizedVariants.txt,
// emoji-variation-sequences.txt, Unicode 17).
func fits(base, sel rune) bool {
	switch {
	case sel >= 0x180B && sel <= 0x180F:
		return unicode.IsLetter(base) && unicode.Is(unicode.Mongolian, base)
	case sel == 0xFE0E || sel == 0xFE0F: // text or emoji presentation
		return unicode.Is(emojiCharacters, base)
	case sel >= 0xFE07: // VS8-VS14: no registered sequence
		return false
	case sel >= 0xFE03: // VS4-VS7: rotations
		return unicode.Is(unicode.Egyptian_Hieroglyphs, base)
	case slices.Contains(eastAsianPunctuation, base), slices.Contains(scriptCapitals, base):
		return sel <= 0xFE01
	case slices.Contains(quotationMarks, base):
		return true
	case sel == 0xFE00:
		return slices.Contains(mathVariants, base) || base == 0x1031 || variants(base)
	}
	return variants(base)
}

// The bases of registered sequences that no class holds: East Asian punctuation corner-justified or
// centred, or full-width, with VS1 or VS2; the quotation marks with VS1-VS3 (proportional,
// full-width, the Sibe form); the 26 mathematical script capitals, chancery with VS1 and roundhand
// with VS2; and with VS1, the 25 mathematical symbols that have a variant and the digit zero and the
// full-width digit zero, slashed.
var (
	eastAsianPunctuation = []rune{0x3001, 0x3002, 0xFF01, 0xFF0C, 0xFF0E, 0xFF1A, 0xFF1B, 0xFF1F}
	quotationMarks       = []rune{0x2018, 0x2019, 0x201C, 0x201D}
	scriptCapitals       = []rune{0x210B, 0x2110, 0x2112, 0x211B, 0x212C, 0x2130, 0x2131, 0x2133, 0x1D49C, 0x1D49E,
		0x1D49F, 0x1D4A2, 0x1D4A5, 0x1D4A6, 0x1D4A9, 0x1D4AA, 0x1D4AB, 0x1D4AC, 0x1D4AE, 0x1D4AF, 0x1D4B0, 0x1D4B1,
		0x1D4B2, 0x1D4B3, 0x1D4B4, 0x1D4B5}
	mathVariants = []rune{0x0030, 0x2205, 0x2229, 0x222A, 0x2268, 0x2269, 0x2272, 0x2273, 0x228A, 0x228B, 0x2293,
		0x2294, 0x2295, 0x2297, 0x229C, 0x22DA, 0x22DB, 0x29B7, 0x2A3C, 0x2A3D, 0x2A9D, 0x2A9E, 0x2AAC, 0x2AAD,
		0x2ACB, 0x2ACC, 0xFF10}
)

// variants: the ideographs and the letters of the scripts with registered VS1–VS3 sequences.
func variants(r rune) bool {
	return unicode.Is(unicode.Ideographic, r) ||
		unicode.IsLetter(r) && unicode.In(r, unicode.Myanmar, unicode.Phags_Pa, unicode.Manichaean, unicode.Egyptian_Hieroglyphs)
}

const blackFlag = 0x1F3F4

// subdivisionFlags are the tag sequences that follow U+1F3F4 in the RGI subdivision flags
// (emoji-test.txt: England, Scotland, Wales).
var subdivisionFlags = []string{tagged("gbeng"), tagged("gbsct"), tagged("gbwls")}

func tagged(code string) string {
	var b strings.Builder
	for _, c := range code {
		b.WriteRune(0xE0000 + c)
	}
	b.WriteRune(0xE007F)
	return b.String()
}

// dropped removes the characters dropped wherever they stand, and counts them; joiners and selectors
// are left for joined, which decides them by their neighbours. A run of blanks is written by blanks.
func dropped(s string) (string, int) {
	var b strings.Builder
	b.Grow(len(s))
	removed := 0
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case blank(r):
			n = blanks(&b, s[i:], &removed)
		case r == blackFlag:
			for _, f := range subdivisionFlags {
				if strings.HasPrefix(s[i+n:], f) {
					n += len(f)
					break
				}
			}
			b.WriteString(s[i : i+n])
		case r == utf8.RuneError && n == 1: // not UTF-8
			removed++
		case joiner(r), !hidden(r): // selectors are marks: hidden never drops them
			b.WriteString(s[i : i+n])
		default:
			removed++
		}
		i += n
	}
	return b.String(), removed
}

// blanks writes the run of blanks s starts with (characters dropped wherever they stand may stand
// inside it, and go, counted in removed): one ordinary space if any blank of the run is not U+0020,
// else its spaces as they are. It returns the run's length in bytes.
func blanks(b *strings.Builder, s string, removed *int) int {
	n, spaces, unusual := 0, 0, false
run:
	for n < len(s) {
		r, size := utf8.DecodeRuneInString(s[n:])
		switch {
		case r == ' ':
			spaces++
		case blank(r):
			unusual = true
		case (r == utf8.RuneError && size == 1) || (hidden(r) && !joiner(r)):
			*removed++
		default:
			break run
		}
		n += size
	}
	if unusual {
		b.WriteByte(' ')
	} else {
		b.WriteString(strings.Repeat(" ", spaces))
	}
	return n
}

// joined keeps a joiner where it joins (joins: marks between belong to the letter or the emoji
// before them), one at most; and one selector directly after a base that fits it; and counts the
// ones it removed. Everything else in t is kept as it is: t holds no character hidden drops.
func joined(t string) (string, int) {
	var b strings.Builder
	b.Grow(len(t))
	removed := 0
	last, base := rune(-1), rune(-1) // the last character kept; the last one kept that is not a mark
	for i := 0; i < len(t); {
		r, n := utf8.DecodeRuneInString(t[i:])
		keep := true
		switch {
		case joiner(r):
			next := rune(-1) // at the end there is nothing to join (DecodeRune would give U+FFFD, a symbol)
			if i+n < len(t) {
				next, _ = utf8.DecodeRuneInString(t[i+n:])
			}
			keep = joins(r, base, last, next)
		case selector(r):
			keep = last >= 0 && fits(last, r)
		}
		if keep {
			b.WriteString(t[i : i+n])
			last = r
			if !unicode.IsMark(r) { // a kept joiner becomes the base: a second one in a row is dropped
				base = r
			}
		} else {
			removed++
		}
		i += n
	}
	return b.String(), removed
}

// Hidden returns what the hidden characters of s spell, one line per run: tag characters
// (U+E0020–E007E) as the ASCII they mirror, and two or more variation selectors in a row as bytes in
// the emoji smuggling encoding (VS1–VS16 are 0–15, VS17–VS256 are 16–255). A model can read such runs;
// a person sees nothing. Run the injection scanners on the result, so that a hidden instruction is
// flagged as one, not only removed.
func Hidden(s string) string {
	var runs []string
	var tags, sel []byte
	endTags := func() {
		if len(tags) > 0 {
			runs = append(runs, string(tags))
			tags = tags[:0]
		}
	}
	endSel := func() {
		if len(sel) >= 2 {
			runs = append(runs, strings.ToValidUTF8(string(sel), ""))
		}
		sel = sel[:0]
	}
	for _, r := range s {
		switch {
		case r >= 0xE0020 && r <= 0xE007E:
			endSel()
			tags = append(tags, byte(r-0xE0000))
		case r >= 0xFE00 && r <= 0xFE0F:
			endTags()
			sel = append(sel, byte(r-0xFE00))
		case r >= 0xE0100 && r <= 0xE01EF:
			endTags()
			sel = append(sel, byte(r-0xE0100+16))
		default:
			endTags()
			endSel()
		}
	}
	endTags()
	endSel()
	return strings.Join(runs, "\n")
}

// Author returns author-supplied text as Text cleans it, and whether it must be refused: it carried
// hidden characters beyond the few honest text carries, which WithoutBenign lists and Text takes
// out like the others. A profile, a hosted name or post, a tag value is refused for the rest.
func Author(s string) (string, bool) {
	out, changed := Text(s)
	if !changed {
		return out, false
	}
	_, other := Text(WithoutBenign(s))
	return out, other
}

// WithoutBenign returns s without the hidden characters honest text carries: the directional marks
// LRM, RLM and ALM, which right-to-left text needs around numbers and punctuation (UAX #9, 2.6
// Implicit Directional Marks); the soft hyphen, a hyphenation point that copy-paste brings along
// (The Unicode Standard, 23.2); the Mongolian vowel separator U+180E, which Mongolian spelling uses
// before a final a or e; and one ideographic variation selector (VS17–VS256) after an ideograph,
// a registered glyph variant of a name (UTS #37). A second selector after the same ideograph is no
// variant but a byte, and stays.
func WithoutBenign(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	prev := rune(-1)
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == 0x200E, r == 0x200F, r == 0x061C, r == 0x00AD, r == 0x180E:
		case r >= 0xE0100 && r <= 0xE01EF && prev >= 0 && unicode.Is(unicode.Ideographic, prev):
		default:
			b.WriteString(s[i : i+n]) // bytes that are not UTF-8 stay as they are, for Text to judge
		}
		prev = r
		i += n
	}
	return b.String()
}

// Sparse reports whether the honest marks of s (WithoutBenign's set) stand only where honest text
// needs them. Text an author signs is relayed as signed (a board post, a profile event, a tag value)
// and cannot be cleaned: marks where no text needs them, a soft hyphen after every letter or a run of
// directional marks, would carry about two bits a position to every reader (A2:SEC-9). What each mark
// is for sets where it may stand:
//
//   - never two side by side: one mark does what a run of them would;
//   - a soft hyphen marks a hyphenation point inside a word (The Unicode Standard, 23.2): between
//     letters, with two letters or more after the word's start and before its end, as hyphenation
//     leaves a word's edges (TeX's lefthyphenmin and righthyphenmin are 2 at least, and German rules
//     split off no single letter there), and one letter or more between two soft hyphens: a syllable
//     inside a word can be one letter (Duden's Na-ti-o-nen and The-a-ter, the dictionaries' cat-e-go-ry);
//   - LRM, RLM and ALM resolve the direction of the digits and neutral characters beside them, and
//     at a line's start set its direction (UAX #9, 2.6 Implicit Directional Marks; rules W1-W7,
//     N1-N2, P2): so only in text that holds a right-to-left letter, one in a run of characters
//     that are no letters, where the run holds a digit, separates letters of the two directions with
//     some other character, or begins or ends a line; a run with a digit may hold two, one before
//     its digits and one after them, setting the number off on both sides (RLM(2)RLM, RLM100$RLM);
//   - the Mongolian vowel separator only between a Mongolian letter and a final a or e (The Unicode
//     Standard, chapter 13, Mongolian);
//   - one ideographic variation selector per ideograph of the text, and eight at most
//     (MaxIdeographicSelectors): each selects a registered glyph variant, chiefly of a name (UTS #37),
//     and five place names hold five; each also spells a byte, so an event keeps eight in all its
//     fields together (IdeographicSelectors).
func Sparse(s string) bool {
	n, _ := misplacedMarks([]rune(s), true, false)
	return n == 0
}

// MisplacedMarks counts the honest marks of s (WithoutBenign's set) that stand where no text needs
// them, by Sparse's rules: each mark beside another, each soft hyphen at a word's edge, each Mongolian
// vowel separator but before a final a or e, and each directional mark of a run Sparse refuses (A1
// round 3, PE-6: the detectors judge the honest marks by where they stand, as signed text is judged).
// The ideographic variation selectors are not bounded here: Selectors bounds them per source.
//
// One rule more than Sparse's (ADR-0167 round 7, PRE-1): in text that holds a right-to-left letter
// a directional mark is out of place only beside one alike or in a run of three. Right-to-left text
// writes them wherever a direction is to be settled: the number and date formats of CLDR as ICU's Intl
// writes them ("15 RLM /11 RLM /2026", "50 LRM % LRM", "RLM LRM -1,234.50 RLM $", "A, RLM B"), and
// Apple's Hebrew and Arabic strings before a Latin word, after a comma, at a line's start two of them
// ("RLM LRM tab"), and inside a word after a one-letter prefix. Every mark in place counts toward the
// source's bound (Selectors, RTLLettersPerMark), so this moves marks from hidden units to that bound,
// which grows only with the right-to-left letters a person sees. Sparse keeps its rule: signed text has
// no source to bound it.
func MisplacedMarks(s string) int {
	n, _ := misplacedMarks([]rune(s), false, true)
	return n
}

// directionalMark: LRM, RLM and ALM.
func directionalMark(r rune) bool { return r == 0x200E || r == 0x200F || r == 0x061C }

// misplacedMarks is MisplacedMarks with each mark it counts flagged in bad (a mark beside another
// and in a run Sparse refuses is counted twice, flagged once); ideographic: the ideographic
// selectors past the bound count too (Sparse's rule for signed text); formats: the runs that number
// and date formats write keep their marks (the detectors', not Sparse's). Sparse is true exactly when
// it counts none with ideographic and without formats.
func misplacedMarks(rs []rune, ideographic, formats bool) (n int, bad []bool) {
	bad = make([]bool, len(rs))
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
	rtl := false
	for _, r := range rs {
		if unicode.IsLetter(r) && rightToLeft(r) {
			rtl = true
			break
		}
	}
	// The directional marks, run by run of characters that are no letters (nor their marks).
	dir := func(r rune) int {
		if rightToLeft(r) {
			return 2
		}
		return 1
	}
	formatted := make([]bool, len(rs)) // the marks the detectors take for in place past Sparse's rule (formats)
	// written: the run rs[i:j] holds its directional marks as right-to-left text writes them: no two
	// alike side by side and no three in a row.
	written := func(i, j int) bool {
		for k := i; k < j; k++ {
			if directionalMark(rs[k]) && (k+1 < j && rs[k+1] == rs[k] || k+2 < j && directionalMark(rs[k+1]) && directionalMark(rs[k+2])) {
				return false
			}
		}
		return true
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
			case directionalMark(r):
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
		switch {
		case marks == 0:
		case formats && rtl && written(i, j):
			for k := i; k < j; k++ {
				formatted[k] = directionalMark(rs[k])
			}
		case !rtl || marks > 1 && !wrapped || !(digit || edge || last != next && others > 0):
			n += marks
			for k := i; k < j; k++ {
				bad[k] = bad[k] || directionalMark(rs[k])
			}
		}
		i = j
	}
	ivs, ideographs := 0, 0
	for i, r := range rs {
		switch {
		case i > 0 && honest(i) && honest(i-1) && !(formatted[i] && formatted[i-1]):
			n++
			bad[i] = true
		case r == 0x00AD && (!syllable(segment(i-1, -1)) || !syllable(segment(i+1, 1))):
			n++
			bad[i] = true
		case r == 0x180E && !(mongolian(i-1) && i+1 < len(rs) && (rs[i+1] == 0x1820 || rs[i+1] == 0x1821) && !mongolian(i+2)):
			n++
			bad[i] = true
		case r >= 0xE0100 && r <= 0xE01EF:
			ivs++
		case unicode.Is(unicode.Ideographic, r):
			ideographs++
		}
	}
	if bound := min(ideographs, MaxIdeographicSelectors); ideographic && ivs > bound {
		n += ivs - bound
	}
	return n, bad
}

// Unseen counts the characters of s a person does not see beyond those honest text carries, for the
// detectors of text an agent reads as its instructions (A1 round 3, PE-6: the invisible operators
// U+2061-2064 spell bits that no detector read, nor U+2060, U+206A-206F, the soft hyphen, U+034F, the
// Hangul fillers, U+FFF9-FFFB, the musical format controls, U+180E or U+061C):
//
//   - what Text removes, but the variation selectors (StraySelectors and Selectors judge them), a
//     carriage return before a line feed (a line's end) and bytes that are not UTF-8 (no character),
//     after the honest marks WithoutBenign sets aside;
//   - those marks where they stand out of place (MisplacedMarks): a soft hyphen inside a word, a
//     directional mark that right-to-left text needs and the Mongolian vowel separator before a final
//     a or e are not counted;
//   - the joiners Text keeps by its allowances for Latin text and symbols alone: a ZWNJ after f or the
//     long s before a Latin letter, a joiner between two symbols that are not both emoji (round 3,
//     R2-P3-3: a bit each in plain English, about one f in ten letters). The joiners of the cursive and
//     Indic scripts and of the emoji ZWJ sequences are not counted.
//
// A code point of the emoji blocks that Go's tables leave unassigned is counted as an emoji
// (laterEmoji, round 4): it may be one a later Unicode version added, drawn as itself or as a missing
// glyph's box, and an honest server's newer emoji cost it nothing until Go's tables move.
//
// The honest marks in place are not counted here: one by one they are honest, in number they spell
// bits, and Selectors bounds them per source (MaxHonestMarks). Nor are the directional isolates in
// balanced pairs, nor its embeddings, in text that holds a right-to-left letter (Reorders, round 7):
// they count with the marks in place.
func Unseen(s string) int { return Measure(s).Unseen }

// Counts is what the detectors of text an agent reads as its instructions count in one text (Measure).
type Counts struct {
	Unseen      int // Unseen
	Hyphens     int // the soft hyphens and Mongolian vowel separators in place
	Directional int // the LRM, RLM and ALM in place, and the isolates and embeddings in balanced pairs (a pair one)
	RTL         int // the right-to-left letters
}

// Measure counts s in one pass for Unseen, HonestMarks and Selectors (round 7, R6-COST-1: the marks
// were judged twice).
func Measure(s string) Counts {
	if plain(s) {
		return Counts{}
	}
	rs := []rune(unseenText(s))
	var c Counts
	for _, r := range rs {
		if unicode.IsLetter(r) && rightToLeft(r) {
			c.RTL++
		}
	}
	if pairs, in := isolatePairs(rs); c.RTL > 0 && pairs > 0 {
		c.Directional = pairs
		kept := rs[:0:0]
		for i, r := range rs {
			if !in[i] {
				kept = append(kept, r)
			}
		}
		rs = kept
	}
	t := string(rs)
	out, n := TextCount(WithoutBenign(t))
	mis, bad := misplacedMarks(rs, false, true)
	c.Unseen = n + mis + latinJoiners(out)
	for i, r := range rs {
		switch {
		case bad[i]:
		case r == 0x00AD, r == 0x180E:
			c.Hyphens++
		case directionalMark(r):
			c.Directional++
		}
	}
	return c
}

// isolatePairs finds the directional isolates and embeddings of rs in balanced pairs (in, two per
// pair): an isolate initiator (LRI, RLI or FSI, U+2066-2068) and the PDI (U+2069) that closes it, or
// an embedding (LRE or RLE, U+202A-202B) and the PDF (U+202C) that closes it, in the same line, with
// something between them but other directional controls and marks. Apple's right-to-left
// localizations set off each name they insert with a pair (U+2068 Apple Inc. U+2069; older strings
// LRE ... PDF around an address or a number); a control alone, or a pair around nothing, is none. The
// overrides (LRO and RLO, U+202D-202E) are never in a pair: they turn the letters inside against
// their own direction.
func isolatePairs(rs []rune) (pairs int, in []bool) {
	var isolates, embeddings []int
	control := func(x rune) bool { return bidiControl(x) || directionalMark(x) }
	closes := func(open *[]int, i int) {
		o := (*open)[len(*open)-1]
		*open = (*open)[:len(*open)-1]
		for _, x := range rs[o+1 : i] {
			if !control(x) {
				if in == nil {
					in = make([]bool, len(rs))
				}
				in[o], in[i] = true, true
				pairs++
				return
			}
		}
	}
	for i, r := range rs {
		switch {
		case r >= 0x2066 && r <= 0x2068:
			isolates = append(isolates, i)
		case r == 0x2069 && len(isolates) > 0:
			closes(&isolates, i)
		case r == 0x202A || r == 0x202B:
			embeddings = append(embeddings, i)
		case r == 0x202C && len(embeddings) > 0:
			closes(&embeddings, i)
		case r == '\n':
			isolates, embeddings = isolates[:0], embeddings[:0]
		}
	}
	return pairs, in
}

// Reorders reports what changes the order a person sees of the text around it: a directional
// override (U+202D-202E), or an isolate or embedding (U+2066-2069, U+202A-202C) that is not in a
// balanced pair in text that holds a right-to-left letter (isolatePairs; round 7, PRE-1: Apple's
// right-to-left localizations write a pair around each name they insert, and text without right-to-
// left letters needs none).
func Reorders(s string) bool {
	return strings.ContainsFunc(s, bidiControl) && len(StripReorders(s)) < len(s)
}

// bidiControl: the directional embeddings and overrides U+202A-202E and the isolates U+2066-2069.
func bidiControl(r rune) bool { return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) }

// StripReorders returns s without what Reorders reports: its overrides, and the isolates and
// embeddings that are not in balanced pairs in text that holds a right-to-left letter. The pairs stay.
func StripReorders(s string) string {
	if !strings.ContainsFunc(s, bidiControl) {
		return s
	}
	rs := []rune(s)
	rtl := false
	for _, r := range rs {
		if unicode.IsLetter(r) && rightToLeft(r) {
			rtl = true
			break
		}
	}
	_, in := isolatePairs(rs)
	var b strings.Builder
	for i, r := range rs {
		if bidiControl(r) && !(rtl && in != nil && in[i]) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// unseenText is s as Unseen judges it: without its variation selectors, its line ends as line feeds,
// and the code points laterEmoji takes for emoji as an emoji.
func unseenText(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case unicode.Is(unicode.Variation_Selector, r):
			return -1
		case laterEmoji(r):
			return 0x1F600 // an emoji: its joiners and selectors are judged as an emoji's
		}
		return r
	}, strings.ReplaceAll(s, "\r\n", "\n")) // Map writes a byte that is not UTF-8 as U+FFFD, which is seen
}

// honestMark: the marks of WithoutBenign's set but the ideographic variation selectors (Selectors
// bounds those): LRM, RLM, ALM, the soft hyphen and the Mongolian vowel separator.
func honestMark(r rune) bool {
	return r == 0x200E || r == 0x200F || r == 0x061C || r == 0x00AD || r == 0x180E
}

// MaxHonestMarks is the most honest marks in place (HonestMarks) the texts of one source may hold
// before each further one counts as a hidden unit (Selectors): an MCP server's instructions and tools
// together, a repository's instruction files. One by one they are honest; in number they spell bits
// where no one sees them: a soft hyphen at each hyphenation point of a word or none, a directional
// mark at each line's end or none in English text with one Hebrew letter (ADR-0167 round 6: 20 bytes
// as 85 soft hyphens, RLM or ALM, gave no flag and an allow). Eight, as for the ideographic variants
// and the later emoji. The directional marks have more in right-to-left text (RTLLettersPerMark).
// What the bound leaves is the choice of eight places: log2 C(N, 8) bits for N places, 139 bits
// (about 17 bytes) for the 644,100 hyphenation points of 300 tools of 4 KiB of English, and log2 3
// more a directional mark for the choice among LRM, RLM and ALM (round 7, R6-CAP-1).
const MaxHonestMarks = 8

// RTLLettersPerMark: the directional marks in place of a source have one more place past
// MaxHonestMarks for each RTLLettersPerMark right-to-left letters of its texts (round 7, R6-FP-1).
// Honest right-to-left text needs them: Apple's Hebrew and Arabic strings for macOS hold one in place
// for 19 right-to-left letters and more at the first percentile, Flutter's Hebrew and Persian ones
// nine in 2.4 KB; with twenty no 4 KiB part of them passes the bound. To hold 85 marks a text shows
// some 1,700 right-to-left letters.
const RTLLettersPerMark = 20

// HonestMarks counts the honest marks of s (honestMark) that stand in place, as Unseen judges s (its
// variation selectors aside), and its directional isolates in balanced pairs (Measure).
func HonestMarks(s string) int {
	c := Measure(s)
	return c.Hyphens + c.Directional
}

// laterEmoji reports a code point Go's Unicode tables (17.0) leave unassigned in the blocks where
// Unicode adds its new emoji, U+1F000–1FAFF (431 of them), where its recent versions assigned
// theirs. Text drops it as unassigned; Unseen and the selector counts take it for an emoji.
func laterEmoji(r rune) bool {
	return r >= 0x1F000 && r <= 0x1FAFF && !unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S, unicode.Z,
		unicode.Cc, unicode.Cf, unicode.Co, unicode.Cs)
}

// MaxLaterEmoji is the most code points one source's texts may hold that Unseen takes for emoji
// (laterEmoji) before each further one counts as a hidden unit: an MCP server's instructions and tools
// together. A run of them spells about 8.7 bits a code point, drawn as missing glyphs' boxes (A1
// round 5, the re-review's P3); eight are more newer emoji than an honest server shows before Go's
// tables move, as for the ideographic variants (MaxIdeographicSelectors).
const MaxLaterEmoji = 8

// LaterEmoji counts the code points of s that Unseen takes for emoji (laterEmoji).
func LaterEmoji(s string) int {
	n := 0
	for _, r := range s {
		if laterEmoji(r) {
			n++
		}
	}
	return n
}

// latinJoiners counts the joiners of t, a text Text has cleaned, that stand by the allowances for
// Latin text and symbols alone (Unseen).
func latinJoiners(t string) int {
	n, base := 0, rune(-1) // base: the last character before, marks aside
	rs := []rune(t)
	for i, r := range rs {
		if joiner(r) && base >= 0 && i+1 < len(rs) {
			next := rs[i+1]
			switch {
			case r == 0x200C && (base == 'f' || base == 0x017F) && unicode.IsLetter(next) && unicode.Is(unicode.Latin, next):
				n++
			case unicode.IsSymbol(base) && unicode.IsSymbol(next) && !(unicode.Is(emojiCharacters, base) && unicode.Is(emojiCharacters, next)):
				n++
			}
		}
		if !unicode.IsMark(r) {
			base = r
		}
	}
	return n
}

// MaxIdeographicSelectors is the most ideographic variation selectors (VS17–VS256) signed text keeps:
// in one text (Sparse), and in one event, all its fields together, which its caller counts with
// IdeographicSelectors. Each selects a registered glyph variant, chiefly of a name (UTS #37), and a
// text names a few: five Japanese place names hold five. Each is also a byte in the emoji smuggling
// encoding, spelled whether or not it stands in a run (A2:SEC-9).
const MaxIdeographicSelectors = 8

// IdeographicSelectors returns the bytes the ideographic variation selectors of s spell, in order,
// wherever they stand: VS17–VS256 are 16–255, as in the runs Hidden decodes. One after each ideograph
// forms no run, yet spells as much: the caller bounds them (MaxIdeographicSelectors) and runs the
// injection scanners on what they spell.
func IdeographicSelectors(s string) []byte {
	var out []byte
	for _, r := range s {
		if r >= 0xE0100 && r <= 0xE01EF {
			out = append(out, byte(r-0xE0100+16))
		}
	}
	return out
}

// StraySelectors returns how many variation selectors of s spell bytes instead of selecting a glyph,
// and the byte offset of the first of them, -1 if none (A1-VS-1). The emoji smuggling encoding hides
// a byte in each selector of a run (VS1–VS16 for 0–15, VS17–VS256 for 16–255) after an emoji or any
// other character: nothing of it shows, and a model reads every one. A selector selects a glyph only
// directly after a base its registered sequences have, as Text keeps it (fits), one at most, and
// VS17–VS256 directly after an ideograph, one at most: an ideographic variation sequence (UTS #37),
// which honest CJK text carries in names and Text drops all the same. The rest are stray: a selector
// at the start, after any other base or after another selector (a run), and the ideographic ones past
// MaxIdeographicSelectors, since each of those spells a byte too (IdeographicSelectors). Text changes
// any text with a stray selector. The detectors of text an agent reads as its instructions judge them
// per source (Selectors): a repository's instruction files, an MCP server's tools and instructions.
func StraySelectors(s string) (n, first int) {
	var c Selectors
	return c.Stray(s)
}

// Selectors judges the variation selectors of the texts of one source as one text: the ideographic
// bound (MaxIdeographicSelectors) holds for the source, not for each of its texts, whose number the
// source chooses (an MCP server lists up to 300 tools, a repository holds many rule files; A1-VS-1,
// round 2). It bounds the honest marks in place of the source the same way (Judge, MaxHonestMarks,
// RTLLettersPerMark; rounds 6 and 7). The zero value is a source with no text yet.
type Selectors struct {
	ideographic int // the ideographic variation selectors of the texts so far that stand where one may
	hyphens     int // the soft hyphens and Mongolian vowel separators in place of the texts so far
	directional int // the directional marks in place and isolate pairs of the texts so far
	rtl         int // the right-to-left letters of the texts so far
	emitted     int // the hidden units Judge has given for honest marks so far
}

// Judge counts the source's next text once (Measure): its Unseen count, and how many of its honest
// marks in place stand past the source's bound, after those of the texts before it, each a hidden
// unit. The bound is MaxHonestMarks for the soft hyphens and the directional marks together, with
// one more place for the directional marks for each RTLLettersPerMark right-to-left letters of the
// source. A unit once given is not taken back when a later text's right-to-left letters raise the
// bound: marks never comes out below zero (round 7, R6-FP-1).
func (c *Selectors) Judge(s string) (unseen, marks int) {
	m := Measure(s)
	c.hyphens += m.Hyphens
	c.directional += m.Directional
	c.rtl += m.RTL
	over := max(0, c.hyphens+max(0, c.directional-c.rtl/RTLLettersPerMark)-MaxHonestMarks)
	marks = max(0, over-c.emitted)
	c.emitted += marks
	return m.Unseen, marks
}

// Marks is Judge's second count.
func (c *Selectors) Marks(s string) int {
	_, n := c.Judge(s)
	return n
}

// Stray is StraySelectors for the source's next text: its ideographic selectors count after those of
// the texts before it. A stray one does not count toward the bound.
func (c *Selectors) Stray(s string) (n, first int) {
	first = -1
	prev := rune(-1)
	for i, r := range s {
		stray := false
		switch {
		case selector(r):
			stray = prev < 0 || unicode.Is(unicode.Variation_Selector, prev) || !fits(prev, r) && !(laterEmoji(prev) && r >= 0xFE0E) // round 4: a later emoji's presentation
		case r >= 0xE0100 && r <= 0xE01EF: // VS17–VS256
			stray = prev < 0 || !unicode.Is(unicode.Ideographic, prev)
			if !stray {
				c.ideographic++
				stray = c.ideographic > MaxIdeographicSelectors
			}
		}
		if stray {
			if n == 0 {
				first = i
			}
			n++
		}
		prev = r
	}
	return n, first
}

// rightToLeftScripts are the scripts whose letters are right to left (bidirectional class R or AL in
// Unicode 17's UnicodeData).
var rightToLeftScripts = []*unicode.RangeTable{
	unicode.Adlam, unicode.Arabic, unicode.Avestan, unicode.Chorasmian, unicode.Cypriot, unicode.Elymaic, unicode.Garay,
	unicode.Hanifi_Rohingya, unicode.Hatran, unicode.Hebrew, unicode.Imperial_Aramaic, unicode.Inscriptional_Pahlavi,
	unicode.Inscriptional_Parthian, unicode.Kharoshthi, unicode.Lydian, unicode.Mandaic, unicode.Manichaean,
	unicode.Mende_Kikakui, unicode.Meroitic_Cursive, unicode.Meroitic_Hieroglyphs, unicode.Nabataean, unicode.Nko,
	unicode.Old_Hungarian, unicode.Old_North_Arabian, unicode.Old_Sogdian, unicode.Old_South_Arabian, unicode.Old_Turkic,
	unicode.Old_Uyghur, unicode.Palmyrene, unicode.Phoenician, unicode.Psalter_Pahlavi, unicode.Samaritan, unicode.Sidetic,
	unicode.Sogdian, unicode.Syriac, unicode.Thaana, unicode.Yezidi,
}

func rightToLeft(r rune) bool { return r >= 0x0590 && unicode.In(r, rightToLeftScripts...) } // none below Hebrew (TestRightToLeftBelowHebrew)

// Visible returns s with each invisible character, directional controls too, as a JSON escape: what
// Text drops wherever it stands, the joiners and every variation selector, as \uXXXX (lowercase hex;
// a code point above U+FFFF as its UTF-16 surrogate pair), and a byte that is not UTF-8 as \ufffd,
// as a JSON decoder reads it. It is for evidence, which must keep every character: inside JSON text
// the result decodes to the same characters, and as text a person sees each one. Text without any
// comes back unchanged, byte for byte.
func Visible(s string) string {
	i := 0
	for i < len(s) {
		r, n := utf8.DecodeRuneInString(s[i:])
		if (r == utf8.RuneError && n == 1) || invisible(r) {
			break
		}
		i += n
	}
	if i == len(s) {
		return s
	}
	const hexDigits = "0123456789abcdef"
	var b strings.Builder
	b.Grow(len(s) + 16)
	b.WriteString(s[:i])
	esc := func(u rune) {
		b.WriteString(`\u`)
		for shift := 12; shift >= 0; shift -= 4 {
			b.WriteByte(hexDigits[(u>>shift)&15])
		}
	}
	for i < len(s) {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && n == 1:
			esc(0xFFFD)
		case invisible(r) && r > 0xFFFF:
			r -= 0x10000
			esc(0xD800 + r>>10)
			esc(0xDC00 + r&0x3FF)
		case invisible(r):
			esc(r)
		default:
			b.WriteString(s[i : i+n])
		}
		i += n
	}
	return b.String()
}

// invisible: what Visible and EscapeHidden escape, hidden's characters (the joiners among them) and
// every variation selector.
func invisible(r rune) bool {
	return hidden(r) || unicode.Is(unicode.Variation_Selector, r)
}

// EscapeHidden returns s with each invisible character (Visible's set) and each byte that is not
// UTF-8 percent-encoded, as %XX of its bytes. It is for identifiers: a URL, a host name, a network
// id. They keep their identity (removing a character could name another resource; a server decodes
// %XX as the bytes it stands for) and show what they hold. Letters of any script stay as they are:
// a catalogue row's id is a hash of its URL as stored, and a visible letter must not move it.
func EscapeHidden(s string) string {
	i := 0
	for i < len(s) {
		r, n := utf8.DecodeRuneInString(s[i:])
		if (r == utf8.RuneError && n == 1) || invisible(r) {
			break
		}
		i += n
	}
	if i == len(s) {
		return s
	}
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s) + 16)
	b.WriteString(s[:i])
	for i < len(s) {
		r, n := utf8.DecodeRuneInString(s[i:])
		if (r == utf8.RuneError && n == 1) || invisible(r) {
			for _, c := range []byte(s[i : i+n]) {
				b.WriteByte('%')
				b.WriteByte(hexDigits[c>>4])
				b.WriteByte(hexDigits[c&15])
			}
		} else {
			b.WriteString(s[i : i+n])
		}
		i += n
	}
	return b.String()
}
