package tooldigest

import (
	"bytes"
	"slices"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// SameValue says whether the JSON values a and b, each valid JSON as written, read the same to every reader
// (FN10-TOOLDESC-NULL P3-1): the same tokens in the same order, white space between them aside, each string
// the same text however escaped — the same UTF-16 code units, which is what JSON.parse gives and what Go and
// Python decode the same way from. A number is compared as written (1 and 1.0 are an int and a float to
// Python), members in another order are another value (a host passes them on in order), and a string that is
// not UTF-8 as written, or whose escapes cannot be read, is compared byte for byte (readers replace such bytes,
// or refuse them, each in its own way).
func SameValue(a, b []byte) bool {
	i, j := Space(a, 0), Space(b, 0)
	for i < len(a) && j < len(b) {
		if a[i] == '"' && b[j] == '"' {
			ea, eb := StringEnd(a, i), StringEnd(b, j)
			if !sameString(a[i:ea], b[j:eb]) {
				return false
			}
			i, j = Space(a, ea), Space(b, eb)
			continue
		}
		if a[i] != b[j] {
			return false
		}
		i, j = Space(a, i+1), Space(b, j+1)
	}
	return i >= len(a) && j >= len(b)
}

// sameString says whether two JSON strings, quotes included, give the same code units.
func sameString(a, b []byte) bool {
	if bytes.Equal(a, b) {
		return true
	}
	ua, oka := codeUnits(a)
	ub, okb := codeUnits(b)
	return oka && okb && slices.Equal(ua, ub)
}

// codeUnits is the UTF-16 code units of the JSON string s, quotes included, as JSON.parse reads it: an escape
// gives its unit, \uXXXX the unit XXXX even when it is half of a pair; false for bytes that are not UTF-8,
// an escape that cannot be read, or a string not closed.
func codeUnits(s []byte) ([]uint16, bool) {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return nil, false
	}
	s = s[1 : len(s)-1]
	out := make([]uint16, 0, len(s))
	for i := 0; i < len(s); {
		switch c := s[i]; {
		case c == '\\':
			if i+1 >= len(s) {
				return nil, false
			}
			if s[i+1] == 'u' {
				if i+6 > len(s) {
					return nil, false
				}
				v, err := strconv.ParseUint(string(s[i+2:i+6]), 16, 16)
				if err != nil {
					return nil, false
				}
				out = append(out, uint16(v))
				i += 6
				continue
			}
			u, ok := escapes[s[i+1]]
			if !ok {
				return nil, false
			}
			out = append(out, u)
			i += 2
		case c < utf8.RuneSelf:
			out = append(out, uint16(c))
			i++
		default:
			r, n := utf8.DecodeRune(s[i:])
			if r == utf8.RuneError && n == 1 {
				return nil, false
			}
			out = utf16.AppendRune(out, r)
			i += n
		}
	}
	return out, true
}

// escapes are JSON's two-character escapes and the units they give.
var escapes = map[byte]uint16{'"': '"', '\\': '\\', '/': '/', 'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t'}
