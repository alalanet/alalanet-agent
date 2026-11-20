package tooldigest

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"unicode/utf16"

	sjson "github.com/segmentio/encoding/json"
)

// Adopted from the batch P3 review of 8c0c02ae (its sub-reviewer's zz_review_samevalue_test.go, P3-4): SameValue is
// true exactly when two JSON strings hold the same UTF-16 code units, however each unit is written, and whenever it
// is true both Go decoders (encoding/json, segmentio) read the same text.

// writeUnits writes the code units u as a JSON string, each unit chosen at random raw or escaped.
func writeUnits(rng *rand.Rand, u []uint16) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(u); i++ {
		c := u[i]
		if utf16.IsSurrogate(rune(c)) && i+1 < len(u) && utf16.DecodeRune(rune(c), rune(u[i+1])) != 0xFFFD && rng.Intn(2) == 0 {
			b.WriteRune(utf16.DecodeRune(rune(c), rune(u[i+1])))
			i++
			continue
		}
		if utf16.IsSurrogate(rune(c)) || c < 0x20 || c == '"' || c == '\\' || rng.Intn(2) == 0 {
			switch {
			case c == '"' && rng.Intn(2) == 0:
				b.WriteString(`\"`)
			case c == '/' && rng.Intn(2) == 0:
				b.WriteString(`\/`)
			case c == '\n' && rng.Intn(2) == 0:
				b.WriteString(`\n`)
			default:
				if rng.Intn(2) == 0 {
					fmt.Fprintf(&b, `\u%04x`, c)
				} else {
					fmt.Fprintf(&b, `\u%04X`, c)
				}
			}
			continue
		}
		b.WriteRune(rune(c))
	}
	b.WriteByte('"')
	return b.String()
}

func randUnits(rng *rand.Rand) []uint16 {
	pool := []uint16{'a', 'b', '"', '\\', '/', '\n', 0, 0xe9, 0xd83d, 0xde00, 0xd800, 0xdc00, 0xdbff, 0xfffd, 0x2028, 0xfeff}
	n := rng.Intn(6)
	u := make([]uint16, n)
	for i := range u {
		u[i] = pool[rng.Intn(len(pool))]
	}
	return u
}

func TestReviewSameValueProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for k := 0; k < 200000; k++ {
		ua, ub := randUnits(rng), randUnits(rng)
		if rng.Intn(3) == 0 {
			ub = ua
		}
		a, b := writeUnits(rng, ua), writeUnits(rng, ub)
		var ga, gb, sa, sb string
		if json.Unmarshal([]byte(a), &ga) != nil || json.Unmarshal([]byte(b), &gb) != nil {
			t.Fatalf("invalid %s %s", a, b)
		}
		if sjson.Unmarshal([]byte(a), &sa) != nil || sjson.Unmarshal([]byte(b), &sb) != nil {
			t.Fatalf("segmentio invalid %s %s", a, b)
		}
		same := SameValue([]byte(a), []byte(b))
		unitsEq := fmt.Sprint(ua) == fmt.Sprint(ub)
		if same != unitsEq {
			t.Fatalf("SameValue(%s,%s)=%v, units equal %v", a, b, same, unitsEq)
		}
		if same && (ga != gb || sa != sb || ga != sa) {
			t.Fatalf("SameValue(%s,%s) true but go %q/%q segmentio %q/%q", a, b, ga, gb, sa, sb)
		}
		// key position
		oa, ob := `{`+a+`:1}`, `{ `+b+` : 1 }`
		if SameValue([]byte(oa), []byte(ob)) != unitsEq {
			t.Fatalf("object %s %s", oa, ob)
		}
	}
}

// Hostile size: a long string of escapes compared to its raw form.
func BenchmarkReviewSameValueLong(b *testing.B) {
	n := 4 << 20
	raw := `"` + strings.Repeat("a", n) + `"`
	esc := `"` + strings.Repeat(`\u0061`, n) + `"`
	for i := 0; i < b.N; i++ {
		if !SameValue([]byte(raw), []byte(esc)) {
			b.Fatal("not same")
		}
	}
}

func FuzzReviewSameValue(f *testing.F) {
	f.Add([]byte(`"a\u00"`), []byte(`{"a":[1,"\ud800"]}`))
	f.Add([]byte(`"\`), []byte(`"`))
	f.Fuzz(func(t *testing.T, a, b []byte) {
		_ = SameValue(a, b)
		if len(a) > 0 && len(b) > 0 {
			_ = sameInstructions(a, b)
		}
		_ = ReadInstructions(append(append([]byte(`{"instructions":`), a...), '}'))
	})
}
