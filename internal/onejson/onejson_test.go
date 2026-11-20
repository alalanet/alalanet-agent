package onejson

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"unicode"
)

const (
	longS  = "\u017f" // folds to s
	kelvin = "\u212a" // folds to k
)

type inner struct {
	Kind int    `json:"kind"`
	Name string `json:"name"`
}

type doc struct {
	Service string            `json:"service"`
	PayTo   string            `json:"payTo"`
	Items   []inner           `json:"items"`
	One     *inner            `json:"one,omitempty"`
	Tags    map[string]string `json:"tags"`
	ByName  map[string]inner  `json:"by_name"`
	Raw     json.RawMessage   `json:"raw"`
	Untag   string
	skip    string // an unexported field names nothing
	Dash    string `json:"-"`
}

func TestStrictRefusesTwoReadings(t *testing.T) {
	for name, c := range map[string]string{
		"long s variant of a field":       `{"service":"a","` + longS + `ervice":"b"}`,
		"long s variant alone":            `{"` + longS + `ervice":"b"}`,
		"kelvin variant in a nested one":  `{"items":[{"kind":1,"` + kelvin + `ind":2}]}`,
		"ASCII case variant":              `{"payTo":"a","PayTo":"b"}`,
		"ASCII case variant behind a ptr": `{"one":{"Name":"x"}}`,
		"untagged field in another case":  `{"untag":"x"}`,
		"exact repeat":                    `{"service":"a","service":"b"}`,
		"unknown names that fold":         `{"note":"a","Note":"b"}`,
		"unknown names, long s":           `{"sum":1,"` + longS + `um":2}`,
		"exact repeat inside a map":       `{"tags":{"a":"1","a":"2"}}`,
		"a field in a map's struct":       `{"by_name":{"x":{"Kind":1}}}`,
		"exact repeat in an unknown":      `{"x":{"a":1,"a":2}}`,
	} {
		var d doc
		if err := Strict([]byte(c), &d); !errors.Is(err, ErrTwoReadings) {
			t.Errorf("%s: %v, want ErrTwoReadings", name, err)
		}
	}
}

func TestStrictReadsOneWay(t *testing.T) {
	in := `{"service":"s1","payTo":"p","items":[{"kind":4321,"name":"n"}],"one":{"kind":1},"tags":{"a":"1","A":"2"},` +
		`"raw":{"x":[1,2]},"Untag":"u","later_field":{"Note":1,"note":2},"skip":"no","Dash":"no"}`
	var d doc
	if err := Strict([]byte(in), &d); err != nil {
		t.Fatal(err)
	}
	if d.Service != "s1" || d.PayTo != "p" || len(d.Items) != 1 || d.Items[0].Kind != 4321 || d.One == nil || d.One.Kind != 1 ||
		d.Tags["a"] != "1" || d.Tags["A"] != "2" || string(d.Raw) != `{"x":[1,2]}` || d.Untag != "u" || d.skip != "" || d.Dash != "" {
		t.Fatalf("%+v", d)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(in), &m); err != nil || m["service"] != d.Service || m["payTo"] != d.PayTo {
		t.Fatalf("a case-sensitive reader: %v %v", m, err)
	}
}

func TestStrictRefusesWhatIsNotOneValue(t *testing.T) {
	for name, c := range map[string]string{
		"data after":   `{"service":"a"} {}`,
		"invalid utf8": "{\"service\":\"a\xff\"}",
		"cut short":    `{"service":"a"`,
		"not JSON":     `x`,
		"wrong type":   `{"service":1}`,
	} {
		var d doc
		if err := Strict([]byte(c), &d); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	var d doc
	if err := Strict([]byte(`{}`), d); err == nil {
		t.Error("a non-pointer was accepted")
	}
	if err := Strict([]byte(" {\"service\":\"a\"}\n"), &d); err != nil || d.Service != "a" {
		t.Errorf("spaces: %v %+v", err, d)
	}
}

// A value with its own UnmarshalJSON is read by it: names inside it are not this package's to judge.
type own struct{ got string }

func (o *own) UnmarshalJSON(b []byte) error { o.got = string(b); return nil }

func TestStrictLeavesAnUnmarshalerItsValue(t *testing.T) {
	var d struct {
		O own `json:"o"`
	}
	if err := Strict([]byte(`{"o":{"a":1,"A":2}}`), &d); err != nil || d.O.got != `{"a":1,"A":2}` {
		t.Fatalf("%v %q", err, d.O.got)
	}
}

func TestAsJSONParse(t *testing.T) {
	var d doc
	in := `{"payTo":"a","PayTo":"b","` + longS + `ervice":"x","service":"s","items":[{"kind":1,"name":"first"}],"items":[{"kind":2}],` +
		`"tags":{"k":"v"},"Tags":null,"one":{"kind":1,"name":"n"},"one":{"kind":2},"raw":[1],"raw":{"r":true}}`
	if err := AsJSONParse([]byte(in), &d); err != nil {
		t.Fatal(err)
	}
	if d.PayTo != "a" || d.Service != "s" || len(d.Items) != 1 || d.Items[0].Kind != 2 || d.Items[0].Name != "" ||
		d.Tags["k"] != "v" || d.One == nil || d.One.Kind != 2 || d.One.Name != "" || string(d.Raw) != `{"r":true}` {
		t.Fatalf("not JSON.parse's reading: %+v", d)
	}
	var s struct {
		S string `json:"s"`
	}
	if err := AsJSONParse([]byte("{\"s\":\"a\xffb\"}"), &s); err != nil || s.S != "a�b" {
		t.Fatalf("invalid UTF-8: %v %q", err, s.S)
	}
	for _, bad := range []string{`{"s":"a"} 1`, `{"s":`, `{"s":1}`} {
		if err := AsJSONParse([]byte(bad), &s); err == nil {
			t.Errorf("%s: accepted", bad)
		}
	}
	// A field's name in another case alone is a member JSON.parse keeps under that name: the field stays empty.
	var only doc
	if err := AsJSONParse([]byte(`{"PayTo":"b","items":[{"`+kelvin+`ind":3,"name":"n"}],"Untag":"u"}`), &only); err != nil ||
		only.PayTo != "" || len(only.Items) != 1 || only.Items[0].Kind != 0 || only.Items[0].Name != "n" || only.Untag != "u" {
		t.Fatalf("variants alone: %v %+v", err, only)
	}
	// What encoding/json tolerated it still does: a value of another type leaves its field empty, the rest is read.
	var tol doc
	err := AsJSONParse([]byte(`{"service":5,"payTo":"p","tags":{"a":"1"}}`), &tol)
	var te *json.UnmarshalTypeError
	if !errors.As(err, &te) || tol.Service != "" || tol.PayTo != "p" || tol.Tags["a"] != "1" {
		t.Fatalf("another type: %v %+v", err, tol)
	}
	var deep any
	if err := AsJSONParse([]byte(strings.Repeat("[", 500)+strings.Repeat("]", 500)), &deep); err != nil {
		t.Fatalf("nested arrays: %v", err)
	}
}

// Fold is one rune of each simple-fold orbit, the same for the whole orbit: Fold(a) == Fold(b) exactly when
// strings.EqualFold(a, b), checked for every rune.
func TestFoldIsEqualFold(t *testing.T) {
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue
		}
		f := Fold(string(r))
		if !strings.EqualFold(f, string(r)) {
			t.Fatalf("Fold(%U) = %q is not in its orbit", r, f)
		}
		for o := unicode.SimpleFold(r); o != r; o = unicode.SimpleFold(o) {
			if Fold(string(o)) != f {
				t.Fatalf("Fold(%U) = %q, Fold(%U) = %q", r, f, o, Fold(string(o)))
			}
		}
	}
	if Fold("tru"+longS+"t_revi"+longS+"ion") != Fold("TRUST_REVISION") || Fold(kelvin+"ind") != Fold("kind") || Fold("a") == Fold("b") {
		t.Fatal("examples")
	}
}
