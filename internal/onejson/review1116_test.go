package onejson

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// The review of develop's trust-onereading (review-1116/onereading, P3-2), adopted: names JSON.parse keeps apart
// stay apart, or the document is refused. The decoder reads each invalid byte and each lone surrogate escape as one
// U+FFFD; Node keeps "a" plus a lone high surrogate and "a" plus a lone low one as two names, and reads a truncated
// sequence as one U+FFFD and two bad bytes as two.
func TestAsJSONParseKeepsNamesApart(t *testing.T) {
	for name, in := range map[string]string{
		"truncated sequence vs two bad bytes": "{\"a\xe2\x82\":{\"url\":\"https://evil\"},\"a\xff\xff\":{\"url\":\"https://ok\"}}",
		"one bad byte vs two":                 "{\"a\xff\":{\"url\":\"https://evil\"},\"a\xff\xfe\":{\"url\":\"https://ok\"}}",
		"two lone surrogates":                 `{"a\ud800":{"url":"https://evil"},"a\udc00":{"url":"https://ok"}}`,
		"lone surrogate vs U+FFFD":            `{"a\ud800":{"url":"https://evil"},"a\ufffd":{"url":"https://ok"}}`,
		"a lone surrogate alone, nested":      `{"ok":{"x\udfff":1}}`,
	} {
		var m map[string]struct {
			URL string `json:"url"`
		}
		if err := AsJSONParse([]byte(in), &m); !errors.Is(err, ErrNameApart) {
			t.Errorf("%s: %v, %d names %v", name, err, len(m), m)
		}
	}
	// A valid pair, an escaped name and a value with invalid UTF-8 are read as before.
	var m map[string]string
	if err := AsJSONParse([]byte("{\"a\\ud83d\\ude00\":\"1\",\"\\u0062\":\"2\",\"c\":\"x\xffy\"}"), &m); err != nil ||
		len(m) != 3 || m["a\U0001F600"] != "1" || m["b"] != "2" || m["c"] != "x\uFFFDy" {
		t.Fatalf("%v %q", err, m)
	}
}

// What a dropped member holds is skipped with it, at any depth: the plan of the first pass and the copy of the
// second stay in step.
func TestAsJSONParseSkipsWhatADroppedMemberHolds(t *testing.T) {
	type in struct {
		Kind int `json:"kind"`
	}
	var d struct {
		A  map[string]any `json:"a"`
		B  int            `json:"b"`
		In []in           `json:"in"`
		C  map[string]int `json:"c"`
	}
	src := `{"a":{"x":1,"y":{"z":2,"z":3},"y":[{"q":1}]},"b":1,"In":[{"kind":9,"Kind":8}],"in":[{"Kind":7,"kind":2,"o":{"p":{"r":1}}}],` +
		`"a":{"w":{"v":4}},"b":2,"c":{"m":1,"n":{"deep":[{"k":1}]},"m":5}}`
	if err := AsJSONParse([]byte(src), &d); err == nil {
		t.Fatal("c's n is not an int: the error encoding/json gives is kept")
	}
	if len(d.A) != 1 || d.A["w"] == nil || d.B != 2 || len(d.In) != 1 || d.In[0].Kind != 2 || d.C["m"] != 5 {
		t.Fatalf("%+v", d)
	}
	var w struct {
		A map[string]map[string]any `json:"a"`
		Z int                       `json:"z"`
	}
	if err := AsJSONParse([]byte(`{"a":{"k":{"x":{"y":1}},"k":{"u":2}},"Z":5,"z":{"bad":[1]},"z":6}`), &w); err != nil ||
		len(w.A["k"]) != 1 || w.A["k"]["u"] != float64(2) || w.Z != 6 {
		t.Fatalf("%v %+v", err, w)
	}
}

// review-1116/onereading P3-1: a value nested d deep was copied d times; a 4 MiB package.json (the tarball reader's
// cap) with a string 9,000 arrays deep took 3.9 s against encoding/json's 4 ms. The rewrite is linear now: bounded
// by a multiple of encoding/json's own time on the same input, with room for -race and a loaded runner.
func TestAsJSONParseCostIsLinear(t *testing.T) {
	for _, depth := range []int{1, 1000, 9000} {
		big := strings.Repeat("x", 4<<20-2*depth-64)
		in := []byte(`{"scripts":` + strings.Repeat("[", depth) + `"` + big + `"` + strings.Repeat("]", depth) + `,"gypfile":true}`)
		var pj struct {
			Scripts any  `json:"scripts"`
			Gypfile bool `json:"gypfile"`
		}
		t0 := time.Now()
		if err := json.Unmarshal(in, &pj); err != nil {
			t.Fatal(err)
		}
		base := time.Since(t0)
		pj.Gypfile = false
		t0 = time.Now()
		if err := AsJSONParse(in, &pj); err != nil || !pj.Gypfile {
			t.Fatalf("depth %d: %v", depth, err)
		}
		took := time.Since(t0)
		t.Logf("depth %d, %d bytes: encoding/json %v, AsJSONParse %v", depth, len(in), base, took)
		if limit := 25*base + 500*time.Millisecond; took > limit {
			t.Errorf("depth %d: AsJSONParse took %v, over %v (encoding/json %v)", depth, took, limit, base)
		}
	}
}

// A struct held in a map, or in a slice in a map, is guided too: a field's name in another case beside it is
// dropped there as at the top (the develop round's mutant P5, the plan not guiding map values, survived without
// this). JSON.parse reads "url" as A; encoding/json would read "URL" over it as B.
func TestAsJSONParseGuidesStructsInMaps(t *testing.T) {
	type server struct {
		URL string `json:"url"`
	}
	var m map[string]server
	if err := AsJSONParse([]byte(`{"a":{"url":"A","URL":"B"},"b":{"Url":"B2"}}`), &m); err != nil ||
		m["a"].URL != "A" || len(m) != 2 || m["b"].URL != "" {
		t.Fatalf("a map of structs: %v %+v", err, m)
	}
	var ms map[string][]server
	if err := AsJSONParse([]byte(`{"a":[{"url":"A","URL":"B"},{"url":"C","uRL":"D"}]}`), &ms); err != nil ||
		len(ms["a"]) != 2 || ms["a"][0].URL != "A" || ms["a"][1].URL != "C" {
		t.Fatalf("a slice of structs in a map: %v %+v", err, ms)
	}
	var nested struct {
		Servers map[string]map[string]server `json:"servers"`
	}
	if err := AsJSONParse([]byte(`{"servers":{"x":{"y":{"url":"A","URL":"B"}}}}`), &nested); err != nil || nested.Servers["x"]["y"].URL != "A" {
		t.Fatalf("a map of maps of structs: %v %+v", err, nested)
	}
}
