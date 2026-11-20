package tooldigest

import "testing"

// FN10-TOOLDESC-NULL P3-1: SameValue says whether two JSON values read the same to every reader: the same
// tokens, a string the same UTF-16 code units however escaped, white space aside.
func TestSameValue(t *testing.T) {
	for _, c := range []struct {
		a, b string
		same bool
	}{
		{`"a"`, `"a"`, true},
		{`"a"`, `"\u0061"`, true},
		{`"Use search."`, `"Use\u0020search."`, true},
		{`"\u00E9"`, `"\u00e9"`, true},
		{"\"\u00e9\"", `"\u00e9"`, true},           // the raw letter and its escape
		{"\"\U0001F600\"", `"\ud83d\ude00"`, true}, // a raw character beyond the BMP and its surrogate pair
		{`"\/"`, `"/"`, true},                      // the escaped solidus
		{`"\n\t\b\f\r\"\\"`, `"\u000a\u0009\u0008\u000c\u000d\u0022\u005c"`, true},
		{`"\ud800"`, `"\ud800"`, true},
		{`"\ud800"`, `"\ufffd"`, false}, // JSON.parse keeps a lone surrogate; Go replaces it
		{`"\ud83d\ude00"`, `"\ude00\ud83d"`, false},
		{`"a"`, `"b"`, false},
		{`"a"`, `"a "`, false},
		{`"a"`, `"A"`, false},
		{`""`, `"\u0000"`, false},
		{"\"a\xffb\"", "\"a\xffb\"", true}, // not UTF-8: compared as written
		{"\"a\xffb\"", `"a\ufffdb"`, false},
		{"\"a\xffb\"", "\"a\xfeb\"", false},
		{`1`, `1`, true},
		{`1`, `1.0`, false}, // Python reads an int and a float
		{`1e2`, `100`, false},
		{`-0`, `0`, false},
		{`true`, `true`, true},
		{`true`, `false`, false},
		{`null`, `null`, true},
		{` null `, `null`, true},
		{`null`, `"null"`, false},
		{`{"a":1}`, `{ "a" : 1 }`, true},
		{`{"\u0061":"x"}`, `{"a":"\u0078"}`, true},
		{`{"a":1,"b":2}`, `{"b":2,"a":1}`, false}, // members in another order: a host passes them on in order
		{`{"title":"x","title":null}`, `{"title":null}`, false},
		{`{"title":"x","title":null}`, `{"title":"x","title":null}`, true},
		{`[1,"a"]`, "[ 1 ,\n\t\"\\u0061\" ]", true},
		{`[1,2]`, `[1,2,3]`, false},
		{`[]`, `{}`, false},
		{`"a"`, `a`, false},
		{`"\u006"`, `"\u006"`, true}, // not valid JSON (no caller passes it): compared as written
		{`"\u006x"`, `"\u006y"`, false},
		{`"\q"`, `"q"`, false},
		{``, ``, true},
		{``, `null`, false},
	} {
		if got := SameValue([]byte(c.a), []byte(c.b)); got != c.same {
			t.Errorf("SameValue(%s, %s) = %v, want %v", c.a, c.b, got, c.same)
		}
		if got := SameValue([]byte(c.b), []byte(c.a)); got != c.same {
			t.Errorf("SameValue(%s, %s) = %v, want %v", c.b, c.a, got, c.same)
		}
	}
	if !SameValue(nil, nil) || SameValue(nil, []byte(`null`)) {
		t.Error("nil")
	}
}
