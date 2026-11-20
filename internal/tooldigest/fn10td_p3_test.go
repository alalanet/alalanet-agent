package tooldigest

import (
	"fmt"
	"slices"
	"testing"
)

// P3-1: instructions given more than once are ambiguous when some client reads the values differently, and
// only then: the same text written with another escaping is no difference; null, a string and a value of
// another type are three readings; two values of another type are refused by every client alike.
func TestReadInstructionsComparesTheReading(t *testing.T) {
	for _, c := range []struct {
		result    string
		text      string
		isNil     bool
		others    []string
		ambiguous bool
	}{
		{`{"instructions":"a","instructions":"\u0061"}`, "a", false, nil, false},
		{`{"instructions":"Use search.","instructions":"Use\u0020search.","instructions":"Use search\u002e"}`, "Use search.", false, nil, false},
		{"{\"instructions\":\"caf\u00e9\",\"instructions\":\"caf\\u00e9\"}", "caf\u00e9", false, nil, false},
		{`{"instructions":"a","instructions":"a"}`, "a", false, nil, false},
		{`{"instructions":"\ud800","instructions":"\ufffd"}`, "\ufffd", false, nil, true},
		{`{"instructions":"a","instructions":"b"}`, "b", false, []string{"a"}, true},
		{`{"instructions":"a","instructions":"\u0062"}`, "b", false, []string{"a"}, true},
		{`{"instructions":"a","instructions":null}`, "a", false, nil, true},
		{`{"instructions":null,"instructions":null}`, "", true, nil, false},
		{`{"instructions":1,"instructions":2}`, "", false, nil, false},
		{`{"instructions":1,"instructions":{"text":"a"}}`, "", false, nil, false},
		{`{"instructions":1,"instructions":"a"}`, "a", false, nil, true},
		{`{"instructions":"a","instructions":1}`, "", false, []string{"a"}, true},
		{`{"instructions":1,"instructions":null}`, "", false, nil, true},
		{`{"instructions":"a","instructions":"\u0061","instructions":"b"}`, "b", false, []string{"a"}, true},
	} {
		in := ReadInstructions([]byte(c.result))
		if (in.Text == nil) != c.isNil || in.TextOf() != c.text || fmt.Sprint(in.Others) != fmt.Sprint(c.others) || in.Ambiguous != c.ambiguous {
			t.Errorf("%s: text nil %v %q, others %q, ambiguous %v; want nil %v %q, others %q, ambiguous %v", c.result,
				in.Text == nil, in.TextOf(), in.Others, in.Ambiguous, c.isNil, c.text, c.others, c.ambiguous)
		}
		if got := in.Flags(nil); slices.Contains(got, InstructionsAmbiguous) != c.ambiguous {
			t.Errorf("%s: flags %q", c.result, got)
		}
	}
}

// P3-1 stops at instructions: a tool's members keep FN-10's rule, under which a name the prober reads given
// twice marks the tool whatever the values (a strict reader, such as a serde-derived struct, refuses a
// repeated field). The same text escaped otherwise is still marked, and the digest is the one the tool given
// once has, as before: no tool digest changes.
func TestToolRepeatsKeepFN10Rule(t *testing.T) {
	for _, c := range []struct{ repeated, once string }{
		{`{"name":"s","description":"a","description":"\u0061"}`, `{"name":"s","description":"a"}`},
		{`{"name":"s","name":"\u0073","description":"a"}`, `{"name":"s","description":"a"}`},
		{`{"name":"s","title":"T","title":"\u0054"}`, `{"name":"s","title":"T"}`},
		{`{"name":"s","annotations":{"title":"t","title":"\u0074","readOnlyHint":true,"readOnlyHint":true}}`, `{"name":"s","annotations":{"title":"t","readOnlyHint":true}}`},
		{`{"name":"s","inputSchema":{"type":"object"},"inputSchema":{ "type" : "object" }}`, `{"name":"s","inputSchema":{"type":"object"}}`},
		{`{"name":"s","annotations":{"readOnlyHint":true},"annotations":{"readOnlyHint":true}}`, `{"name":"s","annotations":{"readOnlyHint":true}}`},
	} {
		_, amb, err := ReadTool([]byte(c.repeated))
		if err != nil || !amb {
			t.Errorf("%s: ambiguous %v, %v", c.repeated, amb, err)
		}
		h1, _, _, ok1 := ParseTools([]byte(`{"tools":[` + c.repeated + `]}`))
		h2, _, _, ok2 := ParseTools([]byte(`{"tools":[` + c.once + `]}`))
		if !ok1 || !ok2 || h1 != h2 {
			t.Errorf("%s: digest %s, given once %s", c.repeated, h1, h2)
		}
	}
}
