package tooldigest

import (
	"encoding/json"
	"slices"
	"strings"
)

// InstructionsAmbiguous is the instructions flag of a result that gives the member "instructions" more
// than once with values some client reads differently (FN10-C1 round 2; sameInstructions): the MCP clients
// do not all receive the same text. It is no injection sign.
const InstructionsAmbiguous = "instructions_ambiguous"

// instructionsName is the one member of an initialize or server/discover result whose text reaches the
// client's model.
const instructionsName = "instructions"

// Instructions is the instructions of one initialize or server/discover result (ReadInstructions).
type Instructions struct {
	Text *string // what a client's model receives; nil: none
	// Given: the result carries instructions for some client: a member by the exact name that is not
	// null, one in another case, or the name more than once.
	Given bool
	// Others: the other strings given by the exact name, which some reader may take instead (Flags scans
	// them too); Ambiguous: the exact name is given more than once with values some client reads
	// differently (sameInstructions), not merely written otherwise.
	Others    []string
	Ambiguous bool
}

// ReadInstructions reads the instructions of an initialize or server/discover result as the MCP clients
// read them (FN10-C1, as FN-10 reads tools/list): by the exact name. Given more than once, JSON.parse
// (the TypeScript SDK) and Python keep the last value whole; the Go SDK (segmentio/encoding) writes no
// null into a string, so it keeps the last string when only nulls follow it (round 2, R1), and refuses
// the result for any other value that is not a string, as the other two do. So the text is the last
// value that is not null: a string, or the empty text for any other value (no client receives text
// then); nil when every value is null or there is none. A result that is not an object has none. The
// prober (initialize, server/discover) and alalanet-agent (initialize) read them so.
func ReadInstructions(result []byte) (in Instructions) {
	var vals []json.RawMessage
	variant := false
	if EachMember(result, func(name, value []byte) {
		if string(name) == instructionsName {
			vals = append(vals, value)
		} else if strings.EqualFold(string(name), instructionsName) {
			variant = true
		}
	}) != nil {
		return in
	}
	in.Given = variant || len(vals) > 1
	for i := len(vals) - 1; i >= 0; i-- {
		if string(vals[i]) != "null" {
			var s string
			_ = json.Unmarshal(vals[i], &s)
			in.Text, in.Given = &s, true
			break
		}
	}
	for _, v := range vals {
		in.Ambiguous = in.Ambiguous || !sameInstructions(v, vals[0])
		var s string
		if v[0] == '"' && json.Unmarshal(v, &s) == nil && s != in.TextOf() && !slices.Contains(in.Others, s) {
			in.Others = append(in.Others, s)
		}
	}
	return in
}

// sameInstructions says whether two values of "instructions" are the same to every client (FN10-TOOLDESC-NULL
// P3-1): null both; strings both, of the same text however escaped (SameValue); or neither null nor a string,
// which every client refuses (the Go SDK at any such value, the TypeScript and Python SDKs at the last). Any
// other two make the clients differ, given in that order: the Go SDK client keeps a string that only nulls
// follow, the TypeScript client refuses a null, Python reads it as none. The comparison is by pairs and does
// not see the order, while the clients' reading of repeats depends on it: a few sequences every client reads
// alike are flagged all the same ("a",null,"a" reads "a" to all three; "a",1 is refused by all three). Those
// are false positives of a warning, flagged before that round too (batch P3 review, P3-4).
func sameInstructions(a, b []byte) bool {
	strA, strB := a[0] == '"', b[0] == '"'
	if strA && strB {
		return SameValue(a, b)
	}
	return strA == strB && (string(a) == "null") == (string(b) == "null")
}

// TextOf is the text a client's model receives, the empty text for none.
func (in Instructions) TextOf() string {
	if in.Text == nil {
		return ""
	}
	return *in.Text
}

// Flags are the flags of in: InstructionFlags of the text, judged with the server's tools (st), then those
// of every other string given by the exact name, each judged alone, then InstructionsAmbiguous when the
// name gives values the clients read differently (Ambiguous).
func (in Instructions) Flags(st *ServerText) []string {
	flags := InstructionFlags(in.TextOf(), st)
	for _, o := range in.Others {
		for _, f := range InstructionFlags(o, nil) {
			if !slices.Contains(flags, f) {
				flags = append(flags, f)
			}
		}
	}
	if in.Ambiguous {
		flags = append(flags, InstructionsAmbiguous)
	}
	return flags
}
