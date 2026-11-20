// Package tooldigest is alalanet's MCP tool digest without the store (VERIFY-AUTO-1): how a tools/list result is
// read (as the MCP clients read it: members by their exact names, the last of a repeated name whole; FN-10), how each
// tool and the set are digested (v3), how descriptions are scanned for instructions to the model, and how two
// signature sets differ. internal/prober records and signs with it; alalanet-agent computes the same digests on the
// user's machine. It imports neither the store nor sqlite, and every digest is the one the prober gave before the move
// (testdata: TestToolDigestSameAsProber).
package tooldigest

import (
	"bytes"
	"encoding/json"
	"errors"
)

// The prober reads an MCP answer as the MCP clients do (FN-10). encoding/json matches a struct's
// fields case-insensitively, lets the last of a repeated member win and decodes a repeated object or
// array into the first one; the clients match member names exactly. JSON.parse, which the TypeScript
// SDK reads every message with, keeps the last value of a repeated name whole (ECMA-262 §25.5.2.1,
// note 2), and so do Python's json and pydantic, which the Python SDK validates messages with; the Go
// SDK matches names exactly too, but decodes a repeated object or array into the first one, as
// encoding/json does. One answer can so read one way to the prober and another to clients, or to two
// clients (RFC 8259 §4: the behaviour of software that receives an object whose names are not unique
// is unpredictable).
//
// So Members reads the members the prober uses as JSON.parse does — by their exact names, the last of a
// repeated name whole — and calls an object ambiguous when another client can read it differently: a
// name the prober uses given twice, or a member whose name is one of them only when case is folded (as
// encoding/json folds it, bytes.EqualFold). The values are then decoded by encoding/json as before: a
// document without such members reads exactly as it did.

var (
	ErrNotJSON   = errors.New("not valid JSON")
	ErrNotObject = errors.New("not a JSON object")
	ErrNotArray  = errors.New("not a JSON array")
	null         = []byte("null")
)

// FieldNames are the member names the prober reads in one kind of object.
type FieldNames [][]byte

func Names(ns ...string) FieldNames {
	out := make(FieldNames, len(ns))
	for i, n := range ns {
		out[i] = []byte(n)
	}
	return out
}

// The members the prober reads: of a JSON-RPC message and its error, of a tools/list result, of a tool
// and of its annotations (what enters the tool digest).
var (
	EnvelopeFields   = Names("id", "result", "error", "method")
	ErrorFields      = Names("code", "message", "data")
	ListFields       = Names("tools", "nextCursor")
	ToolFields       = Names("name", "title", "description", "inputSchema", "outputSchema", "annotations")
	AnnotationFields = Names("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint", "title")
)

// Members sets vals[i] to the value of the last member of the JSON object obj named exactly fields[i],
// as written (nil when there is none), and reports whether obj is ambiguous (see above). obj must be
// valid JSON (json.Valid): Members only finds where each member's name and value begin and end, in one
// pass over obj without recursion, and leaves the values to encoding/json. null sets nothing, as
// encoding/json reads null into a struct; another value that is not an object is ErrNotObject.
func Members(obj []byte, fields FieldNames, vals []json.RawMessage) (ambiguous bool, err error) {
	clear(vals)
	err = EachMember(obj, func(name, value []byte) {
		for n, f := range fields {
			if !bytes.EqualFold(name, f) {
				continue
			}
			exact := bytes.Equal(name, f)
			if !exact || vals[n] != nil {
				ambiguous = true
			}
			if exact {
				vals[n] = value
			}
		}
	})
	return ambiguous && err == nil, err
}

// EachMember calls fn with the name (unescaped) and the value (as written) of each member of the JSON
// object obj, in order (Members). null has none; another value that is not an object is ErrNotObject.
func EachMember(obj []byte, fn func(name, value []byte)) error {
	i := Space(obj, 0)
	if bytes.HasPrefix(obj[i:], null) {
		return nil
	}
	if i >= len(obj) || obj[i] != '{' {
		return ErrNotObject
	}
	for i = Space(obj, i+1); i < len(obj) && obj[i] == '"'; {
		end := StringEnd(obj, i)
		if end < i+2 {
			return ErrNotJSON
		}
		name := obj[i+1 : end-1]
		if bytes.IndexByte(name, '\\') >= 0 { // an escaped name: encoding/json unescapes it, as JSON.parse does
			var s string
			if json.Unmarshal(obj[i:end], &s) != nil {
				return ErrNotJSON
			}
			name = []byte(s)
		}
		if i = Space(obj, end); i >= len(obj) || obj[i] != ':' {
			return ErrNotJSON
		}
		start := Space(obj, i+1)
		if i = ValueEnd(obj, start); i == start {
			return ErrNotJSON
		}
		fn(name, obj[start:i])
		if i = Space(obj, i); i < len(obj) && obj[i] == ',' {
			i = Space(obj, i+1)
		}
	}
	return nil
}

// Elements returns the elements of the JSON array arr, as written. arr must be valid JSON (json.Valid).
// null has none, as encoding/json reads null into a slice; another value that is not an array is
// ErrNotArray.
func Elements(arr []byte) ([]json.RawMessage, error) {
	i := Space(arr, 0)
	if bytes.HasPrefix(arr[i:], null) {
		return nil, nil
	}
	if i >= len(arr) || arr[i] != '[' {
		return nil, ErrNotArray
	}
	out := []json.RawMessage{}
	i = Space(arr, i+1)
	for range len(arr) { // an element takes a byte at least: never more passes than bytes, whatever arr holds
		if i >= len(arr) || arr[i] == ']' {
			return out, nil
		}
		end := ValueEnd(arr, i)
		if end == i {
			return nil, ErrNotJSON
		}
		out = append(out, arr[i:end])
		if i = Space(arr, end); i < len(arr) && arr[i] == ',' {
			i = Space(arr, i+1)
		}
	}
	return nil, ErrNotJSON
}

// space skips JSON whitespace from b[i].
func Space(b []byte, i int) int {
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
		i++
	}
	return i
}

// StringEnd returns where the JSON string that starts at b[i] (a quote) ends: after its first quote
// that no backslash escapes.
func StringEnd(b []byte, i int) int {
	for i++; i < len(b); i++ {
		switch b[i] {
		case '\\':
			i++
		case '"':
			return i + 1
		}
	}
	return len(b)
}

// ValueEnd returns where the JSON value that starts at b[i] ends: a string after its closing quote, an
// object or an array after the bracket that closes it (strings inside are skipped whole), a number or
// a literal before the first delimiter or space.
func ValueEnd(b []byte, i int) int {
	if i >= len(b) {
		return i
	}
	switch b[i] {
	case '"':
		return StringEnd(b, i)
	case '{', '[':
		depth := 0
		for i < len(b) {
			switch b[i] {
			case '"':
				i = StringEnd(b, i)
				continue
			case '{', '[':
				depth++
			case '}', ']':
				if depth--; depth == 0 {
					return i + 1
				}
			}
			i++
		}
		return i
	}
	for ; i < len(b); i++ {
		switch b[i] {
		case ',', '}', ']', ' ', '\t', '\n', '\r':
			return i
		}
	}
	return i
}

// DecodeFields decodes each value that is there into its destination, as encoding/json decodes a struct
// field: null leaves a value as it is and sets a pointer to nil; a value of another type is an error.
func DecodeFields(vals []json.RawMessage, dst ...any) error {
	for i, v := range vals {
		if v != nil {
			if err := json.Unmarshal(v, dst[i]); err != nil {
				return err
			}
		}
	}
	return nil
}

// ReadList reads a tools/list result as a client that matches names exactly reads it: the elements of
// tools and the value of nextCursor, as written, and whether the result is ambiguous. An error for a
// result encoding/json refused: not valid JSON, not an object, tools not an array.
func ReadList(result []byte) (tools []json.RawMessage, cursor json.RawMessage, ambiguous bool, err error) {
	if !json.Valid(result) {
		return nil, nil, false, ErrNotJSON
	}
	var v [2]json.RawMessage
	if ambiguous, err = Members(result, ListFields, v[:]); err != nil {
		return nil, nil, false, err
	}
	if v[0] != nil {
		if tools, err = Elements(v[0]); err != nil {
			return nil, nil, false, err
		}
	}
	return tools, v[1], ambiguous, nil
}

// ToolDef is one tool of a tools/list result as the prober digests it.
type ToolDef struct {
	Name, Title, Description                     string
	InputSchema, OutputSchema                    json.RawMessage
	ReadOnly, Destructive, Idempotent, OpenWorld *bool
	AnnotationsTitle                             string
	// Others: every string a repeated name, title, description or annotations title gives, one of which
	// some client receives (FN10-TOOLDESC-NULL). Scanned for flags (DigestDefs), not digested.
	Others []string
}

// The members a Go SDK client (v1.8.0) decodes into a string or a bool, not a pointer, an interface or a
// map (FN10-TOOLDESC-NULL): segmentio/encoding writes no null into them, so of a member given more than
// once whose last value is null it keeps the last value before that is not null. Their indexes in
// ToolFields and AnnotationFields, and whether each is text (a string) or a hint (a bool).
var (
	toolGoKeeps       = []goKeep{{0, true}, {1, true}, {2, true}}   // name, title, description
	annotationGoKeeps = []goKeep{{0, false}, {2, false}, {4, true}} // readOnlyHint, idempotentHint, title
)

type goKeep struct {
	i    int
	text bool
}

// goKept reads the members keep names of obj, an object Members found ambiguous, as the Go SDK client
// keeps them: for each whose last value is null, vals takes the last value before it that is not null
// when that value is of the member's type (a string for text, true or false for a hint); any other value
// there makes every SDK client refuse the tool, and vals keeps the null (the empty text, no hint), as
// before. It returns every string a text member given more than once gives (ToolDef.Others): one of them
// is what some client receives.
func goKept(obj []byte, fields FieldNames, vals []json.RawMessage, keep []goKeep) (others []string) {
	all := make([][]json.RawMessage, len(fields))
	_ = EachMember(obj, func(name, value []byte) {
		for _, k := range keep {
			if bytes.Equal(name, fields[k.i]) {
				all[k.i] = append(all[k.i], value)
			}
		}
	})
	for _, k := range keep {
		vs := all[k.i]
		if len(vs) > 0 && bytes.Equal(vs[len(vs)-1], null) {
			for j := len(vs) - 2; j >= 0; j-- {
				if bytes.Equal(vs[j], null) {
					continue
				}
				if k.text && vs[j][0] == '"' || !k.text && (vs[j][0] == 't' || vs[j][0] == 'f') {
					vals[k.i] = vs[j]
				}
				break
			}
		}
		for _, v := range vs {
			var s string
			if k.text && len(vs) > 1 && v[0] == '"' && json.Unmarshal(v, &s) == nil {
				others = append(others, s)
			}
		}
	}
	return others
}

// ReadTool reads one element of a tools/list result's tools as a client that matches names exactly
// reads it, and reports whether the tool or its annotations are ambiguous. An error for an element
// encoding/json refused: not an object or null, or a member the prober uses not of its type. A name,
// title, description, annotations title or boolean hint given more than once, the last value null, is
// the value a Go SDK client keeps (goKept).
func ReadTool(raw json.RawMessage) (t ToolDef, ambiguous bool, err error) {
	var v [6]json.RawMessage
	if ambiguous, err = Members(raw, ToolFields, v[:]); err != nil {
		return t, false, err
	}
	if ambiguous {
		t.Others = goKept(raw, ToolFields, v[:], toolGoKeeps)
	}
	if err = DecodeFields(v[:3], &t.Name, &t.Title, &t.Description); err != nil {
		return t, false, err
	}
	t.InputSchema, t.OutputSchema = v[3], v[4]
	if v[5] != nil {
		var a [5]json.RawMessage
		amb, err := Members(v[5], AnnotationFields, a[:])
		if err != nil {
			return t, false, err
		}
		if amb {
			t.Others = append(t.Others, goKept(v[5], AnnotationFields, a[:], annotationGoKeeps)...)
		}
		if err = DecodeFields(a[:], &t.ReadOnly, &t.Destructive, &t.Idempotent, &t.OpenWorld, &t.AnnotationsTitle); err != nil {
			return t, false, err
		}
		ambiguous = ambiguous || amb
	}
	return t, ambiguous, nil
}
