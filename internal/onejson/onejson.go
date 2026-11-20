// Package onejson reads JSON that another program reads too, so that alalanet and that program read the same
// thing (ADR-0185, the round after the batch P3 review).
//
// encoding/json (v1, and Go 1.27's v1 built on v2) fills a struct field from any member whose name equals the
// field's under Unicode simple case folding, and the last such member wins: "PayTo", "PAYTO" and "payTo" are one
// field, and so are "service" and "\u017fervice" (U+017F folds to s) or "kind" and "Kind" with U+212A (the Kelvin sign
// folds to k). A later variant set to null resets a pointer, and a map field met twice is merged. JSON.parse,
// Python's json and most clients match names exactly, the last of an exact repeat whole. So a document whose member
// names another party writes could read one way to alalanet and another way to the client that acts on it. The rule
// is a class rule, not a list of letters: a document another program reads is never decoded into a struct by
// encoding/json; it is read by one of the two functions here.
//
//   - Strict: one reading or a refusal (ErrTwoReadings). For what alalanet signs or verifies, and for terms that
//     clients of several languages read (an x402 402).
//   - AsJSONParse: the reading of JSON.parse, which the program that acts on the document uses (npm, Claude Code,
//     Cursor, VS Code). For files whose readers are all JSON.parse, where a refusal would only hide what they run.
package onejson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
)

// ErrTwoReadings is a document that two readers could read two ways: a name given twice, two names that are one
// under case folding, or a name that is a field's name in another case.
var ErrTwoReadings = errors.New("the JSON reads two ways")

// Strict decodes data, one JSON value and nothing after it, into v (a pointer) by exact member names
// (encoding/json/v2), and refuses with ErrTwoReadings a document two readers could read differently. In every
// object decoded into a struct, at any depth:
//   - no two names are equal under Unicode simple case folding (strings.EqualFold), exactly equal included;
//   - no name equals a field's JSON name under that folding without being it.
//
// A name no field has and that folds onto none is read by no one here and allowed (a field of a later build).
// Invalid UTF-8 is refused. Maps are read by exact keys everywhere, so they only refuse an exact repeat.
func Strict(data []byte, v any) error {
	t := reflect.TypeOf(v)
	if t == nil || t.Kind() != reflect.Pointer {
		return errors.New("onejson: Strict needs a pointer")
	}
	dec := jsontext.NewDecoder(bytes.NewReader(data))
	if err := check(dec, t.Elem()); err != nil {
		if errors.Is(err, ErrTwoReadings) {
			return err
		}
		if errors.Is(err, jsontext.ErrDuplicateName) {
			return fmt.Errorf("%w: %w", ErrTwoReadings, err)
		}
		return fmt.Errorf("onejson: %w", err)
	}
	return jsonv2.Unmarshal(data, v) // which refuses data after the value
}

// AsJSONParse decodes data into v (a pointer) as JSON.parse reads it: member names exactly, the last of a repeated
// name whole (ECMA-262 §25.5.1: a later value replaces an earlier one, objects and arrays included), invalid UTF-8
// in a value read as U+FFFD. A member whose name is a struct field's in another case is one JSON.parse keeps and no
// field reads.
//
// The document is first rewritten to that reading — each object's repeated names dropped but the last, and in an
// object decoded into a struct every name that folds onto a field's name without being it — and then decoded by
// encoding/json as before, so what it tolerated it still tolerates (a value of another type leaves its field
// empty and the rest is read; the error is returned as before). The rewrite is two linear passes: the first
// decides which members stay, the second copies them into one buffer (release-1116b review P3-1: rewriting each
// level into its parent copied a value nested d deep d times). A kept member stands where its last repeat stood.
//
// A name with invalid UTF-8 or a lone surrogate escape is refused (ErrNameApart): the decoder reads each such byte
// or escape as one U+FFFD, so names that JSON.parse keeps apart ("a" with a lone high surrogate and "a" with a lone
// low one; or Node's one U+FFFD for a truncated sequence against two for two bad bytes) would be one name here
// (release-1116b review P3-2). The caller reads such a file as not readable.
func AsJSONParse(data []byte, v any) error {
	t := reflect.TypeOf(v)
	if t == nil || t.Kind() != reflect.Pointer {
		return errors.New("onejson: AsJSONParse needs a pointer")
	}
	opts := []jsontext.Options{jsontext.AllowDuplicateNames(true), jsontext.AllowInvalidUTF8(true)}
	dec := jsontext.NewDecoder(bytes.NewReader(data), opts...)
	var plan []member
	if err := planValue(dec, t.Elem(), &plan); err != nil {
		return fmt.Errorf("onejson: %w", err)
	}
	if _, err := dec.ReadToken(); !errors.Is(err, io.EOF) {
		return errors.New("onejson: data after the JSON value")
	}
	dec = jsontext.NewDecoder(bytes.NewReader(data), opts...)
	i := 0
	norm, err := emitValue(dec, plan, &i, make([]byte, 0, len(data)))
	if err != nil {
		return fmt.Errorf("onejson: %w", err)
	}
	return json.Unmarshal(norm, v)
}

// ErrNameApart is a member name with invalid UTF-8 or a lone surrogate escape, which JSON.parse may keep apart from
// a name this package's decoder reads as the same.
var ErrNameApart = errors.New("a member name with invalid UTF-8 or a lone surrogate")

// member is one object member of the document, in the order of the document: whether JSON.parse keeps it, and how
// many members its value holds (skipped with it when it is not kept).
type member struct {
	keep bool
	span int
}

// planValue reads the next value and appends a member for each object member in it, guided by t as check is.
func planValue(dec *jsontext.Decoder, t reflect.Type, plan *[]member) error {
	t = guide(t)
	switch dec.PeekKind() {
	case '{':
		if _, err := dec.ReadToken(); err != nil {
			return err
		}
		var f *fieldNames
		if t != nil && t.Kind() == reflect.Struct {
			f = namesOf(t)
		}
		at := map[string]int{}
		for dec.PeekKind() != '}' {
			raw, err := dec.ReadValue() // the name, as written
			if err != nil {
				return err
			}
			b, err := jsontext.AppendUnquote(nil, raw) // refuses invalid UTF-8 and a lone surrogate
			if err != nil {
				return fmt.Errorf("%w: %q", ErrNameApart, raw)
			}
			name := string(b)
			var next reflect.Type
			keep := true
			switch {
			case f != nil:
				next = f.exact[name]
				if want, ok := f.byFold[Fold(name)]; ok && want != name {
					keep = false // JSON.parse keeps it under a name no field has; encoding/json would fill the field
				}
			case t != nil && t.Kind() == reflect.Map:
				next = t.Elem()
			}
			idx := len(*plan)
			*plan = append(*plan, member{keep: keep})
			if prev, ok := at[name]; ok {
				(*plan)[prev].keep = false
			}
			at[name] = idx
			if err := planValue(dec, next, plan); err != nil {
				return err
			}
			(*plan)[idx].span = len(*plan) - idx - 1
		}
		_, err := dec.ReadToken()
		return err
	case '[':
		if _, err := dec.ReadToken(); err != nil {
			return err
		}
		var elem reflect.Type
		if t != nil && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) {
			elem = t.Elem()
		}
		for dec.PeekKind() != ']' {
			if err := planValue(dec, elem, plan); err != nil {
				return err
			}
		}
		_, err := dec.ReadToken()
		return err
	default:
		return dec.SkipValue()
	}
}

// emitValue appends the next value to out as JSON.parse reads it, by the plan planValue made of the same document.
func emitValue(dec *jsontext.Decoder, plan []member, i *int, out []byte) ([]byte, error) {
	switch dec.PeekKind() {
	case '{':
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		out = append(out, '{')
		first := true
		for dec.PeekKind() != '}' {
			tok, err := dec.ReadToken()
			if err != nil {
				return nil, err
			}
			if *i >= len(plan) {
				return nil, errors.New("the document changed between the passes")
			}
			m := plan[*i]
			*i++
			if !m.keep {
				if err := dec.SkipValue(); err != nil {
					return nil, err
				}
				*i += m.span
				continue
			}
			if !first {
				out = append(out, ',')
			}
			first = false
			if out, err = jsontext.AppendQuote(out, tok.String()); err != nil {
				return nil, err
			}
			out = append(out, ':')
			if out, err = emitValue(dec, plan, i, out); err != nil {
				return nil, err
			}
		}
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		return append(out, '}'), nil
	case '[':
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		out = append(out, '[')
		for n := 0; dec.PeekKind() != ']'; n++ {
			if n > 0 {
				out = append(out, ',')
			}
			var err error
			if out, err = emitValue(dec, plan, i, out); err != nil {
				return nil, err
			}
		}
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		return append(out, ']'), nil
	default:
		v, err := dec.ReadValue()
		if err != nil {
			return nil, err
		}
		return append(out, v...), nil
	}
}

// guide is the type that guides the reading of a value decoded into t: t without its pointers, or nil when t's own
// method reads it (go-nostr's Event: exact names) or nothing does.
func guide(t reflect.Type) reflect.Type {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t != nil && (reflect.PointerTo(t).Implements(unmarshalerV1) || reflect.PointerTo(t).Implements(unmarshalerV2)) {
		return nil
	}
	return t
}

// check reads the next value and refuses an object, decoded into a struct of type t, whose names fold together or
// onto a field's name. t is nil where nothing here guides the reading (a value no field takes, an UnmarshalJSON).
func check(dec *jsontext.Decoder, t reflect.Type) error {
	t = guide(t)
	switch dec.PeekKind() {
	case '{':
		if _, err := dec.ReadToken(); err != nil {
			return err
		}
		var f *fieldNames
		var seen map[string]string
		if t != nil && t.Kind() == reflect.Struct {
			f, seen = namesOf(t), map[string]string{}
		}
		for dec.PeekKind() != '}' {
			tok, err := dec.ReadToken()
			if err != nil {
				return err
			}
			name := tok.String()
			var next reflect.Type
			switch {
			case f != nil:
				k := Fold(name)
				if prev, ok := seen[k]; ok {
					return fmt.Errorf("%w: the names %q and %q are one name in another case", ErrTwoReadings, prev, name)
				}
				seen[k] = name
				if want, ok := f.byFold[k]; ok && want != name {
					return fmt.Errorf("%w: the name %q is %q in another case", ErrTwoReadings, name, want)
				}
				next = f.exact[name]
			case t != nil && t.Kind() == reflect.Map:
				next = t.Elem()
			}
			if err := check(dec, next); err != nil {
				return err
			}
		}
		_, err := dec.ReadToken()
		return err
	case '[':
		if _, err := dec.ReadToken(); err != nil {
			return err
		}
		var elem reflect.Type
		if t != nil && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) {
			elem = t.Elem()
		}
		for dec.PeekKind() != ']' {
			if err := check(dec, elem); err != nil {
				return err
			}
		}
		_, err := dec.ReadToken()
		return err
	default:
		_, err := dec.ReadValue()
		return err
	}
}

var (
	unmarshalerV1 = reflect.TypeFor[interface{ UnmarshalJSON([]byte) error }]()
	unmarshalerV2 = reflect.TypeFor[jsonv2.UnmarshalerFrom]()
)

// fieldNames are a struct's JSON names, exactly and by their fold.
type fieldNames struct {
	exact  map[string]reflect.Type
	byFold map[string]string
}

var namesCache sync.Map // reflect.Type → *fieldNames

func namesOf(t reflect.Type) *fieldNames {
	if f, ok := namesCache.Load(t); ok {
		return f.(*fieldNames)
	}
	f := &fieldNames{exact: map[string]reflect.Type{}, byFold: map[string]string{}}
	addFields(f, t, 0)
	namesCache.Store(t, f)
	return f
}

func addFields(f *fieldNames, t reflect.Type, depth int) {
	for i := range t.NumField() {
		sf := t.Field(i)
		tag := sf.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if tag == "-" {
			continue
		}
		ft := sf.Type
		for ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if sf.Anonymous && name == "" && ft.Kind() == reflect.Struct && depth < 8 {
			addFields(f, ft, depth+1) // an embedded struct's fields are the outer struct's
			continue
		}
		if !sf.IsExported() {
			continue
		}
		if name == "" {
			name = sf.Name
		}
		f.exact[name] = sf.Type
		f.byFold[Fold(name)] = name
	}
}

// Fold is s under Unicode simple case folding: each rune replaced by the smallest rune of its fold orbit, so that
// Fold(a) == Fold(b) exactly when strings.EqualFold(a, b). Invalid UTF-8 folds as U+FFFD.
func Fold(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		b.WriteRune(foldRune(r))
	}
	return b.String()
}

func foldRune(r rune) rune {
	switch {
	case 'a' <= r && r <= 'z':
		return r - 'a' + 'A' // the orbit's smallest: {A, a}; {K, k, U+212A}; {S, s, U+017F}
	case r < utf8.RuneSelf:
		return r
	}
	m := r
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		m = min(m, f)
	}
	return m
}
