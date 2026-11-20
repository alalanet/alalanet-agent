package tooldigest

import (
	"fmt"
	"testing"
)

// FN10-TOOLDESC-NULL: ReadTool reads a repeated member whose last value is null as the Go SDK client keeps
// it, and gives every string of a repeated text member in Others.
func TestReadToolGoKept(t *testing.T) {
	b := func(v bool) *bool { return &v }
	cases := []struct {
		tool             string
		name, desc       string
		title, annTitle  string
		ro, idem, destr  *bool
		others           []string
		ambiguous, fails bool
	}{
		{tool: `{"name":"s","description":"a","description":null}`, name: "s", desc: "a", others: []string{"a"}, ambiguous: true},
		{tool: `{"name":"s","description":"a","description":"b"}`, name: "s", desc: "b", others: []string{"a", "b"}, ambiguous: true},
		{tool: `{"name":"s","description":null,"description":"b"}`, name: "s", desc: "b", others: []string{"b"}, ambiguous: true},
		{tool: `{"name":"s","description":"a","description":null,"description":null}`, name: "s", desc: "a", others: []string{"a"}, ambiguous: true},
		{tool: `{"name":"s","description":7,"description":null}`, name: "s", ambiguous: true},
		{tool: `{"name":"s","description":"a","description":7}`, fails: true},
		{tool: `{"name":"s","name":null}`, name: "s", others: []string{"s"}, ambiguous: true},
		{tool: `{"name":"s","title":"t","title":null}`, name: "s", title: "t", others: []string{"t"}, ambiguous: true},
		{tool: `{"name":"s","DESCRIPTION":"a"}`, name: "s", ambiguous: true},
		{tool: `{"name":"s","description":"a"}`, name: "s", desc: "a"},
		{tool: `{"name":"s","annotations":{"title":"t","title":null}}`, name: "s", annTitle: "t", others: []string{"t"}, ambiguous: true},
		{tool: `{"name":"s","annotations":{"readOnlyHint":true,"readOnlyHint":null}}`, name: "s", ro: b(true), ambiguous: true},
		{tool: `{"name":"s","annotations":{"readOnlyHint":false,"readOnlyHint":null}}`, name: "s", ro: b(false), ambiguous: true},
		{tool: `{"name":"s","annotations":{"idempotentHint":true,"idempotentHint":null}}`, name: "s", idem: b(true), ambiguous: true},
		{tool: `{"name":"s","annotations":{"destructiveHint":true,"destructiveHint":null}}`, name: "s", ambiguous: true},
		{tool: `{"name":"s","annotations":{"readOnlyHint":"yes","readOnlyHint":null}}`, name: "s", ambiguous: true},
		{tool: `{"name":"s","annotations":{"readOnlyHint":true,"READONLYHINT":null}}`, name: "s", ro: b(true), ambiguous: true},
		{tool: `{"name":"s","description":"a","annotations":{"title":"a","title":"t"}}`, name: "s", desc: "a", annTitle: "t", others: []string{"a", "t"}, ambiguous: true},
	}
	for _, c := range cases {
		got, amb, err := ReadTool([]byte(c.tool))
		if c.fails {
			if err == nil {
				t.Errorf("%s: read, want refused", c.tool)
			}
			continue
		}
		pb := func(p *bool) string { return fmt.Sprint(p != nil && *p, p == nil) }
		if err != nil || got.Name != c.name || got.Description != c.desc || got.Title != c.title || got.AnnotationsTitle != c.annTitle ||
			pb(got.ReadOnly) != pb(c.ro) || pb(got.Idempotent) != pb(c.idem) || pb(got.Destructive) != pb(c.destr) ||
			fmt.Sprint(got.Others) != fmt.Sprint(c.others) || amb != c.ambiguous {
			t.Errorf("%s: %+v ambiguous %v err %v", c.tool, got, amb, err)
		}
	}
}
