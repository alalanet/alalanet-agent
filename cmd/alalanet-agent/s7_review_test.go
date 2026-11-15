package main

// Independent review of s7-passports (1e63a9f): alalanet-agent's own tool texts against /privacy and
// /terms. A passport (kind 0) is stored and never appended (internal/agents, TestPassportIsStoredNotLogged);
// a board post's text is erased on a takedown and only a commitment is logged (TestBoardPosts). Fails on
// the branch.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/alalanet/alalanet-agent/agentkit"
)

func reviewS7ToolDescription(t *testing.T, name string) string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var desc string
	ast.Inspect(f, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		var gotName, gotDesc string
		for _, e := range cl.Elts {
			kv, ok := e.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			k, _ := kv.Key.(*ast.Ident)
			lit, _ := kv.Value.(*ast.BasicLit)
			if k == nil || lit == nil || lit.Kind != token.STRING {
				continue
			}
			v, _ := strconv.Unquote(lit.Value)
			switch k.Name {
			case "Name":
				gotName = v
			case "Description":
				gotDesc = v
			}
		}
		if gotName == name {
			desc = gotDesc
		}
		return true
	})
	if desc == "" {
		t.Fatalf("no tool %s in main.go", name)
	}
	return desc
}

func TestReviewS7_F2_AgentToolTextsContradictThePages(t *testing.T) {
	if d := reviewS7ToolDescription(t, "set_profile"); strings.Contains(d, "permanent in the transparency log") {
		t.Errorf("set_profile (kind 0 passport) tells the agent it is %q; /privacy: \"An agent passport is public on its page and is not written to the log\"",
			"Public and permanent in the transparency log")
	}
	f, _ := reflect.TypeOf(agentkit.Post{}).FieldByName("Text")
	if tag := f.Tag.Get("jsonschema"); strings.Contains(tag, "permanent") {
		t.Errorf("post_board's text schema says %q; /privacy: \"the post's text can be taken down\"", tag)
	}
}
