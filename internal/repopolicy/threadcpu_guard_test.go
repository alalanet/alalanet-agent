package repopolicy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"testing"
)

// quietCPU turns the collector off for the whole test binary while it measures (runtime/debug.SetGCPercent), so no
// test that reaches it may run beside another: none of them calls t.Parallel (flakes-5 review). The functions of this
// package's test files that name quietCPU, directly or through others that do, are found by their syntax; a call to
// Parallel in any of them fails here.
func TestQuietCPUCallersAreNotParallel(t *testing.T) {
	files, err := filepath.Glob("*_test.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("test files: %v %v", files, err)
	}
	fset := token.NewFileSet()
	bodies := map[string]*ast.BlockStmt{}
	for _, name := range files {
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Body != nil {
				bodies[fn.Name.Name] = fn.Body
			}
		}
	}
	names := func(body *ast.BlockStmt) map[string]bool {
		out := map[string]bool{}
		ast.Inspect(body, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok {
				out[id.Name] = true
			}
			return true
		})
		return out
	}
	reach := map[string]bool{"quietCPU": true}
	for grew := true; grew; {
		grew = false
		for fn, body := range bodies {
			if reach[fn] {
				continue
			}
			for n := range names(body) {
				if reach[n] {
					reach[fn], grew = true, true
					break
				}
			}
		}
	}
	var callers []string
	for fn := range reach {
		if fn == "quietCPU" {
			continue
		}
		callers = append(callers, fn)
		parallel := false
		ast.Inspect(bodies[fn], func(n ast.Node) bool {
			if s, ok := n.(*ast.SelectorExpr); ok && s.Sel.Name == "Parallel" {
				parallel = true
			}
			return true
		})
		if parallel {
			t.Errorf("%s reaches quietCPU, which turns the collector off for the whole binary, and calls Parallel", fn)
		}
	}
	sort.Strings(callers)
	if len(callers) == 0 {
		t.Fatal("no function reaches quietCPU: the guard reads nothing")
	}
	t.Logf("functions that reach quietCPU: %v", callers)
}
