package main

// ADR-0150 round 7, after its review (review-1115/codexexit2): R7-P3-1 — under hook codex the diagnostics wait, and on a
// block stderr carries the JSON answer's reason alone (the review's proofs are review_r7_proof_test.go); R7-P3-2 — the
// hook request is held by behaviour to what /privacy says leaves the machine.

import (
	"bytes"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
)

// The request each runtime's hook sends for an install: POST /v1/hooks/claude-code, no query, the command alone in the
// body, and exactly the headers Go's client adds, Content-Type and the User-Agent, with Authorization only with a token.
func TestHookRequestIsExactlyTheCommand(t *testing.T) {
	token := "alalanet" + "-test-" + "token-r7"
	in := shellForms(placeholderInstall)["codex Bash"]
	for name := range hookRuntimes {
		for _, tok := range []string{"", token} {
			f := reviewDeny()
			srv := f.server(t)
			var out bytes.Buffer
			if err := runHookContext(t.Context(), name, strings.NewReader(in), &out, hookCall{client: &http.Client{}, api: srv.URL, token: tok}); err != nil {
				t.Fatal(err)
			}
			what := name + map[bool]string{true: " with a token", false: ""}[tok != ""]
			f.mu.Lock()
			if len(f.headers) != 1 {
				t.Fatalf("%s: %d requests", what, len(f.headers))
			}
			h, body, query := f.headers[0], f.bodies[0], f.queries[0]
			f.mu.Unlock()
			var keys []string
			for k := range h {
				keys = append(keys, k)
			}
			slices.Sort(keys)
			want := []string{"Accept-Encoding", "Content-Length", "Content-Type", "User-Agent"}
			if tok != "" {
				want = []string{"Accept-Encoding", "Authorization", "Content-Length", "Content-Type", "User-Agent"}
			}
			if !slices.Equal(keys, want) {
				t.Errorf("%s: headers %v, want %v", what, keys, want)
			}
			if h.Get("Content-Type") != "application/json" || h.Get("User-Agent") != "alalanet-agent/"+version+" (hook "+name+")" ||
				h.Get("Authorization") != map[bool]string{true: "Bearer " + token, false: ""}[tok != ""] {
				t.Errorf("%s: Content-Type %q, User-Agent %q, Authorization set %v", what, h.Get("Content-Type"), h.Get("User-Agent"), h.Get("Authorization") != "")
			}
			if wantBody := `{"hook_event_name":"PreToolUse","tool_input":{"command":"` + placeholderInstall + `"},"tool_name":"Bash"}`; body != wantBody {
				t.Errorf("%s: body %q, want %q", what, body, wantBody)
			}
			if query != "" {
				t.Errorf("%s: query %q", what, query)
			}
		}
	}
}

// runHookMain (main's entry): under hook codex a block leaves stderr to the reason alone, which mainExit prints, and the
// diagnostics are dropped; without a block they follow. Other runtimes, and runHookContext (the tests' entry), write
// the diagnostics as they come.
func TestRunHookMainCodexDiagnosticsWait(t *testing.T) {
	unreachable := "http://127.0.0.1:1"
	for _, c := range []struct {
		name, runtime, input string
		entry                string // "main" or "context"
		block                bool
		stderr               string // what stderr holds after the call ("" for nothing)
	}{
		{"codex, unreadable input", "codex", "not json", "main", true, ""},
		{"Codex in any case, unreadable input", " Codex ", "not json", "main", true, ""},
		{"codex, alalanet unreachable", "codex", codexInput("Bash", placeholderInstall), "main", false, "the install goes ahead unchecked"},
		{"cursor, unreadable input", "cursor", "not json", "main", false, "nothing was checked, the call is held"},
		{"codex through runHookContext", "codex", "not json", "context", false, "nothing was checked, the call is held"},
	} {
		var out, stderr bytes.Buffer
		call := hookCall{client: &http.Client{}, api: unreachable, stderr: &stderr}
		var err error
		if c.entry == "main" {
			err = runHookMain(t.Context(), c.runtime, strings.NewReader(c.input), &out, call)
		} else {
			err = runHookContext(t.Context(), c.runtime, strings.NewReader(c.input), &out, call)
		}
		if errors.As(err, new(hookBlock)) != c.block || !c.block && err != nil {
			t.Errorf("%s: %v (block %v)", c.name, err, c.block)
		}
		if c.stderr == "" && stderr.Len() != 0 || !strings.Contains(stderr.String(), c.stderr) {
			t.Errorf("%s: stderr %q, want %q", c.name, stderr.String(), c.stderr)
		}
	}
}
