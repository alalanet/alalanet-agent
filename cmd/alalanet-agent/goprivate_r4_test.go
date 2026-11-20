package main

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// ECO-1 Go, round 4 (re-review of a9d7b6b3; the review's agent proofs adopted).

func goR4Call(t *testing.T, srvURL, managed string, env []string) hookCall {
	home := t.TempDir()
	pf := &policyFiles{managed: managed, getwd: func() (string, error) { return "", os.ErrNotExist },
		environ: func() []string { return env }, home: func() (string, error) { return home, nil }}
	return hookCall{client: &http.Client{Timeout: 2 * time.Second}, api: srvURL, stderr: &bytes.Buffer{}, policy: pf}
}

// P3-6: the Go-private local ask goes through the policy, as alalanet's own answers do: on_hold: packages: deny denies
// it, and nothing is sent.
func TestGoR4LocalAskTakesThePolicy(t *testing.T) {
	f := &fakeHook{answer: func(w http.ResponseWriter) { _, _ = w.Write([]byte(notChecked_)) }}
	srv := f.server(t)
	managed := managedFile(t, denyHolds)
	dir := t.TempDir()
	var out bytes.Buffer
	call := goR4Call(t, srv.URL, managed, []string{"GOPRIVATE=corp.example"})
	if err := runHookContext(context.Background(), "claude-code", strings.NewReader(codexInputIn(dir, "go install corp.example/zz@v1.0.0")), &out, call); err != nil {
		t.Fatal(err)
	}
	if form := answerForm(t, "claude-code", out.String()); form != "deny" || len(f.calls()) != 0 {
		t.Errorf("under on_hold deny: %s, %d calls", form, len(f.calls()))
	}
}

// P3-7: the user's Go settings cover every line form, the nested launch of claude and codex mcp add included.
func TestGoR4UserSettingsForms(t *testing.T) {
	f := &fakeHook{answer: func(w http.ResponseWriter) {
		_, _ = w.Write([]byte(`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}`))
	}}
	srv := f.server(t)
	for _, line := range []string{
		"go install corp.example/zz@v1.0.0",
		"go -C /tmp install corp.example/zz@v1.0.0",
		"claude mcp add zz -- go run corp.example/zz@v1.0.0",
		"codex mcp add zz -- go run corp.example/zz@v1.0.0",
		"claude mcp add zz -e A=1 -- go run corp.example/zz@v1.0.0",
		"npx -y @anthropic-ai/claude-code mcp add zz -- go run corp.example/zz@v1.0.0",
		"sh -c 'go install corp.example/zz@v1.0.0'",
		"go1.22.0 install corp.example/zz@v1.0.0",
	} {
		before := len(f.calls())
		var out bytes.Buffer
		if err := runHookContext(context.Background(), "codex", strings.NewReader(runtimeInputs["codex"](line)), &out,
			goR4Call(t, srv.URL, "", []string{"GOPRIVATE=corp.example"})); err != nil {
			t.Fatal(err)
		}
		if len(f.calls()) > before {
			t.Errorf("%s: sent to alalanet though the user's GOPRIVATE covers corp.example", line)
		}
	}
	// a public module under the same settings is sent
	before := len(f.calls())
	var out bytes.Buffer
	if err := runHookContext(context.Background(), "codex", strings.NewReader(runtimeInputs["codex"]("claude mcp add zz -- go run example.com/zz@v1.0.0")), &out,
		goR4Call(t, srv.URL, "", []string{"GOPRIVATE=corp.example"})); err != nil {
		t.Fatal(err)
	}
	if len(f.calls()) == before {
		t.Errorf("a public module was not sent")
	}
}
