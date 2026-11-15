package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// codexInput is a PreToolUse input as Codex documents it (learn.chatgpt.com/docs/hooks, read 2026-11-13): the common
// fields, the turn's fields and the tool's input.
func codexInput(tool, command string) string {
	b, _ := json.Marshal(map[string]any{
		"session_id": "sess-1", "transcript_path": "/home/dev/.codex/sessions/t.jsonl", "cwd": "/home/dev/secret-project",
		"hook_event_name": "PreToolUse", "model": "gpt-5", "permission_mode": "default",
		"turn_id": "turn-7", "tool_name": tool, "tool_use_id": "call-9", "tool_input": map[string]any{"command": command},
	})
	return string(b)
}

// fakeHook records what reaches alalanet's hook check and answers as the server does.
type fakeHook struct {
	mu     sync.Mutex
	bodies []string
	agents []string
	answer func(w http.ResponseWriter)
}

func (f *fakeHook) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/hooks/claude-code" {
			t.Errorf("request %s %s", r.Method, r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.bodies = append(f.bodies, string(b))
		f.agents = append(f.agents, r.Header.Get("User-Agent"))
		f.mu.Unlock()
		if f.answer != nil {
			f.answer(w)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (f *fakeHook) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.bodies...)
}

func runCodex(t *testing.T, api, input string) string {
	t.Helper()
	var out bytes.Buffer
	if err := runHook("codex", strings.NewReader(input), &out, &http.Client{Timeout: 2 * time.Second}, api); err != nil {
		t.Fatalf("runHook: %v", err)
	}
	return out.String()
}

// The install-time check in Codex CLI (RT-1): only an install command leaves the machine — the command and nothing else
// of the hook's input — and the server's three answers come back in Codex's own form.
func TestCodexHookSendsOnlyTheInstallCommand(t *testing.T) {
	f := &fakeHook{}
	srv := f.server(t)
	if out := runCodex(t, srv.URL, codexInput("Bash", "npm install left-pad")); out != "" {
		t.Fatalf("an empty answer printed %q", out)
	}
	calls := f.calls()
	if len(calls) != 1 {
		t.Fatalf("%d calls", len(calls))
	}
	var sent map[string]any
	if err := json.Unmarshal([]byte(calls[0]), &sent); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": map[string]any{"command": "npm install left-pad"}}
	if b1, b2 := mustJSON(sent), mustJSON(want); b1 != b2 {
		t.Fatalf("sent %s, want %s", b1, b2)
	}
	for _, private := range []string{"sess-1", "transcript", "secret-project", "gpt-5", "turn-7", "call-9"} {
		if strings.Contains(calls[0], private) {
			t.Fatalf("the hook's input %q left the machine: %s", private, calls[0])
		}
	}
	if ua := f.agents[0]; !strings.HasPrefix(ua, "alalanet-agent/") || !strings.Contains(ua, "hook codex") {
		t.Fatalf("User-Agent %q", ua)
	}
}

func TestCodexHookAnswers(t *testing.T) {
	for _, c := range []struct {
		name   string
		answer func(w http.ResponseWriter)
		want   string // "" = no output
	}{
		{"block", func(w http.ResponseWriter) {
			_, _ = w.Write([]byte(`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"alalanet install_check: BLOCK — known_malicious"}}`))
		}, "deny:alalanet install_check: BLOCK — known_malicious"},
		{"hold", func(w http.ResponseWriter) {
			_, _ = w.Write([]byte(`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"alalanet install_check: HOLD — new_package"}}`))
		}, "deny:alalanet install_check: HOLD — new_package"},
		{"allow", func(w http.ResponseWriter) {}, ""},
		{"server error", func(w http.ResponseWriter) { w.WriteHeader(http.StatusInternalServerError) }, ""},
		{"not JSON", func(w http.ResponseWriter) { _, _ = w.Write([]byte("<html>")) }, ""},
	} {
		f := &fakeHook{answer: c.answer}
		srv := f.server(t)
		out := runCodex(t, srv.URL, codexInput("Bash", "uvx some-tool"))
		if c.want == "" {
			if out != "" {
				t.Errorf("%s: printed %q", c.name, out)
			}
			continue
		}
		var got struct {
			HookSpecificOutput map[string]string `json:"hookSpecificOutput"`
		}
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatalf("%s: not JSON: %q", c.name, out)
		}
		h := got.HookSpecificOutput
		if h["hookEventName"] != "PreToolUse" || h["permissionDecision"] != "deny" || len(h) != 3 {
			t.Errorf("%s: %v", c.name, h)
		}
		reason := strings.TrimPrefix(c.want, "deny:")
		if !strings.Contains(h["permissionDecisionReason"], reason) {
			t.Errorf("%s: reason %q lacks %q", c.name, h["permissionDecisionReason"], reason)
		}
		// Codex cannot ask (an "ask" lets the call go on): a hold is a deny that says to confirm with the user.
		if c.name == "hold" && !strings.Contains(h["permissionDecisionReason"], "confirm with the user") {
			t.Errorf("hold: the reason does not say to confirm with the user: %q", h["permissionDecisionReason"])
		}
	}
	// alalanet unreachable: the command goes on unchecked, as Claude Code does when its HTTP hook cannot be reached.
	if out := runCodex(t, "http://127.0.0.1:1", codexInput("Bash", "npx -y cowsay")); out != "" {
		t.Errorf("unreachable: printed %q", out)
	}
}

// What the hook sends: what alalanet's own reader acts on (the plugin's 32 prefixes among it) — in a compound command,
// after wrappers and variable assignments, with a path or a Windows extension on the program. Since the second round
// the reader is the server's (internal/installread): an install with nothing named to check (npm install, pip install
// -r requirements.txt) is not sent, because the server answers it with silence.
func TestCodexHookSendsInstallsOnly(t *testing.T) {
	f := &fakeHook{}
	srv := f.server(t)
	sends := []string{
		"npm install left-pad", "npm i -D vitest", "npm add x", "npm exec cowsay", "npx -y @playwright/mcp",
		"pnpm add zod", "pnpm install zod", "pnpm dlx create-x", "pnpx serve", "yarn add react", "yarn dlx create-y",
		"bun add hono", "bun install hono", "bunx cowsay", "pip install requests", "pip3 install flask", "uv add httpx",
		"uv pip install rich", "uv tool install ruff", "uvx mcp-server-fetch", "pipx install black", "pipx run cowsay",
		"claude mcp add fs -- npx -y fs-server", "codex mcp add fs -- npx -y fs-server", "skills add owner/repo",
		"clawhub install slug", "code --install-extension ms-python.python", "code-insiders --install-extension a.b",
		"cursor --install-extension a.b", "windsurf --install-extension a.b", "codium --install-extension a.b",
		"openclaw skills install x",
		"cd app && npm i left-pad", "git pull; pip install requests", "make || npx -y tsx run.ts",
		"sudo -u root npm i -g pnpm", "NODE_ENV=production npm install x", "env -u HOME pip install y",
		"timeout 60 uvx tool", "/usr/local/bin/npm install z", `C:\nodejs\npm.cmd install w`, "(cd sub && pnpm add q)",
		"if true; then npm i a; fi", "echo hi | xargs npm i",
		"sudo -n npm i x", "time -p npm i x", "nice -n 10 npm i x", "doas -u root pip install z", "xargs -n 1 npm i",
	}
	for _, cmd := range sends {
		before := len(f.calls())
		_ = runCodex(t, srv.URL, codexInput("Bash", cmd))
		if len(f.calls()) != before+1 {
			t.Errorf("not sent: %q", cmd)
		}
	}
	quiet := []string{
		"ls -la", "git status", "npm run build", "npm test", "pip list", "pip show requests",
		"uv run main.py", "code --list-extensions", "echo npm install x", `grep "npm install" README.md`,
		"cat package.json", "pnpm run dev", "yarn", "bun run x", "claude mcp list", "skills list",
		"npm install", "npm ci", "git pull; pip install -r requirements.txt", // nothing named: the server stays silent
	}
	for _, cmd := range quiet {
		before := len(f.calls())
		_ = runCodex(t, srv.URL, codexInput("Bash", cmd))
		if len(f.calls()) != before {
			t.Errorf("sent although not an install: %q", cmd)
		}
	}
	// Other tools and other events: nothing sent, nothing printed.
	for _, in := range []string{
		codexInput("apply_patch", "*** Begin Patch\nnpm install x"),
		codexInput("mcp__fs__read", "npm install x"),
		strings.Replace(codexInput("Bash", "npm i x"), `"PreToolUse"`, `"PostToolUse"`, 1),
	} {
		before := len(f.calls())
		if out := runCodex(t, srv.URL, in); out != "" || len(f.calls()) != before {
			t.Errorf("input %.60q: printed %q, sent %d", in, out, len(f.calls())-before)
		}
	}
	// Input it cannot read — not JSON, nothing, a command that is not a string: nothing sent, and held (the server's
	// own answer to a hook input it cannot read), never let through as before the second round.
	for _, in := range []string{"not json", "", `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":42}}`} {
		before := len(f.calls())
		out := runCodex(t, srv.URL, in)
		if len(f.calls()) != before || !strings.Contains(out, `"permissionDecision":"deny"`) || !strings.Contains(out, "NOT CHECKED") {
			t.Errorf("input %.60q: printed %q, sent %d", in, out, len(f.calls())-before)
		}
	}
}

// A runtime name the adapter does not know is an error, so a misconfigured hook is seen, not silent.
func TestHookUnknownRuntime(t *testing.T) {
	if err := runHook("windsurf", strings.NewReader(codexInput("Bash", "npm i x")), io.Discard, http.DefaultClient, "http://127.0.0.1:1"); err == nil {
		t.Fatal("an unknown runtime was accepted")
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
