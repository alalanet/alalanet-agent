package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// Inputs as each runtime documents them (read 2026-11-13): Cursor's beforeShellExecution (cursor.com/docs/hooks), the
// Copilot harness's preToolUse with toolArgs as a JSON string (docs.github.com cli-hooks-reference; github/awesome-copilot
// hooks.instructions.md: "toolArgs is a JSON string"), its PascalCase alias, Antigravity's PreToolUse
// (antigravity.google/docs/hooks).
func cursorInput(command string) string {
	b, _ := json.Marshal(map[string]any{"hook_event_name": "beforeShellExecution", "command": command, "cwd": "/home/dev/secret-project",
		"sandbox": false, "conversation_id": "c-1", "generation_id": "g-1", "model": "m", "user_email": "dev@example.com",
		"workspace_roots": []string{"/home/dev/secret-project"}, "transcript_path": "/home/dev/t.jsonl", "cursor_version": "2.5"})
	return string(b)
}

func copilotInput(tool, command string) string {
	args, _ := json.Marshal(map[string]string{"command": command, "description": "run"})
	b, _ := json.Marshal(map[string]any{"sessionId": "s-1", "timestamp": 1794600000000, "cwd": "/home/dev/secret-project",
		"toolName": tool, "toolArgs": string(args)})
	return string(b)
}

func copilotPascalInput(command string) string {
	b, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "s-1", "timestamp": "2026-11-13T18:00:00Z",
		"cwd": "/home/dev/secret-project", "tool_name": "Bash", "tool_input": map[string]string{"command": command}})
	return string(b)
}

func antigravityInput(tool, command string) string {
	b, _ := json.Marshal(map[string]any{"conversationId": "c-1", "workspacePaths": []string{"/home/dev/secret-project"},
		"transcriptPath": "/home/dev/t", "artifactDirectoryPath": "/home/dev/a", "modelName": "m", "lastUserInput": "install it",
		"stepIdx": 3, "toolCall": map[string]any{"name": tool, "args": map[string]any{"CommandLine": command, "Cwd": "/home/dev/secret-project"}}})
	return string(b)
}

func runRuntime(t *testing.T, runtime, api, input string) string {
	t.Helper()
	var out strings.Builder
	if err := runHook(runtime, strings.NewReader(input), &out, &http.Client{}, api); err != nil {
		t.Fatalf("%s: %v", runtime, err)
	}
	return out.String()
}

func TestHookRuntimes(t *testing.T) {
	answer := map[string]func(w http.ResponseWriter){
		"deny": func(w http.ResponseWriter) {
			_, _ = w.Write([]byte(`{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"alalanet install_check: BLOCK — x"}}`))
		},
		"ask": func(w http.ResponseWriter) {
			_, _ = w.Write([]byte(`{"hookSpecificOutput":{"permissionDecision":"ask","permissionDecisionReason":"alalanet install_check: HOLD — y"}}`))
		},
		"allow": func(w http.ResponseWriter) {},
	}
	for _, rt := range []struct {
		name      string
		install   string
		other     string
		wantDeny  func(t *testing.T, out string)
		wantHold  func(t *testing.T, out string)
		wantQuiet func(t *testing.T, out string) // no opinion, alalanet unreachable, not an install
	}{
		{"cursor", cursorInput("npm i left-pad"), cursorInput("ls -la"),
			func(t *testing.T, out string) { expectFields(t, out, map[string]string{"permission": "deny"}, "BLOCK") },
			// Cursor's "ask" is not reliable (ignored in auto-review mode and sandboxed shells, forum reports): a hold is a deny.
			func(t *testing.T, out string) {
				expectFields(t, out, map[string]string{"permission": "deny"}, "confirm with the user")
			},
			// Cursor reads a missing or invalid answer inconsistently: always valid JSON; its own allow-list still applies.
			func(t *testing.T, out string) { expectFields(t, out, map[string]string{"permission": "allow"}, "") }},
		{"copilot", copilotInput("bash", "npm i left-pad"), copilotInput("bash", "ls -la"),
			func(t *testing.T, out string) {
				expectFields(t, out, map[string]string{"permissionDecision": "deny"}, "BLOCK")
			},
			func(t *testing.T, out string) {
				expectFields(t, out, map[string]string{"permissionDecision": "ask"}, "HOLD")
			},
			func(t *testing.T, out string) { expectEmpty(t, out) }},
		{"antigravity", antigravityInput("run_command", "npm i left-pad"), antigravityInput("run_command", "ls -la"),
			func(t *testing.T, out string) { expectFields(t, out, map[string]string{"decision": "deny"}, "BLOCK") },
			// "ask" respects cached "Always Allow" grants, "force_ask" always prompts (Antigravity's docs; ADR-0150's
			// second round, the review's P2-3).
			func(t *testing.T, out string) {
				expectFields(t, out, map[string]string{"decision": "force_ask"}, "HOLD")
			},
			// "allow" hands the call to the next hook or the default policy (Antigravity's docs).
			func(t *testing.T, out string) { expectFields(t, out, map[string]string{"decision": "allow"}, "") }},
	} {
		for kind, check := range map[string]func(*testing.T, string){"deny": rt.wantDeny, "ask": rt.wantHold, "allow": rt.wantQuiet} {
			f := &fakeHook{answer: answer[kind]}
			srv := f.server(t)
			check(t, runRuntime(t, rt.name, srv.URL, rt.install))
			calls := f.calls()
			if len(calls) != 1 {
				t.Fatalf("%s %s: %d calls", rt.name, kind, len(calls))
			}
			for _, private := range []string{"secret-project", "dev@example.com", "s-1", "c-1", "install it", "t.jsonl"} {
				if strings.Contains(calls[0], private) {
					t.Fatalf("%s: %q left the machine: %s", rt.name, private, calls[0])
				}
			}
			if !strings.Contains(f.agents[0], "hook "+rt.name) {
				t.Errorf("%s: User-Agent %q", rt.name, f.agents[0])
			}
			before := len(f.calls())
			rt.wantQuiet(t, runRuntime(t, rt.name, srv.URL, rt.other))
			if len(f.calls()) != before {
				t.Errorf("%s: a command that is not an install was sent", rt.name)
			}
		}
		rt.wantQuiet(t, runRuntime(t, rt.name, "http://127.0.0.1:1", rt.install))
	}
	// The other forms each runtime documents.
	f := &fakeHook{}
	srv := f.server(t)
	for _, c := range []struct{ runtime, input string }{
		{"copilot", copilotPascalInput("pip install requests")},
		{"copilot", copilotInput("powershell", "npm install x")},
	} {
		before := len(f.calls())
		_ = runRuntime(t, c.runtime, srv.URL, c.input)
		if len(f.calls()) != before+1 {
			t.Errorf("%s: %.80s not sent", c.runtime, c.input)
		}
	}
	// toolArgs as an object, not a string, is read too.
	objectArgs := `{"toolName":"bash","toolArgs":{"command":"npx -y cowsay"}}`
	before := len(f.calls())
	_ = runRuntime(t, "copilot", srv.URL, objectArgs)
	if len(f.calls()) != before+1 {
		t.Errorf("copilot: toolArgs as an object not read")
	}
	// Tools that are not the shell: nothing sent.
	for _, c := range []struct{ runtime, input string }{
		{"copilot", copilotInput("edit", "npm i z")}, {"antigravity", antigravityInput("view_file", "npm i z")},
		{"cursor", strings.Replace(cursorInput("npm i z"), `"beforeShellExecution"`, `"beforeReadFile"`, 1)},
	} {
		before := len(f.calls())
		_ = runRuntime(t, c.runtime, srv.URL, c.input)
		if len(f.calls()) != before {
			t.Errorf("%s: a non-shell call was sent: %.80s", c.runtime, c.input)
		}
	}
}

// Cursor on Windows prefixes the hook's stdin with a UTF-8 byte-order mark (forum report): it must not make the
// command unreadable — that would let every install through unchecked.
func TestHookReadsAByteOrderMark(t *testing.T) {
	f := &fakeHook{}
	srv := f.server(t)
	for _, rt := range []string{"cursor", "codex", "copilot", "antigravity"} {
		in := map[string]string{"cursor": cursorInput("npm i a"), "codex": codexInput("Bash", "npm i a"),
			"copilot": copilotInput("bash", "npm i a"), "antigravity": antigravityInput("run_command", "npm i a")}[rt]
		before := len(f.calls())
		_ = runRuntime(t, rt, srv.URL, "\ufeff"+in)
		if len(f.calls()) != before+1 {
			t.Errorf("%s: a stdin with a byte-order mark was not read", rt)
		}
	}
}

func expectFields(t *testing.T, out string, want map[string]string, reasonHas string) {
	t.Helper()
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("not JSON: %q", out)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %s (%s)", k, got[k], v, out)
		}
	}
	if reasonHas != "" && !strings.Contains(out, reasonHas) {
		t.Errorf("the answer does not say %q: %s", reasonHas, out)
	}
}

func expectEmpty(t *testing.T, out string) {
	t.Helper()
	if strings.TrimSpace(out) != "" {
		t.Errorf("printed %q", out)
	}
}
