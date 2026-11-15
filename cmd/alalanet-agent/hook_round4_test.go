package main

// ADR-0150, fourth round: each runtime's hook format checked again against its own documentation on 2026-11-15
// (cursor.com/docs/hooks, docs.github.com/en/copilot/reference/hooks-configuration,
// code.visualstudio.com/docs/copilot/customization/hooks, antigravity.google/docs/hooks). Cursor documents a second
// pre-tool event that runs shell commands — preToolUse with tool_name "Shell" and tool_input.command — which the
// adapter answered with allow, reading nothing. The samples below are the documented inputs, with every documented
// member filled with data that must stay on the machine.

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

const placeholderInstall = "npm i example-placeholder-pkg"

// cursorPreToolUseInput is Cursor's preToolUse input (cursor.com/docs/hooks, "Common schema" and "preToolUse", read
// 2026-11-15): the common fields, tool_name, tool_input with command and working_directory, tool_use_id, cwd, the
// model's fields and agent_message.
func cursorPreToolUseInput(tool string, toolInput any) string {
	b, _ := json.Marshal(map[string]any{"conversation_id": "c-1", "generation_id": "g-1", "model": "m", "model_id": "m-id",
		"model_params": map[string]any{"temperature": 0}, "hook_event_name": "preToolUse", "cursor_version": "3.2",
		"workspace_roots": []string{"/home/dev/secret-project"}, "user_email": "dev@example.com", "transcript_path": "/home/dev/t.jsonl",
		"tool_name": tool, "tool_input": toolInput, "tool_use_id": "tu-1", "cwd": "/home/dev/secret-project",
		"agent_message": "I will install it now"})
	return string(b)
}

func shellInput(command string) map[string]any {
	return map[string]any{"command": command, "working_directory": "/home/dev/secret-project"}
}

// sentExactly fails unless the one request carries the command in the plugin hook's shape and nothing else.
func sentExactly(t *testing.T, what string, calls []string, command string) {
	t.Helper()
	if len(calls) != 1 {
		t.Fatalf("%s: %d calls, want 1", what, len(calls))
	}
	var got, want map[string]any
	if err := json.Unmarshal([]byte(calls[0]), &got); err != nil {
		t.Fatalf("%s: body %q: %v", what, calls[0], err)
	}
	_ = json.Unmarshal([]byte(mustJSON(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Bash",
		"tool_input": map[string]string{"command": command}})), &want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: sent %s", what, calls[0])
	}
	for _, private := range []string{"secret-project", "dev@example.com", "c-1", "g-1", "s-1", "tu-1", "t.jsonl", "install it now", "m-id"} {
		if strings.Contains(calls[0], private) {
			t.Fatalf("%s: %q left the machine: %s", what, private, calls[0])
		}
	}
}

// cursorSchema: every Cursor answer is a JSON object in the schema of both its shell events (invalid JSON or an
// answer off the schema blocks the action), and never "ask" ("accepted by the schema but not enforced for preToolUse").
func cursorSchema(t *testing.T, out string) {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("Cursor answer is not JSON: %q", out)
	}
	for k, v := range m {
		if _, ok := v.(string); !ok || (k != "permission" && k != "user_message" && k != "agent_message") {
			t.Errorf("Cursor answer member %q = %v: %s", k, v, out)
		}
	}
	if p := m["permission"]; p != "allow" && p != "deny" {
		t.Errorf("Cursor permission %v: %s", p, out)
	}
}

func TestCursorPreToolUseShellIsChecked(t *testing.T) {
	answers := map[string]string{
		"deny":  `{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"alalanet install_check: BLOCK — x"}}`,
		"hold":  `{"hookSpecificOutput":{"permissionDecision":"ask","permissionDecisionReason":"alalanet install_check: HOLD — y"}}`,
		"allow": ``,
	}
	for kind, body := range answers {
		f := &fakeHook{answer: func(w http.ResponseWriter) { _, _ = w.Write([]byte(body)) }}
		srv := f.server(t)
		out := runRuntime(t, "cursor", srv.URL, cursorPreToolUseInput("Shell", shellInput(placeholderInstall)))
		cursorSchema(t, out)
		want := map[string]string{"deny": "deny", "hold": "hold", "allow": "silent"}[kind]
		if got := answerForm(t, "cursor", out); got != want {
			t.Errorf("preToolUse Shell, server %s: %s (%s)", kind, got, out)
		}
		sentExactly(t, "preToolUse Shell "+kind, f.calls(), placeholderInstall)
		if !strings.Contains(f.agents[0], "hook cursor") {
			t.Errorf("User-Agent %q", f.agents[0])
		}
	}
	// alalanet unreachable: the install goes on, as with beforeShellExecution.
	out := runRuntime(t, "cursor", "http://127.0.0.1:1", cursorPreToolUseInput("Shell", shellInput(placeholderInstall)))
	cursorSchema(t, out)
	if answerForm(t, "cursor", out) != "silent" {
		t.Errorf("unreachable: %s", out)
	}
	f := &fakeHook{answer: func(w http.ResponseWriter) { _, _ = w.Write([]byte(answers["deny"])) }}
	srv := f.server(t)
	// Not an install, and the other tools (Read, Write, an MCP tool) whatever their input says: allow, nothing sent.
	for _, in := range []string{
		cursorPreToolUseInput("Shell", shellInput("ls -la")),
		cursorPreToolUseInput("Read", shellInput(placeholderInstall)),
		cursorPreToolUseInput("Write", shellInput(placeholderInstall)),
		cursorPreToolUseInput("MCP:run", shellInput(placeholderInstall)),
		// Another event, Shell or not, is not a pre-tool call: no opinion.
		strings.Replace(cursorPreToolUseInput("Shell", shellInput(placeholderInstall)), `"preToolUse"`, `"postToolUse"`, 1),
		strings.Replace(cursorInput(placeholderInstall), `"beforeShellExecution"`, `"afterShellExecution"`, 1),
	} {
		out := runRuntime(t, "cursor", srv.URL, in)
		cursorSchema(t, out)
		if answerForm(t, "cursor", out) != "silent" || len(f.calls()) != 0 {
			t.Errorf("%.120s: %s, %d calls", in, out, len(f.calls()))
		}
	}
	// A preToolUse whose tool or command cannot be read is held, never let through (as Codex's).
	for _, in := range []string{
		strings.Replace(cursorPreToolUseInput("Shell", shellInput(placeholderInstall)), `"tool_name":"Shell"`, `"tool_name":7`, 1),
		cursorPreToolUseInput("Shell", map[string]any{"command": []string{"npm", "i"}}),
		cursorPreToolUseInput("Shell", map[string]any{"working_directory": "/home/dev/secret-project"}),
	} {
		out := runRuntime(t, "cursor", srv.URL, in)
		cursorSchema(t, out)
		if answerForm(t, "cursor", out) != "hold" || !strings.Contains(out, "NOT CHECKED") || len(f.calls()) != 0 {
			t.Errorf("unreadable %.120s: %s, %d calls", in, out, len(f.calls()))
		}
	}
	// tool_input given as a JSON string is read too.
	args, _ := json.Marshal(shellInput(placeholderInstall))
	out = runRuntime(t, "cursor", srv.URL, cursorPreToolUseInput("Shell", string(args)))
	cursorSchema(t, out)
	if answerForm(t, "cursor", out) != "deny" {
		t.Errorf("tool_input as a string: %s", out)
	}
	sentExactly(t, "tool_input as a string", f.calls(), placeholderInstall)
	// beforeShellExecution still answers in the same schema.
	out = runRuntime(t, "cursor", srv.URL, cursorInput(placeholderInstall))
	cursorSchema(t, out)
}

// The other documented samples of 2026-11-15, confirmed unchanged: the Copilot harness's camelCase preToolUse with
// timestamp a number and toolArgs a JSON string, from powershell too; its PascalCase alias, which reports powershell as
// "Bash" ("powershell … Bash" in the alias table) with tool_input parsed; Antigravity's run_command with every
// documented argument (CommandLine, Cwd, WaitMsBeforeAsync, RunPersistent, RequestedTerminalID) and common field.
func TestHookDocumentedSamples20261115(t *testing.T) {
	copilotCamel := func(tool string) string {
		args, _ := json.Marshal(map[string]any{"command": placeholderInstall, "description": "install it now"})
		b, _ := json.Marshal(map[string]any{"sessionId": "s-1", "timestamp": 1794700000000, "cwd": "/home/dev/secret-project",
			"toolName": tool, "toolArgs": string(args)})
		return string(b)
	}
	pascal, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "s-1", "timestamp": "2026-11-15T03:00:00Z",
		"cwd": "/home/dev/secret-project", "tool_name": "Bash", "tool_input": map[string]any{"command": placeholderInstall, "description": "install it now"}})
	anti, _ := json.Marshal(map[string]any{"conversationId": "c-1", "workspacePaths": []string{"/home/dev/secret-project"},
		"transcriptPath": "/home/dev/t.jsonl", "artifactDirectoryPath": "/home/dev/secret-project/a", "modelName": "m-id",
		"lastUserInput": "install it now", "stepIdx": 0, "toolCall": map[string]any{"name": "run_command", "args": map[string]any{
			"CommandLine": placeholderInstall, "Cwd": "/home/dev/secret-project", "WaitMsBeforeAsync": 500,
			"RunPersistent": false, "RequestedTerminalID": "tu-1"}}})
	for _, c := range []struct{ name, runtime, input, want string }{
		{"copilot bash", "copilot", copilotCamel("bash"), "deny"},
		{"copilot powershell", "copilot", copilotCamel("powershell"), "deny"},
		{"copilot PascalCase", "copilot", string(pascal), "deny"},
		{"antigravity", "antigravity", string(anti), "deny"},
	} {
		f := &fakeHook{answer: func(w http.ResponseWriter) {
			_, _ = w.Write([]byte(`{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"alalanet install_check: BLOCK — x"}}`))
		}}
		srv := f.server(t)
		if got := answerForm(t, c.runtime, runRuntime(t, c.runtime, srv.URL, c.input)); got != c.want {
			t.Errorf("%s: %s", c.name, got)
		}
		sentExactly(t, c.name, f.calls(), placeholderInstall)
	}
}

// Cursor blocks on any answer that is not JSON in its schema: on every input the Cursor adapter prints one line of
// JSON with permission allow or deny, whichever shell event the input names (alalanet unreachable).
func FuzzCursorAnswerAlwaysInSchema(f *testing.F) {
	args, _ := json.Marshal(shellInput(placeholderInstall))
	for _, s := range []string{cursorPreToolUseInput("Shell", shellInput(placeholderInstall)), cursorPreToolUseInput("Shell", string(args)),
		cursorPreToolUseInput("Read", shellInput("x")), cursorInput(placeholderInstall), `{"hook_event_name":"preToolUse"}`,
		`{"hook_event_name":"preToolUse","tool_name":"Shell","tool_input":"{"}`, "\ufeff{}", "[]", "null"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		var out strings.Builder
		if err := runHook("cursor", strings.NewReader(string(in)), &out, &http.Client{Timeout: time.Second}, "http://127.0.0.1:1"); err != nil {
			t.Fatal(err)
		}
		if s := out.String(); strings.Count(s, "\n") != 1 || !strings.HasSuffix(s, "\n") {
			t.Fatalf("not one line: %q", s)
		}
		cursorSchema(t, out.String())
	})
}
