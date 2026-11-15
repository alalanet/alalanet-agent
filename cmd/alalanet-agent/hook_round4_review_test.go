package main

// Independent review of RT-1 round 4 (cc2bccd, 2026-11-15): the forms of Cursor's preToolUse the commit's own tests do
// not cover. The live payload a Cursor 3.13.25 user posted (forum.cursor.com/t/inconsistent-hook-payload/166997, staff
// confirmed: tool_input carries command, cwd and timeout; no agent_message), a byte-order mark before a preToolUse, a
// tool_input that is a plain string, null or a number, duplicate names, the fail-closed policy, and two forms the adapter
// lets through without a check today (pinned so a change to them is deliberate).

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"
)

const reviewInstall = "npm i example-placeholder-pkg"

func reviewDeny() *fakeHook {
	return &fakeHook{answer: func(w http.ResponseWriter) {
		_, _ = w.Write([]byte(`{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"alalanet install_check: BLOCK — x"}}`))
	}}
}

// The live form: tool_input {command, cwd, timeout}; only the command leaves the machine.
func TestReviewR4CursorLivePayload(t *testing.T) {
	f := reviewDeny()
	srv := f.server(t)
	in := cursorPreToolUseInput("Shell", map[string]any{"command": reviewInstall, "cwd": "/home/dev/secret-project", "timeout": 30000})
	out := runRuntime(t, "cursor", srv.URL, in)
	cursorSchema(t, out)
	if answerForm(t, "cursor", out) != "deny" {
		t.Fatalf("live payload: %s", out)
	}
	sentExactly(t, "live payload", f.calls(), reviewInstall)
	if strings.Contains(f.calls()[0], "30000") {
		t.Fatalf("timeout left the machine: %s", f.calls()[0])
	}
}

// A byte-order mark before a preToolUse (Cursor on Windows pipes the JSON through PowerShell) is read as before.
func TestReviewR4CursorPreToolUseBOM(t *testing.T) {
	f := reviewDeny()
	srv := f.server(t)
	out := runRuntime(t, "cursor", srv.URL, "\xef\xbb\xbf"+cursorPreToolUseInput("Shell", shellInput(reviewInstall)))
	cursorSchema(t, out)
	if answerForm(t, "cursor", out) != "deny" {
		t.Fatalf("BOM: %s", out)
	}
	sentExactly(t, "BOM", f.calls(), reviewInstall)
}

// A Shell call whose tool_input is a plain command string, null, a number, an array, or a JSON string whose command is
// not a string is held, never allowed and never sent.
// (Round 6: a JSON string with only cmd is read by cmd, as for exec_command, so the review's {"cmd":"x"} became
// {"cmd":7} and {"other":"x"}; TestHookShellCallWithOnlyCmd covers cmd itself.)
func TestReviewR4CursorUnreadableToolInput(t *testing.T) {
	f := reviewDeny()
	srv := f.server(t)
	for _, ti := range []any{reviewInstall, nil, 7, []string{reviewInstall}, `{"command":["npm","i"]}`, `{"cmd":7}`, `{"other":"x"}`, ``} {
		out := runRuntime(t, "cursor", srv.URL, cursorPreToolUseInput("Shell", ti))
		cursorSchema(t, out)
		if answerForm(t, "cursor", out) != "hold" || !strings.Contains(out, "NOT CHECKED") || len(f.calls()) != 0 {
			t.Errorf("tool_input %#v: %s, %d calls", ti, out, len(f.calls()))
		}
	}
}

// Duplicate names keep the last value (as JSON.parse): the tool and the command the runtime itself would read.
func TestReviewR4CursorDuplicateNames(t *testing.T) {
	f := reviewDeny()
	srv := f.server(t)
	in := `{"hook_event_name":"preToolUse","tool_name":"Read","tool_input":{"command":"ls","command":"` + reviewInstall + `"},"tool_name":"Shell"}`
	out := runRuntime(t, "cursor", srv.URL, in)
	cursorSchema(t, out)
	if answerForm(t, "cursor", out) != "deny" {
		t.Fatalf("duplicates: %s", out)
	}
	sentExactly(t, "duplicates", f.calls(), reviewInstall)
}

// The organisation's fail-closed policy holds a preToolUse install alalanet could not check, as it does for
// beforeShellExecution.
func TestReviewR4CursorPreToolUseFailClosed(t *testing.T) {
	for _, closed := range []bool{false, true} {
		var out, stderr bytes.Buffer
		if err := runHookContext(t.Context(), "cursor", strings.NewReader(cursorPreToolUseInput("Shell", shellInput(reviewInstall))), &out,
			hookCall{client: &http.Client{Timeout: time.Second}, api: "http://127.0.0.1:1", stderr: &stderr, failClosed: closed}); err != nil {
			t.Fatal(err)
		}
		cursorSchema(t, out.String())
		want := map[bool]string{false: "silent", true: "hold"}[closed]
		if got := answerForm(t, "cursor", out.String()); got != want {
			t.Errorf("failClosed=%v: %s, want %s", closed, out.String(), want)
		}
		if stderr.Len() == 0 {
			t.Errorf("failClosed=%v: no line on stderr", closed)
		}
	}
}

// Review finding P3-1, fixed in round 5: forms no Cursor hooks page names for its own hooks, but which reach
// `hook cursor` when Cursor runs a Claude Code hook from .claude/settings*.json (cursor.com/docs/reference/third-party-hooks:
// PreToolUse → preToolUse, Bash → Shell) — a PascalCase event and Claude's tool name Bash — are checked like Shell.
// P3-2 stays a known limit (ADR-0150, round 5): an MCP tool that runs commands is not read, as in the Claude plugin.
func TestReviewR4CursorClaudeFormsChecked(t *testing.T) {
	f := reviewDeny()
	srv := f.server(t)
	for i, in := range []string{
		strings.Replace(cursorPreToolUseInput("Shell", shellInput(reviewInstall)), `"preToolUse"`, `"PreToolUse"`, 1),
		cursorPreToolUseInput("Bash", shellInput(reviewInstall)),
	} {
		out := runRuntime(t, "cursor", srv.URL, in)
		cursorSchema(t, out)
		if answerForm(t, "cursor", out) != "deny" || len(f.calls()) != i+1 {
			t.Errorf("%.100s: %s, %d calls", in, out, len(f.calls()))
		}
	}
	if calls := f.calls(); len(calls) == 2 {
		sentExactly(t, "Claude's names", calls[1:], reviewInstall)
	}
	in := cursorPreToolUseInput("MCP:run_command", map[string]any{"command": reviewInstall})
	out := runRuntime(t, "cursor", srv.URL, in)
	cursorSchema(t, out)
	if answerForm(t, "cursor", out) != "silent" || len(f.calls()) != 2 {
		t.Errorf("%.100s: %s, %d calls", in, out, len(f.calls()))
	}
}
