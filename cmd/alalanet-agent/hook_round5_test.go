package main

// ADR-0150, fifth round (review of cc2bccd, P3-1): a hook file can run one runtime's adapter under another runtime —
// Cursor runs Claude Code hooks from .claude/settings*.json with its own names mapped (cursor.com/docs/reference/
// third-party-hooks), the Copilot harness reads the repository's .claude/settings.json (VS Code agent hooks). So every
// adapter reads every runtime's known form of a shell call — the event and tool names without regard to case where the
// runtimes spell them differently — and checks it or holds it; it never answers no opinion to a shell call. A call in
// another runtime's form is answered in the adapter's own form (Cursor accepts Claude's nested answer and its own flat
// one: "Both formats are equivalent").

import (
	"encoding/json"
	"strings"
	"testing"
)

// form5 is the runtime-independent reading of an answer: deny, hold or silent. Copilot's answer to VS Code's Local
// harness is nested (hookSpecificOutput), the rest are as answerForm reads them.
func form5(t *testing.T, runtime, out string) string {
	t.Helper()
	if runtime == "copilot" && strings.Contains(out, "hookSpecificOutput") {
		var m struct {
			H map[string]string `json:"hookSpecificOutput"`
		}
		if err := json.Unmarshal([]byte(out), &m); err != nil {
			t.Fatalf("copilot printed %q", out)
		}
		return map[string]string{"deny": "deny", "ask": "hold"}[m.H["permissionDecision"]]
	}
	return answerForm(t, runtime, out)
}

func j5(v any) string { return mustJSON(v) }

// shellForms are the shell calls of every runtime, in its documented form and the spellings a mapped hook can bring.
func shellForms(command any) map[string]string {
	camel := func(tool string) string {
		args := j5(map[string]any{"command": command})
		return j5(map[string]any{"sessionId": "s-1", "cwd": "/home/dev/secret-project", "toolName": tool, "toolArgs": args})
	}
	event := func(event, tool string) string {
		return j5(map[string]any{"hook_event_name": event, "tool_name": tool, "session_id": "s-1", "cwd": "/home/dev/secret-project",
			"tool_input": map[string]any{"command": command, "cwd": "/home/dev/secret-project"}})
	}
	return map[string]string{
		"codex Bash":                        event("PreToolUse", "Bash"),
		"codex exec_command cmd":            j5(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "exec_command", "tool_input": map[string]any{"cmd": command}}),
		"cursor beforeShellExecution":       j5(map[string]any{"hook_event_name": "beforeShellExecution", "command": command, "cwd": "/home/dev/secret-project"}),
		"cursor BeforeShellExecution":       j5(map[string]any{"hook_event_name": "BeforeShellExecution", "command": command}),
		"cursor preToolUse Shell":           event("preToolUse", "Shell"),
		"cursor preToolUse Bash (Claude)":   event("preToolUse", "Bash"),
		"cursor PreToolUse Shell":           event("PreToolUse", "Shell"),
		"cursor pretooluse shell":           event("pretooluse", "shell"),
		"cursor PRETOOLUSE SHELL":           event("PRETOOLUSE", "SHELL"),
		"copilot bash":                      camel("bash"),
		"copilot powershell":                camel("powershell"),
		"copilot Bash":                      camel("Bash"),
		"copilot PascalCase Bash":           event("PreToolUse", "Bash"),
		"copilot PascalCase PowerShell":     event("PreToolUse", "PowerShell"),
		"vscode local run_in_terminal":      event("PreToolUse", "run_in_terminal"),
		"antigravity run_command":           j5(map[string]any{"conversationId": "c-1", "toolCall": map[string]any{"name": "run_command", "args": map[string]any{"CommandLine": command}}}),
		"claude form without an event name": j5(map[string]any{"tool_name": "Bash", "tool_input": map[string]any{"command": command}}),
	}
}

// Every adapter checks every runtime's shell call: one request with the command and nothing else, the server's block
// in the adapter's own answer.
func TestHookEveryAdapterReadsEveryForm(t *testing.T) {
	for runtime := range hookRuntimes {
		for name, in := range shellForms(placeholderInstall) {
			f := reviewDeny()
			srv := f.server(t)
			out := runRuntime(t, runtime, srv.URL, in)
			if got := form5(t, runtime, out); got != "deny" {
				t.Errorf("hook %s, %s: %s (%q)", runtime, name, got, out)
				continue
			}
			if runtime == "cursor" {
				cursorSchema(t, out)
			}
			sentExactly(t, "hook "+runtime+", "+name, f.calls(), placeholderInstall)
		}
	}
}

// A shell call in any form whose command cannot be read is held, in every adapter, with nothing sent.
func TestHookEveryAdapterHoldsAnUnreadableShellCall(t *testing.T) {
	for runtime := range hookRuntimes {
		for name, in := range shellForms([]string{"npm", "i"}) {
			f := reviewDeny()
			srv := f.server(t)
			out := runRuntime(t, runtime, srv.URL, in)
			if got := form5(t, runtime, out); got != "hold" || !strings.Contains(out, "NOT CHECKED") || len(f.calls()) != 0 {
				t.Errorf("hook %s, %s: %s, %d calls (%q)", runtime, name, got, len(f.calls()), out)
			}
		}
	}
}

// What is not a shell call in any form stays no opinion in every adapter, with nothing sent: another tool, another
// event, an MCP tool (a known limit, as in the Claude plugin), and the near-misses of the shell tools' names.
func TestHookEveryAdapterLeavesOtherCalls(t *testing.T) {
	ev := func(event, tool string) string {
		return j5(map[string]any{"hook_event_name": event, "tool_name": tool, "tool_input": map[string]any{"command": placeholderInstall}})
	}
	others := []string{
		ev("PreToolUse", "Read"), ev("preToolUse", "Write"), ev("preToolUse", "MCP:run_command"), ev("PreToolUse", "apply_patch"),
		ev("PostToolUse", "Bash"), ev("postToolUse", "Shell"), ev("afterShellExecution", "Shell"),
		ev("PreToolUse", "Bashx"), ev("PreToolUse", "shell_x"), ev("PreToolUse", "Exec_command"), ev("PreToolUse", "Run_in_terminal"),
		j5(map[string]any{"hook_event_name": "beforeMCPExecution", "command": placeholderInstall}),
		j5(map[string]any{"hook_event_name": "afterShellExecution", "command": placeholderInstall}),
		j5(map[string]any{"toolName": "edit", "toolArgs": j5(map[string]any{"command": placeholderInstall})}),
		j5(map[string]any{"toolName": "bash_x", "toolArgs": j5(map[string]any{"command": placeholderInstall})}),
		antigravityInput("view_file", placeholderInstall), antigravityInput("Run_command", placeholderInstall),
	}
	for runtime := range hookRuntimes {
		for _, in := range others {
			f := reviewDeny()
			srv := f.server(t)
			out := runRuntime(t, runtime, srv.URL, in)
			if got := form5(t, runtime, out); got != "silent" || len(f.calls()) != 0 {
				t.Errorf("hook %s, %.100s: %s, %d calls", runtime, in, got, len(f.calls()))
			}
		}
	}
}

// An input that carries two forms: when both are shell calls with one command, it is checked once; with two different
// commands the adapter cannot know which one runs, so it holds; a shell call next to another form's other tool is
// checked.
func TestHookTwoFormsInOneInput(t *testing.T) {
	both := func(a, b string) string {
		return j5(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": map[string]any{"command": a},
			"toolName": "bash", "toolArgs": j5(map[string]any{"command": b})})
	}
	for runtime := range hookRuntimes {
		f := reviewDeny()
		srv := f.server(t)
		if got := form5(t, runtime, runRuntime(t, runtime, srv.URL, both(placeholderInstall, placeholderInstall))); got != "deny" {
			t.Errorf("hook %s, one command twice: %s", runtime, got)
		}
		sentExactly(t, "hook "+runtime+", one command twice", f.calls(), placeholderInstall)
		if out := runRuntime(t, runtime, srv.URL, both("ls", placeholderInstall)); form5(t, runtime, out) != "hold" || len(f.calls()) != 1 {
			t.Errorf("hook %s, two commands: %q, %d calls", runtime, out, len(f.calls()))
		}
		mixed := j5(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": map[string]any{"command": "ls"},
			"toolCall": map[string]any{"name": "run_command", "args": map[string]any{"CommandLine": placeholderInstall}}})
		if out := runRuntime(t, runtime, srv.URL, mixed); form5(t, runtime, out) != "deny" || len(f.calls()) != 2 {
			t.Errorf("hook %s, a shell call next to another tool: %q, %d calls", runtime, out, len(f.calls()))
		}
	}
}

// The printed usage names the event each runtime runs the hook on (review P3-3).
func TestHookUsageNamesTheEvents(t *testing.T) {
	for _, args := range [][]string{{"hook"}, {"hook", "nope"}} {
		err := run(args)
		if err == nil {
			t.Fatalf("%v: no error", args)
		}
		for _, want := range []string{"codex PreToolUse", "cursor beforeShellExecution and preToolUse (matcher Shell)",
			"copilot preToolUse", "antigravity PreToolUse"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%v: %q does not say %q", args, err, want)
			}
		}
	}
}

// A form whose event or tool name is not a string is held in every adapter, also next to another form's other tool;
// so is an input whose second shell reading has a command that cannot be read (the four mutants that survived the
// first pass of ADR-0150's fifth round).
func TestHookNamesThatAreNotStringsAreHeld(t *testing.T) {
	for _, in := range []string{
		j5(map[string]any{"hook_event_name": 7, "tool_name": "Bash", "tool_input": map[string]any{"command": placeholderInstall}}),
		j5(map[string]any{"hook_event_name": 7}),
		j5(map[string]any{"toolName": 7, "toolArgs": map[string]any{"command": placeholderInstall}}),
		j5(map[string]any{"toolCall": map[string]any{"name": 7, "args": map[string]any{"CommandLine": placeholderInstall}}}),
		j5(map[string]any{"hook_event_name": 7, "toolName": "edit"}),
		j5(map[string]any{"toolCall": map[string]any{"name": []string{"run_command"}}, "hook_event_name": "PreToolUse", "tool_name": "Read"}),
		j5(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": map[string]any{"command": placeholderInstall},
			"toolName": "bash", "toolArgs": map[string]any{"command": 7}}),
	} {
		for runtime := range hookRuntimes {
			f := reviewDeny()
			srv := f.server(t)
			out := runRuntime(t, runtime, srv.URL, in)
			if got := form5(t, runtime, out); got != "hold" || !strings.Contains(out, "NOT CHECKED") || len(f.calls()) != 0 {
				t.Errorf("hook %s, %.120s: %s, %d calls", runtime, in, got, len(f.calls()))
			}
		}
	}
}
