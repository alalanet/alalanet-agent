package main

// ADR-0150, sixth round (review of 0d873d6): a runtime's name in any case is that runtime; an unknown one ends the hook
// with exit code 2 and the usage, which Cursor, Codex and Claude Code read as a block and the Copilot harness as a deny
// — a typo in a hook file must never let installs through unchecked, as an exit 1 did (P3-R5-1). A Bash, Shell or
// PowerShell call that carries only cmd is read by cmd, as exec_command's is.

import (
	"errors"
	"strings"
	"testing"
)

func TestHookRuntimeNameInAnyCase(t *testing.T) {
	for name, runtime := range map[string]string{"Cursor": "cursor", "CODEX": "codex", "Copilot": "copilot", "AntiGravity": "antigravity", " cursor ": "cursor"} {
		f := reviewDeny()
		srv := f.server(t)
		out := runRuntime(t, name, srv.URL, shellForms(placeholderInstall)["codex Bash"])
		if got := form5(t, runtime, out); got != "deny" {
			t.Errorf("hook %q: %s (%q)", name, got, out)
		}
		sentExactly(t, "hook "+name, f.calls(), placeholderInstall)
		if !strings.Contains(f.agents[0], "(hook "+runtime+")") {
			t.Errorf("hook %q: User-Agent %q", name, f.agents[0])
		}
	}
}

func TestHookUnknownRuntimeExitsTwo(t *testing.T) {
	for _, args := range [][]string{{"hook", "vscode"}, {"hook", "cursr"}, {"hook", ""}, {"hook"}, {"hook", "cursor", "extra"}} {
		err := run(args)
		if code := exitCode(err); code != 2 {
			t.Errorf("%q: exit %d (%v), want 2", args, code, err)
		}
		if err == nil || !strings.Contains(err.Error(), hookUsage) {
			t.Errorf("%q: %v does not carry the usage", args, err)
		}
	}
	var stderr strings.Builder
	if code := runMain([]string{"hook", "Vscode"}, &stderr); code != 2 || !strings.HasPrefix(stderr.String(), "error: unknown runtime \"Vscode\"") ||
		!strings.Contains(stderr.String(), hookUsage) || strings.Count(stderr.String(), "\n") != 1 {
		t.Errorf("runMain hook Vscode: exit %d, stderr %q", code, stderr.String())
	}
	stderr.Reset()
	if code := runMain([]string{"version"}, &stderr); code != 0 || stderr.Len() != 0 {
		t.Errorf("runMain version: exit %d, stderr %q", code, stderr.String())
	}
	if exitCode(nil) != 0 || exitCode(errors.New("a key file that cannot be read")) != 1 || exitCode(run(nil)) != 1 {
		t.Errorf("exit codes outside hook: %d %d %d", exitCode(nil), exitCode(errors.New("x")), exitCode(run(nil)))
	}
}

func TestHookShellCallWithOnlyCmd(t *testing.T) {
	for _, tool := range []string{"Bash", "Shell", "PowerShell", "bash"} {
		in := j5(map[string]any{"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": map[string]any{"cmd": placeholderInstall}})
		for runtime := range hookRuntimes {
			f := reviewDeny()
			srv := f.server(t)
			if got := form5(t, runtime, runRuntime(t, runtime, srv.URL, in)); got != "deny" {
				t.Errorf("hook %s, %s with cmd: %s", runtime, tool, got)
				continue
			}
			sentExactly(t, "hook "+runtime+", "+tool+" with cmd", f.calls(), placeholderInstall)
		}
	}
	// cmd that is not an install is no opinion, with nothing sent (Cursor's tool_input given as a JSON string too).
	f0 := reviewDeny()
	srv0 := f0.server(t)
	if out := runRuntime(t, "cursor", srv0.URL, cursorPreToolUseInput("Shell", `{"cmd":"ls -la"}`)); answerForm(t, "cursor", out) != "silent" || len(f0.calls()) != 0 {
		t.Errorf("cmd ls: %q, %d calls", out, len(f0.calls()))
	}
	// command, when it is there, is the command.
	f := reviewDeny()
	srv := f.server(t)
	in := j5(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": map[string]any{"command": placeholderInstall, "cmd": "ls"}})
	_ = runRuntime(t, "codex", srv.URL, in)
	sentExactly(t, "command and cmd", f.calls(), placeholderInstall)
}
