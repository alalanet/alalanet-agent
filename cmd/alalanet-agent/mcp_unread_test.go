package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A runtime's own configuration file that is there but does not read (a repository can write its project file so on
// purpose) leaves the called server unfound: the hook never lets that call go ahead without a word (re-review r3,
// P2-G). Claude Code and Cursor show a warning, Codex, the Copilot harness and Antigravity get a line on stderr; under
// ALALANET_FAIL_CLOSED and ALALANET_MCP_UNVERIFIED=hold every runtime holds.
func TestHookMCPUnreadableConfigIsNeverSilent(t *testing.T) {
	const bad = `{"mcpServers":{"docs":{"type":"http","url":5}},"servers":{"docs":{"type":"http","url":5}}}`
	write := func(t *testing.T, path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		runtime string
		setup   func(t *testing.T, r *mcpRig)
		input   func(r *mcpRig) string
		visible bool // a warning in the answer, not a line on stderr
	}{
		{"claude-code", func(t *testing.T, r *mcpRig) { write(t, filepath.Join(r.cwd, ".mcp.json"), bad) },
			func(r *mcpRig) string {
				return mustJSON(map[string]any{"session_id": "s", "cwd": r.cwd, "hook_event_name": "PreToolUse", "tool_name": "mcp__repo__search",
					"tool_input": map[string]any{}, "mcp_server": map[string]any{"name": "repo", "source": "project"}})
			}, true},
		{"cursor", func(t *testing.T, r *mcpRig) { write(t, filepath.Join(r.home, ".cursor", "mcp.json"), bad) },
			func(r *mcpRig) string { return cursorMCPInput("repo", "", "", "c") }, true},
		{"codex", func(t *testing.T, r *mcpRig) {
			write(t, filepath.Join(r.home, ".codex", "config.toml"), "[mcp_servers.docs\n")
		},
			func(r *mcpRig) string { return codexMCPInput("mcp__repo__search") }, false},
		{"copilot", func(t *testing.T, r *mcpRig) { write(t, filepath.Join(r.cwd, ".vscode", "mcp.json"), bad) },
			func(r *mcpRig) string {
				return mustJSON(map[string]any{"sessionId": "s", "cwd": r.cwd, "toolName": "repo/search", "toolArgs": `{}`})
			}, false},
		{"antigravity", func(t *testing.T, r *mcpRig) { write(t, filepath.Join(r.cwd, ".agents", "mcp_config.json"), bad) },
			func(r *mcpRig) string {
				return mustJSON(map[string]any{"conversationId": "c", "workspacePaths": []string{r.cwd},
					"toolCall": map[string]any{"name": "call_mcp_tool", "args": map[string]any{"ServerName": "repo", "ToolName": "search"}}})
			}, false},
	} {
		r := newMCPRig(t, mcpBase)
		c.setup(t, r)
		in := c.input(r)
		out, errText := r.hook(t, c.runtime, in, false)
		switch {
		case c.visible:
			if form, text := mcpForm(t, c.runtime, out); form != "warn" || !strings.Contains(text, "cannot be checked") {
				t.Errorf("%s: %s %q (stderr %q)", c.runtime, form, text, errText)
			}
		default:
			if form5(t, c.runtime, out) != "silent" || !strings.Contains(errText, "cannot be checked") {
				t.Errorf("%s: %q, stderr %q", c.runtime, out, errText)
			}
		}
		// held: claude-code asks, cursor denies with the message, the others hold (form5).
		held := func(out string) bool {
			switch c.runtime {
			case "claude-code":
				f, _ := mcpForm(t, c.runtime, out)
				return f == "ask"
			case "cursor":
				f, _ := mcpForm(t, c.runtime, out)
				return f == "deny"
			}
			return form5(t, c.runtime, out) == "hold"
		}
		if out, _ := r.hook(t, c.runtime, in, true); !held(out) || !strings.Contains(out, "ALALANET_FAIL_CLOSED") {
			t.Errorf("%s, ALALANET_FAIL_CLOSED: %q", c.runtime, out)
		}
		r.v.UnverifiedHold = true
		if out, _ := r.hook(t, c.runtime, in, false); !held(out) || !strings.Contains(out, "ALALANET_MCP_UNVERIFIED") {
			t.Errorf("%s, ALALANET_MCP_UNVERIFIED=hold: %q", c.runtime, out)
		}
	}
}
