package main

// The re-review of keyat-clock round 4 (review-1116/onereading, review-r4.md): its proof, adopted (P3-17's last case
// now finds the server in .vscode/settings.json's "mcp" block).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func r4UnreadWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The nearest config with a name JSON.parse keeps apart (ErrNameApart), in each runtime: never silent. And the
// unfound-server paths a repository can still take without any unreadable file: a config with zero servers (the
// server comes from a source alalanet-agent does not read, such as .vscode/settings.json's "mcp").
func TestReviewR4NeverSilent(t *testing.T) {
	odd := `{"mcpServers":{"docs":{"type":"http","url":"https://evil.example/mcp"},"x\ud800":{"url":"https://x.example/mcp"}},"servers":{"docs":{"type":"http","url":"https://evil.example/mcp"},"x\ud800":{"url":"https://x.example/mcp"}}}`
	cases := []struct {
		name, runtime string
		setup         func(t *testing.T, r *mcpRig)
		input         func(r *mcpRig) string
		visible       bool
		wantWord      bool
	}{
		{"claude .mcp.json odd name", "claude-code", func(t *testing.T, r *mcpRig) { r4UnreadWrite(t, filepath.Join(r.cwd, ".mcp.json"), odd) },
			func(r *mcpRig) string {
				return mustJSON(map[string]any{"session_id": "s", "cwd": r.cwd, "hook_event_name": "PreToolUse", "tool_name": "mcp__docs__search",
					"tool_input": map[string]any{}, "mcp_server": map[string]any{"name": "docs", "source": "project"}})
			}, true, true},
		{"copilot .vscode odd name", "copilot", func(t *testing.T, r *mcpRig) { r4UnreadWrite(t, filepath.Join(r.cwd, ".vscode", "mcp.json"), odd) },
			func(r *mcpRig) string {
				return mustJSON(map[string]any{"sessionId": "s", "cwd": r.cwd, "toolName": "docs/search", "toolArgs": `{}`})
			}, false, true},
		{"antigravity .agents odd name", "antigravity", func(t *testing.T, r *mcpRig) {
			r4UnreadWrite(t, filepath.Join(r.cwd, ".agents", "mcp_config.json"), odd)
		},
			func(r *mcpRig) string {
				return mustJSON(map[string]any{"conversationId": "c", "workspacePaths": []string{r.cwd},
					"toolCall": map[string]any{"name": "call_mcp_tool", "args": map[string]any{"ServerName": "docs", "ToolName": "search"}}})
			}, false, true},
		{"copilot zero servers, server from settings.json", "copilot", func(t *testing.T, r *mcpRig) {
			r4UnreadWrite(t, filepath.Join(r.cwd, ".vscode", "mcp.json"), `{"servers":{}}`)
			r4UnreadWrite(t, filepath.Join(r.cwd, ".vscode", "settings.json"), `{"mcp":{"servers":{"docs":{"type":"http","url":"https://evil.example/mcp"}}}}`)
		},
			func(r *mcpRig) string {
				return mustJSON(map[string]any{"sessionId": "s", "cwd": r.cwd, "toolName": "docs/search", "toolArgs": `{}`})
			}, false, false},
	}
	for _, c := range cases {
		r := newMCPRig(t, mcpBase)
		c.setup(t, r)
		out, errText := r.hook(t, c.runtime, c.input(r), false)
		word := false
		if c.visible {
			form, text := mcpForm(t, c.runtime, out)
			word = form == "warn" && strings.Contains(text, "cannot be checked")
		} else {
			word = strings.Contains(errText, "cannot be checked")
		}
		t.Logf("%s: a word to the user: %v (out %.120q, stderr %.160q)", c.name, word, out, errText)
		if c.wantWord && !word {
			t.Errorf("%s: silent", c.name)
		}
	}
}
