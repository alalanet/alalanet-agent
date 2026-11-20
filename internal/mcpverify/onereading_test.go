package mcpverify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A runtime reads its MCP configuration with JSON.parse: by exact names, the last of a repeated name whole.
// encoding/json folded names, so a cloned repository's .mcp.json could name one server to alalanet-agent and another
// to Claude Code (the batch P3 review's P2-1, as a class).
func writeRawFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestConfigsReadAsTheRuntimesReadThem(t *testing.T) {
	home, proj := t.TempDir(), t.TempDir()
	writeRawFile(t, filepath.Join(home, ".claude.json"), `{"mcpServers":{"u":{"type":"http","url":"https://evil.example/mcp","URL":"https://benign.example/mcp"}},`+
		`"projects":{"`+proj+`":{"enabledMcpjsonServers":["p"],"mcpServers":{"l":{"type":"http","url":"https://evil-l.example/mcp","Url":"https://benign-l.example/mcp"}}}}}`)
	writeRawFile(t, filepath.Join(proj, ".mcp.json"), `{"mcpServers":{"p":{"type":"http","url":"https://evil-p.example/mcp","URL":"https://benign-p.example/mcp"}},"MCPServers":null}`)
	l, note := ClaudeServers(filepath.Join(home, ".claude.json"), proj, false)
	if note != "" {
		t.Fatal(note)
	}
	got := map[string]string{}
	for _, s := range l {
		got[s.Name] = s.URL
	}
	for name, want := range map[string]string{"u": "https://evil.example/mcp", "l": "https://evil-l.example/mcp", "p": "https://evil-p.example/mcp"} {
		if got[name] != want {
			t.Errorf("%s: checked %q, the runtime connects to %q (%v)", name, got[name], want, got)
		}
	}
	writeRawFile(t, filepath.Join(home, ".cursor", "mcp.json"), `{"mcpServers":{"g":{"url":"https://evil-g.example/mcp"}},"mcp`+"\u017f"+`ervers":{"g":{"url":"https://benign-g.example/mcp"}}}`)
	if c := CursorServers(home, proj, false); len(c) != 1 || c[0].URL != "https://evil-g.example/mcp" {
		t.Errorf("cursor: %+v", c)
	}
}

// Claude Code's own file with two user or local server names it keeps apart and Go would read as one: neither is
// checked, and the note says so (onejson.ErrNameApart).
func TestClaudeFileWithOddServerNames(t *testing.T) {
	for name, body := range map[string]func(proj string) string{
		"user scope": func(string) string {
			return `{"mcpServers":{"a\ud800":{"type":"http","url":"https://evil.example/mcp"},"a\udc00":{"type":"http","url":"https://ok.example/mcp"}}}`
		},
		"local scope": func(proj string) string {
			return `{"projects":{"` + proj + `":{"mcpServers":{"a\ud800":{"type":"http","url":"https://evil.example/mcp"},"a\udc00":{"type":"http","url":"https://ok.example/mcp"}}}}}`
		},
	} {
		home, proj := t.TempDir(), t.TempDir()
		writeRawFile(t, filepath.Join(home, ".claude.json"), body(proj))
		l, note := ClaudeServers(filepath.Join(home, ".claude.json"), proj, true)
		if len(l) != 0 || !strings.Contains(note, "not checked") {
			t.Errorf("%s: %d servers, note %q", name, len(l), note)
		}
	}
}

// The nearest project file that is there is the runtime's: any file there that does not read — a server name the
// runtime keeps apart from another, a value of another type, not JSON — ends the walk up for every runtime, checks
// none of its servers instead of a farther file's, and says so (re-review r2, P2-E). The user's own file too.
func TestNearestFileEndsTheWalk(t *testing.T) {
	for name, bad := range map[string]string{
		"odd name":              `{"mcpServers":{"docs":{"type":"http","url":"https://evil.example/mcp"},"x\ud800":{"url":"https://x.example/mcp"}}}`,
		"value of another type": `{"mcpServers":{"docs":{"type":"http","url":5}}}`,
		"not JSON":              `{"mcpServers":`,
	} {
		parent, home := t.TempDir(), t.TempDir()
		cwd := filepath.Join(parent, "repo")
		benign := `{"mcpServers":{"docs":{"type":"http","url":"https://benign.example/mcp"}}}`
		for _, rel := range []string{".mcp.json", filepath.Join(".cursor", "mcp.json"), filepath.Join(".agents", "mcp_config.json")} {
			writeRawFile(t, filepath.Join(cwd, rel), bad)
			writeRawFile(t, filepath.Join(parent, rel), benign)
		}
		check := func(rt string, l []Server, note string) {
			t.Helper()
			for _, s := range l {
				if s.Name == "docs" {
					t.Errorf("%s, %s: docs checked at %s from a farther file", name, rt, s.URL)
				}
			}
			if !strings.Contains(note, "not checked") {
				t.Errorf("%s, %s: no note (%q)", name, rt, note)
			}
		}
		l, note := ClaudeServers(filepath.Join(home, ".claude.json"), cwd, true)
		check("claude-code", l, note)
		l, note = CursorServersNoted(home, cwd, true)
		check("cursor", l, note)
		l, note = CopilotServersNoted(home, cwd, true)
		check("copilot", l, note)
		l, note = AntigravityServersNoted(home, cwd, true)
		check("antigravity", l, note)
	}
	home := t.TempDir()
	writeRawFile(t, filepath.Join(home, ".cursor", "mcp.json"), `{"mcpServers":{"g":{"url":5}}}`)
	if l, note := CursorServersNoted(home, t.TempDir(), false); len(l) != 0 || !strings.Contains(note, "not checked") {
		t.Errorf("the user's own Cursor file: %v %q", l, note)
	}
	writeRawFile(t, filepath.Join(home, ".gemini", "config", "mcp_config.json"), `{`)
	if l, note := AntigravityServersNoted(home, t.TempDir(), false); len(l) != 0 || !strings.Contains(note, "not checked") {
		t.Errorf("the user's own Antigravity file: %v %q", l, note)
	}
	writeRawFile(t, filepath.Join(home, ".copilot", "mcp-config.json"), `{`)
	if _, note := CopilotServersNoted(home, t.TempDir(), false); !strings.Contains(note, "not checked") {
		t.Errorf("the user's own Copilot file: %q", note)
	}
}
