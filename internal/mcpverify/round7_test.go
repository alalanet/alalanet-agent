package mcpverify

// VERIFY-AUTO-1 round 7 (R6-1): Claude Code's precedence, local > approved project > user; an unapproved project
// entry is never the one checked.

import (
	"path/filepath"
	"testing"
)

func TestR7ClaudePrecedence(t *testing.T) {
	home, repo := t.TempDir(), t.TempDir()
	const local, proj, user = "https://local.example.com/mcp", "https://proj.example.com/mcp", "https://user.example.com/mcp"
	cfg := `{"mcpServers":{"a":{"type":"http","url":"` + user + `"},"b":{"type":"http","url":"` + user + `"},"c":{"type":"http","url":"` + user + `"}},` +
		`"projects":{"` + repo + `":{"enabledMcpjsonServers":["a","b"],"mcpServers":{"b":{"type":"http","url":"` + local + `"}}}}}`
	r4write(t, filepath.Join(home, ".claude.json"), cfg)
	r4write(t, filepath.Join(repo, ".mcp.json"), `{"mcpServers":{"a":{"type":"http","url":"`+proj+`"},"b":{"type":"http","url":"`+proj+`"},"c":{"type":"http","url":"`+hostileURL+`"}}}`)
	for _, project := range []bool{false, true} {
		list, _ := ClaudeServers(filepath.Join(home, ".claude.json"), repo, project)
		for name, want := range map[string]string{"a": proj, "b": local, "c": user} {
			s, ok := Find(list, name, "")
			if !ok || s.URL != want || s.Untrusted {
				t.Errorf("project %v, %s: %s (%s) untrusted %v, want %s", project, name, s.URL, s.Scope, s.Untrusted, want)
			}
		}
		if s, _ := Find(list, "c", ""); project && !s.Shadowed {
			t.Errorf("c: an unapproved project entry under the user's name is not told: %+v", s)
		}
		if s, ok := Find(list, "a", "project"); !ok || s.URL != proj {
			t.Errorf("source project: %+v", s)
		}
	}
}
