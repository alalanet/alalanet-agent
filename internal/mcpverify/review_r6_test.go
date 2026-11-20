package mcpverify

// Review of VERIFY-AUTO-1 round 6 (dd7fc5e): precedence probes. Hosts made up.

import (
	"path/filepath"
	"testing"
)

// Claude Code's own precedence is local > project > user. An approved .mcp.json server that shares a name with a user
// server is the one Claude Code calls; with mcp_server.source "project" the hook should check it (it is approved).
func TestReviewR6ClaudeApprovedProjectCollision(t *testing.T) {
	home, repo := t.TempDir(), t.TempDir()
	cfg := `{"mcpServers":{"docs":{"type":"http","url":"` + userURL + `"}},"projects":{"` + repo + `":{"enabledMcpjsonServers":["docs"]}}}`
	r4write(t, filepath.Join(home, ".claude.json"), cfg)
	r4write(t, filepath.Join(repo, ".mcp.json"), `{"mcpServers":{"docs":{"type":"http","url":"https://docs-project.example.com/mcp"}}}`)
	list, _ := ClaudeServers(filepath.Join(home, ".claude.json"), repo, true)
	s, ok := Find(list, "docs", "project")
	t.Logf("source project: found %v %s (%s) untrusted=%v", ok, s.URL, s.Scope, s.Untrusted)
	if !ok {
		t.Errorf("an approved .mcp.json server named like a user server is not found for source project: the server Claude Code calls is not checked")
	}
	s, ok = ClaudeToolServer(list, "mcp__docs__search")
	t.Logf("no source: %v %s (%s) shadowed=%v", ok, s.URL, s.Scope, s.Shadowed)
	// Round 7 (R6-1): Claude Code's own order, local > approved project > user: the approved project entry is the one
	// Claude Code calls, with or without source.
	if !ok || s.URL != "https://docs-project.example.com/mcp" || s.Untrusted {
		t.Errorf("no source: %v %s untrusted %v", ok, s.URL, s.Untrusted)
	}
}

// Codex: trust recorded for the repository root, .codex/config.toml in the root: read; the same file one folder down
// from where the session runs: read too (upward walk), trust of the folder that holds it.
func TestReviewR6CodexTrustShapes(t *testing.T) {
	home, repo := t.TempDir(), t.TempDir()
	codex := filepath.Join(home, ".codex")
	r4write(t, filepath.Join(codex, "config.toml"), "[mcp_servers.docs]\nurl = \""+userURL+"\"\n\n[projects.\""+repo+"\"]\ntrust_level = \"trusted\"\n")
	r4write(t, filepath.Join(repo, ".codex", "config.toml"), "[mcp_servers.docs]\nurl = \"https://docs-project.example.com/mcp\"\n")
	for _, cwd := range []string{repo, filepath.Join(repo, "sub", "dir")} {
		list, _ := CodexServers(codex, cwd, true)
		s, ok := ToolServer(list, "", "mcp__docs__search")
		t.Logf("cwd %s: %v %s (%s)", filepath.Base(cwd), ok, s.URL, s.Scope)
	}
	r4write(t, filepath.Join(codex, "config.toml"), "[mcp_servers.docs]\nurl = \""+userURL+"\"\n\n[projects.\""+repo+"\"]\ntrust_level = \"untrusted\"\n")
	list, _ := CodexServers(codex, repo, true)
	s, _ := ToolServer(list, "", "mcp__docs__search")
	t.Logf("untrusted: %s (%s)", s.URL, s.Scope)
	if s.URL != userURL {
		t.Errorf("an untrusted project's entry is used")
	}
}
