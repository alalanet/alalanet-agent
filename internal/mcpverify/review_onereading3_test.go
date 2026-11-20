package mcpverify

// The re-review of keyat-clock 48bca45 (review-1116/onereading, round 2), P2-E: its proof, adopted.

import (
	"path/filepath"
	"testing"
)

// The nearest project file has a name AsJSONParse refuses (ErrNameApart). The runtime reads that file; alalanet-agent
// skips it without a note and reads the next folder up instead, so a server of the same name is checked at another
// URL than the one the runtime connects to.
func TestReviewR2NearestFileSkippedForAParent(t *testing.T) {
	odd := `"x\ud800":{"url":"https://x.example/mcp"}`
	parent := t.TempDir()
	cwd := filepath.Join(parent, "repo")
	home := t.TempDir()
	// Copilot: .vscode/mcp.json "servers".
	writeRawFile(t, filepath.Join(cwd, ".vscode", "mcp.json"), `{"servers":{"docs":{"type":"http","url":"https://evil.example/mcp"},`+odd+`}}`)
	writeRawFile(t, filepath.Join(parent, ".vscode", "mcp.json"), `{"servers":{"docs":{"type":"http","url":"https://benign.example/mcp"}}}`)
	for _, s := range CopilotServers(home, cwd, true) {
		t.Logf("copilot: %s %s (%s)", s.Name, s.URL, s.Scope)
		if s.Name == "docs" && s.URL != "https://evil.example/mcp" {
			t.Errorf("copilot: docs checked at %s, the harness connects to https://evil.example/mcp", s.URL)
		}
	}
	// Cursor: .cursor/mcp.json.
	writeRawFile(t, filepath.Join(cwd, ".cursor", "mcp.json"), `{"mcpServers":{"docs":{"url":"https://evil.example/mcp"},`+odd+`}}`)
	writeRawFile(t, filepath.Join(parent, ".cursor", "mcp.json"), `{"mcpServers":{"docs":{"url":"https://benign.example/mcp"}}}`)
	for _, s := range CursorServers(home, cwd, true) {
		t.Logf("cursor: %s %s (%s)", s.Name, s.URL, s.Scope)
		if s.Name == "docs" && s.URL != "https://evil.example/mcp" {
			t.Errorf("cursor: docs checked at %s, Cursor connects to https://evil.example/mcp", s.URL)
		}
	}
	// Antigravity: .agents/mcp_config.json.
	writeRawFile(t, filepath.Join(cwd, ".agents", "mcp_config.json"), `{"mcpServers":{"docs":{"serverUrl":"https://evil.example/mcp"},`+odd+`}}`)
	writeRawFile(t, filepath.Join(parent, ".agents", "mcp_config.json"), `{"mcpServers":{"docs":{"serverUrl":"https://benign.example/mcp"}}}`)
	for _, s := range AntigravityServers(home, cwd, true) {
		t.Logf("antigravity: %s %s (%s)", s.Name, s.URL, s.Scope)
		if s.Name == "docs" && s.URL != "https://evil.example/mcp" {
			t.Errorf("antigravity: docs checked at %s, Antigravity connects to https://evil.example/mcp", s.URL)
		}
	}
}
