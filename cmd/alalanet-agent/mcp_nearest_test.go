package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A runtime's nearest project file that does not read checks none of its servers, and alalanet-agent says so: in
// mcp-verify's note for every runtime, and in the hook's note for the server it cannot find (re-review r2, P2-E).
func TestMCPNotesAFileThatDoesNotRead(t *testing.T) {
	home, repo := t.TempDir(), t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(repo, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(".cursor", "mcp.json"), `{"mcpServers":{"docs":{"url":5}}}`)
	write(filepath.Join(".vscode", "mcp.json"), `{"servers":`)
	write(filepath.Join(".agents", "mcp_config.json"), `{"mcpServers":{"docs":{"serverUrl":5}}}`)
	p := mcpPaths{home: home}
	_, note := mcpServers(p, repo, true)
	for _, rt := range []string{"Cursor's", "Copilot harness's", "Antigravity's"} {
		if !strings.Contains(note, rt) {
			t.Errorf("mcp-verify's note does not name %s file: %q", rt, note)
		}
	}
	for rt, ev := range map[string]hookEvent{
		"copilot":     {mcp: true, mcpForm: "slash", mcpTool: "docs/search", cwd: repo},
		"antigravity": {mcp: true, mcpForm: "named", mcpServer: "docs", cwd: repo},
	} {
		if _, why, note, byFiles, _ := mcpServerOf(rt, ev, p, nil); why == "" || !byFiles || !strings.Contains(note, "not checked") {
			t.Errorf("%s hook: why %q, note %q", rt, why, note)
		}
	}
}
