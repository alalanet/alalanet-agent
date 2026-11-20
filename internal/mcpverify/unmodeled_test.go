package mcpverify

import (
	"context"
	"path/filepath"
	"testing"
)

// VS Code's settings name MCP servers too ("mcp": {"servers": …}, JSON with comments): the Copilot harness's servers
// include them, after the mcp.json beside them (re-review r4, P3-17).
func TestCopilotReadsVSCodeSettings(t *testing.T) {
	home, repo := t.TempDir(), t.TempDir()
	writeRawFile(t, filepath.Join(repo, ".vscode", "mcp.json"), `{"servers":{"docs":{"type":"http","url":"https://mcpjson.example/mcp"}}}`)
	writeRawFile(t, filepath.Join(repo, ".vscode", "settings.json"), "{\n  // the workspace's MCP servers\n  \"mcp\": {\"servers\": {\"docs\": {\"type\":\"http\",\"url\":\"https://settings.example/mcp\"}, \"extra\": {\"type\":\"http\",\"url\":\"https://extra.example/mcp\"},},},\n}")
	got := map[string]string{}
	for _, s := range CopilotServers(home, repo, true) {
		got[s.Name] = s.URL
	}
	if got["docs"] != "https://mcpjson.example/mcp" || got["extra"] != "https://extra.example/mcp" {
		t.Fatalf("project: %v", got)
	}
	// settings alone, beside an empty mcp.json, and the user's own settings.json
	repo2 := t.TempDir()
	writeRawFile(t, filepath.Join(repo2, ".vscode", "mcp.json"), `{"servers":{}}`)
	writeRawFile(t, filepath.Join(repo2, ".vscode", "settings.json"), `{"mcp":{"servers":{"docs":{"type":"http","url":"https://settings.example/mcp"}}}}`)
	writeRawFile(t, filepath.Join(filepath.Dir(vscodeUserMCP(home)), "settings.json"), `{"mcp":{"servers":{"mine":{"type":"http","url":"https://mine.example/mcp"}}}}`)
	got = map[string]string{}
	for _, s := range CopilotServers(home, repo2, true) {
		got[s.Name] = s.URL
	}
	if got["docs"] != "https://settings.example/mcp" || got["mine"] != "https://mine.example/mcp" {
		t.Fatalf("settings beside an empty mcp.json, and the user's: %v", got)
	}
}

// The project's sources alalanet-agent does not read are named; none for a plain project.
func TestUnmodeledSources(t *testing.T) {
	repo := t.TempDir()
	if ClaudeUnmodeled(repo) != "" || CopilotUnmodeled(repo) != "" {
		t.Fatal("a plain project")
	}
	writeRawFile(t, filepath.Join(repo, ".claude", "settings.json"), `{"permissions":{"allow":[]}}`)
	writeRawFile(t, filepath.Join(repo, ".vscode", "settings.json"), "{\n // comments are VS Code's\n \"editor.tabSize\": 2,\n}")
	if c, p := ClaudeUnmodeled(repo), CopilotUnmodeled(repo); c != "" || p != "" {
		t.Fatalf("settings without plugins or MCP: %q %q", c, p)
	}
	for name, body := range map[string]string{
		"plugins":      `{"enabledPlugins":{"docs@acme":true}}`,
		"marketplaces": `{"extraKnownMarketplaces":{"acme":{"source":{"source":"github","repo":"acme/plugins"}}}}`,
		"not JSON":     `{`,
	} {
		writeRawFile(t, filepath.Join(repo, ".claude", "settings.local.json"), body)
		if ClaudeUnmodeled(filepath.Join(repo, "sub")) == "" {
			t.Errorf("claude, %s: not named", name)
		}
	}
	writeRawFile(t, filepath.Join(repo, "x.code-workspace"), `{"folders":[],"settings":{"mcp":{}}}`)
	if CopilotUnmodeled(repo) != "x.code-workspace" {
		t.Errorf("a workspace file: %q", CopilotUnmodeled(repo))
	}
	repo3 := t.TempDir()
	writeRawFile(t, filepath.Join(repo3, ".vscode", "settings.json"), `{"mcp":`)
	if CopilotUnmodeled(repo3) == "" {
		t.Error("a settings.json that does not read")
	}
}

// A name that fits two servers goes to the one whose known tools have the rest of it; it stays ambiguous when both or
// neither are known to (re-review r4, P3-18).
func TestResolveToolServer(t *testing.T) {
	list := []Server{{Name: "docs"}, {Name: "docs_v2"}}
	tools := map[string]map[string]bool{"docs": {"search": true}, "docs_v2": {"search": true}}
	known := func(s Server) (map[string]bool, bool) { m, ok := tools[s.Name]; return m, ok }
	if s, n := ResolveToolServer(list, "underscore", "mcp_docs_v2_search", known); n != 1 || s.Name != "docs_v2" {
		t.Fatalf("docs has no v2_search: %v %d", s, n)
	}
	if _, n := ResolveToolServer(list, "underscore", "mcp_docs_v2_search", nil); n != 2 {
		t.Fatalf("without known tools: %d", n)
	}
	tools["docs"]["v2_search"] = true
	if _, n := ResolveToolServer(list, "underscore", "mcp_docs_v2_search", known); n != 2 {
		t.Fatalf("both have it: %d", n)
	}
	delete(tools, "docs")
	if _, n := ResolveToolServer(list, "underscore", "mcp_docs_v2_search", known); n != 2 {
		t.Fatalf("docs not known: %d", n)
	}
	tools["docs"], tools["docs_v2"] = map[string]bool{}, map[string]bool{}
	if _, n := ResolveToolServer(list, "underscore", "mcp_docs_v2_search", known); n != 0 {
		t.Fatalf("neither has it: %d", n)
	}
	if s, n := ResolveToolServer([]Server{{Name: "a"}, {Name: "a/b"}}, "slash", "a/b/x", func(s Server) (map[string]bool, bool) {
		return map[string]bool{"x": s.Name == "a/b"}, true
	}); n != 1 || s.Name != "a/b" {
		t.Fatalf("slash: %v %d", s, n)
	}
}

// KnownTools are the last read's tools, else the pin's; nothing known without either.
func TestKnownTools(t *testing.T) {
	v := &Verifier{StateDir: t.TempDir()}
	ctx := context.Background()
	srv := Server{Name: "docs", URL: "https://docs.example/mcp"}
	if _, ok := v.KnownTools(ctx, srv); ok {
		t.Fatal("an empty state knows tools")
	}
	if err := update(ctx, v.StateDir, stateKey(srv), func(e *entry0) {
		e.Pin = &pinState{Hash: "p", Sigs: []sig{{Name: "pinned"}}}
	}); err != nil {
		t.Fatal(err)
	}
	if m, ok := v.KnownTools(ctx, srv); !ok || !m["pinned"] {
		t.Fatalf("the pin's: %v %v", m, ok)
	}
	if err := update(ctx, v.StateDir, stateKey(srv), func(e *entry0) {
		e.Read = &readState{Hash: "r", Sigs: []sig{{Name: "read"}}}
	}); err != nil {
		t.Fatal(err)
	}
	if m, ok := v.KnownTools(ctx, srv); !ok || !m["read"] || m["pinned"] {
		t.Fatalf("the read's: %v %v", m, ok)
	}
}
