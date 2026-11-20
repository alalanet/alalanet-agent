package mcpverify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(v)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestMCPVerifySkipsUnapprovedProjectServers: Claude Code's user and local scopes are read; a project's .mcp.json
// server only when the user approved it in Claude Code, or when it is used (project true: the runtime already runs
// it). Headers are noted, never kept.
func TestMCPVerifySkipsUnapprovedProjectServers(t *testing.T) {
	home, proj := t.TempDir(), t.TempDir()
	cwd := filepath.Join(proj, "sub")
	writeJSON(t, filepath.Join(home, ".claude.json"), map[string]any{
		"mcpServers": map[string]any{
			"user-http": map[string]any{"type": "http", "url": "https://u.example.com/mcp", "headers": map[string]string{"Authorization": "Bearer zz-header-sentinel"}},
			"user-sse":  map[string]any{"type": "sse", "url": "https://s.example.com/sse"},
			"user-cmd":  map[string]any{"command": "npx", "args": []string{"x"}},
			"shared":    map[string]any{"type": "http", "url": "https://user.example.com/mcp"},
		},
		"projects": map[string]any{proj: map[string]any{
			"mcpServers":            map[string]any{"shared": map[string]any{"type": "http", "url": "https://local.example.com/mcp", "headersHelper": "get-token"}},
			"enabledMcpjsonServers": []string{"approved"},
		}},
	})
	writeJSON(t, filepath.Join(proj, ".mcp.json"), map[string]any{"mcpServers": map[string]any{
		"approved": map[string]any{"type": "http", "url": "https://approved.example.com/mcp"},
		"cloned":   map[string]any{"type": "http", "url": "https://cloned.example.com/mcp"},
	}})
	claude := func(project bool) []Server {
		l, note := ClaudeServers(filepath.Join(home, ".claude.json"), cwd, project)
		if note != "" {
			t.Fatal(note)
		}
		return l
	}
	names := func(list []Server) map[string]Server {
		m := map[string]Server{}
		for _, s := range list {
			if _, ok := m[s.Name]; !ok {
				m[s.Name] = s
			}
		}
		return m
	}
	got := names(claude(false))
	if _, ok := got["cloned"]; ok {
		t.Error("an unapproved project server is listed")
	}
	if s := got["approved"]; s.Scope != "project" || s.URL != "https://approved.example.com/mcp" {
		t.Errorf("approved: %+v", s)
	}
	if s := got["shared"]; s.Scope != "local" || !s.Auth || s.URL != "https://local.example.com/mcp" {
		t.Errorf("the local scope does not win: %+v", s)
	}
	if s := got["user-http"]; !s.Auth || s.Transport != TransportHTTP || s.Scope != "user" {
		t.Errorf("user-http: %+v", s)
	}
	if got["user-sse"].Transport != TransportSSE || got["user-cmd"].Transport != TransportStdio || got["user-cmd"].URL != "" {
		t.Errorf("transports: %+v %+v", got["user-sse"], got["user-cmd"])
	}
	if _, ok := names(claude(true))["cloned"]; !ok {
		t.Error("a project server in use is not found")
	}
	if s, ok := Find(claude(false), "shared", "user"); !ok || s.URL != "https://user.example.com/mcp" {
		t.Errorf("Find in a scope: %+v", s)
	}
	for _, s := range claude(true) {
		if b, _ := json.Marshal(s); strings.Contains(string(b), "zz-header-sentinel") || strings.Contains(string(b), "get-token") {
			t.Error("a header was kept")
		}
	}
	// Without approvals, every .mcp.json server waits; disabled ones too.
	writeJSON(t, filepath.Join(home, ".claude.json"), map[string]any{"projects": map[string]any{proj: map[string]any{
		"enableAllProjectMcpServers": true, "disabledMcpjsonServers": []string{"cloned"}}}})
	got = names(claude(false))
	if _, ok := got["cloned"]; ok || got["approved"].URL == "" {
		t.Errorf("enableAll with a disabled server: %v", got)
	}
}

func TestClaudeToolServer(t *testing.T) {
	list := []Server{{Name: "a"}, {Name: "a__b"}, {Name: "my.server"}, {Name: "x y"}}
	for tool, want := range map[string]string{"mcp__a__t": "a", "mcp__a__b__t": "a__b", "mcp__my_server__get": "my.server",
		"mcp__x_y__t": "x y", "mcp__plugin_p_s__t": "", "mcp__a__": "", "Bash": ""} {
		s, ok := ClaudeToolServer(list, tool)
		if want == "" && ok || want != "" && s.Name != want {
			t.Errorf("%s: %q %v, want %q", tool, s.Name, ok, want)
		}
	}
}

func TestCursorServers(t *testing.T) {
	home, proj := t.TempDir(), t.TempDir()
	writeJSON(t, filepath.Join(home, ".cursor", "mcp.json"), map[string]any{"mcpServers": map[string]any{
		"g": map[string]any{"url": "https://g.example.com/mcp"}, "local": map[string]any{"command": "node", "args": []string{"s.js"}}}})
	writeJSON(t, filepath.Join(proj, ".cursor", "mcp.json"), map[string]any{"mcpServers": map[string]any{"p": map[string]any{"url": "https://p.example.com/mcp"}}})
	if l := CursorServers(home, proj, false); len(l) != 2 || l[0].Name != "g" || l[0].Transport != TransportHTTP || l[1].Transport != TransportStdio {
		t.Errorf("global: %+v", l)
	}
	if l := CursorServers(home, proj, true); len(l) != 3 || l[0].Name != "p" || l[0].Scope != "project" {
		t.Errorf("project: %+v", l)
	}
}

// DefaultStateDir: XDG_CACHE_HOME when it is an absolute path, else ~/.cache/alalanet/mcp.
func TestDefaultStateDir(t *testing.T) {
	env := map[string]string{"XDG_CACHE_HOME": "/x/cache"}
	if d := DefaultStateDir(func(k string) string { return env[k] }, "/home/u"); d != filepath.Join("/x/cache", "alalanet", "mcp") {
		t.Error(d)
	}
	env["XDG_CACHE_HOME"] = "relative"
	if d := DefaultStateDir(func(k string) string { return env[k] }, "/home/u"); d != filepath.Join("/home/u", ".cache", "alalanet", "mcp") {
		t.Error(d)
	}
}
