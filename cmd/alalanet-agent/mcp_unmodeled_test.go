package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeIn(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A server named only in VS Code's own settings ("mcp" block, beside an empty mcp.json) is found and checked like
// any other: a changed tool holds (re-review r4, P3-17). A project's settings are read the same way
// (TestCopilotReadsVSCodeSettings); a server only a project names is Untrusted and not contacted, as for mcp.json.
func TestHookCopilotChecksVSCodeSettingsServers(t *testing.T) {
	r := newMCPRig(t, mcpChanged)
	r.listAs(t, mcpBase)
	user := filepath.Dir(vscodeUserMCPFor(r.home))
	writeIn(t, filepath.Join(user, "mcp.json"), `{"servers":{}}`)
	writeIn(t, filepath.Join(user, "settings.json"), "{\n // VS Code's settings\n \"mcp\": {\"servers\": {\"docs\": {\"type\": \"http\", \"url\": \""+mcpURL+"\"}}},\n}")
	in := mustJSON(map[string]any{"sessionId": "s", "cwd": r.cwd, "toolName": "docs/search", "toolArgs": `{}`})
	if out, _ := r.hook(t, "copilot", in, false); form5(t, "copilot", out) != "hold" || !strings.Contains(out, "docs") {
		t.Fatalf("a settings server with a changed tool: %q", out)
	}
}

// A server no file names, in a project that names servers where alalanet-agent does not read — a plugin its Claude
// Code settings enable, a VS Code workspace file — is not checked, and the hook says so once a session and server; a
// hold under ALALANET_FAIL_CLOSED. Without such a source it stays without an opinion (TestHookMCPUnreadByDesign).
func TestHookMCPUnmodeledSourceWarnsOnce(t *testing.T) {
	for _, c := range []struct {
		runtime string
		setup   func(t *testing.T, r *mcpRig)
		input   func(r *mcpRig, session string) string
		visible bool
	}{
		{"claude-code", func(t *testing.T, r *mcpRig) {
			writeIn(t, filepath.Join(r.cwd, ".claude", "settings.json"), `{"enabledPlugins":{"docs@acme":true},"extraKnownMarketplaces":{"acme":{"source":{"source":"github","repo":"acme/plugins"}}}}`)
		}, func(r *mcpRig, session string) string {
			return mustJSON(map[string]any{"session_id": session, "cwd": r.cwd, "hook_event_name": "PreToolUse", "tool_name": "mcp__plugin_acme_docs__search",
				"tool_input": map[string]any{}, "mcp_server": map[string]any{"name": "plugin_acme_docs", "source": "plugin"}})
		}, true},
		{"claude-code", func(t *testing.T, r *mcpRig) {
			writeIn(t, filepath.Join(r.cwd, ".claude", "settings.local.json"), `{"enabledPlugins":{"docs@acme":true}}`)
		}, func(r *mcpRig, session string) string {
			return mustJSON(map[string]any{"session_id": session, "cwd": r.cwd, "hook_event_name": "PreToolUse", "tool_name": "mcp__nowhere__search",
				"tool_input": map[string]any{}, "mcp_server": map[string]any{"name": "nowhere", "source": "project"}})
		}, true},
		{"copilot", func(t *testing.T, r *mcpRig) {
			writeIn(t, filepath.Join(r.cwd, "team.code-workspace"), `{"folders":[{"path":"."}],"settings":{"mcp":{"servers":{"nowhere":{"type":"http","url":"https://x.example/mcp"}}}}}`)
		}, func(r *mcpRig, session string) string {
			return mustJSON(map[string]any{"sessionId": session, "cwd": r.cwd, "toolName": "nowhere/search", "toolArgs": `{}`})
		}, false},
	} {
		r := newMCPRig(t, mcpBase)
		c.setup(t, r)
		said := func(out, errText string) bool {
			if c.visible {
				form, text := mcpForm(t, c.runtime, out)
				return form == "warn" && strings.Contains(text, "does not read")
			}
			return form5(t, c.runtime, out) == "silent" && strings.Contains(errText, "does not read")
		}
		out, errText := r.hook(t, c.runtime, c.input(r, "s1"), false)
		if !said(out, errText) {
			t.Errorf("%s, first call: %q, stderr %q", c.runtime, out, errText)
		}
		if out, errText := r.hook(t, c.runtime, c.input(r, "s1"), false); said(out, errText) || form5(t, c.runtime, out) != "silent" {
			t.Errorf("%s, second call of the session: %q, stderr %q", c.runtime, out, errText)
		}
		if out, errText := r.hook(t, c.runtime, c.input(r, "s2"), false); !said(out, errText) {
			t.Errorf("%s, another session: %q, stderr %q", c.runtime, out, errText)
		}
		if out, _ := r.hook(t, c.runtime, c.input(r, "s3"), true); !strings.Contains(out, "ALALANET_FAIL_CLOSED") {
			t.Errorf("%s, ALALANET_FAIL_CLOSED: %q", c.runtime, out)
		}
	}
}

// Antigravity's docs_two and docs_two_x both fit mcp_docs_two_x_search; once the state knows their tools (docs_two
// has no x_search), the call is docs_two_x's and is checked, not warned about as ambiguous (re-review r4, P3-18).
func TestHookMCPTwoServerNameResolvedByTools(t *testing.T) {
	r := newMCPRig(t, mcpChanged)
	r.listAs(t, mcpBase)
	configureAll(t, r)
	named := antigravityMCPInput("call_mcp_tool", map[string]any{"ServerName": "docs_two_x", "ToolName": "search"})
	if out, _ := r.hook(t, "antigravity", named, false); form5(t, "antigravity", out) != "hold" {
		t.Fatalf("the named call: %q", out)
	}
	out, errText := r.hook(t, "antigravity", antigravityMCPInput("mcp_docs_two_x_search", map[string]any{}), false)
	if form5(t, "antigravity", out) != "hold" || strings.Contains(out+errText, "more than one") || !strings.Contains(out, "docs_two_x") {
		t.Fatalf("resolved by the tools: %q, stderr %q", out, errText)
	}
}

// vscodeUserMCPFor is VS Code's user mcp.json on this system, as mcpverify finds it (Linux and macOS).
func vscodeUserMCPFor(home string) string {
	if runtime.GOOS == "darwin" {
		return filepath.Join(home, "Library", "Application Support", "Code", "User", "mcp.json")
	}
	return filepath.Join(home, ".config", "Code", "User", "mcp.json")
}

// A server only a project file names is never contacted (R4-1), and its call is not let through without a word: once
// a session and server, on stderr where the runtime has no place for a warning.
func TestHookUntrustedProjectServerWarnsOnce(t *testing.T) {
	r := newMCPRig(t, mcpBase)
	writeIn(t, filepath.Join(r.cwd, ".vscode", "mcp.json"), `{"servers":{"repo":{"type":"http","url":"`+mcpURL+`"}}}`)
	in := func(session string) string {
		return mustJSON(map[string]any{"sessionId": session, "cwd": r.cwd, "toolName": "repo/search", "toolArgs": `{}`})
	}
	if out, errText := r.hook(t, "copilot", in("s1"), false); form5(t, "copilot", out) != "silent" || !strings.Contains(errText, "does not contact it") {
		t.Fatalf("first call: %q, stderr %q", out, errText)
	}
	if _, errText := r.hook(t, "copilot", in("s1"), false); strings.Contains(errText, "does not contact it") {
		t.Fatalf("second call of the session: stderr %q", errText)
	}
	if _, errText := r.hook(t, "copilot", in("s2"), false); !strings.Contains(errText, "does not contact it") {
		t.Fatalf("another session: stderr %q", errText)
	}
	if n := len(r.srv.Requests()); n != 0 {
		t.Fatalf("the server only the project names was contacted %d times", n)
	}
}
