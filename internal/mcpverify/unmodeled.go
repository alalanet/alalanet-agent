package mcpverify

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/alalanet/alalanet-agent/internal/installread"
	"github.com/alalanet/alalanet-agent/internal/onejson"
)

// A server the call names may come from a source alalanet-agent does not read: a plugin a repository's Claude Code
// settings enable, a VS Code workspace file's settings. Such a call is not checked, and the hook says so once a
// session and server rather than at every call (re-review r4, P3-17).

// vscodeSettingsServers are the servers of a VS Code settings file's "mcp" block (JSON with comments and trailing
// commas, read as VS Code reads it). found says the file names servers there; a file that is there but does not read
// names none (VSCodeUnread says so).
func vscodeSettingsServers(path, scope string) ([]Server, bool) {
	b, err := readSmall(path)
	if err != nil {
		return nil, false
	}
	var f struct {
		MCP *struct {
			Servers map[string]entry `json:"servers"`
		} `json:"mcp"`
	}
	if onejson.AsJSONParse(installread.JSONC(b), &f) != nil || f.MCP == nil || f.MCP.Servers == nil {
		return nil, false
	}
	return copilotServers(f.MCP.Servers, scope), true
}

// notIn is l without the servers whose names are in have.
func notIn(l, have []Server) []Server {
	names := map[string]bool{}
	for _, s := range have {
		names[s.Name] = true
	}
	var out []Server
	for _, s := range l {
		if !names[s.Name] {
			out = append(out, s)
		}
	}
	return out
}

// ClaudeUnmodeled names, for cwd or a folder above it, a Claude Code settings file of the project that enables
// plugins or names plugin marketplaces (.claude/settings.json, .claude/settings.local.json), or that does not read:
// the servers of those plugins are in no file alalanet-agent reads. "" when there is none.
func ClaudeUnmodeled(cwd string) string {
	for _, dir := range upward(cwd) {
		for _, name := range []string{"settings.json", "settings.local.json"} {
			path := filepath.Join(dir, ".claude", name)
			b, err := readSmall(path)
			if err != nil {
				if !os.IsNotExist(err) {
					return filepath.Join(".claude", name) + " (not read)"
				}
				continue
			}
			var f struct {
				Plugins     map[string]any `json:"enabledPlugins"`
				Marketplace map[string]any `json:"extraKnownMarketplaces"`
			}
			if onejson.AsJSONParse(b, &f) != nil {
				return filepath.Join(".claude", name) + " (not read)"
			}
			if len(f.Plugins) > 0 || len(f.Marketplace) > 0 {
				return filepath.Join(".claude", name) + " (plugins)"
			}
		}
	}
	return ""
}

// CopilotUnmodeled names, for cwd or a folder above it, a VS Code source of MCP servers alalanet-agent does not read:
// a *.code-workspace file (its "settings" can hold "mcp"), or a .vscode/settings.json that does not read. "" when there
// is none.
func CopilotUnmodeled(cwd string) string {
	for _, dir := range upward(cwd) {
		if m, _ := filepath.Glob(filepath.Join(dir, "*.code-workspace")); len(m) > 0 {
			return filepath.Base(m[0])
		}
		path := filepath.Join(dir, ".vscode", "settings.json")
		if b, err := readSmall(path); err == nil {
			var v map[string]any
			if onejson.AsJSONParse(installread.JSONC(b), &v) != nil {
				return filepath.Join(".vscode", "settings.json") + " (not read)"
			}
		} else if !os.IsNotExist(err) {
			return filepath.Join(".vscode", "settings.json") + " (not read)"
		}
	}
	return ""
}

// KnownTools are the tool names the state holds for srv: its last read's, else its pin's; known is false when it
// holds neither.
func (v *Verifier) KnownTools(ctx context.Context, srv Server) (map[string]bool, bool) {
	e, err := snapshot(ctx, v.StateDir, stateKey(srv))
	if err != nil {
		return nil, false
	}
	var sigs []sig
	switch {
	case e.Read != nil && e.Read.Hash != "":
		sigs = e.Read.Sigs
	case e.Pin != nil && e.Pin.Hash != "":
		sigs = e.Pin.Sigs
	default:
		return nil, false
	}
	out := map[string]bool{}
	for _, s := range sigs {
		out[s.Name] = true
	}
	return out, true
}

// TellOnce records that session was told what about the server runtime names name; told says it already was. A
// state that cannot be written tells again.
func (v *Verifier) TellOnce(ctx context.Context, runtime, name, session, what string) (told bool) {
	k := toldKey(session, what, strings.ToLower(name))
	err := update(ctx, v.StateDir, serverKey("told\x00"+runtime+"\x00"+name), func(s *entry0) {
		told = s.told(k)
		s.tell(k)
	})
	return told && err == nil
}
