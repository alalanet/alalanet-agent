package mcpverify

// The configurations of Codex CLI, the Copilot harness and Antigravity (VERIFY-AUTO-1 step 1b, research section 1).
// Each file is a regular file of 1 MiB at most (readSmall); headers and tokens are noted, never kept.

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/BurntSushi/toml"
)

// CodexHome is Codex's folder: CODEX_HOME when it is set, else ~/.codex.
func CodexHome(getenv func(string) string, home string) string {
	if d := strings.TrimSpace(getenv("CODEX_HOME")); d != "" {
		return d
	}
	return filepath.Join(home, ".codex")
}

type codexEntry struct {
	URL               string            `toml:"url"`
	Command           string            `toml:"command"`
	BearerTokenEnvVar string            `toml:"bearer_token_env_var"`
	HTTPHeaders       map[string]string `toml:"http_headers"`
	EnvHTTPHeaders    map[string]string `toml:"env_http_headers"`
}

type codexFile struct {
	MCPServers map[string]codexEntry `toml:"mcp_servers"`
	Projects   map[string]struct {
		TrustLevel string `toml:"trust_level"`
	} `toml:"projects"`
}

func readCodex(path string) (codexFile, error) {
	var f codexFile
	b, err := readSmall(path)
	if err != nil {
		return f, err
	}
	_, err = toml.Decode(string(b), &f)
	return f, err
}

func (e codexEntry) server(name, scope string) Server {
	s := Server{Name: name, Runtime: "codex", Scope: scope, URL: strings.TrimSpace(e.URL),
		Auth: e.BearerTokenEnvVar != "" || len(e.HTTPHeaders) > 0 || len(e.EnvHTTPHeaders) > 0}
	if s.URL == "" {
		s.Transport = TransportStdio
	} else {
		s.Transport = TransportHTTP // Codex's url is streamable HTTP
	}
	return s
}

// CodexServers are the MCP servers Codex is configured with: a project's .codex/config.toml (in cwd or a folder above
// it) only when Codex trusts the project ([projects."<folder>"] trust_level = "trusted" in the user's file), whose
// entries then override the user's as Codex layers them; then codexHome's config.toml. Codex loads an untrusted
// project's file not at all, so neither does alalanet-agent, in use or not (review r4, R4-1; project is kept for the
// other runtimes' signature). note says why the user's file could not be read.
func CodexServers(codexHome, cwd string, _ bool) (list []Server, note string) {
	user, err := readCodex(filepath.Join(codexHome, "config.toml"))
	if err != nil && !os.IsNotExist(err) {
		note = "Codex's config.toml could not be read: its servers are not checked"
	}
	for _, dir := range upward(cwd) {
		f, err := readCodex(filepath.Join(dir, ".codex", "config.toml"))
		if err != nil {
			continue
		}
		if user.Projects[dir].TrustLevel == "trusted" {
			list = append(list, codexServers(f.MCPServers, "project")...)
		}
		break
	}
	return append(list, codexServers(user.MCPServers, "user")...), note
}

func codexServers(m map[string]codexEntry, scope string) []Server {
	var out []Server
	for name, e := range m {
		out = append(out, e.server(name, scope))
	}
	sortServers(out)
	return out
}

// copilotServers: the Copilot CLI's and VS Code's server entries (type http, sse, local or stdio: a local one has no
// URL, which makes it stdio).
func copilotServers(m map[string]entry, scope string) []Server {
	var out []Server
	for name, e := range m {
		s := e.server(name, "copilot", scope)
		out = append(out, s)
	}
	sortServers(out)
	return out
}

// vscodeUserMCP is VS Code's user mcp.json on this system.
func vscodeUserMCP(home string) string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Code", "User", "mcp.json")
	case "windows":
		if d := os.Getenv("APPDATA"); d != "" {
			return filepath.Join(d, "Code", "User", "mcp.json")
		}
	}
	return filepath.Join(home, ".config", "Code", "User", "mcp.json")
}

// CopilotServers is CopilotServersNoted without its note.
func CopilotServers(home, cwd string, project bool) []Server {
	l, _ := CopilotServersNoted(home, cwd, project)
	return l
}

// CopilotServersNoted are the MCP servers the Copilot harness is configured with: ~/.copilot/mcp-config.json and VS Code's
// user mcp.json first, then, when project is true, a project's .vscode/mcp.json ("servers"), .github/mcp.json and
// .mcp.json ("mcpServers"), in cwd or the nearest folder above it that has one of them, for names no user file has,
// and Untrusted (userFirst). note says which file is there but does not read: none of its servers is checked.
func CopilotServersNoted(home, cwd string, project bool) (list []Server, note string) {
	type file struct {
		MCPServers map[string]entry `json:"mcpServers"`
		Servers    map[string]entry `json:"servers"`
	}
	read := func(path, scope string) ([]Server, bool) {
		var f file
		found, why := readNearest(path, &f, "the Copilot harness")
		if why != "" {
			note = strings.TrimSpace(note + " " + why)
			return nil, found
		}
		return append(copilotServers(f.MCPServers, scope), copilotServers(f.Servers, scope)...), found
	}
	u1, _ := read(filepath.Join(home, ".copilot", "mcp-config.json"), "user")
	u2, _ := read(vscodeUserMCP(home), "vscode")
	u3, _ := vscodeSettingsServers(filepath.Join(filepath.Dir(vscodeUserMCP(home)), "settings.json"), "vscode")
	user := append(append(u1, u2...), notIn(u3, append(u1, u2...))...)
	var proj []Server
	if project {
		for _, dir := range upward(cwd) {
			any := false
			var here []Server
			for _, rel := range []string{filepath.Join(".vscode", "mcp.json"), filepath.Join(".github", "mcp.json"), ".mcp.json"} {
				l, found := read(filepath.Join(dir, rel), "project")
				here, any = append(here, l...), any || found
			}
			// VS Code's workspace settings name servers too ("mcp": {"servers": …}, before mcp.json): names the
			// mcp.json beside them does not have (re-review r4, P3-17).
			l, found := vscodeSettingsServers(filepath.Join(dir, ".vscode", "settings.json"), "project")
			proj, any = append(proj, append(here, notIn(l, here)...)...), any || found
			if any {
				break
			}
		}
	}
	// Whether the harness trusts the workspace is not known here: a name only the project has is Untrusted (R4-1).
	return userFirst(user, proj, nil), note
}

// AntigravityServers is AntigravityServersNoted without its note.
func AntigravityServers(home, cwd string, project bool) []Server {
	l, _ := AntigravityServersNoted(home, cwd, project)
	return l
}

// AntigravityServersNoted are the MCP servers Antigravity is configured with: ~/.gemini/config/mcp_config.json first, then,
// when project is true, a workspace's .agents/mcp_config.json (in cwd or the nearest folder above it that has one) for
// names the user's file does not have, and Untrusted (userFirst). note says which file is there but does not read:
// none of its servers is checked.
func AntigravityServersNoted(home, cwd string, project bool) (list []Server, note string) {
	type file struct {
		MCPServers map[string]entry `json:"mcpServers"`
	}
	read := func(path, scope string) ([]Server, bool) {
		var f file
		found, why := readNearest(path, &f, "Antigravity")
		if why != "" {
			note = strings.TrimSpace(note + " " + why)
			return nil, found
		}
		var out []Server
		for name, e := range f.MCPServers {
			out = append(out, e.server(name, "antigravity", scope))
		}
		sortServers(out)
		return out, found
	}
	var proj []Server
	if project {
		for _, dir := range upward(cwd) {
			l, found := read(filepath.Join(dir, ".agents", "mcp_config.json"), "project")
			if found {
				proj = l
				break
			}
		}
	}
	user, _ := read(filepath.Join(home, ".gemini", "config", "mcp_config.json"), "user")
	// Whether Antigravity trusts the workspace is not known here: a name only the project has is Untrusted (R4-1).
	return userFirst(user, proj, nil), note
}

func sortServers(l []Server) {
	for i := 1; i < len(l); i++ {
		for j := i; j > 0 && l[j].Name < l[j-1].Name; j-- {
			l[j], l[j-1] = l[j-1], l[j]
		}
	}
}

// ToolServer is the configured server a tool name of a runtime belongs to, and whether the name is clear:
//   - Codex, and the PreToolUse alias of the Copilot harness: mcp__<server>__<tool> (as Claude Code writes it,
//     ClaudeToolServer);
//   - the Copilot harness's toolName <server>/<tool> (one third-party source; a device check);
//   - Antigravity's eager form mcp_<server>_<tool>: a name more than one configured server fits is not clear.
func ToolServer(list []Server, form, tool string) (Server, bool) {
	s, n := ToolServers(list, form, tool)
	return s, n == 1
}

// ToolServers is ToolServer with the number of configured servers the tool's name fits (more than one: none is
// taken). Claude Code's form takes the longest name, so it fits one or none.
func ToolServers(list []Server, form, tool string) (Server, int) {
	return ResolveToolServer(list, form, tool, nil)
}

// ResolveToolServer is ToolServers that, when the name fits more than one server, leaves out each whose tools are
// known (known: the state's last read or pin) and have none of the name left after its prefix: docs and docs_v2 in
// the mcp_<server>_<tool> form both fit mcp_docs_v2_search, and when docs has no tool v2_search the call is
// docs_v2's. Only a real ambiguity stays one (re-review r4, P3-18).
func ResolveToolServer(list []Server, form, tool string, known func(Server) (map[string]bool, bool)) (Server, int) {
	var prefix func(s Server) string
	switch form {
	case "slash":
		prefix = func(s Server) string { return s.Name + "/" }
	case "underscore":
		prefix = func(s Server) string { return "mcp_" + s.Name + "_" }
	default:
		if s, ok := ClaudeToolServer(list, tool); ok {
			return s, 1
		}
		return Server{}, 0
	}
	type fit struct {
		s    Server
		tool string
	}
	var found []fit
	names := map[string]bool{}
	for _, s := range list {
		if p := prefix(s); strings.HasPrefix(tool, p) && len(tool) > len(p) && !names[s.Name] {
			names[s.Name] = true
			found = append(found, fit{s, tool[len(p):]})
		}
	}
	if len(found) > 1 && known != nil {
		var left []fit
		for _, f := range found {
			if tools, ok := known(f.s); ok && !tools[f.tool] {
				continue
			}
			left = append(left, f)
		}
		found = left
	}
	if len(found) != 1 {
		return Server{}, len(found)
	}
	return found[0].s, 1
}
