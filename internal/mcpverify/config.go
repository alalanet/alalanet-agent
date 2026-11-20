// Package mcpverify is alalanet-agent's check of the remote MCP servers an agent runtime is configured with
// (VERIFY-AUTO-1): it reads each server's tools/list itself, anonymously, digests it with internal/tooldigest exactly
// as alalanet's prober does, and compares it with the set this machine accepted (the local pin) and with the set the
// server serves alalanet (its public record, GET /v1/services/{id}/tools, looked up by the listing's id: a hash, never
// the configured URL). Tool texts, headers, the configured URL, the session and the working folder never leave the
// machine. It imports neither the store nor sqlite: alalanet-agent links it.
package mcpverify

import (
	"bufio"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/alalanet/alalanet-agent/internal/onejson"
)

// Transports of a configured server.
const (
	TransportHTTP  = "http"
	TransportSSE   = "sse"
	TransportStdio = "stdio"
)

// Server is one configured MCP server: where it was configured and how it is reached. Its headers are not kept, only
// whether there were any: alalanet-agent reads every server anonymously.
type Server struct {
	Name      string // the name it is configured under
	Runtime   string // claude-code or cursor
	Scope     string // claude-code: user, local or project; cursor: global, project or hook
	Transport string // http, sse or stdio
	URL       string // the configured URL as written ("" for stdio): it never leaves the machine
	Auth      bool   // the configuration gives headers, a headers helper or OAuth settings
	// AgentView: the agent's own copy of the server's tools when the runtime keeps one on disk (Cursor, Antigravity);
	// nil when it does not.
	AgentView *AgentView
	// Untrusted: only a project file names the server, and alalanet-agent cannot tell that the runtime trusts that
	// workspace: it is never contacted (review r4, R4-1).
	Untrusted bool
	// Shadowed: a project file names a server of this name at another URL; the user's entry is the one checked.
	Shadowed bool
}

// userFirst is a runtime's servers with the user's own entries first: a name a user file defines resolves to the
// user's entry, never to a project file's (a cloned repository's) one, which is marked Shadowed when it gives another
// URL; a name only a project file has is kept after them, Untrusted unless trusted says the runtime trusts it.
func userFirst(user, project []Server, trusted func(Server) bool) []Server {
	out := append([]Server(nil), user...)
	byName := map[string]int{}
	for i, s := range out {
		if _, ok := byName[s.Name]; !ok {
			byName[s.Name] = i
		}
	}
	for _, p := range project {
		if i, ok := byName[p.Name]; ok {
			if out[i].URL != p.URL {
				out[i].Shadowed = true
			}
			continue
		}
		p.Untrusted = trusted == nil || !trusted(p)
		out = append(out, p)
	}
	return out
}

// maxConfig bounds a configuration file read. ~/.claude.json keeps the history of every project too: it is read as a
// stream, only its mcpServers and the projects of the session's folders kept, so the bound is on time, not memory.
var maxConfig int64 = 256 << 20

// entry is one server's configuration as Claude Code and Cursor write it.
type entry struct {
	Type          string          `json:"type"`
	URL           string          `json:"url"`
	ServerURL     string          `json:"serverUrl"`
	Command       string          `json:"command"`
	Headers       json.RawMessage `json:"headers"`
	HeadersHelper json.RawMessage `json:"headersHelper"`
	OAuth         json.RawMessage `json:"oauth"`
}

func (e entry) server(name, runtime, scope string) Server {
	s := Server{Name: name, Runtime: runtime, Scope: scope, URL: strings.TrimSpace(e.URL)}
	if s.URL == "" {
		s.URL = strings.TrimSpace(e.ServerURL)
	}
	present := func(r json.RawMessage) bool {
		v := strings.TrimSpace(string(r))
		return v != "" && v != "null" && v != "{}" && v != `""`
	}
	s.Auth = present(e.Headers) || present(e.HeadersHelper) || present(e.OAuth)
	switch t := strings.ToLower(strings.TrimSpace(e.Type)); {
	case t == "sse":
		s.Transport = TransportSSE
	case t == "stdio", s.URL == "":
		s.Transport, s.URL = TransportStdio, ""
	default: // http, streamable-http, streamableHttp, or a URL without a type
		s.Transport = TransportHTTP
	}
	return s
}

// maxSmallConfig bounds every configuration file but Claude Code's own (.mcp.json, Cursor's, Codex's, Copilot's,
// Antigravity's): 1 MiB is far more than a list of servers takes (review r3, P3-3).
const maxSmallConfig = 1 << 20

// readJSON reads a small configuration file: a regular file of maxSmallConfig at most (openRegular: never a device, a
// FIFO or a folder). It reads it as the runtimes do, with JSON.parse (onejson.AsJSONParse): encoding/json read
// "url":"https://a","URL":"https://b" as b, so a cloned repository's .mcp.json had alalanet-agent check b while
// Claude Code connected to a, and "mcpServers":{…},"MCPServers":null hid every server.
func readJSON(path string, v any) error {
	b, err := readSmall(path)
	if err != nil {
		return err
	}
	return onejson.AsJSONParse(b, v)
}

// readSmall is a regular file of maxSmallConfig bytes at most.
func readSmall(path string) ([]byte, error) {
	f, fi, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi.Size() > maxSmallConfig {
		return nil, errors.New("larger than a configuration file")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxSmallConfig+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxSmallConfig {
		return nil, errors.New("larger than a configuration file")
	}
	return b, nil
}

func servers(m map[string]entry, runtime, scope string) []Server {
	var out []Server
	for name, e := range m {
		out = append(out, e.server(name, runtime, scope))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// upward is dir and the folders above it, nearest first.
func upward(dir string) []string {
	if dir == "" {
		return nil
	}
	dir = filepath.Clean(dir)
	var out []string
	for range 64 {
		out = append(out, dir)
		up := filepath.Dir(dir)
		if up == dir {
			break
		}
		dir = up
	}
	return out
}

type claudeProject struct {
	MCPServers map[string]entry `json:"mcpServers"`
	Enabled    []string         `json:"enabledMcpjsonServers"`
	Disabled   []string         `json:"disabledMcpjsonServers"`
	EnableAll  bool             `json:"enableAllProjectMcpServers"`
}

type claudeFile struct {
	MCPServers map[string]entry
	Projects   map[string]claudeProject
}

// ClaudeConfigFile is Claude Code's own configuration file: .claude.json in CLAUDE_CONFIG_DIR when it is set, else in
// the home folder.
func ClaudeConfigFile(getenv func(string) string, home string) string {
	if d := strings.TrimSpace(getenv("CLAUDE_CONFIG_DIR")); d != "" {
		return filepath.Join(d, ".claude.json")
	}
	return filepath.Join(home, ".claude.json")
}

// readClaudeFile reads Claude Code's file as a stream: mcpServers, and of projects only the folders in want; every
// other value (each project's history) is skipped token by token. note says why the file could not be read ("" when
// it was, or when there is none).
func readClaudeFile(path string, want map[string]bool) (cf claudeFile, note string) {
	cf.Projects = map[string]claudeProject{}
	f, fi, err := openRegular(path)
	if errors.Is(err, os.ErrNotExist) {
		return cf, ""
	}
	if err != nil {
		return cf, "Claude Code's configuration file could not be opened as a regular file"
	}
	defer f.Close()
	if fi.Size() > maxConfig {
		return cf, fmt.Sprintf("Claude Code's configuration file is larger than alalanet-agent reads (%d MiB): its user and local servers are not checked", maxConfig>>20)
	}
	d := jsontext.NewDecoder(bufio.NewReader(io.LimitReader(f, maxConfig)), jsontext.AllowDuplicateNames(true), jsontext.AllowInvalidUTF8(true))
	bad := func() (claudeFile, string) {
		return claudeFile{Projects: map[string]claudeProject{}}, "Claude Code's configuration file is not JSON alalanet-agent can read: its user and local servers are not checked"
	}
	// Claude Code keeps apart two server names Go would read as one (invalid UTF-8, a lone surrogate): none is checked
	// rather than one in the other's place (onejson.ErrNameApart).
	oddName := func() (claudeFile, string) {
		return claudeFile{Projects: map[string]claudeProject{}}, oddNameNote("Claude Code's configuration file", "its user and local servers")
	}
	if t, err := d.ReadToken(); err != nil || t.Kind() != '{' {
		return bad()
	}
	for d.PeekKind() != '}' {
		tok, err := d.ReadToken()
		if err != nil {
			return bad()
		}
		switch name := tok.String(); name {
		case "mcpServers":
			v, err := d.ReadValue()
			if err != nil {
				return bad()
			}
			cf.MCPServers = nil
			if err := onejson.AsJSONParse(v, &cf.MCPServers); errors.Is(err, onejson.ErrNameApart) { // as Claude Code reads it (readJSON)
				return oddName()
			}
		case "projects":
			if d.PeekKind() != '{' {
				if d.SkipValue() != nil {
					return bad()
				}
				continue
			}
			_, _ = d.ReadToken()
			for d.PeekKind() != '}' {
				tok, err := d.ReadToken()
				if err != nil {
					return bad()
				}
				dir := tok.String() // copied now: the next read voids the token
				if !want[dir] {
					if d.SkipValue() != nil {
						return bad()
					}
					continue
				}
				v, err := d.ReadValue()
				if err != nil {
					return bad()
				}
				var p claudeProject
				if err := onejson.AsJSONParse(v, &p); errors.Is(err, onejson.ErrNameApart) {
					return oddName()
				}
				cf.Projects[dir] = p
			}
			if _, err := d.ReadToken(); err != nil {
				return bad()
			}
		default:
			if d.SkipValue() != nil {
				return bad()
			}
		}
	}
	return cf, ""
}

// ClaudeServers are the MCP servers Claude Code is configured with for a session in cwd, in the order Claude Code
// prefers one name (local, approved project, user), from its configuration file (ClaudeConfigFile): the user scope (mcpServers), the local scope (its
// projects[<folder>].mcpServers, for cwd or a folder above it) and the project scope (.mcp.json in cwd or a folder
// above it). A project server is listed only when project is true or the user approved it in Claude Code
// (enabledMcpjsonServers, enableAllProjectMcpServers): a cloned repository's .mcp.json must not make alalanet-agent
// contact a server the user has not approved. Plugin servers and claude.ai connectors are not in these files. note
// says why the configuration file could not be read ("" when it was).
func ClaudeServers(configFile, cwd string, project bool) (list []Server, note string) {
	want := map[string]bool{}
	for _, dir := range upward(cwd) {
		want[dir] = true
	}
	cf, note := readClaudeFile(configFile, want)
	var local, proj []Server
	var p claudeProject
	for _, dir := range upward(cwd) {
		if pr, ok := cf.Projects[dir]; ok {
			p = pr
			local = servers(pr.MCPServers, "claude-code", "local")
			break
		}
	}
	for _, dir := range upward(cwd) {
		var mf struct {
			MCPServers map[string]entry `json:"mcpServers"`
		}
		found, why := readNearest(filepath.Join(dir, ".mcp.json"), &mf, "Claude Code")
		if !found {
			continue
		}
		if why != "" {
			note = strings.TrimSpace(note + " " + why)
			break
		}
		for _, s := range servers(mf.MCPServers, "claude-code", "project") {
			if project || approved(p, s.Name) {
				proj = append(proj, s)
			}
		}
		break
	}
	// Claude Code's own order: local, then a .mcp.json server the user approved, then user (review r6, R6-1). An
	// unapproved .mcp.json server, listed only for project, never wins a name the user's files have, and is Untrusted
	// (review r4, R4-1).
	var approvedProj, unapproved []Server
	for _, s := range proj {
		if approved(p, s.Name) {
			approvedProj = append(approvedProj, s)
		} else {
			unapproved = append(unapproved, s)
		}
	}
	trusted := append(append(local, approvedProj...), servers(cf.MCPServers, "claude-code", "user")...)
	return userFirst(trusted, unapproved, nil), note
}

// CursorServers is CursorServersNoted without its note.
func CursorServers(home, cwd string, project bool) []Server {
	l, _ := CursorServersNoted(home, cwd, project)
	return l
}

// CursorServersNoted are the MCP servers Cursor is configured with: the project's .cursor/mcp.json (in cwd or the nearest
// folder above it that has one) when project is true, then the global ~/.cursor/mcp.json. note says which file is
// there but does not read: none of its servers is checked (readNearest).
func CursorServersNoted(home, cwd string, project bool) (out []Server, note string) {
	type file struct {
		MCPServers map[string]entry `json:"mcpServers"`
	}
	if project {
		for _, dir := range upward(cwd) {
			var f file
			found, why := readNearest(filepath.Join(dir, ".cursor", "mcp.json"), &f, "Cursor")
			if !found {
				continue
			}
			if why == "" {
				out = append(out, servers(f.MCPServers, "cursor", "project")...)
			}
			note = why
			break
		}
	}
	var g file
	if _, why := readNearest(filepath.Join(home, ".cursor", "mcp.json"), &g, "Cursor"); why != "" {
		return out, strings.TrimSpace(note + " " + why)
	}
	return append(out, servers(g.MCPServers, "cursor", "global")...), note
}

// approved: Claude Code runs the .mcp.json server name for this project (the user approved it).
func approved(p claudeProject, name string) bool {
	return (p.EnableAll || contains(p.Enabled, name)) && !contains(p.Disabled, name)
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Find is the server named name: the first of list (in the runtime's order of preference) with that name, in scope
// when scope is not "".
func Find(list []Server, name, scope string) (Server, bool) {
	for _, s := range list {
		if s.Name == name && (scope == "" || s.Scope == scope) {
			return s, true
		}
	}
	return Server{}, false
}

var claudeUnsafe = regexp.MustCompile(`[^a-zA-Z0-9_-]`)

// ClaudeToolServer is the configured server a Claude Code MCP tool name (mcp__<server>__<tool>, the server's name with
// every character other than a letter, a digit, _ and - written _) belongs to: the longest name that fits, so that a
// server whose name holds "__" is not cut short.
func ClaudeToolServer(list []Server, tool string) (Server, bool) {
	var best Server
	found := false
	for _, s := range list {
		prefix := "mcp__" + claudeUnsafe.ReplaceAllString(s.Name, "_") + "__"
		if strings.HasPrefix(tool, prefix) && len(tool) > len(prefix) && (!found || len(s.Name) > len(best.Name)) {
			best, found = s, true
		}
	}
	return best, found
}

// oddNameNote says that a file is not read because a server name in it has invalid UTF-8 or a lone surrogate, which
// the runtime's JSON.parse keeps apart from another name that Go would read as the same one.
func oddNameNote(file, servers string) string {
	return file + " names a server with invalid UTF-8 or a lone surrogate, which the runtime keeps apart from another name: " + servers + " are not checked"
}

// readNearest reads the configuration file at path as readJSON does. found says whether a file is there at all,
// read or not: the nearest file that is there is the runtime's, so a walk up the folders ends at it, and a file that
// does not read checks none of its scope's servers instead of a farther file's (re-review r2, P2-E). note says why
// such a file was not read, for the runtime's name ("" when it was read or is not there).
func readNearest(path string, v any, runtime string) (found bool, note string) {
	err := readJSON(path, v)
	switch {
	case err == nil:
		return true, ""
	case errors.Is(err, os.ErrNotExist):
		return false, ""
	case errors.Is(err, onejson.ErrNameApart):
		return true, oddNameNote(runtime+"'s "+filepath.Base(filepath.Dir(path))+"/"+filepath.Base(path), "its servers")
	}
	return true, runtime + "'s " + filepath.Base(filepath.Dir(path)) + "/" + filepath.Base(path) + " is there but does not read: its servers are not checked"
}
