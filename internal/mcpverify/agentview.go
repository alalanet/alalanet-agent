package mcpverify

// The agent's own copy of a server's tools (VERIFY-AUTO-1 step 1b, research 1.1 and 3.9). Cursor writes it to
// ~/.cursor/projects/<project>/mcps/<server>/tools/<tool>.json (name, description, arguments) beside
// SERVER_METADATA.json (serverName) and INSTRUCTIONS.md; Antigravity to ~/.gemini/antigravity/mcp/<server>/<tool>.json
// (name, description, parameters) beside instructions.md (~/.gemini/antigravity-cli/mcp for its CLI). It is what the
// model reads, so it sees what alalanet-agent's anonymous read cannot: a server that needs authorization, one on this
// machine, one that answers clients differently. It has fewer fields than alalanet's v3 digest covers (no titles,
// annotations or output schema), and whether the runtimes keep the schema as served is not known (a device check):
// so it is pinned on this machine and scanned, and only its descriptions are compared with alalanet-agent's read; it
// is not compared with alalanet's record (the server's "av" digest is a server step).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/alalanet/alalanet-agent/internal/tooldigest"
)

// AgentView is the agent's own copy of one server's tools.
type AgentView struct {
	Source       string // cursor or antigravity
	Tools        []AgentTool
	Instructions string
	// Others: Cursor's copies of the same server in other projects, when the hook names no workspace and they differ
	// from this one: each is judged, the worst verdict taken (review r4, R4-2).
	Others []*AgentView
}

// AgentTool is one tool of the copy.
type AgentTool struct {
	Name, Description string
	Schema            json.RawMessage
}

// maxCopyFiles bounds a copy's tool files, as the read's tools are bounded.
const maxCopyFiles = tooldigest.MaxTools

// readCopyTools reads the tool files of dir (regular files of 1 MiB at most; at most maxCopyFiles), schemaKey naming
// the member that holds the input schema.
func readCopyTools(dir, schemaKey string) []AgentTool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []AgentTool
	for _, e := range entries {
		if len(out) == maxCopyFiles {
			break
		}
		if !strings.HasSuffix(e.Name(), ".json") || e.Name() == "SERVER_METADATA.json" {
			continue
		}
		b, err := readSmall(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var m map[string]json.RawMessage
		if json.Unmarshal(b, &m) != nil {
			continue
		}
		var t AgentTool
		if json.Unmarshal(m["name"], &t.Name) != nil || t.Name == "" {
			continue
		}
		_ = json.Unmarshal(m["description"], &t.Description)
		t.Schema = m[schemaKey]
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func readText(path string) string {
	b, err := readSmall(path)
	if err != nil {
		return ""
	}
	return string(b)
}

var nonSlug = regexp.MustCompile(`[^A-Za-z0-9]+`)

// cursorSlug is the folder name Cursor is taken to give a workspace's project: the path's letters and digits, runs of
// anything else written "-" (a device check).
func cursorSlug(path string) string { return strings.Trim(nonSlug.ReplaceAllString(path, "-"), "-") }

// CursorAgentView is Cursor's copy of the server named server: the one in a workspace's project folder when Cursor
// names one (workspaces), else the copies of every project, used only when they agree. why says why there is none
// to use ("" with no copy at all).
func CursorAgentView(home, server string, workspaces []string) (*AgentView, string) {
	if !safeFolder(server) {
		return nil, ""
	}
	metas, _ := filepath.Glob(filepath.Join(home, ".cursor", "projects", "*", "mcps", "*", "SERVER_METADATA.json"))
	want := map[string]bool{}
	for _, w := range workspaces {
		want[cursorSlug(w)] = true
	}
	var mine, all []*AgentView
	for _, m := range metas {
		var meta struct {
			Name string `json:"serverName"`
		}
		if readJSON(m, &meta) != nil || meta.Name != server {
			continue
		}
		dir := filepath.Dir(m)
		av := &AgentView{Source: "cursor", Tools: readCopyTools(filepath.Join(dir, "tools"), "arguments"), Instructions: readText(filepath.Join(dir, "INSTRUCTIONS.md"))}
		all = append(all, av)
		if want[filepath.Base(filepath.Dir(filepath.Dir(dir)))] {
			mine = append(mine, av)
		}
	}
	switch {
	case len(mine) == 1:
		return mine[0], ""
	case len(all) == 0:
		return nil, ""
	}
	first := digestView(all[0]).hash
	for _, av := range all[1:] {
		if digestView(av).hash != first {
			all[0].Others = append(all[0].Others, av)
		}
	}
	return all[0], ""
}

// AntigravityAgentView is Antigravity's copy of the server named server (the app's, else its CLI's).
func AntigravityAgentView(home, server string) (*AgentView, string) {
	if !safeFolder(server) {
		return nil, ""
	}
	for _, base := range []string{filepath.Join(home, ".gemini", "antigravity", "mcp"), filepath.Join(home, ".gemini", "antigravity-cli", "mcp")} {
		dir := filepath.Join(base, server)
		if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() {
			continue
		}
		return &AgentView{Source: "antigravity", Tools: readCopyTools(dir, "parameters"), Instructions: readText(filepath.Join(dir, "instructions.md"))}, ""
	}
	return nil, ""
}

// safeFolder: a server name that is one folder's name, never a path.
func safeFolder(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, `/\`) && filepath.Base(name) == name
}

// viewDigest is a copy as alalanet-agent compares it: per tool sha256(name 0x00 description 0x00 schema) and
// sha256(name 0x00 description), the first 16 bytes in hex; the set's hash over the lines name:digest; the flags of
// its texts (instructions included), judged as the prober judges a server's.
type viewDigest struct {
	hash  string
	sigs  []sig // Digest: the whole tool's
	descs []sig // Digest: the name's and the description's
	flags []string
}

func digestView(av *AgentView) viewDigest {
	var d viewDigest
	st := &tooldigest.ServerText{}
	seen := map[string]bool{}
	for _, f := range tooldigest.InstructionFlags(av.Instructions, st) {
		seen[f] = true
	}
	h := sha256.New()
	tools := append([]AgentTool(nil), av.Tools...)
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	units, marks, reorders := 0, 0, false
	for _, t := range tools {
		name := validName(t.Name)
		full := sha256.Sum256([]byte(t.Name + "\x00" + t.Description + "\x00" + tooldigest.Canonical(t.Schema)))
		desc := sha256.Sum256([]byte(t.Name + "\x00" + t.Description))
		d.sigs = append(d.sigs, sig{Name: name, Digest: hex.EncodeToString(full[:16]), V: tooldigest.SigVersion})
		d.descs = append(d.descs, sig{Name: name, Digest: hex.EncodeToString(desc[:16]), V: tooldigest.SigVersion})
		fmt.Fprintf(h, "%s:%s\n", name, hex.EncodeToString(full[:16]))
		text := t.Name + "\n" + t.Description + "\n" + tooldigest.DecodedJSON(t.Schema)
		for _, f := range tooldigest.ScanPatterns(text) {
			seen[f] = true
		}
		u, m, r := st.Judge(text)
		units, marks, reorders = units+u, marks+m, reorders || r
	}
	if f := tooldigest.HiddenFlag(units, marks, reorders); f != "" {
		seen[f] = true
	}
	for f := range seen {
		d.flags = append(d.flags, f)
	}
	sort.Strings(d.flags)
	d.hash = hex.EncodeToString(h.Sum(nil))
	return d
}

// descSigs are the read's tools as the copy is compared with them: sha256(name 0x00 description).
func descSigs(tools []tooldigest.ToolDef) []sig {
	var out []sig
	for _, t := range tools {
		sum := sha256.Sum256([]byte(t.Name + "\x00" + t.Description))
		out = append(out, sig{Name: validName(t.Name), Digest: hex.EncodeToString(sum[:16]), V: tooldigest.SigVersion})
	}
	return out
}

// evaluateView is the verdict on the copy d against its pin and against the read's descriptions (nil: none read).
func evaluateView(d viewDigest, pin *pinState, readDescs []sig) (holds, warns []string) {
	approved := pin != nil && pin.Hash == d.hash && pin.Approved
	if f := onlyStrong(d.flags); len(f) > 0 && !approved {
		holds = append(holds, "the agent's own copy of its tools carries signs of instructions to the model ("+strings.Join(f, ", ")+")")
	}
	if pin != nil && pin.Hash != d.hash {
		prev := tools(pin.accepted())
		added, _, changed := tooldigest.DiffTools(prev, tools(d.sigs))
		switch {
		case len(changed) > 0:
			holds = append(holds, "the agent's own copy of its tools changed since this machine accepted it: "+changes(changed, nil))
		case len(added) > 0:
			warns = append(warns, fmt.Sprintf("the agent's own copy lists %s added since this machine accepted it", count(len(added), "tool")))
		}
	}
	if len(readDescs) > 0 {
		_, _, differ := tooldigest.DiffTools(tools(readDescs), tools(d.descs))
		if len(differ) > 0 {
			warns = append(warns, fmt.Sprintf("the agent's own copy of %s has other descriptions than alalanet-agent's anonymous read (%s): a per-user server, or one that answers clients differently",
				count(len(differ), "tool"), names(differ)))
		}
	}
	return holds, warns
}

// viewKey is the state's key of a server read through its copy only (no URL): its runtime and name.
func viewKey(srv Server) string { return serverKey("agent-view\x00" + srv.Runtime + "\x00" + srv.Name) }
