package main

// The MCP side of alalanet-agent (VERIFY-AUTO-1, ADR-0181): at the first use of a remote MCP server's tool, hook
// claude-code and hook cursor read the server's tools/list themselves, anonymously, and compare it with the set this
// machine accepted and with the set the server serves alalanet (internal/mcpverify). mcp-verify checks every
// configured server and prints the result; mcp-approve accepts a server's current set, on the user's own terminal.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/alalanet/alalanet-agent/internal/mcpverify"
)

// mcpHookBudget bounds the MCP check of one hook call: one read (3 s) and alalanet's record (2 s), at once; a call
// past it goes on unchecked (or is held with ALALANET_FAIL_CLOSED=1). Within every runtime's hook timeout.
const mcpHookBudget = 5 * time.Second

// newVerifier is the MCP check as the commands run it.
func newVerifier(getenv func(string) string, home string) *mcpverify.Verifier {
	return &mcpverify.Verifier{API: api(), StateDir: mcpverify.DefaultStateDir(getenv, home), Version: version,
		FailClosed: failClosed(getenv("ALALANET_FAIL_CLOSED")), UnverifiedHold: strings.EqualFold(strings.TrimSpace(getenv("ALALANET_MCP_UNVERIFIED")), "hold")}
}

// claudeScopes are the mcp_server.source values Claude Code gives a server of a configuration file on this machine.
var claudeScopes = map[string]bool{"user": true, "local": true, "project": true}

// mcpPaths are where the runtimes' configurations are: home, Claude Code's file (CLAUDE_CONFIG_DIR) and Codex's folder
// (CODEX_HOME); "" for their places under home.
type mcpPaths struct{ home, claudeConfig, codexHome string }

func (p mcpPaths) codex() string {
	if p.codexHome != "" {
		return p.codexHome
	}
	return filepath.Join(p.home, ".codex")
}

// mcpServerOf is the configured server an MCP call goes to, with the agent's own copy of its tools when the runtime
// keeps one (Cursor, Antigravity); why says why there is none to check (a claude.ai connector, a plugin's server, a
// name in no configuration file, a name that fits two servers or is of a form not known). byFiles says that the
// reason is one the configuration files decide, which a repository can write: a file of the runtime that is there
// but does not read (note says which), or a tool name that fits more than one configured server. mcpHook never lets
// such a call go ahead without a word (re-review r3, P2-G). unmodeled names a source of servers in the project that
// alalanet-agent does not read (a plugin the repository's Claude Code settings enable, a VS Code workspace file):
// the hook says once a session and server that such a call is not checked (re-review r4, P3-17). known gives the
// tools the state holds for a server, to tell apart a name that fits two (P3-18); nil leaves them apart.
func mcpServerOf(runtime string, ev hookEvent, p mcpPaths, known func(mcpverify.Server) (map[string]bool, bool)) (s mcpverify.Server, why, note string, byFiles bool, unmodeled string) {
	ok := false
	n := 0
	// fits: the reason for a name that fits no configured server (n == 0) or more than one.
	fits := func(rt string) string {
		if n > 1 {
			return "its name fits more than one of " + rt + "'s configured servers"
		}
		return "its name fits none of " + rt + "'s configured servers"
	}
	switch runtime {
	case "claude-code":
		if ev.mcpSource != "" && !claudeScopes[ev.mcpSource] {
			return s, "a " + mcpverify.SafeName(ev.mcpSource) + " server: no configuration file on this machine names its URL", "", false, mcpverify.ClaudeUnmodeled(ev.cwd)
		}
		var list []mcpverify.Server
		list, note = mcpverify.ClaudeServers(claudeFile(p.home, p.claudeConfig), ev.cwd, true) // a project server in use is one the user approved
		if ev.mcpServer != "" {
			s, ok = mcpverify.Find(list, ev.mcpServer, ev.mcpSource)
		} else {
			s, ok = mcpverify.ClaudeToolServer(list, ev.mcpTool)
		}
		if !ok {
			return s, "it is in none of Claude Code's configuration files", note, note != "", mcpverify.ClaudeUnmodeled(ev.cwd)
		}
	case "codex":
		var list []mcpverify.Server
		list, note = mcpverify.CodexServers(p.codex(), ev.cwd, true)
		if s, n = mcpverify.ResolveToolServer(list, "", ev.mcpTool, known); n != 1 {
			return mcpverify.Server{}, fits("Codex"), note, note != "" || n > 1, ""
		}
	case "copilot":
		var list []mcpverify.Server
		list, note = mcpverify.CopilotServersNoted(p.home, ev.cwd, true)
		if s, n = mcpverify.ResolveToolServer(list, ev.mcpForm, ev.mcpTool, known); n != 1 {
			return mcpverify.Server{}, fits("the Copilot harness"), note, note != "" || n > 1, mcpverify.CopilotUnmodeled(ev.cwd)
		}
	case "antigravity":
		var list []mcpverify.Server
		list, note = mcpverify.AntigravityServersNoted(p.home, ev.cwd, true)
		name := ev.mcpServer
		if ev.mcpForm == "named" {
			s, ok = mcpverify.Find(list, name, "")
		} else if s, n = mcpverify.ResolveToolServer(list, ev.mcpForm, ev.mcpTool, known); n == 1 {
			ok, name = true, s.Name
		}
		if !ok && name != "" { // not configured where alalanet-agent looks, but Antigravity keeps its copy
			s = mcpverify.Server{Name: name, Runtime: "antigravity", Scope: "copy", Transport: mcpverify.TransportStdio}
		}
		if s.Name != "" {
			s.AgentView, _ = mcpverify.AntigravityAgentView(p.home, s.Name)
		}
		if !ok && s.AgentView == nil {
			return mcpverify.Server{}, fits("Antigravity"), note, note != "" || n > 1, ""
		}
	case "cursor":
		name := ev.mcpServer
		list, cfgNote := mcpverify.CursorServersNoted(p.home, "", false)
		configured, found := mcpverify.Find(list, name, "")
		switch {
		case ev.mcpURL != "":
			s = mcpverify.Server{Name: name, Runtime: "cursor", Scope: "hook", Transport: mcpverify.TransportHTTP, URL: ev.mcpURL}
			if found && configured.URL == ev.mcpURL {
				s.Transport, s.Auth = configured.Transport, configured.Auth
			}
		case ev.mcpStdio:
			s = mcpverify.Server{Name: name, Runtime: "cursor", Scope: "hook", Transport: mcpverify.TransportStdio}
		case found:
			s = configured
		}
		var copyWhy string
		if name != "" {
			s.AgentView, copyWhy = mcpverify.CursorAgentView(p.home, name, ev.workspaces)
		}
		if s.Name == "" && s.URL == "" && !ev.mcpStdio && s.AgentView == nil {
			return s, "it is in none of Cursor's configuration files", strings.TrimSpace(cfgNote + " " + copyWhy), cfgNote != "", ""
		}
		note = strings.TrimSpace(cfgNote + " " + copyWhy)
	}
	return s, "", note, false, ""
}

// claudeFile is Claude Code's configuration file: claudeConfig when it is given (ClaudeConfigFile of the environment,
// CLAUDE_CONFIG_DIR), else ~/.claude.json.
func claudeFile(home, claudeConfig string) string {
	if claudeConfig != "" {
		return claudeConfig
	}
	return filepath.Join(home, ".claude.json")
}

func serverName(name string) string {
	if name == "" {
		return "(unnamed)"
	}
	return mcpverify.SafeName(name)
}

// mcpHook answers one MCP call: held on a changed known tool, gained authority or signs of instructions to the model;
// a warning for a difference honest servers show; no opinion otherwise. Nothing of the call's input leaves the machine.
func mcpHook(ctx context.Context, runtime string, rt hookRuntime, w io.Writer, ev hookEvent, call hookCall) error {
	if call.mcp == nil {
		return rt.answer(w, ev, verdict{}, true)
	}
	v := *call.mcp
	v.FailClosed = v.FailClosed || call.failClosed
	known := func(s mcpverify.Server) (map[string]bool, bool) { return v.KnownTools(ctx, s) }
	srv, why, note, byFiles, unmodeled := mcpServerOf(runtime, ev, mcpPaths{call.home, call.claudeConfig, call.codexHome}, known)
	if note != "" && call.stderr != nil {
		fmt.Fprintf(call.stderr, "alalanet-agent hook %s: %s\n", runtime, note)
	}
	var out mcpverify.Outcome
	if why != "" {
		out = mcpverify.Outcome{Kind: mcpverify.Unread, Reasons: []string{why}}
		if byFiles && note != "" {
			why += " (" + note + ")"
		}
		switch {
		case v.UnverifiedHold:
			out.Kind = mcpverify.Hold
			out.Reasons[0] = "it cannot be checked: " + why + "; this organisation holds such servers (ALALANET_MCP_UNVERIFIED=hold)"
		case byFiles && v.FailClosed:
			out.Kind = mcpverify.Hold
			out.Reasons[0] = "it cannot be checked: " + why + "; this organisation holds what alalanet could not check (ALALANET_FAIL_CLOSED=1)"
		case byFiles:
			// The configuration files decide this reason, and a repository writes them: never a silent go-ahead.
			out.Kind = mcpverify.Warn
			out.Reasons[0] = "it cannot be checked: " + why + "; its tools go ahead unchecked"
		case unmodeled != "" && v.FailClosed:
			out.Kind = mcpverify.Hold
			out.Reasons[0] = "it cannot be checked: " + why + ", and the project names servers where alalanet-agent does not read (" + unmodeled + "); this organisation holds what alalanet could not check (ALALANET_FAIL_CLOSED=1)"
		case unmodeled != "":
			// Once a session and server: an honest plugin or workspace server is not a warning at every call.
			out.Kind = mcpverify.Warn
			out.Reasons[0] = "it cannot be checked: " + why + ", and the project names servers where alalanet-agent does not read (" + unmodeled + "); its tools go ahead unchecked"
			out.Told = v.TellOnce(ctx, runtime, unfoundName(ev), ev.session, "unfound")
		}
	} else {
		cctx, cancel := context.WithTimeout(ctx, mcpHookBudget)
		out = v.Check(cctx, srv, ev.session)
		cancel()
		if out.Kind == mcpverify.Unread && srv.Untrusted {
			// A server only a project file names is not contacted (R4-1, never a request); the call it makes is not
			// let through without a word either: once a session and server (re-review r4, P3-17).
			out = mcpverify.Outcome{Kind: mcpverify.Warn, Reasons: []string{"it is named only by a project file of a workspace the runtime may not trust, " +
				"so alalanet-agent does not contact it; its tools go ahead unchecked"}, Told: v.TellOnce(ctx, runtime, srv.Name, ev.session, "untrusted")}
		}
	}
	if ctx.Err() != nil {
		return rt.answer(w, ev, verdict{}, false) // stopped by a signal: the runtime no longer waits
	}
	name, text := serverName(firstNonEmpty(srv.Name, ev.mcpServer)), strings.Join(out.Reasons, "; ")
	switch out.Kind {
	case mcpverify.Hold:
		return rt.answer(w, ev, verdict{Decision: "ask",
			Reason: "alalanet mcp_verify: HOLD — the MCP server " + name + ": " + text + ". Use its tools only if the user confirms."}, true)
	case mcpverify.Warn:
		switch {
		case out.Told:
		case runtime == "claude-code" || runtime == "cursor": // a message to the user without a hold
			return rt.answer(w, ev, verdict{warn: "alalanet mcp_verify: the MCP server " + name + ": " + text + "."}, true)
		case call.stderr != nil: // Codex, the Copilot harness and Antigravity document none: stderr
			fmt.Fprintf(call.stderr, "alalanet-agent hook %s: alalanet mcp_verify: the MCP server %s: %s.\n", runtime, name, text)
		}
	case mcpverify.NotChecked:
		if !out.Told && call.stderr != nil {
			fmt.Fprintf(call.stderr, "alalanet-agent hook %s: the MCP server %s: %s; its tools go ahead unchecked (ALALANET_FAIL_CLOSED=1 holds them instead)\n", runtime, name, text)
		}
	}
	return rt.answer(w, ev, verdict{}, true)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// mcpServers are the servers mcp-verify and mcp-approve read: Claude Code's user and local scopes and its approved
// project servers, Cursor's global configuration, Codex's (and its trusted projects'), the Copilot harness's and
// Antigravity's user configurations; project is true for every project server (the user asked). Cursor's and
// Antigravity's servers come with the agent's own copy of their tools when there is one.
func mcpServers(p mcpPaths, cwd string, project bool) ([]mcpverify.Server, string) {
	list, note := mcpverify.ClaudeServers(claudeFile(p.home, p.claudeConfig), cwd, project)
	cursor, cursorNote := mcpverify.CursorServersNoted(p.home, cwd, project)
	for _, s := range cursor {
		s.AgentView, _ = mcpverify.CursorAgentView(p.home, s.Name, []string{cwd})
		list = append(list, s)
	}
	codex, codexNote := mcpverify.CodexServers(p.codex(), cwd, project)
	copilot, copilotNote := mcpverify.CopilotServersNoted(p.home, cwd, project)
	list = append(append(list, codex...), copilot...)
	antigravity, antigravityNote := mcpverify.AntigravityServersNoted(p.home, cwd, project)
	for _, s := range antigravity {
		s.AgentView, _ = mcpverify.AntigravityAgentView(p.home, s.Name)
		list = append(list, s)
	}
	return list, strings.Join(strings.Fields(strings.Join([]string{note, cursorNote, codexNote, copilotNote, antigravityNote}, " ")), " ")
}

// mcpVerify checks every configured server at once and prints one line for each, by its configured name.
func mcpVerify(ctx context.Context, w io.Writer, v *mcpverify.Verifier, p mcpPaths, cwd string, project bool) error {
	list, note := mcpServers(p, cwd, project)
	if note != "" {
		fmt.Fprintln(w, note)
	}
	if len(list) == 0 {
		_, err := fmt.Fprintln(w, "no MCP server is configured for Claude Code or Cursor here")
		return err
	}
	outs := make([]mcpverify.Outcome, len(list))
	var wg sync.WaitGroup
	for i, s := range list {
		wg.Go(func() {
			cctx, cancel := context.WithTimeout(ctx, 2*mcpHookBudget)
			defer cancel()
			outs[i] = v.Check(cctx, s, "mcp-verify")
		})
	}
	wg.Wait()
	for i, s := range list {
		line := fmt.Sprintf("%s (%s %s): %s", serverName(s.Name), s.Runtime, s.Scope, outs[i].Kind)
		if outs[i].Pinned {
			line += ", pinned as this machine's accepted set"
		}
		if len(outs[i].Reasons) > 0 {
			line += ": " + strings.Join(outs[i].Reasons, "; ")
		}
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}

// mcpApprove accepts the current tool set of the server name on the user's own terminal: it refuses without one, reads
// the server afresh, shows what it serves and a random code on the terminal only, and pins the set when the code is
// typed back. An agent's shell has no terminal of its own, and what is written to the terminal never reaches the model.
func mcpApprove(ctx context.Context, w io.Writer, v *mcpverify.Verifier, p mcpPaths, cwd, name string, tty func() (io.Reader, io.Writer, func(), error)) error {
	in, screen, closeTTY, err := tty()
	if err != nil {
		return errors.New("mcp-approve asks on a terminal and there is none: the user runs it in their own terminal")
	}
	defer closeTTY()
	var found []mcpverify.Server
	seen := map[string]bool{}
	all, _ := mcpServers(p, cwd, true)
	for _, s := range all {
		if s.Name == name && !seen[s.URL] { // one URL, one pin: Claude Code's and Cursor's alike
			seen[s.URL] = true
			found = append(found, s)
		}
	}
	if len(found) == 0 {
		return fmt.Errorf("no MCP server named %s is configured for Claude Code or Cursor here", serverName(name))
	}
	lines := bufio.NewScanner(in)
	for _, s := range found {
		cctx, cancel := context.WithTimeout(ctx, 2*mcpHookBudget)
		a, err := v.Approve(cctx, s)
		cancel()
		if err != nil {
			return err
		}
		code := terminalCode()
		reasons := "it matches what this machine and alalanet know"
		if len(a.Outcome.Reasons) > 0 {
			reasons = strings.Join(a.Outcome.Reasons, "; ")
		}
		fmt.Fprintf(screen, "%s (%s %s) serves %d tools now: %s: %s.\nType %s and Enter to accept this tool set as this machine's (anything else cancels): ",
			serverName(s.Name), s.Runtime, s.Scope, a.Tools, a.Outcome.Kind, reasons, code)
		if !lines.Scan() || strings.TrimSpace(lines.Text()) != code {
			fmt.Fprintln(screen, "Not accepted.")
			return errors.New("not accepted")
		}
		if err := a.Pin(); err != nil {
			return err
		}
		fmt.Fprintf(w, "%s (%s %s): accepted\n", serverName(s.Name), s.Runtime, s.Scope)
	}
	return nil
}

// unfoundName is the server a call names when no configured server fits it: the runtime's own name for it, else the
// part of the tool's name before its tool (mcp__<server>__, <server>/), else the tool's name.
func unfoundName(ev hookEvent) string {
	switch {
	case ev.mcpServer != "":
		return ev.mcpServer
	case ev.mcpForm == "slash":
		if i := strings.Index(ev.mcpTool, "/"); i > 0 {
			return ev.mcpTool[:i]
		}
	case ev.mcpForm == "" && strings.HasPrefix(ev.mcpTool, "mcp__"):
		if name, _, ok := strings.Cut(strings.TrimPrefix(ev.mcpTool, "mcp__"), "__"); ok {
			return name
		}
	}
	return ev.mcpTool
}
