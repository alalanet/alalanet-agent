package main

// alalanet-agent hook <runtime> — the install-time check for agent runtimes other than Claude Code (RT-1, ADR-0150):
// codex, cursor, copilot (the Copilot harness: Copilot CLI, the Copilot app, VS Code — its Local harness too) and
// antigravity.
// The runtime runs it as its pre-tool command hook. It reads the hook's input on stdin and sends the shell command, and
// nothing else of the input, to alalanet's hook check (the endpoint the plugin's HTTP hook uses, ADR-0052) exactly when
// alalanet's own reader (internal/installread, the code the server runs) would act on it — check a package or hold —
// or when the line has a command substitution, which Claude Code itself sends to the plugin's hook whatever its rules
// say. It prints the runtime's own answer (hookRuntimes). When alalanet cannot be reached, the command goes on
// unchecked, as Claude Code does when its HTTP hook cannot be reached; a shell call whose input it cannot read is held.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/alalanet/alalanet-agent/agentkit"
	"github.com/alalanet/alalanet-agent/internal/installread"
)

const (
	// hookDeadline bounds the call to alalanet. The server answers within its own 15 s budget for this endpoint (a
	// check past it answers ask: internal/web/api.go apiClaudeHook); 20 s leaves 5 s for the network and the request's
	// reading, so an answer the server gives — a block included — is never lost to this deadline. It stays within each
	// runtime's default hook timeout: Codex 600 s, the Copilot harness and VS Code 30 s, Antigravity 30 s; Cursor gives
	// no number ("platform default"), so the install page sets one.
	hookDeadline = 20 * time.Second
	// serverBodyCap: the server reads at most 1 MiB of a hook request (internal/web/server.go) and answers ask past it.
	serverBodyCap = 1 << 20
	// maxTokenFile: a plan token is short; a larger file is not one.
	maxTokenFile = 4 << 10
	// maxHookReason bounds the reason alalanet gives, which the runtime hands the agent: alalanet's own name at
	// most ten targets with their codes (installread.MaxHookTargets), a few KB.
	maxHookReason = 8 << 10
)

// maxHookInput: how much of the hook's input is read. The input is read as a stream and only the members a shell call
// needs are kept (Antigravity puts the user's last message into every input); past this the call is held, not let
// through.
var maxHookInput int64 = 64 << 20

// isInstall tells whether the hook sends the line to alalanet: exactly when the server's reader acts on it — a target
// to check, or a reason to hold from either of its two readers, the decision internal/app InstallHook makes before it
// checks anything. A command substitution alone is no reason (RT-1 round 3): the server's reader already reads
// $(which npm) and holds an install inside or next to a substitution, so where it finds nothing the server can only
// stay silent, and the line (a commit message, a header with a token) would leave the machine for no check.
func isInstall(line string) bool {
	targets, unread, _, subst := installread.ParseLine(line)
	return len(targets) > 0 || len(unread) > 0 || len(installread.HookExtra(line, targets, unread, subst)) > 0
}

// verdict is alalanet's answer in the plugin's form: deny, ask or nothing. dailyLimit: an ask the server marks as only
// its daily limit (Alalanet-Not-Checked: daily-limit) — a refusal, not a verdict.
type verdict struct {
	Decision, Reason string
	dailyLimit       bool
}

// reason never leaves a deny or a hold without words: Codex treats a deny without a reason as an invalid answer and
// runs the command, and the Copilot harness requires one.
func (v verdict) reason() string {
	switch {
	case strings.TrimSpace(v.Reason) != "":
		return v.Reason
	case v.Decision == "deny":
		return "alalanet install_check: BLOCK. Do not install; tell the user."
	}
	return "alalanet install_check: HOLD. Install only if the user confirms."
}

// notChecked is a hold in the server's own words (apiClaudeHook): what could not be checked, and why.
func notChecked(why string) verdict {
	return verdict{Decision: "ask", Reason: "alalanet install_check: NOT CHECKED — " + why + ". Install only if the user confirms."}
}

// hookEvent is what one hook input says about the call.
type hookEvent struct {
	known   bool   // the input names its event or tool in a form the runtime documents
	shell   bool   // a shell call
	command string // its command line
	read    bool   // the command line was read
	local   bool   // VS Code's Local harness, which reads the answer from hookSpecificOutput
}

// hookRuntime is one runtime's side: its own answer for alalanet's verdict — reached is false when alalanet could not
// be reached or did not answer as the hook does. Every runtime reads its input the same way (shellCall): a hook file
// can run one runtime's adapter under another runtime (RT-1 round 5).
type hookRuntime struct {
	answer func(w io.Writer, ev hookEvent, v verdict, reached bool) error
}

// The answer mapping (RT-1.md, its addendum, ADR-0150's second round): block → deny everywhere; hold → deny with a
// reason to confirm with the user where ask does not hold the call (Codex does not support it; Cursor's has been
// ignored), ask in the Copilot harness, force_ask in Antigravity (its ask respects cached "Always Allow" grants); no
// opinion → silence where silence is the default (Codex, Copilot), an explicit allow where the answer must be JSON
// (Cursor, Antigravity — whose allow keeps the default policy).
var hookRuntimes = map[string]hookRuntime{
	"codex":       {codexAnswer},
	"cursor":      {cursorAnswer},
	"copilot":     {copilotAnswer},
	"antigravity": {antigravityAnswer},
}

// hookUsageError: the hook cannot run as configured — no runtime, or one it does not know. alalanet-agent exits 2 with
// the usage on stderr: Cursor, Codex and Claude Code read exit 2 as a block and the Copilot harness any non-zero exit as
// a deny, so a typo in a hook file shows at once and never lets installs through unchecked, as exit 1 did (Cursor and
// Codex go on after a failed hook; RT-1 round 6, review P3-R5-1). Antigravity does not document its exit codes.
type hookUsageError struct{ msg string }

func (e hookUsageError) Error() string { return e.msg }

// hookUsage names the runtimes and the event each runs the hook on (RT-1 round 5).
const hookUsage = "hook codex|cursor|copilot|antigravity, run as the runtime's pre-tool command hook on: " +
	"codex PreToolUse; cursor beforeShellExecution and preToolUse (matcher Shell), in .cursor/hooks.json; " +
	"copilot preToolUse (or its PreToolUse alias); antigravity PreToolUse (tool run_command)"

const holdNote = " — this agent runtime cannot pause for the user here: confirm with the user before installing; if they agree, they can run it themselves."

// hookCall is how one hook call reaches alalanet.
type hookCall struct {
	client   *http.Client
	api      string
	token    string    // a plan token, sent as Authorization: Bearer; "" for none
	tokenBad string    // why a configured token cannot be used (never the token): installs are held
	stderr   io.Writer // one line when the input cannot be read or an install goes ahead unchecked; nil for none
	// failClosed: the organisation's policy (ALALANET_FAIL_CLOSED=1) — an install alalanet did not check, because it
	// could not be reached or its daily limit is spent, is held instead of going ahead with a warning.
	failClosed bool
}

func hookClient() *http.Client { return &http.Client{Timeout: hookDeadline} }

// runHook handles one hook call of runtime without a token or a signal (the tests' entry).
func runHook(runtime string, stdin io.Reader, stdout io.Writer, client *http.Client, api string) error {
	return runHookContext(context.Background(), runtime, stdin, stdout, hookCall{client: client, api: api})
}

// runHookContext handles one hook call of runtime; ctx ends it early (SIGTERM, SIGINT). An error is returned only for
// an unknown runtime; everything else ends with the runtime's answer.
func runHookContext(ctx context.Context, runtime string, stdin io.Reader, stdout io.Writer, call hookCall) error {
	name := runtime
	runtime = strings.ToLower(strings.TrimSpace(runtime)) // a runtime's name in any case (RT-1 round 6)
	rt, ok := hookRuntimes[runtime]
	if !ok {
		return hookUsageError{fmt.Sprintf("unknown runtime %q; usage: %s", name, hookUsage)}
	}
	type input struct {
		ev   hookEvent
		over bool
		err  error
	}
	got := make(chan input, 1)
	go func() {
		ev, over, err := readHookInput(stdin)
		got <- input{ev, over, err}
	}()
	var in input
	select {
	case in = <-got:
	case <-ctx.Done():
		return nil // stopped while the input was still coming: the runtime no longer waits for an answer
	}
	say := func(what string) {
		if call.stderr != nil {
			fmt.Fprintf(call.stderr, "alalanet-agent hook %s: %s; nothing was checked, the call is held\n", runtime, what)
		}
	}
	switch ev := in.ev; {
	case in.over:
		say(fmt.Sprintf("the hook input is longer than %d MiB", maxHookInput>>20))
		return rt.answer(stdout, ev, notChecked("the hook input is too large for alalanet-agent to read"), true)
	case !ev.known && in.err != nil:
		say("the hook input is not a JSON object it can read")
		return rt.answer(stdout, ev, notChecked("alalanet-agent could not read the hook input"), true)
	case !ev.known:
		say("the hook input has a form this version does not know (update alalanet-agent)")
		return rt.answer(stdout, ev, notChecked("alalanet-agent does not know this hook input's form"), true)
	case !ev.shell:
		return rt.answer(stdout, ev, verdict{}, true)
	case !ev.read:
		say("the shell call's command could not be read")
		return rt.answer(stdout, ev, notChecked("alalanet-agent could not read the command"), true)
	case !isInstall(ev.command):
		return rt.answer(stdout, ev, verdict{}, true)
	}
	v, reached := askAlalanet(ctx, call, in.ev.command, runtime)
	// Not checked is not a verdict (RT-1 round 3, R2-P2-2): alalanet unreachable, or its daily limit spent, lets the
	// install go with a warning on stderr — as Claude Code goes on when its HTTP hook fails — unless the organisation's
	// policy holds it (ALALANET_FAIL_CLOSED).
	goesAhead := func(what string) {
		if call.stderr != nil {
			fmt.Fprintf(call.stderr, "alalanet-agent hook %s: %s; the install goes ahead unchecked (ALALANET_FAIL_CLOSED=1 holds it instead)\n", runtime, what)
		}
	}
	switch {
	case ctx.Err() != nil:
		return rt.answer(stdout, in.ev, verdict{}, false) // stopped by a signal: the runtime no longer waits
	case !reached && call.failClosed:
		say("alalanet could not be reached")
		return rt.answer(stdout, in.ev, notChecked("alalanet could not be reached"), true)
	case !reached:
		goesAhead("alalanet could not be reached")
	case v.dailyLimit && !call.failClosed:
		goesAhead("alalanet's daily limit for this client is reached")
		return rt.answer(stdout, in.ev, verdict{}, true)
	}
	return rt.answer(stdout, in.ev, v, reached)
}

// fields are the members read from a hook input, raw, by path.
type fields map[string]jsontext.Value

func path(members ...string) string { return strings.Join(members, "\x00") }

// str is a string member.
func (f fields) str(p string) (string, bool) {
	v, ok := f[p]
	if !ok || v.Kind() != '"' {
		return "", false
	}
	var s string
	return s, json.Unmarshal(v, &s) == nil // invalid UTF-8 and lone surrogates read as U+FFFD
}

// arg is a string member of a tool's arguments, given either as an object or as a JSON string holding one.
func (f fields) arg(obj, name string) (string, bool) {
	if s, ok := f.str(path(obj, name)); ok {
		return s, true
	}
	raw, ok := f.str(obj)
	if !ok {
		return "", false
	}
	var m map[string]any
	if json.Unmarshal([]byte(raw), &m) != nil {
		return "", false
	}
	s, ok := m[name].(string)
	return s, ok
}

var errTooLarge = errors.New("hook input too large")

// capReader stops a stream at maxHookInput; over is set only when a byte beyond it arrives.
type capReader struct {
	r    io.Reader
	left int64
	over bool
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.left <= 0 {
		var one [1]byte
		if n, err := c.r.Read(one[:]); n == 0 {
			return 0, err
		}
		c.over = true
		return 0, errTooLarge
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}

// readHookInput reads the members rt needs from the hook's JSON input as a stream: every other member (Antigravity's
// lastUserInput, a tool's long arguments) is skipped token by token and not kept. over is true when the input is
// longer than maxHookInput.
func readHookInput(r io.Reader) (ev hookEvent, over bool, err error) {
	cr := &capReader{r: r, left: maxHookInput}
	br := bufio.NewReader(cr)
	if b, _ := br.Peek(3); bytes.Equal(b, []byte("\xef\xbb\xbf")) {
		_, _ = br.Discard(3) // Cursor on Windows prefixes a byte-order mark (forum report)
	}
	f, err := readFields(br, hookPaths)
	return shellCall(f), cr.over, err
}

// readFields keeps the members at paths (an object on the way to one is entered, any other value kept raw) of the JSON
// object on r. A name given twice keeps its last value, as JavaScript's JSON.parse does; invalid UTF-8 is read as is.
func readFields(r io.Reader, paths []string) (fields, error) {
	want, under := map[string]bool{}, map[string]bool{}
	for _, p := range paths {
		want[p] = true
		for i := range len(p) {
			if p[i] == 0 {
				under[p[:i]] = true
			}
		}
	}
	f := fields{}
	d := jsontext.NewDecoder(r, jsontext.AllowDuplicateNames(true), jsontext.AllowInvalidUTF8(true))
	var object func(prefix string) error
	object = func(prefix string) error {
		if _, err := d.ReadToken(); err != nil { // {
			return err
		}
		for d.PeekKind() != '}' {
			name, err := d.ReadToken()
			if err != nil {
				return err
			}
			p := prefix + name.String()
			switch {
			case under[p] && d.PeekKind() == '{':
				err = object(p + "\x00")
			case want[p]:
				var v jsontext.Value
				if v, err = d.ReadValue(); err == nil {
					f[p] = v.Clone()
				}
			default:
				err = d.SkipValue()
			}
			if err != nil {
				return err
			}
		}
		_, err := d.ReadToken() // }
		return err
	}
	if d.PeekKind() != '{' {
		if _, err := d.ReadToken(); err != nil {
			return f, err
		}
		return f, errors.New("the hook input is not a JSON object")
	}
	return f, object("")
}

// hookPaths are the members of a hook input that say what the call is, in every runtime's form.
var hookPaths = []string{
	"hook_event_name", "command", "tool_name", "tool_input", path("tool_input", "command"), path("tool_input", "cmd"),
	"toolName", "toolArgs", path("toolArgs", "command"),
	path("toolCall", "name"), path("toolCall", "args"), path("toolCall", "args", "CommandLine"),
}

// shellCall reads a hook input in any runtime's form, whichever runtime's adapter was asked (RT-1 round 5): a hook file
// can run one runtime's adapter under another — Cursor runs Claude Code's hooks from .claude/settings*.json with
// PreToolUse mapped to preToolUse and Bash to Shell (cursor.com/docs/reference/third-party-hooks), the Copilot harness
// reads the repository's .claude/settings.json (code.visualstudio.com/docs/copilot/customization/hooks). So a shell call
// in any known form is checked, or held when its command cannot be read, and never left without an opinion. When the
// input has more than one form, a shell call in any of them counts; two different commands are held.
func shellCall(f fields) hookEvent {
	var shell []hookEvent
	unknown, other := false, false
	for _, form := range []func(fields) (hookEvent, bool){eventForm, toolNameForm, toolCallForm} {
		ev, present := form(f)
		switch {
		case !present:
		case !ev.known:
			unknown = true
		case ev.shell:
			shell = append(shell, ev)
		default:
			other = true
		}
	}
	switch {
	case len(shell) > 0:
		for _, ev := range shell[1:] {
			if !ev.read || ev.command != shell[0].command {
				return hookEvent{known: true, shell: true, local: shell[0].local} // which command runs is unknown: held
			}
		}
		return shell[0]
	case unknown || !other:
		return hookEvent{}
	}
	return hookEvent{known: true}
}

// shellName: the shell tools' names that runtimes spell differently, compared without case — Claude Code and Codex
// Bash, the Copilot harness bash and powershell (PowerShell, and Bash for both in its PascalCase alias), Cursor Shell.
func shellName(tool string) bool {
	for _, name := range []string{"Bash", "Shell", "PowerShell"} {
		if strings.EqualFold(tool, name) {
			return true
		}
	}
	return false
}

// eventForm reads the form named by hook_event_name (or, without it, by tool_name): Claude Code's and Codex's
// PreToolUse (tool_name, tool_input; Codex's exec_command may carry cmd — learn.chatgpt.com/docs/hooks), the Copilot
// harness's PascalCase alias, VS Code's Local harness (tool_name run_in_terminal, answered in hookSpecificOutput: a
// payload captured in rtk-ai/rtk issue 1425; VS Code's reference names only "<local-tool-name>"), and Cursor's
// beforeShellExecution (command) and preToolUse (tool_name Shell) — cursor.com/docs/hooks. Event names are compared
// without case: Cursor spells PreToolUse preToolUse.
func eventForm(f fields) (hookEvent, bool) {
	_, hasEvent := f["hook_event_name"]
	_, hasTool := f["tool_name"]
	if !hasEvent && !hasTool {
		return hookEvent{}, false
	}
	if hasEvent {
		event, ok := f.str("hook_event_name")
		switch {
		case !ok:
			return hookEvent{}, true
		case strings.EqualFold(event, "beforeShellExecution"):
			ev := hookEvent{known: true, shell: true}
			ev.command, ev.read = f.str("command")
			return ev, true
		case !strings.EqualFold(event, "PreToolUse"):
			return hookEvent{known: true}, true
		}
	}
	tool, ok := f.str("tool_name")
	if !ok {
		return hookEvent{}, true
	}
	ev := hookEvent{known: true}
	switch {
	case shellName(tool), tool == "exec_command": // command, else cmd (Codex's exec_command; RT-1 round 6: any shell)
		ev.shell = true
		if ev.command, ev.read = f.arg("tool_input", "command"); !ev.read {
			ev.command, ev.read = f.arg("tool_input", "cmd")
		}
	case tool == "run_in_terminal":
		ev.shell, ev.local = true, true
		ev.command, ev.read = f.arg("tool_input", "command")
	}
	return ev, true
}

// toolNameForm reads the Copilot harness's camelCase preToolUse: toolName bash or powershell, toolArgs a JSON string or
// an object with command (docs.github.com/en/copilot/reference/hooks-configuration types toolArgs as unknown; GitHub's
// github/awesome-copilot example: "toolArgs is a JSON string").
func toolNameForm(f fields) (hookEvent, bool) {
	if _, has := f["toolName"]; !has {
		return hookEvent{}, false
	}
	name, ok := f.str("toolName")
	if !ok {
		return hookEvent{}, true
	}
	ev := hookEvent{known: true, shell: shellName(name)}
	if ev.shell {
		ev.command, ev.read = f.arg("toolArgs", "command")
	}
	return ev, true
}

// toolCallForm reads Antigravity's PreToolUse: toolCall.name run_command, toolCall.args.CommandLine
// (antigravity.google/docs/hooks).
func toolCallForm(f fields) (hookEvent, bool) {
	if _, has := f[path("toolCall", "name")]; !has {
		return hookEvent{}, false
	}
	name, ok := f.str(path("toolCall", "name"))
	if !ok {
		return hookEvent{}, true
	}
	ev := hookEvent{known: true, shell: name == "run_command"}
	if ev.shell {
		ev.command, ev.read = f.arg(path("toolCall", "args"), "CommandLine")
	}
	return ev, true
}

func codexAnswer(w io.Writer, _ hookEvent, v verdict, reached bool) error {
	if !reached {
		return nil
	}
	switch v.Decision {
	case "deny":
		return writeJSONLine(w, map[string]any{"hookSpecificOutput": map[string]string{
			"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": v.reason()}})
	case "ask": // Codex parses ask but lets the call go on: a hold is a deny that says why
		return writeJSONLine(w, map[string]any{"hookSpecificOutput": map[string]string{
			"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": v.reason() + holdNote}})
	}
	return nil
}

func cursorAnswer(w io.Writer, _ hookEvent, v verdict, reached bool) error {
	if reached {
		switch v.Decision {
		case "deny":
			return writeJSONLine(w, map[string]string{"permission": "deny", "user_message": v.reason(), "agent_message": v.reason()})
		case "ask":
			return writeJSONLine(w, map[string]string{"permission": "deny", "user_message": v.reason() + holdNote, "agent_message": v.reason() + holdNote})
		}
	}
	return writeJSONLine(w, map[string]string{"permission": "allow"})
}

func copilotAnswer(w io.Writer, ev hookEvent, v verdict, reached bool) error {
	if !reached || (v.Decision != "deny" && v.Decision != "ask") {
		return nil
	}
	if ev.local { // VS Code's Local harness reads hookSpecificOutput
		return writeJSONLine(w, map[string]any{"hookSpecificOutput": map[string]string{
			"hookEventName": "PreToolUse", "permissionDecision": v.Decision, "permissionDecisionReason": v.reason()}})
	}
	return writeJSONLine(w, map[string]string{"permissionDecision": v.Decision, "permissionDecisionReason": v.reason()})
}

func antigravityAnswer(w io.Writer, _ hookEvent, v verdict, reached bool) error {
	if reached {
		switch v.Decision {
		case "deny":
			return writeJSONLine(w, map[string]string{"decision": "deny", "reason": v.reason()})
		case "ask": // ask "respects 'Always Allow' settings"; force_ask "ignores cached permissions" (Antigravity's docs)
			return writeJSONLine(w, map[string]string{"decision": "force_ask", "reason": v.reason()})
		}
	}
	return writeJSONLine(w, map[string]string{"decision": "allow"})
}

func writeJSONLine(w io.Writer, v any) error {
	b, _ := json.Marshal(v)
	_, err := w.Write(append(b, '\n'))
	return err
}

// askAlalanet sends only the command, in the shape of the plugin's HTTP hook, with the plan token if there is one, and
// reads the answer. reached is false when alalanet could not be reached or did not answer as the hook does. A command
// too large for the server, or a token that cannot be sent, is held here with the reason, without a request.
func askAlalanet(ctx context.Context, call hookCall, command, runtime string) (v verdict, reached bool) {
	body, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": map[string]string{"command": command}})
	switch {
	case len(body) > serverBodyCap:
		return notChecked("the command is too large for alalanet to read"), true // the server's own answer past its cap
	case call.tokenBad != "":
		return notChecked(call.tokenBad), true
	case call.token != "" && plainRemote(call.api):
		return notChecked("ALALANET_API is plain http to another machine, and the token is not sent there"), true
	}
	ctx, cancel := context.WithTimeout(ctx, hookDeadline)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(call.api, "/")+"/v1/hooks/claude-code", bytes.NewReader(body))
	if err != nil {
		return verdict{}, false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "alalanet-agent/"+version+" (hook "+runtime+")")
	if call.token != "" {
		req.Header.Set("Authorization", "Bearer "+call.token)
	}
	// The endpoint never redirects: a redirect is not followed, so the token never goes to another scheme or host (Go
	// keeps Authorization on a redirect to the same host or a subdomain, https to http included; RT-1 round 3).
	client := *call.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return verdict{}, false
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return verdict{}, false
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return verdict{}, true
	}
	var out struct {
		H struct {
			Decision string `json:"permissionDecision"`
			Reason   string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if json.Unmarshal(b, &out) != nil {
		return verdict{}, false
	}
	// The reason reaches the agent through the runtime: without hidden characters and bounded, as alalanet-agent
	// passes on any text from outside (agentkit.Shown). alalanet writes none and short ones; another API in
	// ALALANET_API writes what it likes (SEC9-AGENT, the re-review's R2-4).
	return verdict{Decision: out.H.Decision, Reason: agentkit.Shown(out.H.Reason, maxHookReason),
		dailyLimit: out.H.Decision == "ask" && resp.Header.Get("Alalanet-Not-Checked") == "daily-limit"}, true
}

// plainRemote: an address over plain http to another machine; a token is never sent there in the clear (this machine
// itself — a local test server — is fine).
func plainRemote(api string) bool {
	u, err := url.Parse(strings.TrimSpace(api))
	if err != nil || u.Scheme != "http" {
		return false
	}
	ip := net.ParseIP(u.Hostname())
	return !strings.EqualFold(u.Hostname(), "localhost") && (ip == nil || !ip.IsLoopback())
}

// hookToken reads the plan token: ALALANET_TOKEN, else the file ALALANET_TOKEN_FILE names (where an organisation's
// device management puts it). bad says why a configured token cannot be used; it never holds the token, the file's
// contents or its name.
func hookToken(getenv func(string) string, open func(string) (io.ReadCloser, error)) (token, bad string) {
	if t := strings.TrimSpace(getenv("ALALANET_TOKEN")); t != "" {
		return headerToken(t, "ALALANET_TOKEN")
	}
	name := getenv("ALALANET_TOKEN_FILE")
	if name == "" {
		return "", ""
	}
	const file = "the token file ALALANET_TOKEN_FILE names"
	r, err := open(name)
	if err != nil {
		return "", file + " could not be read"
	}
	defer r.Close()
	b, err := io.ReadAll(io.LimitReader(r, maxTokenFile+1))
	switch {
	case err != nil:
		return "", file + " could not be read"
	case len(b) > maxTokenFile:
		return "", file + " is larger than a token"
	}
	t, ok := tokenText(b)
	if !ok {
		return "", file + " is not text a token is written in"
	}
	if t = strings.TrimSpace(t); t == "" {
		return "", file + " is empty"
	}
	return headerToken(t, file)
}

// tokenText decodes a token file as the tools that write one do: UTF-8, with or without a byte-order mark, or UTF-16
// with one. Windows PowerShell 5.1's Out-File and ">" write UTF-16LE with a BOM and Set-Content -Encoding UTF8 UTF-8
// with a BOM (learn.microsoft.com, about_Character_Encoding for 5.1, read 2026-11-14; RT-1 round 3).
func tokenText(b []byte) (string, bool) {
	switch {
	case bytes.HasPrefix(b, []byte("\xef\xbb\xbf")):
		return string(b[3:]), true
	case bytes.HasPrefix(b, []byte{0xff, 0xfe}), bytes.HasPrefix(b, []byte{0xfe, 0xff}):
		if len(b)%2 != 0 {
			return "", false
		}
		u := make([]uint16, 0, len(b)/2-1)
		for i := 2; i < len(b); i += 2 {
			if b[0] == 0xff { // little-endian
				u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
			} else {
				u = append(u, uint16(b[i])<<8|uint16(b[i+1]))
			}
		}
		return string(utf16.Decode(u)), true
	}
	return string(b), true
}

// headerToken accepts a token an Authorization header can carry: visible ASCII, no spaces.
func headerToken(t, where string) (token, bad string) {
	for i := range len(t) {
		if t[i] < 0x21 || t[i] > 0x7e {
			return "", where + " holds a character an HTTP header cannot carry"
		}
	}
	return t, ""
}

// failClosed reads the organisation's policy ALALANET_FAIL_CLOSED: 1, true, yes or on hold an install alalanet could
// not check (unreachable, daily limit spent); anything else lets it go with a warning.
func failClosed(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
