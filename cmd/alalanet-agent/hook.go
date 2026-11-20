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
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/alalanet/alalanet-agent/agentkit"
	"github.com/alalanet/alalanet-agent/internal/installread"
	"github.com/alalanet/alalanet-agent/internal/mcpverify"
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
// stay silent, and the line (a commit message, a header with a token) would leave the machine for no check. A line it
// holds only for its own shell, naming no package (installread.OwnShellAsk), is answered on the machine and not sent
// either (ADR-0159 round 39).
func isInstall(line string) bool {
	targets, unread, _, subst := installread.ParseLine(line)
	return len(targets) > 0 || len(unread) > 0 || len(installread.HookExtra(line, targets, unread, subst)) > 0
}

// verdict is alalanet's answer in the plugin's form: deny, ask or nothing. dailyLimit: an ask the server marks as only
// a limit of its own — the daily limit (Alalanet-Not-Checked: daily-limit) or the address's request rate (rate, M-6
// round 2) — a refusal, not a verdict; limit says which.
type verdict struct {
	Decision, Reason string
	dailyLimit       bool
	limit            string
	warn             string // a line for the user with no hold (an MCP server's tools differ in a way honest servers show)
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
	// An MCP tool's call (VERIFY-AUTO-1): Claude Code's PreToolUse of an mcp__ tool, Cursor's beforeMCPExecution. Its
	// arguments are never read.
	mcp       bool
	mcpTool   string // Claude Code's tool name, mcp__<server>__<tool>
	mcpServer string // the server's configured name (Claude Code's mcp_server.name, Cursor's mcp_server_name)
	mcpSource string // Claude Code's mcp_server.source: user, local, project, plugin, claudeai ...
	mcpURL    string // Cursor's mcp_server_url (or url): the configured URL, which never leaves the machine
	mcpStdio  bool   // Cursor's command: a server that runs on this machine
	// mcpForm: how the tool's name names its server: "" (mcp__<server>__<tool>), "slash" (the Copilot harness's
	// <server>/<tool>), "underscore" (Antigravity's eager mcp_<server>_<tool>), "named" (Antigravity's call_mcp_tool,
	// whose ServerName names it)
	mcpForm    string
	workspaces []string // Cursor's workspace_roots, Antigravity's workspacePaths: where the runtime keeps its copy
	session    string   // kept hashed in the local state, never sent
	cwd        string   // where the runtime says the agent works ("" when it does not): the workspace whose policy applies, and where Claude Code's local and project configuration is looked for; never sent
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
	"claude-code": {claudeAnswer},
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

// hookBlock: hook codex's deny — a block, or a hold, which Codex can only answer as a deny — which alalanet-agent also
// gives as exit code 2 with the reason alone on stderr. Codex starts a hook as $SHELL -lc '<command>': whatever the
// user's login profile prints lands on stdout before the JSON answer, Codex cannot parse that stdout and lets the call
// go on, as if the hook had said nothing. On exit 2 Codex blocks with stderr as the reason and does not read stdout
// (codex-rs hooks events/pre_tool_use.rs), so the deny holds whatever the profile prints (HOOK-CODEX-EXIT2, ADR-0150
// round 7). The JSON answer stays on stdout too; the hook's diagnostics are held back (runHookMain).
type hookBlock struct{ reason string }

func (e hookBlock) Error() string { return e.reason }

// hookUsage names the runtimes and the event each runs the hook on (RT-1 round 5).
const hookUsage = "hook claude-code|codex|cursor|copilot|antigravity, run as the runtime's pre-tool command hook on: " +
	"claude-code PreToolUse (matcher mcp__.* for MCP tools, Bash for installs); codex PreToolUse (MCP tools too); " +
	"cursor beforeShellExecution and preToolUse (matcher Shell), in .cursor/hooks.json, and beforeMCPExecution for MCP tools; " +
	"copilot preToolUse (or its PreToolUse alias; MCP tools too); antigravity PreToolUse (tool run_command, and call_mcp_tool or mcp_* for MCP tools)"

const holdNote = " — this agent runtime cannot pause for the user here: confirm with the user before installing; if they agree, they can run it themselves."

// mcpHoldNote is holdNote for an MCP server's tools: the user accepts the set in their own terminal (mcp-approve asks
// there and nowhere else).
const mcpHoldNote = " — this agent runtime cannot pause for the user here: confirm with the user before using this server's tools; the user can accept this tool set in their own terminal with alalanet-agent mcp-approve and the server's name."

// mcpApproveHold: accepting an MCP server's tool set is the user's step in their own terminal; a call of mcp-approve
// through the agent's shell is held whatever else the line holds (a description that tells the model to run it must
// not work).
const mcpApproveHold = "alalanet-agent: HOLD — accepting an MCP server's tool set (mcp-approve) is the user's own step in their own terminal, not the agent's. Run it only if the user asks for it."

// approvesMCP: the line may run alalanet-agent's approval, as far as a reading of the line can tell (review F7, N2):
// with its quotes and backslashes removed it names mcp-approve; or it names alalanet-agent and either "approve" right
// after mcp (mcp-approve with a variable, a substitution or nothing between), a word mcp-... the shell completes from a
// variable or a substitution, or a program that gives alalanet-agent a terminal of its own (script, expect, unbuffer,
// a Python pty). A line that merely mentions mcp-approve (a grep of the README) is held too: a hold, which the user
// lifts; lines about alalanet that do not name alalanet-agent this way stay plain. This is defence in depth against
// a model that is not trying to get past it; a model that is (a decoded string, a script file written first) is not
// stopped by any reading of one line, nor by mcp-approve's terminal and code (ADR-0181, rounds 2 and 3).
func approvesMCP(line string) bool {
	norm := strings.NewReplacer(`"`, "", `'`, "", `\`, "").Replace(strings.ToLower(line))
	if strings.Contains(norm, "mcp-approve") {
		return true
	}
	if !strings.Contains(norm, "alalanet-agent") {
		return false
	}
	return approveWord.MatchString(norm) || computedSubcommand.MatchString(norm) || ptyRunner.MatchString(norm)
}

var (
	// approveWord: approve right after mcp, with nothing but what a shell expands between (mcp-${x}approve).
	approveWord = regexp.MustCompile("mcp-?[a-z0-9_$`{}()]*approve")
	// computedSubcommand: a word mcp-... that the shell completes ($X, ${X}, $(...), backticks).
	computedSubcommand = regexp.MustCompile("(^|[^a-z0-9_-])mcp-[a-z0-9_-]*(\\$|`)")
	// ptyRunner: a program that runs another under a terminal of its own.
	ptyRunner = regexp.MustCompile(`(^|[^a-z0-9_.-])(script|expect|unbuffer|pexpect|ptyprocess|pty)([^a-z0-9_-]|$)`)
)

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
	mcp        *mcpverify.Verifier // the MCP side (VERIFY-AUTO-1); nil: MCP calls get no opinion
	home       string              // where the runtimes' configuration files are
	// claudeConfig: Claude Code's configuration file (mcpverify.ClaudeConfigFile: CLAUDE_CONFIG_DIR); "" for
	// ~/.claude.json.
	claudeConfig string
	codexHome    string // Codex's folder (mcpverify.CodexHome: CODEX_HOME); "" for ~/.codex
	// policy: where the organisation's policy and the workspace's .alalanet.yml are read (REPO-POL-1 round 2), applied
	// to alalanet's answer here and never sent; nil reads none.
	policy *policyFiles
	// getenv: the environment pip expands ${NAME} in a requirements file from (READER-REQFILE-1); nil expands none.
	getenv func(string) string
	// device: where the hook's free device key comes from (devicekey.go), sent when no plan token is; nil sends none.
	device *deviceKeySource
}

func hookClient() *http.Client { return &http.Client{Timeout: hookDeadline} }

// runHook handles one hook call of runtime without a token or a signal (the tests' entry).
func runHook(runtime string, stdin io.Reader, stdout io.Writer, client *http.Client, api string) error {
	return runHookContext(context.Background(), runtime, stdin, stdout, hookCall{client: client, api: api})
}

// runHookContext is answerHook with hook codex's deny as its printed answer alone and the diagnostics as they come (the
// tests' entry for the answers; the exit code and the stderr of that deny are runHookMain's and main's, tested through
// main).
func runHookContext(ctx context.Context, runtime string, stdin io.Reader, stdout io.Writer, call hookCall) error {
	if err := answerHook(ctx, runtime, stdin, stdout, call); !errors.As(err, new(hookBlock)) {
		return err
	}
	return nil
}

// runHookMain is main's hook call. Under hook codex the diagnostics wait: Codex takes all of stderr on exit 2 as the
// block's reason, which the model reads, and a diagnostic can quote text from outside (a repository's .alalanet.yml
// that does not parse). So on a block stderr carries the reason alone — the JSON answer's reason, which mainExit prints
// — and the diagnostics are dropped; without a block they follow on stderr, as before (ADR-0150 round 7, R7-P3-1).
func runHookMain(ctx context.Context, runtime string, stdin io.Reader, stdout io.Writer, call hookCall) error {
	if strings.ToLower(strings.TrimSpace(runtime)) != "codex" || call.stderr == nil {
		return answerHook(ctx, runtime, stdin, stdout, call)
	}
	stderr := call.stderr
	var diagnostics bytes.Buffer
	call.stderr = &diagnostics
	err := answerHook(ctx, runtime, stdin, stdout, call)
	if !errors.As(err, new(hookBlock)) {
		_, _ = stderr.Write(diagnostics.Bytes())
	}
	return err
}

// answerHook handles one hook call of runtime; ctx ends it early (SIGTERM, SIGINT). An error is returned only for an
// unknown runtime (hookUsageError), a failed write of the answer, and hook codex's deny (hookBlock, after its JSON
// answer); everything else ends with the runtime's answer.
func answerHook(ctx context.Context, runtime string, stdin io.Reader, stdout io.Writer, call hookCall) error {
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
	case ev.mcp:
		return mcpHook(ctx, runtime, rt, stdout, ev, call)
	case !ev.shell:
		return rt.answer(stdout, ev, verdict{}, true)
	case !ev.read:
		say("the shell call's command could not be read")
		return rt.answer(stdout, ev, notChecked("alalanet-agent could not read the command"), true)
	case approvesMCP(ev.command):
		return rt.answer(stdout, ev, verdict{Decision: "ask", Reason: mcpApproveHold}, true)
	case approvesPolicy(ev.command):
		return rt.answer(stdout, ev, verdict{Decision: "ask", Reason: policyApproveHold}, true)
	case touchesPin(ev.command):
		return rt.answer(stdout, ev, verdict{Decision: "ask", Reason: pinPathHold}, true)
	}
	// the requirements files the line names, and the files a line that installs sources (round 20), read here
	// (READER-REQFILE-1): a file that moves the index, or a sourced file that is no known activate script, holds the line,
	// whatever alalanet says of the packages it names, unless alalanet blocks them. Only "does the line name one" is read
	// outside the policy files' deadline (round 15): the folders and the files are read under it, and past it the line
	// holds — a stalled folder or a line built to cost does not let it through.
	local := ""
	if len(in.ev.command) > installread.MaxLineBytes {
		// round 23: a line past the readers' cap is read by none of them, here or on the server (whose hook takes 1 MiB)
		local = fmt.Sprintf("the line is %d KiB, longer than alalanet-agent reads (%d KiB)", len(in.ev.command)>>10, installread.MaxLineBytes>>10)
	} else if len(installread.RequirementFiles(in.ev.command)) > 0 || len(installread.SourcedFiles(in.ev.command)) > 0 {
		var inTime bool
		if local, inTime = within(policyDeadline, func() string { return reqFileHold(in.ev.cwd, call.home, in.ev.command, call.getenv) }); !inTime {
			local = "its requirements files or sourced files were not read in time"
		}
	}
	if !isInstall(in.ev.command) {
		if local != "" {
			return rt.answer(stdout, in.ev, reqFileVerdict(verdict{}, local), true)
		}
		return rt.answer(stdout, in.ev, verdict{}, true)
	}
	// withPolicy applies the organisation's policy and the workspace's .alalanet.yml to alalanet's answer (ADR-0174)
	// and says their notes on stderr.
	withPolicy := func(v verdict) verdict {
		var notes []string
		v, notes = loadPolicy(call.policy, in.ev.cwd).applyNotes(v, in.ev.command, time.Now())
		if call.stderr != nil {
			for _, n := range notes {
				fmt.Fprintf(call.stderr, "alalanet-agent hook %s: %s\n", runtime, n)
			}
		}
		return v
	}
	if why, ok := installread.OwnShellAsk(in.ev.command); ok {
		// held only for its own shell (a zsh group on a word) and naming no package: the server's own ask, given here,
		// and the line, which alalanet would check nothing in, is not sent (ADR-0159 round 39). The policy is applied to
		// it as to the server's answer, so an on_hold deny denies it (batch P3 review 5, R-1).
		v := verdict{Decision: "ask", Reason: why}
		if call.policy != nil {
			v = withPolicy(v)
		}
		if local != "" && v.Decision != "deny" {
			v = reqFileVerdict(v, local)
		}
		return rt.answer(stdout, in.ev, v, true)
	}
	if targets, _, _, _ := installread.ParseLine(in.ev.command); call.policy != nil {
		// a Go module the user's own settings fetch from elsewhere: its path is not sent (ECO-1 Go, round 3, P3-5)
		if where, ok := within(policyDeadline, func() string { return goPrivateHere(call.policy, in.ev.cwd, targets) }); !ok || where != "" {
			if !ok {
				where = "the user's Go settings, which could not be read in time"
			}
			v := verdict{Decision: "ask", Reason: "alalanet-agent: " + where + " fetches the Go module from somewhere other than the public Go proxy, so the line was not sent to alalanet to check; install only if the user confirms."}
			// the policy applies to this ask as to alalanet's own (round 4, P3-6; as OwnShellAsk's, batch P3 review 5)
			v = withPolicy(v)
			if local != "" && v.Decision != "deny" {
				v = reqFileVerdict(v, local)
			}
			return rt.answer(stdout, in.ev, v, true)
		}
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
		if v.limit == "rate" {
			goesAhead("alalanet's request rate for this address is reached")
		} else {
			goesAhead("alalanet's daily limit for this client is reached")
		}
		v = verdict{} // the local files' hold below still applies (READER-REQFILE-1)
		reached = true
	case call.policy != nil && !v.dailyLimit && v.Decision != "deny":
		// The policy is applied to alalanet's own answer only, here (ADR-0174): not to an install that went unchecked,
		// and not to a block, which nothing relaxes — a block is answered before any policy file is read (round 4, S1).
		v = withPolicy(v)
	}
	if local != "" && v.Decision != "deny" && ctx.Err() == nil {
		v, reached = reqFileVerdict(v, local), true
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
	f, err := readFields(br, append(slices.Clone(hookPaths), "cwd", path("toolCall", "args", "Cwd")))
	ev = shellCall(f)
	if ev.shell {
		// the directory the call runs in (Codex, Cursor and the Copilot harness: cwd; Antigravity: the tool's Cwd)
		if ev.cwd, _ = f.str("cwd"); ev.cwd == "" {
			ev.cwd, _ = f.arg(path("toolCall", "args"), "Cwd")
		}
	}
	return ev, cr.over, err
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
	"session_id", "cwd", "conversation_id", path("mcp_server", "name"), path("mcp_server", "source"), "mcp_server_name", "mcp_server_url", "url",
	"sessionId", "conversationId", "workspace_roots", "workspacePaths", path("toolCall", "args", "ServerName"), path("toolCall", "args", "ToolName"),
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
	var mcp *hookEvent
	unknown, other := false, false
	for _, form := range []func(fields) (hookEvent, bool){eventForm, toolNameForm, toolCallForm} {
		ev, present := form(f)
		switch {
		case !present:
		case !ev.known:
			unknown = true
		case ev.shell:
			shell = append(shell, ev)
		case ev.mcp:
			mcp = &ev
			other = true
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
	case mcp != nil:
		return *mcp
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
		case strings.EqualFold(event, "beforeMCPExecution"): // Cursor: the server's URL or its command, never the arguments read
			ev := hookEvent{known: true, mcp: true}
			ev.mcpServer, _ = f.str("mcp_server_name")
			if ev.mcpURL, _ = f.str("mcp_server_url"); ev.mcpURL == "" {
				ev.mcpURL, _ = f.str("url")
			}
			_, ev.mcpStdio = f["command"]
			ev.session, _ = f.str("conversation_id")
			ev.workspaces = f.strs("workspace_roots")
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
	case strings.HasPrefix(tool, "mcp__"): // Claude Code's (and Codex's) MCP tools
		ev.mcp, ev.mcpTool = true, tool
		ev.mcpServer, _ = f.str(path("mcp_server", "name"))
		ev.mcpSource, _ = f.str(path("mcp_server", "source"))
		if ev.session, _ = f.str("session_id"); ev.session == "" {
			ev.session, _ = f.str("sessionId")
		}
		ev.cwd, _ = f.str("cwd")
	}
	return ev, true
}

// strs is a member that is an array of strings (the others in it left out).
func (f fields) strs(p string) []string {
	v, ok := f[p]
	if !ok {
		return nil
	}
	var raw []json.RawMessage
	if json.Unmarshal(v, &raw) != nil {
		return nil
	}
	var out []string
	for _, r := range raw {
		var s string
		if json.Unmarshal(r, &s) == nil {
			out = append(out, s)
		}
	}
	return out
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
	switch {
	case ev.shell:
		ev.command, ev.read = f.arg("toolArgs", "command")
	case strings.Contains(name, "/"): // an MCP tool as <server>/<tool> (a third-party source; a device check)
		ev.mcp, ev.mcpTool, ev.mcpForm = true, name, "slash"
		ev.session, _ = f.str("sessionId")
		ev.cwd, _ = f.str("cwd")
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
	switch {
	case ev.shell:
		ev.command, ev.read = f.arg(path("toolCall", "args"), "CommandLine")
	case name == "call_mcp_tool", strings.HasPrefix(name, "mcp_"): // lazy (ServerName, ToolName) or eager MCP tools
		ev.mcp, ev.mcpTool, ev.mcpForm = true, name, "underscore"
		if name == "call_mcp_tool" {
			ev.mcpForm = "named"
			ev.mcpServer, _ = f.arg(path("toolCall", "args"), "ServerName")
			ev.mcpTool, _ = f.arg(path("toolCall", "args"), "ToolName")
		}
		ev.session, _ = f.str("conversationId")
		if ev.workspaces = f.strs("workspacePaths"); len(ev.workspaces) > 0 {
			ev.cwd = ev.workspaces[0]
		}
	}
	return ev, true
}

func codexAnswer(w io.Writer, ev hookEvent, v verdict, reached bool) error {
	if !reached {
		return nil
	}
	note := holdNote
	if ev.mcp {
		note = mcpHoldNote
	}
	switch v.Decision {
	case "deny":
		return codexDeny(w, v.reason())
	case "ask": // Codex parses ask but lets the call go on: a hold is a deny that says why
		return codexDeny(w, v.reason()+note)
	}
	return nil
}

// codexDeny prints Codex's deny and ends the hook with exit 2 and the reason on stderr (hookBlock); a stdout that cannot
// be written does not lose the block.
func codexDeny(w io.Writer, reason string) error {
	_ = writeJSONLine(w, map[string]any{"hookSpecificOutput": map[string]string{
		"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason}})
	return hookBlock{reason}
}

func cursorAnswer(w io.Writer, ev hookEvent, v verdict, reached bool) error {
	note := holdNote
	if ev.mcp {
		note = mcpHoldNote
	}
	if reached {
		switch v.Decision {
		case "deny":
			return writeJSONLine(w, map[string]string{"permission": "deny", "user_message": v.reason(), "agent_message": v.reason()})
		case "ask":
			return writeJSONLine(w, map[string]string{"permission": "deny", "user_message": v.reason() + note, "agent_message": v.reason() + note})
		}
	}
	if v.warn != "" { // for the user; the agent is not told
		return writeJSONLine(w, map[string]string{"permission": "allow", "user_message": v.warn})
	}
	return writeJSONLine(w, map[string]string{"permission": "allow"})
}

// claudeAnswer is Claude Code's PreToolUse answer: deny and ask as they are (Claude Code asks the user itself); a warning
// is a systemMessage, shown to the user; no opinion is silence.
func claudeAnswer(w io.Writer, _ hookEvent, v verdict, reached bool) error {
	if reached && (v.Decision == "deny" || v.Decision == "ask") {
		return writeJSONLine(w, map[string]any{"hookSpecificOutput": map[string]string{
			"hookEventName": "PreToolUse", "permissionDecision": v.Decision, "permissionDecisionReason": v.reason()}})
	}
	if v.warn != "" {
		return writeJSONLine(w, map[string]string{"systemMessage": v.warn})
	}
	return nil
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
	} else if k := call.device.key(ctx); k != "" {
		req.Header.Set(deviceKeyHeader, k) // the hook's 1,000 checks a day without a plan (QUOTA-ONE-BUCKET-1)
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
		dailyLimit: out.H.Decision == "ask" && notCheckedMarks[resp.Header.Get("Alalanet-Not-Checked")],
		limit:      resp.Header.Get("Alalanet-Not-Checked")}, true
}

// notCheckedMarks are the server's marks of an ask that is only a limit of its own: the daily limit, and the request
// rate of the address (M-6 round 2: the hook answers its rate's refusal 200 "ask", never 429).
var notCheckedMarks = map[string]bool{"daily-limit": true, "rate": true}

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
