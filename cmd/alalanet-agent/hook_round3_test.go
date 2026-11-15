package main

// ADR-0150, third round: what the hook does when alalanet did not check (its daily limit, unreachable) and under the
// organisation's fail-closed policy, the token file as Windows writes it, redirects, and the boundaries the round-2
// re-review's surviving mutants showed no test pinned (its mutants A04-A09; ADR-0150, third round).

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"
)

var runtimeInputs = map[string]func(command string) string{
	"codex":       func(c string) string { return codexInput("Bash", c) },
	"cursor":      cursorInput,
	"copilot":     func(c string) string { return copilotInput("bash", c) },
	"antigravity": func(c string) string { return antigravityInput("run_command", c) },
}

// answerForm reads a runtime's answer as one of "silent" (no opinion: the runtime's default policy), "hold" (the
// call stops until the user confirms, in the runtime's own form) or "deny".
func answerForm(t *testing.T, runtime, out string) string {
	t.Helper()
	if strings.TrimSpace(out) == "" {
		return "silent"
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("%s printed %q: %v", runtime, out, err)
	}
	str := func(o any, k string) string {
		s, _ := o.(map[string]any)[k].(string)
		return s
	}
	switch runtime {
	case "codex":
		if h, ok := m["hookSpecificOutput"].(map[string]any); ok && str(h, "permissionDecision") == "deny" {
			if strings.HasSuffix(str(h, "permissionDecisionReason"), holdNote) {
				return "hold"
			}
			return "deny"
		}
	case "cursor":
		switch str(m, "permission") {
		case "allow":
			return "silent"
		case "deny":
			if strings.HasSuffix(str(m, "agent_message"), holdNote) {
				return "hold"
			}
			return "deny"
		}
	case "copilot":
		switch str(m, "permissionDecision") {
		case "ask":
			return "hold"
		case "deny":
			return "deny"
		}
	case "antigravity":
		switch str(m, "decision") {
		case "allow":
			return "silent"
		case "force_ask":
			return "hold"
		case "deny":
			return "deny"
		}
	}
	t.Fatalf("%s printed %q", runtime, out)
	return ""
}

// The server's daily limit is a refusal, not a verdict (R2-P2-2): an ask it marks Alalanet-Not-Checked: daily-limit
// lets the install go with a line on stderr, in every runtime; the organisation's policy (failClosed) holds it instead.
// An unmarked ask, another mark, and a deny that carries the mark stay what they are.
func TestHookDailyLimitIsNotAVerdict(t *testing.T) {
	const limitWhy = "alalanet install_check: NOT CHECKED. npm:left-pad — alalanet's daily limit for this client is reached. Install only if the user confirms."
	for _, c := range []struct {
		name, decision, mark string
		failClosed           bool
		want, stderr         string
	}{
		{"the daily limit", "ask", "daily-limit", false, "silent", "alalanet's daily limit for this client is reached; the install goes ahead unchecked (ALALANET_FAIL_CLOSED=1 holds it instead)"},
		{"the daily limit, fail closed", "ask", "daily-limit", true, "hold", ""},
		{"a hold", "ask", "", false, "hold", ""},
		{"another mark", "ask", "something-else", false, "hold", ""},
		{"a deny with the mark", "deny", "daily-limit", false, "deny", ""},
	} {
		for runtime, input := range runtimeInputs {
			f := &fakeHook{answer: func(w http.ResponseWriter) {
				if c.mark != "" {
					w.Header().Set("Alalanet-Not-Checked", c.mark)
				}
				_, _ = w.Write([]byte(`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"` + c.decision + `","permissionDecisionReason":"` + limitWhy + `"}}`))
			}}
			srv := f.server(t)
			var out, stderr bytes.Buffer
			if err := runHookContext(t.Context(), runtime, strings.NewReader(input("npm i left-pad")), &out,
				hookCall{client: &http.Client{Timeout: 2 * time.Second}, api: srv.URL, stderr: &stderr, failClosed: c.failClosed}); err != nil {
				t.Fatal(err)
			}
			got := answerForm(t, runtime, out.String())
			if got != c.want || len(f.calls()) != 1 || (c.stderr == "") != (stderr.Len() == 0) || !strings.Contains(stderr.String(), c.stderr) {
				t.Errorf("%s in %s: %s (want %s), %d calls, stderr %q", c.name, runtime, got, c.want, len(f.calls()), stderr.String())
			}
			if got == "hold" && !strings.Contains(out.String(), "daily limit") {
				t.Errorf("%s in %s: the hold does not say why: %q", c.name, runtime, out.String())
			}
		}
	}
}

// alalanet unreachable — no answer, an error status, a redirect — lets the install go with a line on stderr, as Claude
// Code goes on when its HTTP hook fails; under the organisation's policy it is held, in the runtime's form, saying so.
func TestHookUnreachableUnderEitherPolicy(t *testing.T) {
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadGateway) }))
	defer broken.Close()
	moved := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/v1/hooks/claude-code", http.StatusTemporaryRedirect)
	}))
	defer moved.Close()
	for _, api := range []string{"http://127.0.0.1:1", broken.URL, moved.URL} {
		for runtime, input := range runtimeInputs {
			for _, closed := range []bool{false, true} {
				var out, stderr bytes.Buffer
				if err := runHookContext(t.Context(), runtime, strings.NewReader(input("npm i left-pad")), &out,
					hookCall{client: &http.Client{Timeout: 2 * time.Second}, api: api, stderr: &stderr, failClosed: closed}); err != nil {
					t.Fatal(err)
				}
				want, says := "silent", "alalanet could not be reached; the install goes ahead unchecked"
				if closed {
					want, says = "hold", "alalanet could not be reached; nothing was checked, the call is held"
				}
				if got := answerForm(t, runtime, out.String()); got != want || !strings.Contains(stderr.String(), says) ||
					closed && !strings.Contains(out.String(), "NOT CHECKED — alalanet could not be reached") {
					t.Errorf("%s in %s, fail closed %v: %s (want %s), printed %q, stderr %q", api, runtime, closed, got, want, out.String(), stderr.String())
				}
			}
		}
	}
	for v, want := range map[string]bool{"1": true, "true": true, " YES ": true, "on": true, "": false, "0": false, "false": false, "no": false, "off": false, "2": false} {
		if failClosed(v) != want {
			t.Errorf("failClosed(%q) = %v", v, !want)
		}
	}
}

// Through main, as a runtime starts it: ALALANET_FAIL_CLOSED=1 holds an install when alalanet cannot be reached; without
// it the install goes ahead (Codex: no answer) with the warning on stderr.
func TestHookFailClosedThroughMain(t *testing.T) {
	for _, c := range []struct {
		env        []string
		hold, warn string
	}{
		{[]string{"ALALANET_FAIL_CLOSED=1"}, "NOT CHECKED — alalanet could not be reached", "nothing was checked, the call is held"},
		{nil, "", "the install goes ahead unchecked"},
	} {
		cmd := exec.Command(os.Args[0], "-test.run=^$") // without the TestMain the child runs no test (never a fork chain)
		cmd.Env = append(append(withoutToken(withoutFailClosed(os.Environ())), "ZZ_REVIEW_RT1_MAIN=1", "ALALANET_API=http://127.0.0.1:1"), c.env...)
		cmd.Stdin = strings.NewReader(codexInput("Bash", "npm install left-pad"))
		var out, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("%v: %v %s", c.env, err, stderr.String())
		}
		if (c.hold == "") != (out.Len() == 0) || !strings.Contains(out.String(), c.hold) || !strings.Contains(stderr.String(), c.warn) {
			t.Errorf("%v: printed %q, stderr %q", c.env, out.String(), stderr.String())
		}
	}
}

// withoutToken: the environment without a plan token or another API (moved here from hook_round2_test.go so the
// public repository's test set builds without internal/app).
func withoutToken(env []string) []string {
	var out []string
	for _, e := range env {
		if !strings.HasPrefix(e, "ALALANET_TOKEN") && !strings.HasPrefix(e, "ALALANET_API=") {
			out = append(out, e)
		}
	}
	return out
}

func withoutFailClosed(env []string) []string {
	var out []string
	for _, e := range env {
		if !strings.HasPrefix(e, "ALALANET_FAIL_CLOSED=") {
			out = append(out, e)
		}
	}
	return out
}

// A redirect from the API is never followed, with a token or without: nothing — the command, the token — reaches the
// address it points to, on this host or another (the endpoint never redirects; RT-1 round 3).
func TestHookRedirectIsNotFollowed(t *testing.T) {
	const tok = "aln_SECRETMARKER0123"
	var mu sync.Mutex
	var elsewhere []string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		elsewhere = append(elsewhere, r.Header.Get("Authorization")+" "+string(b))
		mu.Unlock()
	}))
	defer other.Close()
	asked := 0
	for _, code := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		for _, target := range []string{other.URL, strings.Replace(other.URL, "127.0.0.1", "localhost", 1)} {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				asked++
				mu.Unlock()
				http.Redirect(w, r, target+r.URL.Path, code)
			}))
			for _, token := range []string{"", tok} {
				var out, stderr bytes.Buffer
				if err := runHookContext(t.Context(), "codex", strings.NewReader(codexInput("Bash", "npm i left-pad")), &out,
					hookCall{client: &http.Client{Timeout: 2 * time.Second}, api: api.URL, token: token, stderr: &stderr}); err != nil {
					t.Fatal(err)
				}
				if out.Len() != 0 || !strings.Contains(stderr.String(), "could not be reached") || strings.Contains(out.String()+stderr.String(), "SECRETMARKER") {
					t.Errorf("%d to %s: printed %q, stderr %q", code, target, out.String(), stderr.String())
				}
			}
			api.Close()
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(elsewhere) != 0 || asked != 16 {
		t.Fatalf("the API was asked %d times (want 16); the redirect's target got %d requests: %.200q", asked, len(elsewhere), elsewhere)
	}
}

// A token file as the tools that write one leave it: UTF-8 with or without a byte-order mark, UTF-16 little- or
// big-endian with one (Windows PowerShell 5.1's Out-File and ">"), with CRLF. Text that is not one — UTF-16 cut in the
// middle of a character, UTF-16 without a mark, a character outside ASCII — is a reason that never names the token.
func TestHookTokenFileEncodings(t *testing.T) {
	const tok = "aln_SECRETMARKER0123"
	le := func(s string, bom bool) string {
		var b []byte
		if bom {
			b = []byte{0xff, 0xfe}
		}
		for _, u := range utf16.Encode([]rune(s)) {
			b = append(b, byte(u), byte(u>>8))
		}
		return string(b)
	}
	be := func(s string) string {
		b := []byte{0xfe, 0xff}
		for _, u := range utf16.Encode([]rune(s)) {
			b = append(b, byte(u>>8), byte(u))
		}
		return string(b)
	}
	for name, c := range map[string]struct{ content, token, bad string }{
		"UTF-8":                            {tok + "\n", tok, ""},
		"UTF-8 with a mark and CRLF":       {"\xef\xbb\xbf" + tok + "\r\n", tok, ""},
		"UTF-16LE with a mark":             {le(tok, true), tok, ""},
		"UTF-16LE with a mark and CRLF":    {le(tok+"\r\n", true), tok, ""},
		"UTF-16BE with a mark and CRLF":    {be(tok + "\r\n"), tok, ""},
		"UTF-16LE cut in a character":      {le(tok, true)[:7], "", "is not text a token is written in"},
		"UTF-16BE cut in a character":      {be(tok)[:9], "", "is not text a token is written in"},
		"UTF-16LE without a mark":          {le(tok, false), "", "an HTTP header cannot carry"},
		"UTF-16LE with a character beyond": {le(tok+"é", true), "", "an HTTP header cannot carry"},
		"only a mark":                      {le("", true), "", "is empty"},
		"a UTF-8 mark and spaces":          {"\xef\xbb\xbf \r\n", "", "is empty"},
	} {
		token, bad := hookToken(func(k string) string {
			if k == "ALALANET_TOKEN_FILE" {
				return `C:\ProgramData\alalanet\token`
			}
			return ""
		}, func(string) (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(c.content)), nil })
		if token != c.token || (c.bad == "") != (bad == "") || !strings.Contains(bad, c.bad) || strings.Contains(bad, "SECRETMARKER") || strings.Contains(bad, "ProgramData") {
			t.Errorf("%s: token %q, bad %q", name, strings.Replace(token, tok, "<token>", 1), bad)
		}
	}
}

// The server's cap is on the request's body, not on the command (A04): a command under 1 MiB whose JSON is over it (JSON
// writes < as \u003c) is held here without a request; a body of exactly the cap is sent, a byte more is held (A05).
func TestHookCapIsMeasuredOnTheBody(t *testing.T) {
	f := &fakeHook{}
	srv := f.server(t)
	body := func(command string) int {
		b, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": map[string]string{"command": command}})
		return len(b)
	}
	angles := "npm i left-pad && echo '" + strings.Repeat("<", 200<<10) + "'"
	if len(angles) >= serverBodyCap || body(angles) <= serverBodyCap {
		t.Fatalf("the command is %d bytes, its body %d: want under and over %d", len(angles), body(angles), serverBodyCap)
	}
	if out := runCodex(t, srv.URL, codexInput("Bash", angles)); len(f.calls()) != 0 || !strings.Contains(out, "too large for alalanet to read") {
		t.Fatalf("a body over the cap: %d calls, printed %.200q", len(f.calls()), out)
	}
	exact := "npm i left-pad && echo "
	exact += strings.Repeat("a", serverBodyCap-body(exact))
	if body(exact) != serverBodyCap {
		t.Fatalf("body %d", body(exact))
	}
	if out := runCodex(t, srv.URL, codexInput("Bash", exact)); len(f.calls()) != 1 || out != "" {
		t.Fatalf("a body of exactly the cap: %d calls, printed %.200q", len(f.calls()), out)
	}
	if out := runCodex(t, srv.URL, codexInput("Bash", exact+"a")); len(f.calls()) != 1 || !strings.Contains(out, "too large for alalanet to read") {
		t.Fatalf("a byte over the cap: %d calls, printed %.200q", len(f.calls()), out)
	}
}

// Only each runtime's shell tool is read (A06, A07): Antigravity's other tools whose names contain "command"
// (command_status, send_command_input) and VS Code's other Local tools (get_terminal_output, read_file) are no opinion,
// with nothing sent, whatever their arguments say.
func TestHookOnlyTheShellToolIsRead(t *testing.T) {
	f := &fakeHook{answer: func(w http.ResponseWriter) {
		_, _ = w.Write([]byte(`{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"alalanet install_check: BLOCK — x"}}`))
	}}
	srv := f.server(t)
	for _, tool := range []string{"command_status", "send_command_input", "run_command_x", "Run_command"} {
		if out := runRuntime(t, "antigravity", srv.URL, antigravityInput(tool, "npm i left-pad")); answerForm(t, "antigravity", out) != "silent" || len(f.calls()) != 0 {
			t.Errorf("Antigravity %s: printed %q, %d calls", tool, out, len(f.calls()))
		}
	}
	for _, tool := range []string{"get_terminal_output", "read_file", "run_in_terminal_x", "terminal_last_command"} {
		in, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "tool_name": tool, "session_id": "s-1",
			"tool_input": map[string]any{"command": "npm i left-pad", "id": "t-1"}})
		if out := runRuntime(t, "copilot", srv.URL, string(in)); out != "" || len(f.calls()) != 0 {
			t.Errorf("VS Code Local %s: printed %q, %d calls", tool, out, len(f.calls()))
		}
	}
	if out := runRuntime(t, "antigravity", srv.URL, antigravityInput("run_command", "npm i left-pad")); answerForm(t, "antigravity", out) != "deny" || len(f.calls()) != 1 {
		t.Fatalf("the shell tool itself: printed %q, %d calls", out, len(f.calls()))
	}
}

// A deny or a hold the server sends without words still says which it is (A09): a deny BLOCK, a hold HOLD.
func TestHookFallbackReasonSaysWhichAnswer(t *testing.T) {
	for decision, c := range map[string]struct{ says, never string }{"deny": {"BLOCK", "HOLD"}, "ask": {"HOLD", "BLOCK"}} {
		if r := (verdict{Decision: decision}).reason(); !strings.Contains(r, c.says) || strings.Contains(r, c.never) {
			t.Errorf("%s without a reason: %q", decision, r)
		}
		f := &fakeHook{answer: func(w http.ResponseWriter) {
			_, _ = w.Write([]byte(`{"hookSpecificOutput":{"permissionDecision":"` + decision + `","permissionDecisionReason":"  "}}`))
		}}
		srv := f.server(t)
		for runtime, input := range runtimeInputs {
			if out := runRuntime(t, runtime, srv.URL, input("npm i left-pad")); !strings.Contains(out, c.says) || strings.Contains(out, c.never) {
				t.Errorf("%s in %s: %q", decision, runtime, out)
			}
		}
	}
	if r := (verdict{Decision: "deny", Reason: "alalanet install_check: BLOCK. npm:x — known_malicious"}).reason(); r != "alalanet install_check: BLOCK. npm:x — known_malicious" {
		t.Errorf("a reason given: %q", r)
	}
}
