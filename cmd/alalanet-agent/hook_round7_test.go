package main

// ADR-0150, seventh round (HOOK-CODEX-EXIT2, the agent-plugin review's P3-2): Codex starts a hook as $SHELL -lc
// '<command>', so whatever the user's login profile prints lands on stdout before alalanet-agent's JSON answer. Codex
// cannot parse that stdout, ignores it and lets the call go on: a deny was lost without a word. Codex blocks a call
// when a PreToolUse hook exits 2 with the reason on stderr, whatever stdout holds (codex-rs hooks
// events/pre_tool_use.rs at 5cb38e7). So hook codex answers every deny — a block, and a hold, which Codex can only
// answer as a deny — also with exit code 2 and the reason on stderr. No opinion stays silent with exit 0, and the other
// runtimes' answers do not change.

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// codexReads is what Codex makes of a PreToolUse hook's run (events/pre_tool_use.rs, parse_completed): exit 0 with
// stdout that parses as its JSON answer and denies → blocked with that reason; exit 0 with stdout it cannot parse →
// not blocked (only stdout that looks like JSON is even reported as an error); exit 2 with a non-empty stderr →
// blocked with stderr as the reason; any other exit → the hook failed, the call goes on.
func codexReads(exit int, stdout, stderr string) (blocked bool, reason string) {
	switch exit {
	case 0:
		var m struct {
			H struct {
				Decision string `json:"permissionDecision"`
				Reason   string `json:"permissionDecisionReason"`
			} `json:"hookSpecificOutput"`
		}
		if s := strings.TrimSpace(stdout); s == "" || json.Unmarshal([]byte(s), &m) != nil {
			return false, ""
		}
		return m.H.Decision == "deny" && strings.TrimSpace(m.H.Reason) != "", m.H.Reason
	case 2:
		r := strings.TrimSpace(stderr)
		return r != "", r
	}
	return false, ""
}

const profileLine = "Welcome back"

// loginHome is a home folder whose login profiles print a line, as the review's .zprofile did.
func loginHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	for _, f := range []string{".profile", ".bash_profile", ".zprofile", ".zshenv"} {
		if err := os.WriteFile(filepath.Join(home, f), []byte("echo \""+profileLine+"\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

// TestCodexDenyHoldsThroughALoginShell runs alalanet-agent hook codex (this test binary as main, through TestMain) the
// way Codex does, as <shell> -lc '<command>', with a home whose profile prints a line.
func TestCodexDenyHoldsThroughALoginShell(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Codex starts hooks through a login shell on Unix")
	}
	var shells []string
	for _, s := range []string{"sh", "bash", "zsh"} {
		if p, err := exec.LookPath(s); err == nil {
			shells = append(shells, p)
		}
	}
	if len(shells) == 0 {
		t.Fatal("no shell to run the hook through")
	}
	agent, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	const block = "alalanet install_check: BLOCK — example-placeholder-pkg is known malware"
	const hold = "alalanet install_check: HOLD — example-placeholder-pkg is two days old"
	answer := func(decision, reason string) func(w http.ResponseWriter) {
		return func(w http.ResponseWriter) {
			if decision != "" {
				_, _ = w.Write([]byte(mustJSON(map[string]any{"hookSpecificOutput": map[string]string{
					"hookEventName": "PreToolUse", "permissionDecision": decision, "permissionDecisionReason": reason}})))
			}
		}
	}
	for _, shell := range shells {
		home := loginHome(t)
		for _, c := range []struct {
			name, command string
			server        func(w http.ResponseWriter)
			exit          int
			reason        string // Codex's block reason; "" for no block
			calls         int
		}{
			{"block", placeholderInstall, answer("deny", block), 2, block, 1},
			{"hold", placeholderInstall, answer("ask", hold), 2, hold + holdNote, 1},
			{"no opinion", placeholderInstall, answer("", ""), 0, "", 1},
			{"not an install", "ls -la", answer("deny", block), 0, "", 0},
		} {
			f := &fakeHook{answer: c.server}
			srv := f.server(t)
			cmd := exec.Command(shell, "-lc", `"$ZZ_AGENT" -test.run='^$'`) // without the TestMain the child runs no test
			cmd.Env = []string{"HOME=" + home, "SHELL=" + shell, "PATH=/usr/bin:/bin", "ZZ_REVIEW_RT1_MAIN=1",
				"ALALANET_API=" + srv.URL, "ZZ_AGENT=" + agent}
			cmd.Stdin = strings.NewReader(codexInput("Bash", c.command))
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			exit := 0
			if err := cmd.Run(); err != nil {
				var ee *exec.ExitError
				if !errors.As(err, &ee) {
					t.Fatalf("%s, %s: %v", shell, c.name, err)
				}
				exit = ee.ExitCode()
			}
			what := filepath.Base(shell) + " -lc, " + c.name
			// The profile's line is there: the proof runs with the stdout Codex would get.
			if !strings.HasPrefix(stdout.String(), profileLine+"\n") {
				t.Fatalf("%s: stdout %q does not start with the profile's line", what, stdout.String())
			}
			blocked, reason := codexReads(exit, stdout.String(), stderr.String())
			if exit != c.exit || blocked != (c.reason != "") || reason != c.reason {
				t.Errorf("%s: exit %d (want %d), Codex blocks %v with %q (want %q); stdout %q, stderr %q",
					what, exit, c.exit, blocked, reason, c.reason, stdout.String(), stderr.String())
			}
			if c.exit == 0 && (stderr.Len() != 0 || stdout.String() != profileLine+"\n") {
				t.Errorf("%s: printed %q, stderr %q; want only the profile's line and no stderr", what, stdout.String(), stderr.String())
			}
			if c.exit == 2 && !strings.Contains(stdout.String(), `"permissionDecision":"deny"`) {
				t.Errorf("%s: the JSON answer is gone from stdout: %q", what, stdout.String())
			}
			if len(f.calls()) != c.calls {
				t.Errorf("%s: %d calls to alalanet, want %d", what, len(f.calls()), c.calls)
			}
		}
	}
}

// Every runtime's answer to each verdict: hook codex's deny and hold come back as a hookBlock with the reason of its JSON
// answer (exit 2, the reason on stderr); everything else — no opinion, a warning, alalanet not reached, and every
// answer of the other runtimes — is no error, as before.
func TestHookBlockOnlyForCodexDenies(t *testing.T) {
	verdicts := map[string]struct {
		v       verdict
		reached bool
	}{
		"block":           {verdict{Decision: "deny", Reason: "alalanet install_check: BLOCK — x"}, true},
		"block, no words": {verdict{Decision: "deny"}, true},
		"hold":            {verdict{Decision: "ask", Reason: "alalanet install_check: HOLD — y"}, true},
		"no opinion":      {verdict{}, true},
		"warning":         {verdict{warn: "alalanet mcp_verify: the MCP server s: tools changed."}, true},
		"not reached":     {verdict{Decision: "deny", Reason: "z"}, false},
	}
	for name, rt := range hookRuntimes {
		for vname, c := range verdicts {
			for _, ev := range []hookEvent{{known: true, shell: true}, {known: true, mcp: true}, {known: true, shell: true, local: true}} {
				var out bytes.Buffer
				err := rt.answer(&out, ev, c.v, c.reached)
				what := name + ", " + vname + ", mcp " + map[bool]string{true: "yes", false: "no"}[ev.mcp]
				var blk hookBlock
				denies := name == "codex" && c.reached && (c.v.Decision == "deny" || c.v.Decision == "ask")
				if !denies {
					if err != nil {
						t.Errorf("%s: %v, want no error (the answer as before)", what, err)
					}
					continue
				}
				if !errors.As(err, &blk) {
					t.Errorf("%s: %v, want a hookBlock", what, err)
					continue
				}
				var m struct {
					H map[string]string `json:"hookSpecificOutput"`
				}
				if json.Unmarshal(out.Bytes(), &m) != nil || m.H["permissionDecision"] != "deny" || m.H["permissionDecisionReason"] != blk.reason ||
					blk.reason == "" || exitCode(err) != 2 {
					t.Errorf("%s: printed %q, block %q, exit %d", what, out.String(), blk.reason, exitCode(err))
				}
				if note := map[bool]string{true: mcpHoldNote, false: holdNote}[ev.mcp]; (c.v.Decision == "ask") != strings.HasSuffix(blk.reason, note) {
					t.Errorf("%s: block reason %q", what, blk.reason)
				}
			}
		}
	}
}

// Through runHookMain (main's entry), a call alalanet blocks: hook codex ends with the block; every other runtime and
// runHookContext (the tests' entry) with the answer alone, as before.
func TestRunHookMainBlocksOnlyCodex(t *testing.T) {
	for name := range hookRuntimes {
		in := shellForms(placeholderInstall)["codex Bash"]
		for _, entry := range []string{"main", "context"} {
			f := reviewDeny()
			srv := f.server(t)
			var out bytes.Buffer
			call := hookCall{client: &http.Client{}, api: srv.URL}
			var err error
			if entry == "main" {
				err = runHookMain(t.Context(), name, strings.NewReader(in), &out, call)
			} else {
				err = runHookContext(t.Context(), name, strings.NewReader(in), &out, call)
			}
			var blk hookBlock
			if got := form5(t, name, out.String()); got != "deny" {
				t.Errorf("%s through %s: %s (%q)", name, entry, got, out.String())
			}
			if name == "codex" && entry == "main" {
				if !errors.As(err, &blk) || blk.reason != "alalanet install_check: BLOCK — x" {
					t.Errorf("codex through main: %v, want the block", err)
				}
			} else if err != nil {
				t.Errorf("%s through %s: %v, want none", name, entry, err)
			}
		}
	}
}

// A stdout that cannot be written does not lose the block: exit 2 carries it alone.
func TestCodexBlockWithoutStdout(t *testing.T) {
	err := codexAnswer(failingWriter{}, hookEvent{known: true, shell: true}, verdict{Decision: "deny", Reason: "r"}, true)
	var blk hookBlock
	if !errors.As(err, &blk) || blk.reason != "r" || err.Error() != "r" || exitCode(err) != 2 {
		t.Errorf("deny with a closed stdout: %v, exit %d", err, exitCode(err))
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }

// runMain prints a block's reason alone on stderr (Codex shows stderr as the reason), with exit 2.
func TestRunMainPrintsTheBlockReason(t *testing.T) {
	var stderr strings.Builder
	if code := mainExit(hookBlock{reason: "alalanet install_check: BLOCK — x"}, &stderr); code != 2 || stderr.String() != "alalanet install_check: BLOCK — x\n" {
		t.Errorf("a block: exit %d, stderr %q", code, stderr.String())
	}
	stderr.Reset()
	if code := mainExit(errors.New("a key file that cannot be read"), &stderr); code != 1 || stderr.String() != "error: a key file that cannot be read\n" {
		t.Errorf("another error: exit %d, stderr %q", code, stderr.String())
	}
	stderr.Reset()
	if code := mainExit(nil, &stderr); code != 0 || stderr.Len() != 0 {
		t.Errorf("no error: exit %d, stderr %q", code, stderr.String())
	}
}
