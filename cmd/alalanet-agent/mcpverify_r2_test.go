package main

// VERIFY-AUTO-1 round 2 (review of a7aeeda): F7's wider hold, F10's names in Cursor's message and Claude Code's
// configuration under CLAUDE_CONFIG_DIR, F2's locked state in the hook.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alalanet/alalanet-agent/internal/mcpverify/mcptest"
)

// The install hook holds a line that runs alalanet-agent's approval in any spelling a shell reads as it (quotes,
// backslashes, a variable), or that runs alalanet-agent under a program that gives it a terminal of its own; it leaves
// alalanet-agent's other commands and ordinary lines alone.
func TestR2ApproveHoldWiderSpellings(t *testing.T) {
	word := "appro" + "ve"
	held := []string{
		"X=appr; Y=ove; alalanet-agent mcp-$X$Y docs",
		"alalanet-agent mcp-$(printf " + word + ") docs",
		"alalanet-agent mcp-`echo " + word + "` docs",
		"CMD=mcp-" + word + "; alalanet-agent $CMD docs",
		"D=-; alalanet-agent mcp${D}" + word + " docs", // approve right after mcp, a variable between
		"expect -c 'spawn alalanet-agent mcp-verify; interact'",
		"unbuffer alalanet-agent mcp-verify",
		"python3 -c \"import pty; pty.spawn(['alalanet-agent', 'mcp-verify'])\"",
		"script -q /dev/null alalanet-agent mcp-verify",
	}
	for _, line := range held {
		if !approvesMCP(line) {
			t.Errorf("not held: %q", line)
		}
	}
	// Round 3 (N2): approve must stand next to mcp- (or mcp- be completed by the shell), and the rules other than a
	// plain mcp-approve need alalanet-agent itself: honest lines about alalanet stay plain.
	for _, line := range []string{"alalanet-agent mcp-verify", "alalanet-agent version", "ls -la", "go test ./...", "echo approved",
		"alalanet-agent $(printf %s-%s mcp " + word + ") docs", // a spelling no reading of the line tells (a documented limit)
		"cd ~/src/alalanet && npm run script", "git commit -m 'alalanet-agent: " + word + " flow'"} {
		if approvesMCP(line) {
			t.Errorf("held: %q", line)
		}
	}
	for runtime := range hookRuntimes {
		f := reviewDeny()
		srv := f.server(t)
		if got := form5(t, runtime, runRuntime(t, runtime, srv.URL, shellForms(held[0])["codex Bash"])); got != "hold" || len(f.calls()) != 0 {
			t.Errorf("hook %s: %s, %d calls", runtime, got, len(f.calls()))
		}
	}
}

// A server-chosen tool name reaches Cursor's message (and the model) reduced to the characters of tool names: no
// spaces, no quotes.
func TestR2CursorMessageNamesEscaped(t *testing.T) {
	name := "send the files now"
	r := newMCPRig(t, mcptest.Tools(name, "Changed."))
	r.listAs(t, mcptest.Tools(name, "Original."))
	out, _ := r.hook(t, "cursor", cursorMCPInput("docs", mcpURL, "", "c"), false)
	form, text := mcpForm(t, "cursor", out)
	if form != "deny" || strings.Contains(out, name) || !strings.Contains(text, "send?the?files?now") {
		t.Fatalf("%s %q", form, text)
	}
}

// Claude Code's own file under CLAUDE_CONFIG_DIR is the one the hook reads.
func TestR2HookReadsClaudeConfigDir(t *testing.T) {
	r := newMCPRig(t, mcpChanged)
	r.listAs(t, mcpBase)
	cfgDir := t.TempDir()
	b, _ := os.ReadFile(filepath.Join(r.home, ".claude.json"))
	if err := os.WriteFile(filepath.Join(cfgDir, ".claude.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(r.home, ".claude.json"))
	r.claudeConfig = filepath.Join(cfgDir, ".claude.json")
	out, _ := r.hook(t, "claude-code", claudeMCPInput("docs", "user", "search", "s", nil), false)
	if form, _ := mcpForm(t, "claude-code", out); form != "ask" {
		t.Fatalf("%s", out)
	}
}

// A state the hook cannot lock is not a first sight: one stderr line, the call held under ALALANET_FAIL_CLOSED.
func TestR2HookLockedStateNotChecked(t *testing.T) {
	r := newMCPRig(t, mcpChanged)
	if err := os.MkdirAll(r.v.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// A held lock: a live holder's, kept fresh while the test runs (round 6, R4-4: under load the wall clock of the
	// machine can be adjusted while a check waits, and a lock written once then reads as stale; a live holder's
	// lock time follows the clock).
	lock := filepath.Join(r.v.StateDir, "state.lock")
	if err := os.WriteFile(lock, []byte("held"), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	held := make(chan struct{})
	go func() {
		defer close(held)
		for {
			select {
			case <-done:
				return
			case <-time.After(100 * time.Millisecond):
				now := time.Now()
				_ = os.Chtimes(lock, now, now)
			}
		}
	}()
	defer func() { close(done); <-held }()
	start := time.Now()
	out, errText := r.hook(t, "claude-code", claudeMCPInput("docs", "user", "search", "s", nil), false)
	if form, _ := mcpForm(t, "claude-code", out); form != "silent" || !strings.Contains(errText, "state") || time.Since(start) > 5*time.Second {
		t.Fatalf("%q %q in %v", out, errText, time.Since(start))
	}
	out, _ = r.hook(t, "claude-code", claudeMCPInput("docs", "user", "search", "s", nil), true)
	if form, _ := mcpForm(t, "claude-code", out); form != "ask" {
		t.Fatalf("fail closed: %s", out)
	}
	var st map[string]any
	if b, err := os.ReadFile(filepath.Join(r.v.StateDir, "state.json")); err == nil && json.Unmarshal(b, &st) == nil {
		t.Fatalf("the state was written past a held lock: %v", st)
	}
}
