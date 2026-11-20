//go:build !windows

package mcpverify

// VERIFY-AUTO-1 round 4 (re-review of 99e0418, P3-1 and P3-3): the files the check reads are regular files, read
// without blocking, within their bounds.

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func within(t *testing.T, what string, d time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not return within %v", what, d)
	}
}

// A FIFO in place of a configuration file or the lock does not block, and is not read.
func TestR4FIFOsDoNotBlock(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{".mcp.json", "claude.json"} {
		if err := syscall.Mkfifo(filepath.Join(dir, name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	within(t, "ClaudeServers on FIFOs", 2*time.Second, func() {
		if list, note := ClaudeServers(filepath.Join(dir, "claude.json"), dir, true); len(list) != 0 || note == "" {
			t.Errorf("%v %q", list, note)
		}
	})
	lockDir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(lockDir, lockName), 0o600); err != nil {
		t.Fatal(err)
	}
	within(t, "removeIfOwn on a FIFO", 2*time.Second, func() { removeIfOwn(filepath.Join(lockDir, lockName), "t") })
	if _, err := os.Lstat(filepath.Join(lockDir, lockName)); err != nil {
		t.Fatal("another holder's lock (a FIFO) was removed")
	}
}

// A configuration file other than Claude Code's own is read up to 1 MiB; a larger one is not read.
func TestR4SmallConfigFilesOnly(t *testing.T) {
	home, cwd := t.TempDir(), t.TempDir()
	big := `{"mcpServers":{"g":{"url":"https://g.example.com/mcp"}},"pad":"` + strings.Repeat("x", 1<<20) + `"}`
	_ = os.MkdirAll(filepath.Join(home, ".cursor"), 0o700)
	if err := os.WriteFile(filepath.Join(home, ".cursor", "mcp.json"), []byte(big), 0o600); err != nil {
		t.Fatal(err)
	}
	if l := CursorServers(home, cwd, false); len(l) != 0 {
		t.Errorf("a 1 MiB+ Cursor file was read: %v", l)
	}
	small := `{"mcpServers":{"g":{"url":"https://g.example.com/mcp"}}}`
	if err := os.WriteFile(filepath.Join(home, ".cursor", "mcp.json"), []byte(small), 0o600); err != nil {
		t.Fatal(err)
	}
	if l := CursorServers(home, cwd, false); len(l) != 1 {
		t.Errorf("a small Cursor file: %v", l)
	}
}
