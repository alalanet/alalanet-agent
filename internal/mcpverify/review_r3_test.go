//go:build !windows

package mcpverify

// Review of VERIFY-AUTO-1 round 3 (99e0418): probes. Values built from parts; hosts made up.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"
)

// R3-A: with an unloadable state nothing is saved, so the minute's wait and the 10-minute cache do not apply: how many
// lookups and reads do five calls send? (/privacy: "normally at most once per server every 10 minutes").
func TestReviewR3BrokenStateLookupsPerCall(t *testing.T) {
	url := "https://" + hostA + "/mcp"
	r := newRig(t, map[string]string{hostA: base})
	var mu sync.Mutex
	n := 0
	alal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		n++
		mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
	}))
	defer alal.Close()
	r.v.API = alal.URL
	if err := os.MkdirAll(r.v.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.v.StateDir, stateName), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		r.v.Check(context.Background(), srv(url), "s")
	}
	mu.Lock()
	defer mu.Unlock()
	t.Logf("broken state, five calls: %d lookups at alalanet, %d requests to the server", n, len(r.mcp[hostA].Requests()))
	// Round 4 (P3-2): one lookup a call at most, as the /privacy sentence now says ("and on every check while its
	// state file cannot be read").
	if n > 5 {
		t.Errorf("%d lookups in five calls", n)
	}
}

// R3-B: a FIFO in place of state.json (a model can mkfifo there): does the check stay within its budget?
func TestReviewR3StateFIFO(t *testing.T) {
	url := "https://" + hostA + "/mcp"
	r := newRig(t, map[string]string{hostA: base})
	if err := os.MkdirAll(r.v.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(r.v.StateDir, stateName), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan Outcome, 1)
	start := time.Now()
	go func() { done <- r.v.Check(context.Background(), srv(url), "s") }()
	select {
	case out := <-done:
		t.Logf("FIFO state: %v %q in %v", out.Kind, out.Reasons, time.Since(start))
	case <-time.After(12 * time.Second):
		t.Errorf("FIFO state: the check has not returned after 12 s (its budget is 5 s)")
		// unblock the opener so the test binary can end
		if f, err := os.OpenFile(filepath.Join(r.v.StateDir, stateName), os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			f.Close()
		}
		<-done
	}
}

// R3-C: a project's .mcp.json that is a link to /dev/zero: how much does one ClaudeServers call allocate?
func TestReviewR3McpJSONToDevZero(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink("/dev/zero", filepath.Join(dir, ".mcp.json")); err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	list, _ := ClaudeServers(filepath.Join(dir, "no-claude.json"), dir, true)
	took := time.Since(start)
	runtime.ReadMemStats(&after)
	t.Logf(".mcp.json -> /dev/zero: %d servers, %v, %d MiB allocated", len(list), took, (after.TotalAlloc-before.TotalAlloc)>>20)
	// Round 4 (P3-3): a configuration file is a regular file of 1 MiB at most.
	if len(list) != 0 || after.TotalAlloc-before.TotalAlloc > 8<<20 || took > time.Second {
		t.Errorf("a link to /dev/zero: %d servers, %d MiB, %v", len(list), (after.TotalAlloc-before.TotalAlloc)>>20, took)
	}
}
