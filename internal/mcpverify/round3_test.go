package mcpverify

// VERIFY-AUTO-1 round 3 (re-review of 8f23a0e): N3's state that does not load, N4's failed lookup.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A state that does not load: the check reads the server and alalanet's record without a pin, holds what the record
// holds, is not checked otherwise, names the file and how to start again, and writes nothing.
func TestR3UnloadableStateWithoutPin(t *testing.T) {
	url := "https://" + hostA + "/mcp"
	r := newRig(t, map[string]string{hostA: base})
	r.list(t, url, base, "")
	if err := os.MkdirAll(r.v.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(r.v.StateDir, stateName)
	bad := []byte("{not json")
	if err := os.WriteFile(path, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	out := r.v.Check(context.Background(), srv(url), "s")
	if out.Kind != NotChecked || !strings.Contains(out.Reasons[0], path) || !strings.Contains(out.Reasons[0], "remove it to start again") {
		t.Fatalf("matching the record: %+v", out)
	}
	if len(r.mcp[hostA].Requests()) == 0 || len(r.alal.Requests()) == 0 {
		t.Fatal("the server or alalanet's record was not read")
	}
	r.mcp[hostA].SetResult(changed)
	if out := r.v.Check(context.Background(), srv(url), "s"); out.Kind != Hold || !strings.Contains(strings.Join(out.Reasons, "; "), path) {
		t.Fatalf("a changed tool against the record: %+v", out)
	}
	if got, _ := os.ReadFile(path); string(got) != string(bad) {
		t.Fatal("the state was written")
	}
	left, _ := filepath.Glob(filepath.Join(r.v.StateDir, "*"))
	if len(left) != 1 {
		t.Fatalf("files: %v", left)
	}
}

// A lookup that failed is not repeated for a minute; after it, alalanet is asked again.
func TestR3FailedLookupCachedAMinute(t *testing.T) {
	url := "https://" + hostA + "/mcp"
	r := newRig(t, map[string]string{hostA: base})
	var n atomic.Int64
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer failing.Close()
	r.v.API = failing.URL
	start := time.Now()
	for _, at := range []time.Duration{0, 20 * time.Second, 59 * time.Second} {
		r.v.Now = func() time.Time { return start.Add(at) }
		if out := r.v.Check(context.Background(), srv(url), "s"); out.Kind != NotChecked {
			t.Fatalf("at %v: %+v", at, out)
		}
	}
	if n.Load() != 1 {
		t.Fatalf("%d lookups within the minute", n.Load())
	}
	r.v.Now = func() time.Time { return start.Add(61 * time.Second) }
	r.v.Check(context.Background(), srv(url), "s")
	if n.Load() != 2 {
		t.Fatalf("%d lookups after the minute", n.Load())
	}
}
