package agentkit

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

// AGENTKIT-REDIRECT-1 (ADR-0214 round 2, review P3-2): a request that carries the signed NIP-98 Authorization
// follows no redirect, not even on alalanet's own host: the 3xx is the answer and nothing reaches its Location,
// as the hook's call already does. A request without it follows as before, and the Kit's client is left as it was.
func TestKitAuthorizedRequestFollowsNoRedirect(t *testing.T) {
	for _, code := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		var mu sync.Mutex
		var moved []string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(r.URL.Path) > 6 && r.URL.Path[:7] == "/moved/" {
				mu.Lock()
				moved = append(moved, r.URL.Path+" auth="+strconv.FormatBool(r.Header.Get("Authorization") != ""))
				mu.Unlock()
				_, _ = io.WriteString(w, `{"ok":true}`)
				return
			}
			w.Header().Set("Location", "/moved"+r.URL.Path)
			w.WriteHeader(code)
		}))
		k, _, err := Load(filepath.Join(t.TempDir(), "agent.nsec"), srv.URL, true)
		if err != nil {
			t.Fatal(err)
		}
		k.HTTP = &http.Client{Timeout: 60 * time.Second} // cmd/alalanet-agent's defaultHTTP: follows by itself
		if _, err := k.MemoryList(context.Background()); err == nil {
			t.Errorf("%d: a redirect read as the answer to a signed request", code)
		}
		mu.Lock()
		if len(moved) != 0 {
			t.Errorf("%d: the signed request followed: %q", code, moved)
		}
		moved = nil
		mu.Unlock()
		// Unsigned: follows, as before.
		if out, err := k.do(context.Background(), http.MethodGet, "/v1/public", nil, false); err != nil || out["ok"] != true {
			t.Errorf("%d: unsigned request: %v %v", code, out, err)
		}
		mu.Lock()
		if len(moved) != 1 || moved[0] != "/moved/v1/public auth=false" {
			t.Errorf("%d: unsigned request: %q", code, moved)
		}
		mu.Unlock()
		if k.HTTP.CheckRedirect != nil {
			t.Errorf("%d: the Kit's client was changed", code)
		}
		srv.Close()
	}
}
