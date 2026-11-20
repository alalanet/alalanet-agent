package netguard

import (
	"net/http"
	"testing"
	"time"
)

// The outbound client for chain RPCs waits longer for headers than the prober (8 s default).
func TestHeaderTimeout(t *testing.T) {
	rt := func(c *http.Client) *http.Transport { return c.Transport.(uaTransport).rt.(*http.Transport) }
	if got := rt(Client(Options{})).ResponseHeaderTimeout; got != 8*time.Second {
		t.Fatalf("default: %v", got)
	}
	if got := rt(Client(Options{HeaderTimeout: 55 * time.Second})).ResponseHeaderTimeout; got != 55*time.Second {
		t.Fatalf("set: %v", got)
	}
}
