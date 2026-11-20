package netguard

import (
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

// SEC-10-FIRSTHOP (A2): a client made with EveryRequest holds its first request to the redirect rule too —
// https on 443 or 8443, no userinfo — since the prober's first URLs are named by the servers it checks and by
// chain data (a 401's resource_metadata, an authorization server, ERC-8004 endpoints and files). A URL off
// the rule is refused before any connection, with a fixed text that names neither the host nor the port.

const (
	firstScheme   = "request to a non-https URL refused"
	firstPort     = "request to a port that is not checked refused"
	firstUserinfo = "request to a URL with credentials refused"
)

func TestEveryRequestRefusesAFirstRequestOffTheRule(t *testing.T) {
	g := newRedirectRig(t, func(http.ResponseWriter, *http.Request) bool { return false })
	c := g.client(t, Options{EveryRequest: true})
	for _, x := range []struct{ url, reason string }{
		{"https://a.example.com:9000/x", firstPort},
		{"https://a.example.com:80/x", firstPort},
		{"https://a.example.com:0443/x", firstPort},
		{"https://a.example.com:4430/x", firstPort},
		{"http://a.example.com/x", firstScheme},
		{"http://a.example.com:443/x", firstScheme},
		{"HTTP://a.example.com/x", firstScheme},
		{"https://user:pw@a.example.com/x", firstUserinfo},
		{"https://user@a.example.com:8443/x", firstUserinfo},
		{"http://user:pw@a.example.com:9000/x", firstScheme}, // the scheme first, as on a redirect
		{"https://user:pw@a.example.com:9000/x", firstUserinfo},
	} {
		_, err := get(t, c, x.url, nil)
		if !IsPolicy(err) || PolicyReason(err) != x.reason {
			t.Errorf("%s: err %v, reason %q; want %q", x.url, err, PolicyReason(err), x.reason)
		}
		if r := PolicyReason(err); strings.Contains(r, "example") || strings.Contains(r, "9000") || strings.Contains(r, "pw") {
			t.Errorf("%s: the reason names the URL: %q", x.url, r)
		}
	}
	if n, h := g.accepted("a"), g.received("a"); n != 0 || len(h) != 0 {
		t.Fatalf("a refused first request was sent: %d connections, %d requests", n, len(h))
	}
	for _, u := range []string{"https://a.example.com/x", "https://a.example.com:443/x", "https://a.example.com:8443/x", "https://a.example.com:/x"} {
		resp, err := get(t, c, u, nil)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Errorf("%s: %v", u, err)
		}
	}
	if h := g.received("a"); len(h) != 4 {
		t.Fatalf("the allowed first requests reached a %d times, want 4", len(h))
	}
}

// A redirect of such a client keeps the redirect's own texts: the first request's rule does not replace the
// hop's.
func TestEveryRequestKeepsTheRedirectReasons(t *testing.T) {
	g := newRedirectRig(t, redirectTo(http.StatusFound))
	c := g.client(t, Options{EveryRequest: true})
	for _, x := range []struct{ to, reason string }{
		{"https://b.example.com:9000/x", reasonPort},
		{"http://b.example.com/x", reasonScheme},
		{"https://u:p@b.example.com/x", reasonUserinfo},
	} {
		_, err := get(t, c, "https://a.example.com/start?to="+x.to, nil)
		if PolicyReason(err) != x.reason {
			t.Errorf("redirect to %s: reason %q, want %q", x.to, PolicyReason(err), x.reason)
		}
	}
	if n := g.accepted("b"); n != 0 {
		t.Fatalf("b reached %d times", n)
	}
}

// Without EveryRequest the first request is not judged (the rule's other clients: the outbound one, whose
// first URLs are our own configuration); AllowPrivate without RedirectPorts lifts the rule for the first
// request as for a redirect (local servers: plain http on random ports).
func TestEveryRequestOnlyWhereAsked(t *testing.T) {
	g := newRedirectRig(t, func(http.ResponseWriter, *http.Request) bool { return false })
	if _, err := get(t, g.client(t, Options{}), "https://a.example.com:9000/x", nil); err != nil {
		t.Fatalf("without EveryRequest: %v", err)
	}
	if n := len(g.received("a")); n != 1 {
		t.Fatalf("without EveryRequest the first request reached a %d times", n)
	}
	srv := plainServer(t)
	c := Client(Options{AllowPrivate: true, EveryRequest: true})
	if _, err := get(t, c, srv+"/x", nil); err != nil {
		t.Fatalf("AllowPrivate without RedirectPorts: %v", err)
	}
}

// A request the rule refuses has its body closed, as a RoundTripper must on every error.
func TestEveryRequestClosesTheRefusedBody(t *testing.T) {
	g := newRedirectRig(t, func(http.ResponseWriter, *http.Request) bool { return false })
	c := g.client(t, Options{EveryRequest: true})
	b := &closeBody{Reader: strings.NewReader("{}")}
	req, _ := http.NewRequest(http.MethodPost, "https://a.example.com:9000/x", b)
	if _, err := c.Transport.RoundTrip(req); PolicyReason(err) != firstPort {
		t.Fatalf("err %v", err)
	}
	if !b.closed.Load() {
		t.Fatal("the refused request's body was left open")
	}
}

// The policy's reasons, the first request's included: every text PolicyReason gives, each once.
func TestPolicyReasonsListTheFirstRequestTexts(t *testing.T) {
	got := PolicyReasons()
	for _, w := range []string{reasonScheme, reasonPort, reasonUserinfo, reasonBody, reasonPayment, firstScheme, firstPort, firstUserinfo} {
		if !slices.Contains(got, w) {
			t.Errorf("PolicyReasons lacks %q", w)
		}
	}
	if len(got) != 8 {
		t.Errorf("PolicyReasons = %q", got)
	}
}

type closeBody struct {
	io.Reader
	closed atomic.Bool
}

func (b *closeBody) Close() error { b.closed.Store(true); return nil }

func plainServer(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)
	return srv.URL
}
