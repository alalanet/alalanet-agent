package netguard

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// SEC-10/11/15 (A2): the outbound policy on redirects. Every redirect goes to https on 443 or 8443 and
// carries no userinfo; Referer never follows; once a chain has left its first host only the safelisted
// headers go on; a request body is not re-sent to another host unless the client says so; a payment
// header never follows a redirect at all.

// hop is one request a test server received.
type hop struct {
	host   string
	path   string
	header http.Header
	body   string
}

// redirectRig: two TLS servers that a client reaches as a.example.com and b.example.com on any port
// (the dial is mapped to the servers; the dialer's own check still runs), and what each received.
type redirectRig struct {
	mu    sync.Mutex
	hops  []hop
	conns map[string]int // server name -> connections accepted
	a, b  *httptest.Server
}

func newRedirectRig(t *testing.T, handle func(w http.ResponseWriter, r *http.Request) bool) *redirectRig {
	t.Helper()
	g := &redirectRig{conns: map[string]int{}}
	mk := func(name string) *httptest.Server {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			g.mu.Lock()
			g.hops = append(g.hops, hop{host: name, path: r.URL.Path, header: r.Header.Clone(), body: string(b)})
			g.mu.Unlock()
			if handle(w, r) {
				return
			}
			_, _ = io.WriteString(w, "ok")
		}))
		srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
			if s == http.StateNew {
				g.mu.Lock()
				g.conns[name]++
				g.mu.Unlock()
			}
		}
		srv.StartTLS()
		t.Cleanup(srv.Close)
		return srv
	}
	g.a, g.b = mk("a"), mk("b")
	return g
}

// client is a netguard client with the production redirect rule (RedirectPorts set, so AllowPrivate,
// needed to reach the local servers, does not lift it) whose dial maps a.example.com and b.example.com
// to the two servers.
func (g *redirectRig) client(t *testing.T, o Options) *http.Client {
	t.Helper()
	o.AllowPrivate = true
	if o.RedirectPorts == nil {
		o.RedirectPorts = defaultRedirectPorts
	}
	if o.Timeout == 0 {
		o.Timeout = 5 * time.Second
	}
	if o.MaxRedirects == 0 {
		o.MaxRedirects = 3
	}
	c := Client(o)
	tr := c.Transport.(uaTransport).rt.(*http.Transport)
	pool := x509.NewCertPool()
	pool.AddCert(g.a.Certificate())
	pool.AddCert(g.b.Certificate())
	tr.TLSClientConfig = &tls.Config{RootCAs: pool}
	dial := tr.DialContext
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(addr)
		switch strings.ToLower(host) {
		case "a.example.com":
			return dial(ctx, network, g.a.Listener.Addr().String())
		case "b.example.com":
			return dial(ctx, network, g.b.Listener.Addr().String())
		}
		return nil, errors.New("rig: unknown host " + host)
	}
	return c
}

func (g *redirectRig) received(name string) []hop {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []hop
	for _, h := range g.hops {
		if h.host == name {
			out = append(out, h)
		}
	}
	return out
}

func (g *redirectRig) accepted(name string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.conns[name]
}

// redirectTo answers /start (and /back on b) with a redirect to the URL in the "to" query value.
func redirectTo(code int) func(w http.ResponseWriter, r *http.Request) bool {
	return func(w http.ResponseWriter, r *http.Request) bool {
		if to := r.URL.Query().Get("to"); to != "" {
			w.Header().Set("Location", to)
			w.WriteHeader(code)
			return true
		}
		return false
	}
}

func get(t *testing.T, c *http.Client, u string, hdr map[string]string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	return resp, err
}

// A redirect that leaves https is refused before anything is sent to its target: no request, no
// connection, and the error says why in a fixed text.
func TestRedirectToHTTPRefused(t *testing.T) {
	g := newRedirectRig(t, redirectTo(http.StatusFound))
	c := g.client(t, Options{})
	for _, to := range []string{"http://b.example.com/x", "http://b.example.com:443/x", "HTTP://b.example.com/x"} {
		_, err := get(t, c, "https://a.example.com/start?to="+to, nil)
		if !IsPolicy(err) || PolicyReason(err) != reasonScheme {
			t.Errorf("redirect to %s: err %v, reason %q; want the scheme refusal", to, err, PolicyReason(err))
		}
	}
	if n, h := g.accepted("b"), g.received("b"); n != 0 || len(h) != 0 {
		t.Fatalf("the http target was reached: %d connections, %d requests", n, len(h))
	}
}

// A redirect to https on a port outside 443 and 8443 is refused before a connection; 8443 and an
// explicit 443 are followed.
func TestRedirectToOtherPortRefused(t *testing.T) {
	g := newRedirectRig(t, redirectTo(http.StatusFound))
	c := g.client(t, Options{})
	for _, to := range []string{"https://b.example.com:9000/x", "https://b.example.com:80/x", "https://b.example.com:22/x", "https://b.example.com:4430/x"} {
		_, err := get(t, c, "https://a.example.com/start?to="+to, nil)
		if !IsPolicy(err) || PolicyReason(err) != reasonPort {
			t.Errorf("redirect to %s: err %v, reason %q; want the port refusal", to, err, PolicyReason(err))
		}
	}
	if n := g.accepted("b"); n != 0 {
		t.Fatalf("a refused port was connected to %d times", n)
	}
	for _, to := range []string{"https://b.example.com:8443/x", "https://b.example.com:443/x", "https://b.example.com/x"} {
		resp, err := get(t, c, "https://a.example.com/start?to="+to, nil)
		if err != nil || resp.StatusCode != 200 {
			t.Errorf("redirect to %s: %v", to, err)
		}
	}
	if h := g.received("b"); len(h) != 3 {
		t.Fatalf("the allowed ports were reached %d times, want 3", len(h))
	}
}

// A redirect whose URL carries userinfo is refused: net/http would turn it into an Authorization header.
func TestRedirectWithUserinfoRefused(t *testing.T) {
	g := newRedirectRig(t, redirectTo(http.StatusFound))
	c := g.client(t, Options{})
	_, err := get(t, c, "https://a.example.com/start?to=https://user:pw@b.example.com/x", nil)
	if !IsPolicy(err) || PolicyReason(err) != reasonUserinfo {
		t.Fatalf("err %v, reason %q", err, PolicyReason(err))
	}
	if n := g.accepted("b"); n != 0 {
		t.Fatalf("the target was connected to")
	}
}

// What a request carries that is not on the safelist: credentials, sessions, keys, payments' neighbours,
// and an unknown header. None of it reaches another host.
var secretish = map[string]string{
	"Authorization":        "Bearer " + "tok" + "en-1",
	"Cookie":               "sid=" + "abc",
	"Tron-Pro-Api-Key":     "k" + "ey-1",
	"X-Alalanet-Signature": "sig-1",
	"X-Anything":           "custom",
	"X-Github-Api-Version": "2022-11-28",
}

var safe = map[string]string{
	"Accept":               "application/json",
	"Content-Type":         "application/json",
	"User-Agent":           "alalanet-test/1",
	"Mcp-Protocol-Version": "2025-06-18",
	"Mcp-Session-Id":       "session-1", // the remote's own value (a moved MCP server's session)
	"Accept-Encoding":      "identity",  // not net/http's own gzip: a stripped one would read as kept
	"Origin":               "https://alalanet.com",
}

func both() map[string]string {
	m := map[string]string{}
	for k, v := range secretish {
		m[k] = v
	}
	for k, v := range safe {
		m[k] = v
	}
	return m
}

func TestCrossHostRedirectKeepsOnlySafelistedHeaders(t *testing.T) {
	// A header set under a non-canonical key (req.Header["..."] directly) is judged by its canonical name.
	raw := func(r *http.Request) {
		r.Header["mcp-protocol-version"] = []string{"raw-kept"}
		r.Header["x-raw-secret"] = []string{"raw-dropped"}
	}
	g := newRedirectRig(t, redirectTo(http.StatusFound))
	req, _ := http.NewRequest(http.MethodGet, "https://a.example.com/start?to=https://b.example.com/x", nil)
	raw(req)
	if resp, err := g.client(t, Options{}).Do(req); err != nil {
		t.Fatal(err)
	} else {
		resp.Body.Close()
	}
	if h := g.received("b"); len(h) != 1 || h[0].header.Get("Mcp-Protocol-Version") != "raw-kept" || h[0].header.Get("X-Raw-Secret") != "" {
		t.Errorf("non-canonical keys: %+v", h)
	}

	for _, code := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		g := newRedirectRig(t, redirectTo(code))
		c := g.client(t, Options{})
		resp, err := get(t, c, "https://a.example.com/start?q=private&to=https://b.example.com/x", both())
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("%d: %v", code, err)
		}
		h := g.received("b")
		if len(h) != 1 {
			t.Fatalf("%d: b received %d requests", code, len(h))
		}
		for k := range secretish {
			if v := h[0].header.Get(k); v != "" {
				t.Errorf("%d: %s reached another host: %q", code, k, v)
			}
		}
		for k, v := range safe {
			if k == "Content-Type" && code != http.StatusTemporaryRedirect && code != http.StatusPermanentRedirect {
				v = "" // net/http itself drops it when a 301, 302 or 303 turns the request into a GET
			}
			if got := h[0].header.Get(k); got != v {
				t.Errorf("%d: safelisted %s = %q, want %q", code, k, got, v)
			}
		}
		if r := h[0].header.Get("Referer"); r != "" {
			t.Errorf("%d: Referer sent across hosts: %q", code, r)
		}
	}
}

// The same host on another port is another host: the comparison is host and port, exactly.
func TestRedirectToOtherPortOfSameHostIsCrossHost(t *testing.T) {
	g := newRedirectRig(t, redirectTo(http.StatusFound))
	c := g.client(t, Options{})
	if _, err := get(t, c, "https://a.example.com/start?to=https://a.example.com:8443/x", both()); err != nil {
		t.Fatal(err)
	}
	h := g.received("a")
	if len(h) != 2 || h[1].header.Get("Authorization") != "" || h[1].header.Get("X-Anything") != "" {
		t.Fatalf("a redirect to another port kept the headers: %+v", h)
	}
}

// A sub-domain of the first host is another host (net/http's own rule would keep Authorization for it).
func TestRedirectToSubdomainIsCrossHost(t *testing.T) {
	g := newRedirectRig(t, redirectTo(http.StatusFound))
	c := g.client(t, Options{})
	c.Transport.(uaTransport).rt.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		if strings.HasPrefix(addr, "api.example.com:") {
			return d.DialContext(ctx, network, g.b.Listener.Addr().String())
		}
		return d.DialContext(ctx, network, g.a.Listener.Addr().String())
	}
	if _, err := get(t, c, "https://example.com/start?to=https://api.example.com/x", both()); err != nil {
		t.Fatal(err)
	}
	h := g.received("b")
	if len(h) != 1 || h[0].header.Get("Authorization") != "" || h[0].header.Get("Cookie") != "" {
		t.Fatalf("a sub-domain received the credentials: %+v", h)
	}
}

// On the same host and port the headers stay (a moved path keeps working), and Referer does not.
func TestSameHostRedirectKeepsHeadersWithoutReferer(t *testing.T) {
	g := newRedirectRig(t, redirectTo(http.StatusPermanentRedirect)) // a 301 would lose Content-Type in net/http itself
	c := g.client(t, Options{})
	resp, err := get(t, c, "https://a.example.com/start?q=private&to=https://A.example.com:443/moved", both())
	if err != nil || resp.StatusCode != 200 {
		t.Fatal(err)
	}
	h := g.received("a")
	if len(h) != 2 || h[1].path != "/moved" {
		t.Fatalf("hops %+v", h)
	}
	for k, v := range both() {
		if got := h[1].header.Get(k); got != v {
			t.Errorf("same host: %s = %q, want %q", k, got, v)
		}
	}
	if r := h[1].header.Get("Referer"); r != "" {
		t.Errorf("Referer sent: %q", r)
	}
}

// A chain first host -> another host -> first host stays stripped: the client copies the first
// request's headers at every hop, so the whole chain counts, not the last step.
func TestChainBackToFirstHostStaysStripped(t *testing.T) {
	g := newRedirectRig(t, redirectTo(http.StatusFound))
	c := g.client(t, Options{})
	back := "https://a.example.com/final"
	if _, err := get(t, c, "https://a.example.com/start?to=https://b.example.com/x%3Fto%3D"+back, both()); err != nil {
		t.Fatal(err)
	}
	h := g.received("a")
	if len(h) != 2 || h[1].path != "/final" {
		t.Fatalf("hops %+v", g.hops)
	}
	for k := range secretish {
		if v := h[1].header.Get(k); v != "" {
			t.Errorf("back on the first host after another: %s = %q", k, v)
		}
	}
	if h[1].header.Get("Accept") != "application/json" {
		t.Errorf("safelisted Accept lost")
	}
}

// A payment header never follows a redirect: not to another host, not on the same host, under either
// name and any spelling. Nothing is sent to the redirect's target.
func TestPaymentHeaderNeverFollowsARedirect(t *testing.T) {
	for _, name := range []string{"X-PAYMENT", "PAYMENT-SIGNATURE", "x-payment", "Payment-Signature"} {
		for _, to := range []string{"https://b.example.com/x", "https://a.example.com/again"} {
			for _, code := range []int{http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
				g := newRedirectRig(t, redirectTo(code))
				c := g.client(t, Options{BodyAcrossHosts: true})
				req, _ := http.NewRequest(http.MethodGet, "https://a.example.com/start?to="+to, nil)
				req.Header[name] = []string{"eyJwYXltZW50IjoxfQ"}
				resp, err := c.Do(req)
				if err == nil {
					resp.Body.Close()
				}
				if !IsPolicy(err) || PolicyReason(err) != reasonPayment {
					t.Errorf("%s %d to %s: err %v, reason %q", name, code, to, err, PolicyReason(err))
				}
				if len(g.received("b")) != 0 || len(g.received("a")) != 1 {
					t.Errorf("%s %d to %s: the redirect's target was sent a request: %+v", name, code, to, g.hops)
				}
			}
		}
	}
}

// A body is not re-sent to another host on a 307 or 308 (the facilitator's payload, a chain read): the
// target gets no request. With BodyAcrossHosts (the prober: its bodies are public constants) it gets the
// body and only the safelisted headers. On the same host the body is re-sent as net/http does.
func TestBodyNotResentAcrossHosts(t *testing.T) {
	post := func(c *http.Client, u string) (*http.Response, error) {
		req, _ := http.NewRequest(http.MethodPost, u, strings.NewReader(`{"payload":1}`))
		for k, v := range both() {
			req.Header.Set(k, v)
		}
		resp, err := c.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		return resp, err
	}
	for _, code := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		g := newRedirectRig(t, redirectTo(code))
		_, err := post(g.client(t, Options{}), "https://a.example.com/start?to=https://b.example.com/x")
		if !IsPolicy(err) || PolicyReason(err) != reasonBody {
			t.Errorf("%d: err %v, reason %q", code, err, PolicyReason(err))
		}
		if len(g.received("b")) != 0 {
			t.Errorf("%d: the body went to another host", code)
		}

		g = newRedirectRig(t, redirectTo(code))
		resp, err := post(g.client(t, Options{BodyAcrossHosts: true}), "https://a.example.com/start?to=https://b.example.com/x")
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("%d with BodyAcrossHosts: %v", code, err)
		}
		h := g.received("b")
		if len(h) != 1 || h[0].body != `{"payload":1}` || h[0].header.Get("Authorization") != "" || h[0].header.Get("Content-Type") != "application/json" {
			t.Errorf("%d with BodyAcrossHosts: %+v", code, h)
		}

		g = newRedirectRig(t, redirectTo(code))
		resp, err = post(g.client(t, Options{}), "https://a.example.com/start?to=https://a.example.com/moved")
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("%d same host: %v", code, err)
		}
		if h := g.received("a"); len(h) != 2 || h[1].body != `{"payload":1}` || h[1].header.Get("Authorization") == "" {
			t.Errorf("%d same host: %+v", code, h)
		}
	}
	// An empty body (http.NoBody) is no body: a 307 with it crosses hosts.
	g0 := newRedirectRig(t, redirectTo(http.StatusTemporaryRedirect))
	req, _ := http.NewRequest(http.MethodPost, "https://a.example.com/start?to=https://b.example.com/x", strings.NewReader("")) // NoBody, re-made by GetBody
	if resp, err := g0.client(t, Options{}).Do(req); err != nil {
		t.Errorf("307 with an empty body across hosts: %v", err)
	} else {
		resp.Body.Close()
	}
	if len(g0.received("b")) != 1 {
		t.Errorf("307 with an empty body: b received %d", len(g0.received("b")))
	}
	// A 302 or 303 turns the POST into a GET without a body: it may cross hosts, stripped.
	g := newRedirectRig(t, redirectTo(http.StatusSeeOther))
	if _, err := post(g.client(t, Options{}), "https://a.example.com/start?to=https://b.example.com/x"); err != nil {
		t.Fatalf("303 across hosts: %v", err)
	}
	if h := g.received("b"); len(h) != 1 || h[0].body != "" || h[0].header.Get("Authorization") != "" {
		t.Errorf("303 across hosts: %+v", h)
	}
}

// The rule is the client's, not CheckRedirect's: a caller that replaces CheckRedirect (the prober's
// tools/list read, the opt-out and same-origin wrappers) keeps it.
func TestPolicyHoldsUnderAReplacedCheckRedirect(t *testing.T) {
	g := newRedirectRig(t, redirectTo(http.StatusFound))
	c := g.client(t, Options{})
	follow := *c
	follow.CheckRedirect = func(*http.Request, []*http.Request) error { return nil }
	if _, err := get(t, &follow, "https://a.example.com/start?to=http://b.example.com/x", nil); !IsPolicy(err) {
		t.Errorf("http redirect under a replaced CheckRedirect: %v", err)
	}
	if _, err := get(t, &follow, "https://a.example.com/start?to=https://b.example.com/x", both()); err != nil {
		t.Fatal(err)
	}
	if h := g.received("b"); len(h) != 1 || h[0].header.Get("Authorization") != "" {
		t.Errorf("headers under a replaced CheckRedirect: %+v", h)
	}
}

// The first request is not a redirect: its scheme, port and headers are the caller's business (the
// catalogue's URL rule), and it is sent as given.
func TestFirstRequestIsNotJudgedAsARedirect(t *testing.T) {
	g := newRedirectRig(t, func(http.ResponseWriter, *http.Request) bool { return false })
	c := g.client(t, Options{})
	if _, err := get(t, c, "https://a.example.com:9000/x", map[string]string{"X-Payment": "p", "Authorization": "a", "Referer": "r"}); err != nil {
		t.Fatal(err)
	}
	h := g.received("a")
	if len(h) != 1 || h[0].header.Get("X-Payment") != "p" || h[0].header.Get("Authorization") != "a" || h[0].header.Get("Referer") != "r" {
		t.Fatalf("first request changed: %+v", h)
	}
}

// The rule's ports: 443 and 8443 by default; AllowPrivate alone (local servers, plain http on random
// ports) lifts the scheme and port rule; RedirectPorts with it keeps the rule. The header, body and
// payment rules hold in every case.
func TestRedirectPortsFromOptions(t *testing.T) {
	ports := func(o Options) []string { return Client(o).Transport.(uaTransport).ports }
	if p := ports(Options{}); strings.Join(p, ",") != "443,8443" {
		t.Errorf("default ports %v", p)
	}
	if p := ports(Options{AllowPrivate: true}); p != nil {
		t.Errorf("AllowPrivate alone: ports %v, want the rule lifted", p)
	}
	if p := ports(Options{AllowPrivate: true, RedirectPorts: []string{"443", "9443"}}); strings.Join(p, ",") != "443,9443" {
		t.Errorf("explicit ports %v", p)
	}
	if p := ports(Options{RedirectPorts: []string{"443"}}); strings.Join(p, ",") != "443" {
		t.Errorf("explicit ports without AllowPrivate %v", p)
	}
	if !Client(Options{BodyAcrossHosts: true}).Transport.(uaTransport).bodyAcross || Client(Options{}).Transport.(uaTransport).bodyAcross {
		t.Error("BodyAcrossHosts not carried")
	}
	// Lifted: a plain-http local redirect to another port is followed, stripped across hosts.
	var seen http.Header
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen = r.Header.Clone() }))
	defer b.Close()
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, b.URL+"/x", http.StatusFound)
	}))
	defer a.Close()
	c := Client(Options{AllowPrivate: true, MaxRedirects: 2, Timeout: 5 * time.Second})
	if _, err := get(t, c, a.URL, both()); err != nil {
		t.Fatalf("lifted rule: %v", err)
	}
	if seen == nil || seen.Get("Authorization") != "" || seen.Get("Accept") != "application/json" {
		t.Errorf("lifted rule, stripped headers: %v", seen)
	}
	req, _ := http.NewRequest(http.MethodGet, a.URL, nil)
	req.Header.Set("X-Payment", "p")
	if _, err := c.Do(req); !IsPolicy(err) {
		t.Errorf("lifted rule, payment: %v", err)
	}
}

// hostPort names a URL's host and port, the scheme's default filled in: http and https on one name are
// two hosts.
func TestHostPort(t *testing.T) {
	for raw, want := range map[string]string{
		"https://A.Example.com/x": "a.example.com 443", "http://a.example.com/": "a.example.com 80",
		"https://a.example.com:8443/": "a.example.com 8443", "http://a.example.com:443/": "a.example.com 443",
		"https://[2606:4700::1111]/": "2606:4700::1111 443",
	} {
		u, _ := url.Parse(raw)
		if got := hostPort(u); got != want {
			t.Errorf("hostPort(%s) = %q, want %q", raw, got, want)
		}
	}
}

// PolicyReason gives the fixed text of a refusal, and nothing for other errors.
func TestPolicyReason(t *testing.T) {
	if PolicyReason(errors.New("x")) != "" || PolicyReason(nil) != "" || IsPolicy(ErrBlocked) {
		t.Fatal("PolicyReason of a non-policy error")
	}
	for _, r := range []string{reasonScheme, reasonPort, reasonUserinfo, reasonBody, reasonPayment} {
		if r == "" || strings.ContainsAny(r, "/:") {
			t.Errorf("reason %q is not a fixed plain text", r)
		}
	}
}

// SEC-15: an IPv6 address is public only inside 2000::/3 (IANA's global unicast) and outside the listed
// prefixes. The IPv4-translated range ::ffff:0:0:0/96 (SIIT, RFC 2765) was the one missing: it, the
// IPv4-compatible ::/96, site-local fec0::/10, 5f00::/16 and the documentation range 3fff::/20 are refused.
func TestPublicIPv6Ranges(t *testing.T) {
	cases := map[string]bool{
		"::ffff:0:7f00:1":      false, // IPv4-translated 127.0.0.1
		"::ffff:0:a9fe:a9fe":   false, // IPv4-translated 169.254.169.254
		"::ffff:0:808:808":     false, // IPv4-translated, even of a public address: not routed as such
		"::127.0.0.1":          false, // IPv4-compatible
		"::169.254.169.254":    false,
		"::8.8.8.8":            false,
		"fec0::1":              false,
		"3fff::1":              false,
		"5f00::1":              false,
		"4000::1":              false,
		"::ffff:169.254.0.1":   false, // IPv4-mapped: judged as IPv4
		"::ffff:8.8.8.8":       true,
		"2606:4700::1111":      true,
		"2a00:1450::1":         true,
		"2001:4860:4860::8888": true,
		"2002:7f00:1::1":       false, // 6to4 of 127.0.0.1
		"2001:0:4136:e378::1":  false, // Teredo
		"64:ff9b::7f00:1":      false, // NAT64
		"64:ff9b:1::7f00:1":    false,
	}
	for s, want := range cases {
		if got := Public(netip.MustParseAddr(s)); got != want {
			t.Errorf("Public(%s) = %v, want %v", s, got, want)
		}
	}
}

// The new ranges are refused at dial time, by the dialer's own check: in every spelling a URL can give.
func TestDialRefusesTranslatedRanges(t *testing.T) {
	for _, addr := range []string{"[::ffff:0:7f00:1]:443", "[::127.0.0.1]:443", "[fec0::1]:443", "[::ffff:127.0.0.1]:443", "127.0.0.1:443"} {
		if err := dialControl(false)("tcp", addr, nil); !IsBlocked(err) {
			t.Errorf("control(%s) = %v, want blocked", addr, err)
		}
	}
	if err := dialControl(false)("tcp", "[2606:4700::1111]:443", nil); err != nil {
		t.Errorf("a public address refused: %v", err)
	}
	if err := dialControl(true)("tcp", "[::ffff:0:7f00:1]:443", nil); err != nil {
		t.Errorf("AllowPrivate: %v", err)
	}
	c := Client(Options{Timeout: 3 * time.Second})
	for _, u := range []string{"https://[::ffff:0:7f00:1]/", "https://[::127.0.0.1]/", "https://[::ffff:7f00:1]/"} {
		_, err := c.Get(u)
		if err == nil {
			t.Errorf("%s: no error", u)
			continue
		}
		if !IsBlocked(err) {
			if strings.Contains(err.Error(), "address family not supported") {
				t.Logf("%s: no IPv6 sockets here: %v", u, err)
				continue
			}
			t.Errorf("%s: %v, want blocked at the dial", u, err)
		}
	}
}
