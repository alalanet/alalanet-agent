package netguard

// Independent review of sec-redirects (6bcb0742): proofs of findings. Each test here is RED on the target.

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"testing"
)

// F1 (P3): hostPort folds case with strings.ToLower (Unicode simple case mapping), but net/http dials the
// UTS #46 / IDNA mapping of the host (DialName). The two disagree on U+0130 (LATIN CAPITAL LETTER I WITH DOT
// ABOVE): ToLower gives ASCII "i", IDNA gives "i" + U+0307, which is a different punycode (xn--) label, a
// different registrable name. A redirect from i.example.com to İ.example.com is therefore judged "the same
// host" — every off-safelist header (TRON-PRO-API-KEY, X-Alalanet-Signature, ...) stays on — while the
// connection goes to another host. net/http's own Authorization/Cookie stripping compares IDNA forms, so it
// strips those two; the custom key headers are the ones that leak.
func TestReviewSecredirHomoglyphHostKeepsOffSafelistHeaders(t *testing.T) {
	first, evil := "i.example.com", "İ.example.com"
	dialEvil := DialName(evil)
	if dialEvil == first || !strings.HasPrefix(dialEvil, "xn--") {
		t.Skipf("this Go maps %q to %q: no divergence", evil, dialEvil)
	}
	g := newRedirectRig(t, redirectTo(http.StatusFound))
	c := Client(Options{AllowPrivate: true, RedirectPorts: defaultRedirectPorts, MaxRedirects: 3})
	tr := c.Transport.(uaTransport).rt.(*http.Transport)
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // the rig's certificate does not name xn-- labels
	dial := tr.DialContext
	var dialed []string
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(addr)
		dialed = append(dialed, host)
		switch host {
		case first:
			return dial(ctx, network, g.a.Listener.Addr().String())
		case dialEvil:
			return dial(ctx, network, g.b.Listener.Addr().String())
		}
		return nil, net.UnknownNetworkError("rig: unknown host " + host)
	}
	key := "k" + "ey-" + "part"
	// The Location carries the host percent-encoded (url.Parse decodes non-ASCII escapes in a host).
	resp, err := get(t, c, "https://"+first+"/start?to=https://%C4%B0.example.com/collect",
		map[string]string{"Tron-Pro-Api-Key": key, "X-Alalanet-Signature": "s" + "ig"})
	if err != nil {
		t.Fatalf("redirect not followed: %v (dialed %v)", err, dialed)
	}
	_ = resp
	h := g.received("b")
	if len(h) != 1 {
		t.Fatalf("the other host received %d requests (dialed %v)", len(h), dialed)
	}
	if v := h[0].header.Get("Tron-Pro-Api-Key"); v != "" {
		t.Errorf("TRON-PRO-API-KEY reached %s (dialed as %s), a host other than %s: %q", evil, dialEvil, first, v)
	}
	if v := h[0].header.Get("X-Alalanet-Signature"); v != "" {
		t.Errorf("X-Alalanet-Signature reached another host: %q", v)
	}
}

// F1, body form: an outbound client without BodyAcrossHosts (the facilitator's /settle, chain reads) re-sends
// a 307 body to the look-alike host, since the chain "never left" its first host.
func TestReviewSecredirHomoglyphHostGetsBodyOn307(t *testing.T) {
	first, evil := "i.example.com", "İ.example.com"
	dialEvil := DialName(evil)
	if dialEvil == first {
		t.Skip("no divergence on this Go")
	}
	g := newRedirectRig(t, redirectTo(http.StatusTemporaryRedirect))
	c := Client(Options{AllowPrivate: true, RedirectPorts: defaultRedirectPorts, MaxRedirects: 3})
	tr := c.Transport.(uaTransport).rt.(*http.Transport)
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	dial := tr.DialContext
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(addr)
		if host == dialEvil {
			return dial(ctx, network, g.b.Listener.Addr().String())
		}
		return dial(ctx, network, g.a.Listener.Addr().String())
	}
	req, _ := http.NewRequest(http.MethodPost, "https://"+first+"/start?to=https://%C4%B0.example.com/settle",
		strings.NewReader(`{"paymentPayload":"signed-authorization"}`))
	resp, err := c.Do(req)
	if err == nil {
		resp.Body.Close()
	}
	if h := g.received("b"); len(h) != 0 && h[0].body != "" {
		t.Errorf("a 307 re-sent the body to %s (dialed %s), another host: %q", evil, dialEvil, h[0].body)
	}
}

// F1, unit form: the two keys agree although the dialed names differ.
func TestReviewSecredirHostPortAgreesWithDialName(t *testing.T) {
	for _, pair := range [][2]string{
		{"https://i.example.com/", "https://%C4%B0.example.com/"},
		{"https://k.example.com/", "https://%E2%84%AA.example.com/"}, // KELVIN SIGN: both map to k (consistent)
	} {
		a, b := mustURL(t, pair[0]), mustURL(t, pair[1])
		sameKey := hostPort(a) == hostPort(b)
		sameDial := strings.EqualFold(DialName(a.Hostname()), DialName(b.Hostname()))
		if sameKey && !sameDial {
			t.Errorf("hostPort says %s and %s are one host; net/http dials %q and %q", pair[0], pair[1],
				DialName(a.Hostname()), DialName(b.Hostname()))
		}
	}
}
