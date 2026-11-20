package netguard

// Independent review of sec-redirects (6bcb0742): confirmations of claims that hold. GREEN on the target;
// kept as regression guards for the bypasses tried.

import (
	"bytes"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// Odd spellings of credential headers, set under raw keys, never cross hosts.
func TestReviewSecredirOddCaseCredentialsStripped(t *testing.T) {
	g := newRedirectRig(t, redirectTo(http.StatusTemporaryRedirect))
	req, _ := http.NewRequest(http.MethodGet, "https://a.example.com/start?to=https://b.example.com/x", nil)
	for _, k := range []string{"authorization", "AUTHORIZATION", "proxy-authorization", "cookie", "COOKIE2",
		"tron-pro-api-key", "TRON-PRO-API-KEY", "x-api-key", "x-goog-api-key", "x-alalanet-signature"} {
		req.Header[k] = []string{"v-" + "secret"}
	}
	resp, err := g.client(t, Options{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	h := g.received("b")
	if len(h) != 1 {
		t.Fatalf("b received %d", len(h))
	}
	for k, v := range h[0].header {
		if strings.Contains(strings.Join(v, ","), "secret") {
			t.Errorf("%s crossed hosts", k)
		}
	}
}

// Payment headers in any key spelling are refused on a same-host redirect and on a cross-host one, and the
// target receives nothing.
func TestReviewSecredirPaymentAnySpelling(t *testing.T) {
	for _, k := range []string{"x-payment", "X-PAYMENT", "x-Payment", "payment-signature", "PAYMENT-SIGNATURE"} {
		for _, to := range []string{"https://a.example.com/again", "https://b.example.com/x"} {
			g := newRedirectRig(t, redirectTo(http.StatusPermanentRedirect))
			req, _ := http.NewRequest(http.MethodPost, "https://a.example.com/start?to="+to, bytes.NewReader([]byte("{}")))
			req.Header[k] = []string{"pay"}
			_, err := g.client(t, Options{BodyAcrossHosts: true}).Do(req)
			if !IsPolicy(err) || PolicyReason(err) != reasonPayment {
				t.Errorf("%s to %s: %v", k, to, err)
			}
			if n := len(g.hops); n != 1 {
				t.Errorf("%s to %s: %d requests reached the servers, want only the first", k, to, n)
			}
		}
	}
}

// IPv6 forms: zones, NAT64, 6to4 and Teredo embedding private IPv4, translated and compatible forms.
func TestReviewSecredirIPv6Forms(t *testing.T) {
	refused := []string{
		"2606:4700::1111%eth0", "2001:db8::1%1", "fe80::1%lo0", // a zone never passes (Prefix.Contains is false)
		"64:ff9b::7f00:1", "64:ff9b::a00:1", "64:ff9b:1::a00:1", // NAT64
		"2002:7f00:1::1", "2002:a00:1::1", "2002:c0a8:101::1", "2002:808:808::1", // 6to4, even a public v4
		"2001:0:4136:e378:8000:63bf:80ff:fffe", "2001::ffff:ffff", // Teredo (2001::/32 in 2001::/23)
		"::ffff:0:7f00:1", "::ffff:0:a00:1", "::127.0.0.1", "::a00:1", "::ffff:127.0.0.1", "::ffff:10.0.0.1",
		"fec0::1", "5f00::1", "3fff::1", "100::1", "4000::1", "e000::1",
		"2001:2::1", "2001:10::1", "2001:20::1",
	}
	for _, s := range refused {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if Public(a) {
			t.Errorf("%s judged public", s)
		}
		if err := dialControl(false)("tcp", netip.AddrPortFrom(a, 443).String(), nil); !IsBlocked(err) {
			t.Errorf("dial %s: %v", s, err)
		}
	}
	for _, s := range []string{"2606:4700::1111", "2a00:1450:4001::64", "::ffff:8.8.8.8", "8.8.8.8"} {
		if !Public(netip.MustParseAddr(s)) {
			t.Errorf("%s refused", s)
		}
	}
}

// A same-host http -> https upgrade counts as leaving the first host (port 80 vs 443): conservative.
func TestReviewSecredirUpgradeIsCrossHost(t *testing.T) {
	r0 := &http.Request{URL: mustURL(t, "http://a.example.com/")}
	r1 := &http.Request{URL: mustURL(t, "https://a.example.com/"), Response: &http.Response{Request: r0}, Header: http.Header{}}
	if !leftFirstHost(r1) {
		t.Error("http -> https on one host kept as the same host")
	}
}
