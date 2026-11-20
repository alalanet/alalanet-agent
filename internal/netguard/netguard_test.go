package netguard

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestPublic(t *testing.T) {
	cases := map[string]bool{
		"8.8.8.8":          true,
		"1.1.1.1":          true,
		"2606:4700::1111":  true,
		"10.201.0.2":       false,
		"127.0.0.1":        false,
		"169.254.169.254":  false, // cloud metadata
		"172.16.5.4":       false,
		"192.168.1.1":      false,
		"100.64.0.1":       false,
		"::1":              false,
		"fd00::1":          false,
		"fe80::1":          false,
		"::ffff:127.0.0.1": false,
		"::ffff:10.0.0.1":  false,
		"0.0.0.0":          false,
		"224.0.0.1":        false,
		"64:ff9b::a00:1":   false, // NAT64 of 10.0.0.1
	}
	for s, want := range cases {
		if got := Public(netip.MustParseAddr(s)); got != want {
			t.Errorf("Public(%s) = %v, want %v", s, got, want)
		}
	}
}

func TestClientRefusesLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	c := Client(Options{Timeout: 3 * time.Second})
	_, err := c.Get(srv.URL)
	if err == nil || !IsBlocked(err) {
		t.Fatalf("want blocked error, got %v", err)
	}
	c = Client(Options{Timeout: 3 * time.Second, AllowPrivate: true})
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("allow-private: %v", err)
	}
	resp.Body.Close()
}

// NoReuse: every request opens a connection of its own, over TLS too (no HTTP/2 connection is kept),
// while the default client keeps one. The outbound sentinel's proof depends on it (ADR-0134).
func TestNoReuseOpensAConnectionPerRequest(t *testing.T) {
	for _, noReuse := range []bool{true, false} {
		var mu sync.Mutex
		conns := 0
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		srv.EnableHTTP2 = true
		srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
			if s == http.StateNew {
				mu.Lock()
				conns++
				mu.Unlock()
			}
		}
		srv.StartTLS()
		c := Client(Options{Timeout: 3 * time.Second, AllowPrivate: true, NoReuse: noReuse})
		pool := x509.NewCertPool()
		pool.AddCert(srv.Certificate())
		c.Transport.(uaTransport).rt.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: pool}
		for i := 0; i < 3; i++ {
			resp, err := c.Head(srv.URL)
			if err != nil {
				t.Fatalf("NoReuse %v: %v", noReuse, err)
			}
			if noReuse && resp.ProtoMajor != 1 {
				t.Errorf("NoReuse: the answer came over HTTP/%d: an HTTP/2 connection is one that is kept", resp.ProtoMajor)
			}
			resp.Body.Close()
		}
		srv.Close()
		mu.Lock()
		got := conns
		mu.Unlock()
		if noReuse && got != 3 {
			t.Errorf("NoReuse: 3 requests used %d connections, want 3", got)
		}
		if !noReuse && got != 1 {
			t.Errorf("default client: 3 requests used %d connections, want 1 (the test would prove nothing otherwise)", got)
		}
	}
}

// CheckRedirect follows at most its limit of redirects (then the last answer is returned as it is), to
// http and https only, and counts the redirects it let through (FN-10 round 4: tools/list follows as
// many as fetch, each hop's connection checked by the dialer as the first one is).
func TestCheckRedirect(t *testing.T) {
	followed := 0
	check := CheckRedirect(3, &followed)
	via := []*http.Request{}
	for i := 1; i <= 3; i++ {
		via = append(via, &http.Request{})
		req, _ := http.NewRequest(http.MethodPost, "https://example.com/hop", nil)
		if err := check(req, via); err != nil || followed != i {
			t.Fatalf("redirect %d: %v, followed %d", i, err, followed)
		}
	}
	via = append(via, &http.Request{})
	req, _ := http.NewRequest(http.MethodPost, "https://example.com/hop", nil)
	if err := check(req, via); !errors.Is(err, http.ErrUseLastResponse) || followed != 3 {
		t.Errorf("past the limit: %v, followed %d", err, followed)
	}
	ftp, _ := http.NewRequest(http.MethodGet, "ftp://example.com/", nil)
	if err := CheckRedirect(3, nil)(ftp, via[:1]); err == nil {
		t.Error("a redirect to ftp is followed")
	}
}
