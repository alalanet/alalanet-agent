package netguard

import (
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ADR-0214 round 2 (review P3-1): out.redirect.stripped counts every hop past the chain's first host whose first
// request carried a header off the safelist, whoever took it off: net/http itself drops Authorization and Cookie
// for an unrelated host before the transport sees the hop, and that credential did not follow either.
func TestStrippedCountsNetHTTPsOwnStrip(t *testing.T) {
	var mu sync.Mutex
	got := map[string]string{}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got[r.Host] = r.Header.Get("Authorization") + "|" + r.Header.Get("Cookie")
		mu.Unlock()
		_, _ = io.WriteString(w, "ok")
	}))
	defer target.Close()
	port := target.URL[strings.LastIndex(target.URL, ":")+1:]
	run := func(to string, hdr map[string]string) []string {
		first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", to)
			w.WriteHeader(http.StatusFound)
		}))
		defer first.Close()
		var n noted
		c := Client(Options{AllowPrivate: true, MaxRedirects: 2, OnRedirect: n.note})
		req, _ := http.NewRequest(http.MethodGet, first.URL+"/", nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", to, err)
		}
		resp.Body.Close()
		return n.take()
	}
	for _, hdr := range []map[string]string{{"Authorization": "Bearer " + "t-1"}, {"Cookie": "sid=" + "x"}} {
		// an unrelated host name: net/http drops the credential itself; the hop is counted all the same
		if n := run("http://localhost:"+port+"/", hdr); !slices.Equal(n, []string{CountStripped}) {
			t.Errorf("%v to an unrelated host: counted %q", hdr, n)
		}
		if g := got["localhost:"+port]; g != "|" {
			t.Errorf("%v reached the unrelated host: %q", hdr, g)
		}
		// another port of the same address: netguard drops it, counted once
		if n := run("http://127.0.0.1:"+port+"/", hdr); !slices.Equal(n, []string{CountStripped}) {
			t.Errorf("%v to another port: counted %q", hdr, n)
		}
	}
	// Nothing off the safelist in the first request: nothing to strip, nothing counted.
	if n := run("http://localhost:"+port+"/", map[string]string{"Accept": "application/json", "User-Agent": "x/1"}); len(n) != 0 {
		t.Errorf("safelisted headers only: counted %q", n)
	}
	// A Referer set by the caller is dropped on every hop, as net/http's own; it is not a strip.
	if n := run("http://localhost:"+port+"/", map[string]string{"Referer": "https://alalanet.com/"}); len(n) != 0 {
		t.Errorf("Referer only: counted %q", n)
	}
}

// A redirect back to the first host after another stays stripped and is counted (the chain left).
func TestStrippedCountsEachHopPastTheFirstHost(t *testing.T) {
	g := newRedirectRig(t, redirectTo(http.StatusFound))
	var n noted
	c := g.client(t, Options{OnRedirect: n.note})
	if _, err := get(t, c, "https://a.example.com/start?to=https://b.example.com/x%3Fto%3Dhttps://a.example.com/final",
		map[string]string{"Authorization": "Bearer " + "t-1"}); err != nil {
		t.Fatal(err)
	}
	if got := n.take(); !slices.Equal(got, []string{CountStripped, CountStripped}) {
		t.Fatalf("counted %q, want one strip per hop past the first host", got)
	}
}

// Review gap: a caller that replaces CheckRedirect with CheckRedirectOf keeps the client's count of a redirect
// to a scheme other than http and https (the prober's tools/list read).
func TestCheckRedirectOfCountsTheScheme(t *testing.T) {
	away := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/next" {
			_, _ = io.WriteString(w, "ok")
			return
		}
		w.Header().Set("Location", r.URL.Query().Get("to"))
		w.WriteHeader(http.StatusFound)
	}))
	defer away.Close()
	var n noted
	base := Client(Options{AllowPrivate: true, MaxRedirects: 2, OnRedirect: n.note})
	hops := 0
	c := *base
	c.CheckRedirect = CheckRedirectOf(base, 20, &hops)
	if resp, err := c.Get(away.URL + "/x?to=ftp://b.example/x"); err == nil {
		resp.Body.Close()
		t.Fatal("a redirect to ftp followed")
	}
	if got := n.take(); !slices.Equal(got, []string{CountRefusedScheme}) {
		t.Fatalf("counted %q", got)
	}
	resp, err := c.Get(away.URL + "/x?to=/next")
	if err != nil || resp.StatusCode != 200 || hops != 1 {
		t.Fatalf("a followed hop: %v %v, hops %d", resp, err, hops)
	}
	resp.Body.Close()
	if got := n.take(); len(got) != 0 {
		t.Fatalf("a followed hop counted %q", got)
	}
	// The limit is c's own: past it the last answer is returned, nothing counted.
	c.CheckRedirect = CheckRedirectOf(base, 0, nil)
	resp, err = c.Get(away.URL + "/x?to=/next")
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("limit 0: %v %v", resp, err)
	}
	resp.Body.Close()
	// A client that is not this package's has nothing to tell.
	plain := &http.Client{CheckRedirect: CheckRedirectOf(http.DefaultClient, 2, nil)}
	if resp, err := plain.Get(away.URL + "/x?to=ftp://b.example/x"); err == nil {
		resp.Body.Close()
		t.Fatal("plain: a redirect to ftp followed")
	}
	if got := n.take(); len(got) != 0 {
		t.Fatalf("plain counted %q", got)
	}
}

// Review P3-3: SameHostOnly follows only a GET to https on the exact first host (its port included); anything
// else comes back as the answer, with nothing sent to its Location. c's own rule applies first, and c is left
// as it was.
func TestSameHostOnly(t *testing.T) {
	for _, tc := range []struct {
		name, method, to string
		code             int
		follow           bool
	}{
		{"same host 301", http.MethodGet, "https://a.example.com/repositories/7", http.StatusMovedPermanently, true},
		{"same host 307", http.MethodGet, "https://a.example.com/again", http.StatusTemporaryRedirect, true},
		{"same host, case", http.MethodGet, "https://A.EXAMPLE.COM/again", http.StatusFound, true},
		{"another host", http.MethodGet, "https://b.example.com/x", http.StatusFound, false},
		{"a sub-domain", http.MethodGet, "https://api.a.example.com/x", http.StatusFound, false},
		{"another port", http.MethodGet, "https://a.example.com:8443/x", http.StatusFound, false},
		{"an explicit 443", http.MethodGet, "https://a.example.com:443/x", http.StatusFound, false},
		{"http", http.MethodGet, "http://a.example.com/x", http.StatusFound, false},
		{"a POST kept by 307", http.MethodPost, "https://a.example.com/again", http.StatusTemporaryRedirect, false},
		{"a POST turned GET by 303", http.MethodPost, "https://a.example.com/again", http.StatusSeeOther, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newRedirectRig(t, redirectTo(tc.code))
			var n noted
			c := g.client(t, Options{OnRedirect: n.note})
			sc := SameHostOnly(c)
			req, _ := http.NewRequest(tc.method, "https://a.example.com/start?to="+tc.to, strings.NewReader(""))
			req.Header.Set("Authorization", "Bearer "+"t-1")
			resp, err := sc.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if tc.follow {
				if resp.StatusCode != 200 || len(g.received("a")) != 2 || g.received("a")[1].header.Get("Authorization") == "" {
					t.Fatalf("not followed: %d, hops %+v", resp.StatusCode, g.hops)
				}
			} else if resp.StatusCode != tc.code || len(g.received("a")) != 1 || len(g.received("b")) != 0 {
				t.Fatalf("followed: %d, hops %+v", resp.StatusCode, g.hops)
			}
			if got := n.take(); len(got) != 0 {
				t.Fatalf("counted %q: a redirect not followed by choice is no refusal", got)
			}
			// c itself still follows another host.
			if resp, err := get(t, c, "https://a.example.com/start?to=https://b.example.com/x", nil); err != nil || resp.StatusCode != 200 {
				t.Fatalf("c changed: %v %v", resp, err)
			}
		})
	}
	// c's own rule first: its limit, and its count of a refused scheme.
	g := newRedirectRig(t, redirectTo(http.StatusFound))
	var n noted
	c := g.client(t, Options{OnRedirect: n.note, MaxRedirects: -1})
	resp, err := get(t, SameHostOnly(c), "https://a.example.com/start?to=https://a.example.com/again", nil)
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("c's limit: %v %v", resp, err)
	}
	c = g.client(t, Options{OnRedirect: n.note})
	if _, err := get(t, SameHostOnly(c), "https://a.example.com/start?to=ftp://a.example.com/x", nil); err == nil {
		t.Fatal("ftp followed")
	}
	if got := n.take(); !slices.Equal(got, []string{CountRefusedScheme}) {
		t.Fatalf("c's scheme refusal: counted %q", got)
	}
	// A client without a CheckRedirect keeps net/http's limit of 10. The error's text is SameHostOnly's own, so the
	// loop's server counts the requests: 10 sent (9 redirects followed), the 10th redirect refused (batch P3 review,
	// P3-1: a limit of 100 ended within the timeout with the same text).
	var hops atomic.Int32
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hops.Add(1)
		http.Redirect(w, r, "/again", http.StatusFound)
	}))
	defer tls.Close()
	plainTLS := tls.Client()
	plainTLS.Timeout = 5 * time.Second // a loop without a limit ends here, not at 10
	if resp, err := SameHostOnly(plainTLS).Get(tls.URL + "/"); err == nil {
		resp.Body.Close()
		t.Fatal("a same-host loop without a limit ended without an error")
	} else if !strings.Contains(err.Error(), "stopped after 10 redirects") {
		t.Fatalf("loop: %v", err)
	}
	if n := hops.Load(); n != 10 {
		t.Fatalf("the loop's server got %d requests; net/http's limit sends 10", n)
	}
}
