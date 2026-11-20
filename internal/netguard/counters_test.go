package netguard

import (
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
)

// SEC-11-COUNTERS (A2): every redirect the policy refuses or strips is told to Options.OnRedirect once, by a
// fixed name; nothing else is.

type noted struct {
	mu    sync.Mutex
	names []string
}

func (n *noted) note(name string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.names = append(n.names, name)
}

func (n *noted) take() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := n.names
	n.names = nil
	return out
}

func TestRedirectCountersAreFixedNames(t *testing.T) {
	want := []string{"out.redirect.refused.scheme", "out.redirect.refused.port", "out.redirect.refused.userinfo",
		"out.redirect.refused.body", "out.redirect.refused.payment", "out.redirect.stripped"}
	if got := RedirectCounters(); !slices.Equal(got, want) {
		t.Fatalf("RedirectCounters() = %q, want %q", got, want)
	}
	// Every refusal a redirect can get has its counter.
	for _, reason := range []string{reasonScheme, reasonPort, reasonUserinfo, reasonBody, reasonPayment} {
		if !slices.Contains(want, redirectCounts[reason]) {
			t.Errorf("reason %q has no counter", reason)
		}
	}
}

func TestOnRedirectCountsEachRefusalAndStrip(t *testing.T) {
	for _, tc := range []struct {
		name   string
		to     string
		method string
		hdr    map[string]string
		code   int
		o      Options
		want   []string
	}{
		{"scheme", "http://b.example.com/x", http.MethodGet, nil, http.StatusFound, Options{}, []string{CountRefusedScheme}},
		{"scheme outside http", "ftp://b.example.com/x", http.MethodGet, nil, http.StatusFound, Options{}, []string{CountRefusedScheme}},
		{"port", "https://b.example.com:9000/x", http.MethodGet, nil, http.StatusFound, Options{}, []string{CountRefusedPort}},
		{"userinfo", "https://u:p@b.example.com/x", http.MethodGet, nil, http.StatusFound, Options{}, []string{CountRefusedUserinfo}},
		{"body", "https://b.example.com/x", http.MethodPost, nil, http.StatusTemporaryRedirect, Options{}, []string{CountRefusedBody}},
		{"payment", "https://a.example.com/again", http.MethodGet, map[string]string{"X-Payment": "eyJ4IjoxfQ"}, http.StatusFound, Options{}, []string{CountRefusedPayment}},
		// net/http itself drops Authorization and Cookie for another domain before the transport sees the hop;
		// a key under its own header name is the policy's to take off.
		{"stripped", "https://b.example.com/x", http.MethodGet, map[string]string{"Tron-Pro-Api-Key": "k" + "ey-1"}, http.StatusFound, Options{}, []string{CountStripped}},
		// Followed with nothing taken off: the safelisted headers only, or the same host.
		{"across hosts, safelisted only", "https://b.example.com/x", http.MethodGet, map[string]string{"Accept": "application/json"}, http.StatusFound, Options{}, nil},
		{"same host keeps its headers", "https://a.example.com/again", http.MethodGet, map[string]string{"Authorization": "Bearer " + "t-1"}, http.StatusFound, Options{}, nil},
		{"body across hosts allowed", "https://b.example.com/x", http.MethodPost, nil, http.StatusTemporaryRedirect, Options{BodyAcrossHosts: true}, nil},
		// The limit is not a refusal of the policy (-1 stops at the first redirect as 0 does; the rig makes 0 three).
		{"limit reached", "https://b.example.com/x", http.MethodGet, nil, http.StatusFound, Options{MaxRedirects: -1}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newRedirectRig(t, redirectTo(tc.code))
			var n noted
			o := tc.o
			o.OnRedirect = n.note
			c := g.client(t, o)
			var body *strings.Reader
			if tc.method == http.MethodPost {
				body = strings.NewReader(`{"a":1}`)
			}
			var req *http.Request
			if body != nil {
				req, _ = http.NewRequest(tc.method, "https://a.example.com/start?to="+tc.to, body)
			} else {
				req, _ = http.NewRequest(tc.method, "https://a.example.com/start?to="+tc.to, nil)
			}
			for k, v := range tc.hdr {
				req.Header.Set(k, v)
			}
			if resp, err := c.Do(req); err == nil {
				resp.Body.Close()
			}
			if got := n.take(); !slices.Equal(got, tc.want) {
				t.Fatalf("counted %q, want %q", got, tc.want)
			}
		})
	}
}

// A hop only judged (HopRefused, a redirect hook's question before it takes a budget) is not counted: the
// transport counts it when, and if, it is sent.
func TestHopRefusedCountsNothing(t *testing.T) {
	var n noted
	c := Client(Options{OnRedirect: n.note, MaxRedirects: 2})
	first, _ := http.NewRequest(http.MethodGet, "https://a.example.com/start", nil)
	first.Header.Set("Authorization", "Bearer "+"t-1")
	hop, _ := http.NewRequest(http.MethodGet, "http://b.example.com/x", nil)
	hop.Header = first.Header.Clone()
	hop.Response = &http.Response{Request: first}
	if err := HopRefused(c, hop); PolicyReason(err) != reasonScheme {
		t.Fatalf("HopRefused: %v", err)
	}
	hop.URL.Scheme = "https"
	if err := HopRefused(c, hop); err != nil {
		t.Fatalf("HopRefused: %v", err)
	}
	if got := n.take(); len(got) != 0 {
		t.Fatalf("HopRefused counted %q", got)
	}
}

// A name the policy has no counter for is told to nobody: an empty name is never a counter.
func TestCountTellsNoEmptyName(t *testing.T) {
	var n noted
	tr := uaTransport{note: n.note}
	tr.count("")
	tr.count(CountStripped)
	uaTransport{}.count(CountStripped) // no callback: nothing to tell, and no panic
	if got := n.take(); !slices.Equal(got, []string{CountStripped}) {
		t.Fatalf("counted %q", got)
	}
}

// No callback: nothing to tell, and the policy holds as before.
func TestNoOnRedirectStillRefuses(t *testing.T) {
	g := newRedirectRig(t, redirectTo(http.StatusFound))
	c := g.client(t, Options{})
	if _, err := get(t, c, "https://a.example.com/start?to=http://b.example.com/x", nil); PolicyReason(err) != reasonScheme {
		t.Fatalf("err %v", err)
	}
	if _, err := get(t, c, "https://a.example.com/start?to=ftp://b.example.com/x", nil); err == nil || IsPolicy(err) {
		t.Fatalf("ftp: err %v", err)
	}
}

// SEC-11-NOREDIRECT: NoRedirects answers a 3xx as it came, sends nothing to its Location, and keeps c's
// transport (every rule of it) and c itself as they were.
func TestNoRedirects(t *testing.T) {
	for _, code := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		g := newRedirectRig(t, redirectTo(code))
		c := g.client(t, Options{})
		nc := NoRedirects(c)
		resp, err := get(t, nc, "https://a.example.com/start?to=https://a.example.com/again", map[string]string{"Authorization": "Bearer " + "t-1"})
		if err != nil || resp.StatusCode != code || resp.Header.Get("Location") != "https://a.example.com/again" {
			t.Fatalf("%d: resp %v, err %v", code, resp, err)
		}
		if h := g.received("a"); len(h) != 1 {
			t.Fatalf("%d: %d requests reached the server, want only the first", code, len(h))
		}
		if !Guarded(nc) {
			t.Fatalf("NoRedirects lost the transport")
		}
		resp, err = get(t, c, "https://a.example.com/start?to=https://a.example.com/again", nil)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("%d: the original client no longer follows: %v %v", code, resp, err)
		}
	}
}
