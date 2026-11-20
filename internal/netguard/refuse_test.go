package netguard

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// OPT-1 round 2 (ADR-0154): the name net/http dials, and a client that refuses hosts by it.

// The spellings the review found net/http mapping to one ASCII name (fullwidth letters, ideographic
// full stops, a soft hyphen, mathematical and circled letters): DialName gives exactly the name a client
// dials for each — read here from a client's own dialer, which records the address and refuses it.
func TestDialNameIsTheNameAClientDials(t *testing.T) {
	var mu sync.Mutex
	var dialed string
	c := &http.Client{Transport: &http.Transport{Proxy: nil, DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
		mu.Lock()
		dialed = addr
		mu.Unlock()
		return nil, errors.New("recorded, not dialed")
	}}}
	for _, s := range []string{"ｏｐｔｅｄ.example.com", "ＯＰＴＥＤ.example.com", "opted。example。com", "opted.example.com。", "op\u00adted.example.com", "𝐨pted.example.com", "ⓞpted.example.com"} {
		_, _ = c.Get("http://" + s + "/")
		mu.Lock()
		host, _, err := net.SplitHostPort(dialed)
		mu.Unlock()
		if err != nil {
			t.Fatalf("%q: the client dialed %q", s, dialed)
		}
		if got := DialName(s); got != host || strings.TrimRight(got, ".") != "opted.example.com" {
			t.Errorf("DialName(%q) = %q; the client dials %q, which is opted.example.com", s, got, host)
		}
	}
	if got := DialName("bücher.example"); got != "xn--bcher-kva.example" {
		t.Errorf("DialName(bücher.example) = %q, want its xn-- form", got)
	}
	for _, s := range []string{"OPTED.example.com.", "2001:db8::1", "xn--bcher-kva.example", "localhost", ""} {
		if got := DialName(s); got != s {
			t.Errorf("DialName(%q) = %q: an ASCII name is dialed as written", s, got)
		}
	}
}

// A client with Refuse sends no request to a refused host: not the first one, not a redirect's, not
// under another spelling of its name; the error wraps ErrRefused. Other hosts are read as before.
func TestRefuseKeepsTheHostUnreached(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/to-refused" {
			http.Redirect(w, r, "http://localhost:"+r.URL.Query().Get("port")+"/x", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	var asked []string
	var mu sync.Mutex
	c := Client(Options{AllowPrivate: true, MaxRedirects: 2, Refuse: func(_ context.Context, host string) bool {
		mu.Lock()
		asked = append(asked, host)
		mu.Unlock()
		return host == "localhost"
	}})
	get := func(u string) error {
		resp, err := c.Get(u)
		if err == nil {
			resp.Body.Close()
		}
		return err
	}
	if err := get("http://localhost:" + port + "/x"); !IsRefused(err) || hits.Load() != 0 {
		t.Fatalf("the refused host itself: %v, %d requests; want ErrRefused and none", err, hits.Load())
	}
	if err := get("http://ｌｏｃａｌｈｏｓｔ:" + port + "/x"); !IsRefused(err) || hits.Load() != 0 {
		t.Fatalf("the refused host in fullwidth: %v, %d requests; want ErrRefused and none", err, hits.Load())
	}
	if err := get(srv.URL + "/to-refused?port=" + port); !IsRefused(err) || hits.Load() != 1 {
		t.Fatalf("a redirect to it: %v, %d requests; want ErrRefused and only the first", err, hits.Load())
	}
	if err := get(srv.URL + "/ok"); err != nil || hits.Load() != 2 {
		t.Fatalf("another host: %v, %d requests; want it read", err, hits.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(asked) == 0 || asked[1] != "localhost" {
		t.Errorf("Refuse was asked about %v: the fullwidth spelling must reach it as the name dialed", asked)
	}
}

// The transport closes a refused request's body (RoundTripper's contract) and never calls the next one.
func TestRefusedRoundTripClosesTheBody(t *testing.T) {
	var next atomic.Int64
	tr := uaTransport{rt: roundTrip(func(*http.Request) (*http.Response, error) { next.Add(1); return nil, errors.New("sent") }),
		refuse: func(_ context.Context, h string) bool { return strings.EqualFold(h, "opted.example.com") }} // as the store's list folds case
	body := &closeRecorder{Reader: strings.NewReader("{}")}
	req, _ := http.NewRequest(http.MethodPost, "https://OPTED.example.com/pay", body)
	if _, err := tr.RoundTrip(req); !IsRefused(err) || !body.closed.Load() || next.Load() != 0 {
		t.Fatalf("err %v, body closed %v, next called %d times; want ErrRefused, closed, 0", err, body.closed.Load(), next.Load())
	}
	req, _ = http.NewRequest(http.MethodGet, "https://ok.example.com/", nil)
	if _, err := tr.RoundTrip(req); IsRefused(err) || next.Load() != 1 {
		t.Fatalf("another host: err %v, next called %d times; want it sent", err, next.Load())
	}
}

// The dial asks again: a host refused only by the time its connection is opened (an opt-out recorded
// after the request was let through) gets no connection either.
func TestRefuseIsAskedAgainAtTheDial(t *testing.T) {
	var hits, asked atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1) }))
	defer srv.Close()
	c := Client(Options{AllowPrivate: true, Refuse: func(context.Context, string) bool { return asked.Add(1) > 1 }})
	if _, err := c.Get(srv.URL + "/x"); !IsRefused(err) || hits.Load() != 0 || asked.Load() != 2 {
		t.Fatalf("err %v, %d requests, asked %d times; want ErrRefused at the dial, none, twice", err, hits.Load(), asked.Load())
	}
}

// The dial's own check, on the name being dialed: a refused host is not dialed, another one is.
func TestRefusingDialChecksTheDialedName(t *testing.T) {
	var dials []string
	dial := refusingDial(func(_ context.Context, h string) bool { return h == "opted.example.com" }, func(_ context.Context, _, addr string) (net.Conn, error) {
		dials = append(dials, addr)
		return nil, errors.New("dialed")
	})
	if _, err := dial(context.Background(), "tcp", "opted.example.com:443"); !IsRefused(err) || len(dials) != 0 {
		t.Fatalf("refused host: %v, dials %v; want ErrRefused and none", err, dials)
	}
	if _, err := dial(context.Background(), "tcp", "ok.example.com:443"); IsRefused(err) || len(dials) != 1 || dials[0] != "ok.example.com:443" {
		t.Fatalf("another host: %v, dials %v; want it dialed", err, dials)
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type closeRecorder struct {
	io.Reader
	closed atomic.Bool
}

func (c *closeRecorder) Close() error { c.closed.Store(true); return nil }
