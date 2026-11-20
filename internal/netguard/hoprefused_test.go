package netguard

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"
)

// AG-1 round 3: HopRefused answers what the transport would, without sending: the opt-out (Refuse), the
// redirect policy, or nil; and nil for a client that is not this package's.
func TestHopRefused(t *testing.T) {
	c := Client(Options{Timeout: time.Second, Refuse: func(_ context.Context, h string) bool { return h == "no.example" }})
	first, _ := http.NewRequest(http.MethodGet, "https://start.example/a", nil)
	hop := func(raw string) *http.Request {
		u, _ := url.Parse(raw)
		return &http.Request{Method: http.MethodGet, URL: u, Header: http.Header{}, Response: &http.Response{Request: first}}
	}
	if err := HopRefused(c, hop("https://no.example/x")); !errors.Is(err, ErrRefused) {
		t.Errorf("opted-out host: %v", err)
	}
	if err := HopRefused(c, hop("https://ok.example:9999/x")); !IsPolicy(err) {
		t.Errorf("port 9999: %v", err)
	}
	if err := HopRefused(c, hop("http://ok.example/x")); !IsPolicy(err) {
		t.Errorf("http: %v", err)
	}
	if err := HopRefused(c, hop("https://ok.example/x")); err != nil {
		t.Errorf("https on 443: %v", err)
	}
	if err := HopRefused(&http.Client{}, hop("http://ok.example:9999/x")); err != nil {
		t.Errorf("another client: %v", err)
	}
}

// Guarded: this package's client, not a plain one nor one whose transport is wrapped.
func TestGuarded(t *testing.T) {
	c := Client(Options{Timeout: time.Second})
	wrapped := *c
	wrapped.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) { return c.Transport.RoundTrip(r) })
	if !Guarded(c) || Guarded(&http.Client{}) || Guarded(&wrapped) {
		t.Fatalf("guarded: %v, plain %v, wrapped %v", Guarded(c), Guarded(&http.Client{}), Guarded(&wrapped))
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
