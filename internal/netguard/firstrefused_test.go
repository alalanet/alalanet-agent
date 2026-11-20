package netguard

import (
	"net/http"
	"testing"
)

// sec10b (A2:SEC-10-FIRSTHOP, P3 round): FirstRefused says, without sending anything, what a client's transport
// would answer a first request — the check a reader asks before it takes a read budget or records a read.
func TestFirstRefusedIsTheTransportsAnswer(t *testing.T) {
	ruled := Client(Options{EveryRequest: true})
	for _, x := range []struct{ url, reason string }{
		{"https://x.invalid:9000/a", reasonFirstPort},
		{"https://x.invalid:0443/a", reasonFirstPort},
		{"http://x.invalid/a", reasonFirstScheme},
		{"https://u:p@x.invalid/a", reasonFirstUserinfo},
		{"https://x.invalid/a", ""},
		{"https://x.invalid:443/a", ""},
		{"https://x.invalid:8443/a", ""},
		{"https://x.invalid:/a", ""},
		{"https://x.invalid/%zz", ""}, // does not parse: the request fails its own way
	} {
		err := FirstRefused(ruled, x.url)
		if PolicyReason(err) != x.reason || (x.reason != "") != IsPolicy(err) {
			t.Errorf("FirstRefused(%s) = %v, want %q", x.url, err, x.reason)
		}
		if x.reason == "" {
			continue
		}
		// what the transport itself answers, with nothing sent
		req, _ := http.NewRequest(http.MethodGet, x.url, nil)
		if _, err := ruled.Do(req); PolicyReason(err) != x.reason {
			t.Errorf("%s: the transport answers %v", x.url, err)
		}
	}
	copied := *ruled // a copy keeps the transport (the readers' wrappers)
	if PolicyReason(FirstRefused(&copied, "https://x.invalid:9000/a")) != reasonFirstPort {
		t.Error("a copy of the client lost the rule")
	}
	for name, c := range map[string]*http.Client{
		"without EveryRequest":           Client(Options{}),
		"AllowPrivate without the ports": Client(Options{AllowPrivate: true, EveryRequest: true}),
		"not this package's":             http.DefaultClient,
		"nil transport":                  {},
	} {
		if err := FirstRefused(c, "https://x.invalid:9000/a"); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := FirstRefused(Client(Options{AllowPrivate: true, RedirectPorts: []string{"9000"}, EveryRequest: true}), "https://x.invalid:9000/a"); err != nil {
		t.Errorf("the client's own ports: %v", err)
	}
}
