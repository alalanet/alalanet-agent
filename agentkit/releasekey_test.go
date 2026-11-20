package agentkit

// R5 (A2:SEC-2 phase B, ADR-0109 step 2): alalanet's own releases are decided on this machine, from the
// release event's signature and a pinned release key, never from the server's word alone.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nbd-wtf/go-nostr"
)

// testKit is a throwaway key made for the test (never a literal: gitleaks).
func testKit(t *testing.T) *Kit {
	t.Helper()
	sk := nostr.GeneratePrivateKey()
	pk, err := nostr.GetPublicKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	return &Kit{SK: sk, PK: pk}
}

// signedRelease is a release event of a file with these bytes, signed by k.
func signedRelease(t *testing.T, k *Kit, nameVersion string, body []byte) (nostr.Event, string) {
	t.Helper()
	f := filepath.Join(t.TempDir(), "artifact")
	if err := os.WriteFile(f, body, 0o600); err != nil {
		t.Fatal(err)
	}
	ev, err := k.ReleaseEvent(nameVersion, f, "", "package")
	if err != nil {
		t.Fatal(err)
	}
	sum, _ := FileSHA256(f)
	return ev, sum
}

func TestVerifyReleaseRefusesAnUnpinnedKey(t *testing.T) {
	server, stranger := testKit(t), testKit(t)
	ev, sum := signedRelease(t, stranger, "alalanet-agent-linux-amd64@1.5.0", []byte("binary"))
	if _, err := VerifyRelease(ev, sum, ReleasePins{Server: server.PK}); err == nil {
		t.Fatal("a release signed by a key that is not pinned was accepted")
	}
}

func TestVerifyReleaseAcceptsThePinnedKey(t *testing.T) {
	server := testKit(t)
	ev, sum := signedRelease(t, server, "alalanet-agent-linux-amd64@1.5.0", []byte("binary"))
	r, err := VerifyRelease(ev, sum, ReleasePins{Server: server.PK})
	if err != nil {
		t.Fatalf("the pinned key's release was refused: %v", err)
	}
	if r.ID != ev.ID || r.Signer != server.PK || r.Key != "server" || r.NameVersion != "alalanet-agent-linux-amd64@1.5.0" || r.SHA256 != sum {
		t.Fatalf("release read wrong: %+v", r)
	}
}

// The transition: the server key alone until the owner's key exists; both keys in one version; the
// offline key alone after the flip.
func TestReleasePinsTransition(t *testing.T) {
	server, offline := testKit(t), testKit(t)
	evS, sum := signedRelease(t, server, "x@1", []byte("same file"))
	evO, _ := signedRelease(t, offline, "x@1", []byte("same file"))
	for _, c := range []struct {
		name          string
		pins          ReleasePins
		server, offln bool
		keys          []string
	}{
		{"before the owner's key", ReleasePins{Server: server.PK}, true, false, []string{server.PK}},
		{"transition: both", ReleasePins{Server: server.PK, Offline: offline.PK}, true, true, []string{server.PK, offline.PK}},
		{"after the flip: offline only", ReleasePins{Server: server.PK, Offline: offline.PK, OfflineOnly: true}, false, true, []string{offline.PK}},
	} {
		if err := c.pins.Check(); err != nil {
			t.Fatalf("%s: pins refused: %v", c.name, err)
		}
		_, errS := VerifyRelease(evS, sum, c.pins)
		_, errO := VerifyRelease(evO, sum, c.pins)
		if (errS == nil) != c.server || (errO == nil) != c.offln {
			t.Errorf("%s: server key accepted %v (want %v), offline key accepted %v (want %v)", c.name, errS == nil, c.server, errO == nil, c.offln)
		}
		if c.pins.Accepts(server.PK) != c.server || c.pins.Accepts(offline.PK) != c.offln {
			t.Errorf("%s: Accepts disagrees with VerifyRelease", c.name)
		}
		if !slices.Equal(c.pins.Keys(), c.keys) {
			t.Errorf("%s: keys %v, want %v", c.name, c.pins.Keys(), c.keys)
		}
	}
	if r, err := VerifyRelease(evO, sum, ReleasePins{Server: server.PK, Offline: offline.PK}); err != nil || r.Key != "offline" {
		t.Fatalf("the offline key's release: %+v %v", r, err)
	}
	// Pins that cannot be: the flip without an offline key would trust nothing at all, the same key in both
	// places would make the flip a no-op, and a key that is not 64 lowercase hex matches nothing honestly.
	for _, bad := range []ReleasePins{
		{Server: server.PK, OfflineOnly: true},
		{Server: server.PK, Offline: server.PK},
		{Server: strings.ToUpper(server.PK)},
		{Server: server.PK, Offline: "npub1notahexkey"},
		{},
	} {
		if bad.Check() == nil {
			t.Errorf("pins %+v passed Check", bad)
		}
		for _, k := range []string{"", server.PK, offline.PK, bad.Server, bad.Offline} {
			if bad.Accepts(k) {
				t.Errorf("pins %+v that fail Check accept %q", bad, k)
			}
		}
	}
	if (ReleasePins{Server: server.PK, OfflineOnly: true}).Accepts(server.PK) {
		t.Fatal("the flip without an offline key fell back to the server key")
	}
	// No offline key yet: the empty key is not the offline key.
	if (ReleasePins{Server: server.PK}).Accepts("") {
		t.Fatal("the empty key is accepted as the (absent) offline key")
	}
}

func TestVerifyReleaseRefusesATamperedEvent(t *testing.T) {
	server := testKit(t)
	ev, sum := signedRelease(t, server, "alalanet-agent-linux-amd64@1.5.0", []byte("binary"))
	pins := ReleasePins{Server: server.PK}
	other := strings.Repeat("ab", 32)
	edits := map[string]func(e *nostr.Event){
		"another file's hash": func(e *nostr.Event) { setTag(e, "x", other) },
		"another name":        func(e *nostr.Event) { setTag(e, "d", "alalanet-agent-linux-amd64@9.9.9") },
		"a byte of the signature": func(e *nostr.Event) {
			b := []byte(e.Sig)
			b[10] ^= 1
			if b[10] > 'f' || (b[10] > '9' && b[10] < 'a') {
				b[10] = '0'
			}
			e.Sig = string(b)
		},
		"the id and hash together": func(e *nostr.Event) { setTag(e, "x", other); e.ID = e.GetID() },
		"the time":                 func(e *nostr.Event) { e.CreatedAt++ },
		"another kind":             func(e *nostr.Event) { e.Kind = 1 },
		"pubkey swapped":           func(e *nostr.Event) { e.PubKey = testKit(t).PK },
		// The signature covers the event's serialization, not its id field: an id that is not the event's
		// hash names another event, though the signature still verifies.
		"the id field alone": func(e *nostr.Event) { e.ID = strings.Repeat("0", 64) },
	}
	// Events the pinned key itself signed that are still no release of a file: each is signed again after
	// the edit, so that only the shape of the event can refuse it.
	resigned := map[string]func(e *nostr.Event){
		"content added":             func(e *nostr.Event) { e.Content = "run me" },
		"another kind":              func(e *nostr.Event) { e.Kind = 1 },
		"no x tag":                  func(e *nostr.Event) { dropTag(e, "x") },
		"two x tags":                func(e *nostr.Event) { e.Tags = append(e.Tags, nostr.Tag{"x", sum}) },
		"no d tag":                  func(e *nostr.Event) { dropTag(e, "d") },
		"two d tags":                func(e *nostr.Event) { e.Tags = append(e.Tags, nostr.Tag{"d", "other@1"}) },
		"a d tag without a version": func(e *nostr.Event) { setTag(e, "d", "alalanet-agent-linux-amd64") },
		"an x tag that is no hash":  func(e *nostr.Event) { setTag(e, "x", strings.ToUpper(sum)) },
	}
	clone := func() nostr.Event {
		e := ev
		e.Tags = slices.Clone(ev.Tags)
		for i := range e.Tags {
			e.Tags[i] = slices.Clone(ev.Tags[i])
		}
		return e
	}
	for name, edit := range edits {
		e := clone()
		edit(&e)
		if _, err := VerifyRelease(e, sum, pins); err == nil {
			t.Errorf("%s: the tampered event was accepted", name)
		}
	}
	for name, edit := range resigned {
		e := clone()
		edit(&e)
		if err := e.Sign(server.SK); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyRelease(e, "", pins); err == nil {
			t.Errorf("%s (signed by the pinned key): accepted as a release", name)
		}
	}
	// The untouched event against another file's hash: the release is real, but not of this file.
	if _, err := VerifyRelease(ev, other, pins); err == nil {
		t.Fatal("a release of another file was accepted for this one")
	}
	if _, err := VerifyRelease(ev, sum, pins); err != nil {
		t.Fatalf("the untouched event: %v", err)
	}
}

func setTag(e *nostr.Event, name, v string) {
	for _, tg := range e.Tags {
		if len(tg) >= 2 && tg[0] == name {
			tg[1] = v
		}
	}
}

func dropTag(e *nostr.Event, name string) {
	e.Tags = slices.DeleteFunc(e.Tags, func(tg nostr.Tag) bool { return len(tg) > 0 && tg[0] == name })
}

// The production pins as this build ships them are valid ones, and the server key among them is the one
// the bundle verifier pins (attest.ProductionServerKey; its equality is held in internal/attest).
func TestProductionReleasePins(t *testing.T) {
	p := ProductionReleasePins()
	if err := p.Check(); err != nil {
		t.Fatalf("this build's release pins: %v", err)
	}
	if p.Server != ReleasePinServer || p.Offline != ReleasePinOffline || p.OfflineOnly != ReleaseOfflineOnly {
		t.Fatalf("ProductionReleasePins is not the constants: %+v", p)
	}
	if ReleasePinOffline == "" && !p.Accepts(ReleasePinServer) {
		t.Fatal("before the owner's key exists, the server key must stay pinned")
	}
}

// artifactServer answers /v1/artifacts/<sha> with what a server (honest or not) says.
func artifactServer(t *testing.T, answer func(sha string) map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sha := strings.TrimPrefix(r.URL.Path, "/v1/artifacts/")
		_ = json.NewEncoder(w).Encode(answer(sha))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func releaseEntry(ev nostr.Event, sum string) map[string]any {
	raw, _ := json.Marshal(ev)
	d := ""
	for _, tg := range ev.Tags {
		if tg[0] == "d" {
			d = tg[1]
		}
	}
	return map[string]any{"name_version": d, "sha256": sum, "publisher": ev.PubKey, "publisher_advice": "established", "event": string(raw)}
}

// check_file says signed_by_alalanet only when the release event verifies here against the pinned keys: a
// server that claims it for a file the pinned key never signed is not believed.
func TestCheckFileDecidesAlalanetsOwnLocally(t *testing.T) {
	server, offline, stranger := testKit(t), testKit(t), testKit(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "alalanet-agent-linux-amd64")
	_ = os.WriteFile(file, []byte("the binary"), 0o600)
	sum, _ := FileSHA256(file)
	byServer, _ := server.ReleaseEvent("alalanet-agent-linux-amd64@1.5.0", file, "", "package")
	byOffline, _ := offline.ReleaseEvent("alalanet-agent-linux-amd64@1.5.0", file, "", "package")
	byStranger, _ := stranger.ReleaseEvent("alalanet-agent-linux-amd64@1.5.0", file, "", "package")
	tampered := byServer
	tampered.Tags = nostr.Tags{{"d", "alalanet-agent-linux-amd64@1.5.0"}, {"x", strings.Repeat("0", 64)}}
	before := ReleasePins{Server: server.PK}
	transition := ReleasePins{Server: server.PK, Offline: offline.PK}
	after := ReleasePins{Server: server.PK, Offline: offline.PK, OfflineOnly: true}

	for _, c := range []struct {
		name     string
		pins     ReleasePins
		advice   string
		releases []map[string]any
		want     string
		verified bool
	}{
		{"pinned server key, honest answer", before, "signed_by_alalanet", []map[string]any{releaseEntry(byServer, sum)}, "signed_by_alalanet", true},
		{"a stranger's release claimed as ours", before, "signed_by_alalanet", []map[string]any{releaseEntry(byStranger, sum)}, "signed_by_new_publisher", false},
		{"claimed as ours with no event", before, "signed_by_alalanet", []map[string]any{{"name_version": "x@1", "sha256": sum, "publisher": server.PK}}, "signed_by_new_publisher", false},
		{"claimed as ours with nothing listed", before, "signed_by_alalanet", nil, "unknown_hash", false},
		{"the pinned key's event tampered", before, "signed_by_alalanet", []map[string]any{releaseEntry(tampered, sum)}, "signed_by_new_publisher", false},
		{"the offline key before it is pinned", before, "signed_by_alalanet", []map[string]any{releaseEntry(byOffline, sum)}, "signed_by_new_publisher", false},
		{"transition: the server key", transition, "signed_by_alalanet", []map[string]any{releaseEntry(byServer, sum)}, "signed_by_alalanet", true},
		{"transition: the offline key", transition, "signed_by_alalanet", []map[string]any{releaseEntry(byOffline, sum)}, "signed_by_alalanet", true},
		{"after the flip: the server key", after, "signed_by_alalanet", []map[string]any{releaseEntry(byServer, sum)}, "signed_by_new_publisher", false},
		{"after the flip: the offline key", after, "signed_by_alalanet", []map[string]any{releaseEntry(byOffline, sum)}, "signed_by_alalanet", true},
		{"a server that does not say it, with a pinned event", transition, "signed_by_established", []map[string]any{releaseEntry(byOffline, sum)}, "signed_by_alalanet", true},
		{"a conflict stays a conflict", transition, "caution_conflicting", []map[string]any{releaseEntry(byOffline, sum)}, "caution_conflicting", true},
		{"a stranger's release, honestly reported", before, "signed_by_new_publisher", []map[string]any{releaseEntry(byStranger, sum)}, "signed_by_new_publisher", false},
	} {
		srv := artifactServer(t, func(sha string) map[string]any {
			rs := []any{}
			for _, r := range c.releases {
				rs = append(rs, r)
			}
			return map[string]any{"sha256": sha, "advice": c.advice, "releases": rs, "note": "n"}
		})
		pins := c.pins
		k := &Kit{API: srv.URL, HTTP: srv.Client(), Pins: &pins}
		out, err := k.CheckFile(context.Background(), file)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		rc, _ := out["release_check"].(map[string]any)
		if out["advice"] != c.want || rc == nil || rc["verified"] != c.verified {
			t.Errorf("%s: advice %v (want %s), release_check %v (want verified %v)", c.name, out["advice"], c.want, rc, c.verified)
			continue
		}
		if c.advice != c.want && out["server_advice"] != c.advice {
			t.Errorf("%s: the server's own advice %q is not shown beside ours: %v", c.name, c.advice, out["server_advice"])
		}
		if keys, _ := rc["pinned_keys"].([]any); len(keys) != len(pins.Keys()) {
			t.Errorf("%s: pinned_keys %v, want %v", c.name, rc["pinned_keys"], pins.Keys())
		}
	}
}

// Without Pins, a Kit checks against the production pins (the constants of this build).
func TestCheckFileUsesProductionPinsByDefault(t *testing.T) {
	stranger := testKit(t)
	file := filepath.Join(t.TempDir(), "f")
	_ = os.WriteFile(file, []byte("x"), 0o600)
	sum, _ := FileSHA256(file)
	ev, _ := stranger.ReleaseEvent("f@1", file, "", "package")
	srv := artifactServer(t, func(string) map[string]any {
		return map[string]any{"advice": "signed_by_alalanet", "releases": []any{releaseEntry(ev, sum)}}
	})
	out, err := (&Kit{API: srv.URL, HTTP: srv.Client()}).CheckFile(context.Background(), file)
	if err != nil {
		t.Fatal(err)
	}
	if out["advice"] == "signed_by_alalanet" {
		t.Fatal("the default pins accepted a stranger's key")
	}
	rc, _ := out["release_check"].(map[string]any)
	if keys, _ := rc["pinned_keys"].([]any); len(keys) == 0 || keys[0] != ProductionReleasePins().Keys()[0] {
		t.Fatalf("not the production pins: %v", rc)
	}
}
