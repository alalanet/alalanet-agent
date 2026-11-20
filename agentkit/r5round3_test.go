package agentkit

// R5 round 3 (R2-5): the client release's guard in Go. `make release-agent` runs TestClientReleasePins with
// ALALANET_CLIENT_RELEASE=1: it fails while this build's pins are not a client release's (an offline key
// pinned), whatever the spacing of the constants' lines.

import (
	"os"
	"testing"
)

func TestClientReleaseReady(t *testing.T) {
	s, o := testKit(t).PK, testKit(t).PK
	for _, c := range []struct {
		pins ReleasePins
		ok   bool
	}{
		{ReleasePins{Server: s}, false},                               // the server key alone: never a client release
		{ReleasePins{Server: s, Offline: o}, true},                    // both keys (1.6.0)
		{ReleasePins{Server: s, Offline: o, OfflineOnly: true}, true}, // the flip (1.7.0)
		{ReleasePins{Server: s, OfflineOnly: true}, false},            // the flip without a key
		{ReleasePins{Server: s, Offline: s}, false},                   // one key twice
		{ReleasePins{}, false},                                        // nothing
	} {
		if err := ClientReleaseReady(c.pins); (err == nil) != c.ok {
			t.Errorf("%+v: ready %v, want %v (%v)", c.pins, err == nil, c.ok, err)
		}
	}
}

// TestClientReleasePins is the release-agent guard: skipped in every other run.
func TestClientReleasePins(t *testing.T) {
	if os.Getenv("ALALANET_CLIENT_RELEASE") != "1" {
		t.Skip("the release-agent guard (ALALANET_CLIENT_RELEASE=1)")
	}
	if err := ClientReleaseReady(ProductionReleasePins()); err != nil {
		t.Fatal(err)
	}
}
