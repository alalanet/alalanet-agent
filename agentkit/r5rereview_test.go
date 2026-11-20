package agentkit

// Proof tests of the R5 re-review (2026-11-15, commit ff8b2aa). Each fails on ff8b2aa.

import (
	"testing"
)

// R2-1 (P3): with a verified release, an advice outside both sets (not positive, not a warning) is kept as
// the server wrote it: the server's own extra claim rides on a file that is ours.
func TestR5ReRevFoundKeepsOnlyKnownAdvice(t *testing.T) {
	server := testKit(t)
	file, sum := r5revFile(t)
	ev, _ := server.ReleaseEvent("alalanet-agent-linux-amd64@1.5.0", file, "", "package")
	for _, lie := range []string{"signed_by_alalanet_and_audited", "safe_to_run_without_hooks"} {
		out := r5revCheck(t, ReleasePins{Server: server.PK}, file, lie, releaseEntry(ev, sum))
		a, _ := out["advice"].(string)
		if a != "signed_by_alalanet" && !relayed(a) {
			t.Errorf("verified release, server advice %q relayed as %q", lie, a)
		}
	}
}

// R2-2 (P3): top-level fields the client writes itself (name_version, server_advice) are left as the
// server sent them when the client has nothing to write: a lying server's name_version reads as checked.
func TestR5ReRevServerCannotPreFillClientFields(t *testing.T) {
	server, stranger := testKit(t), testKit(t)
	file, sum := r5revFile(t)
	ev, _ := stranger.ReleaseEvent("alalanet-agent-linux-amd64@1.6.0", file, "", "package")
	srv := artifactServer(t, func(sha string) map[string]any {
		return map[string]any{"sha256": sha, "advice": "signed_by_new_publisher", "releases": []any{releaseEntry(ev, sum)},
			"name_version": "alalanet-agent-linux-amd64@1.6.0", "server_advice": "signed_by_alalanet"}
	})
	pins := ReleasePins{Server: server.PK}
	out, err := (&Kit{API: srv.URL, HTTP: srv.Client(), Pins: &pins}).CheckFile(t.Context(), file)
	if err != nil {
		t.Fatal(err)
	}
	if out["name_version"] != nil || out["server_advice"] != nil {
		t.Fatalf("nothing verified, yet name_version %v and server_advice %v came through from the server", out["name_version"], out["server_advice"])
	}
}
