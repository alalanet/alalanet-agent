package agentkit

// Proof tests of the independent R5 review (2026-11-15, commit 02b00bd). The ones named ...Fails... show a
// finding and fail on 02b00bd; the rest hold what the review checked and passes.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nbd-wtf/go-nostr"
)

func r5revFile(t *testing.T) (string, string) {
	t.Helper()
	f := filepath.Join(t.TempDir(), "alalanet-agent-linux-amd64")
	if err := os.WriteFile(f, []byte("r5 review binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum, _ := FileSHA256(f)
	return f, sum
}

func r5revCheck(t *testing.T, pins ReleasePins, file, advice string, releases ...map[string]any) map[string]any {
	t.Helper()
	srv := artifactServer(t, func(sha string) map[string]any {
		rs := []any{}
		for _, r := range releases {
			rs = append(rs, r)
		}
		return map[string]any{"sha256": sha, "advice": advice, "releases": rs}
	})
	k := &Kit{API: srv.URL, HTTP: srv.Client(), Pins: &pins}
	out, err := k.CheckFile(context.Background(), file)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// F1 (P2): a server warning the client does not know (a revocation or any caution_* added later) is
// overwritten with signed_by_alalanet as soon as a pinned event is listed: the server can never warn
// about one of our own files except with the exact word caution_conflicting, and a 1.5.0 client in the
// field would override every warning a later server adds.
func TestR5RevFailsUnknownServerWarningIsKept(t *testing.T) {
	server := testKit(t)
	file, sum := r5revFile(t)
	ev, _ := server.ReleaseEvent("alalanet-agent-linux-amd64@1.5.0", file, "", "package")
	for _, warn := range []string{"caution_revoked", "caution_known_vulnerable", "do_not_install"} {
		out := r5revCheck(t, ReleasePins{Server: server.PK}, file, warn, releaseEntry(ev, sum))
		if out["advice"] == "signed_by_alalanet" {
			t.Errorf("server advice %q was replaced by signed_by_alalanet (only a known positive advice may be upgraded)", warn)
		}
	}
}

// F2 (P2): with no event that verifies, only the exact word signed_by_alalanet is taken back. A lying
// server's near words reach the agent's model unchanged and read as "ours".
func TestR5RevFailsLookalikeOursAdviceIsNotRelayed(t *testing.T) {
	server, stranger := testKit(t), testKit(t)
	file, sum := r5revFile(t)
	ev, _ := stranger.ReleaseEvent("alalanet-agent-linux-amd64@1.5.0", file, "", "package")
	for _, lie := range []string{"signed_by_alalanet_offline", "Signed_By_Alalanet", "signed by alalanet", "signed_by_alalanet."} {
		out := r5revCheck(t, ReleasePins{Server: server.PK}, file, lie, releaseEntry(ev, sum))
		a, _ := out["advice"].(string)
		switch a {
		case "unknown_hash", "signed_by_new_publisher", "signed_by_established", "caution_conflicting":
		default:
			t.Errorf("server advice %q relayed as %q with no release that verifies here", lie, a)
		}
	}
}

// Holds: the edge cases of question 1 that 02b00bd already refuses.
func TestR5RevVerifyReleaseEdges(t *testing.T) {
	server, offline := testKit(t), testKit(t)
	file, sum := r5revFile(t)
	ev, _ := server.ReleaseEvent("alalanet-agent-linux-amd64@1.5.0", file, "", "package")
	pins := ReleasePins{Server: server.PK}

	// An upper-case pubkey: the signature verifies (hex decodes either case), the pin does not match.
	up := ev
	up.PubKey = strings.ToUpper(ev.PubKey)
	up.ID = up.GetID()
	if _, err := VerifyRelease(up, sum, pins); err == nil {
		t.Error("an upper-case signer was taken for the pinned key")
	}
	// A one-element ["d"] tag beside the real one, and an extra unknown tag: neither changes the verdict
	// or the name read (they are signed, so a pinned key made them).
	odd := ev
	odd.Tags = append(nostr.Tags{{"d"}}, ev.Tags...)
	odd.Tags = append(odd.Tags, nostr.Tag{"zz", "x"})
	if err := odd.Sign(server.SK); err != nil {
		t.Fatal(err)
	}
	if r, err := VerifyRelease(odd, sum, pins); err != nil || r.NameVersion != "alalanet-agent-linux-amd64@1.5.0" {
		t.Errorf("odd but signed tags: %+v %v", r, err)
	}
	// JSON with a duplicated key: whichever value the parser keeps, the id and signature are checked over
	// it, so the second "tags" (another file's hash) is refused.
	raw, _ := json.Marshal(ev)
	dup := strings.Replace(string(raw), `"tags":`, `"tags":[["d","a@1"],["x","`+strings.Repeat("ab", 32)+`"]],"tags":`, 1)
	dup2 := strings.Replace(string(raw), `"sig":`, `"tags":[["d","a@1"],["x","`+strings.Repeat("ab", 32)+`"]],"sig":`, 1)
	for _, js := range []string{dup, dup2} {
		var e nostr.Event
		if e.UnmarshalJSON([]byte(js)) != nil {
			continue
		}
		if r, err := VerifyRelease(e, "", pins); err == nil && r.SHA256 != sum {
			t.Errorf("a duplicated key smuggled another hash in: %+v", r)
		}
	}
	// Pins that fail Check trust nothing, through the whole client path too.
	for _, bad := range []ReleasePins{{}, {Server: server.PK, OfflineOnly: true}, {Server: strings.ToUpper(server.PK)}, {Server: server.PK, Offline: server.PK}} {
		out := r5revCheck(t, bad, file, "signed_by_alalanet", releaseEntry(ev, sum))
		if out["advice"] == "signed_by_alalanet" {
			t.Errorf("pins %+v: ours", bad)
		}
	}
	_ = offline
}

// Holds: a valid event whose tag the client's cleaning changes (a soft hyphen in r) is still verified on
// the raw bytes, so cleaning never makes our own file "not ours".
func TestR5RevSoftHyphenTagStillVerifies(t *testing.T) {
	server := testKit(t)
	file, sum := r5revFile(t)
	ev, err := server.ReleaseEvent("alalanet-agent-linux-amd64@1.5.0", file, "https://exa\u00admple.com/x", "package")
	if err != nil {
		t.Fatal(err)
	}
	out := r5revCheck(t, ReleasePins{Server: server.PK}, file, "signed_by_alalanet", releaseEntry(ev, sum))
	if out["advice"] != "signed_by_alalanet" {
		t.Fatalf("a soft hyphen in a signed tag broke the check: %v", out["advice"])
	}
}
