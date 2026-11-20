package agentkit

// R5 round 2 (the review of 02b00bd): what check_file keeps and relays around signed_by_alalanet (F1, F2),
// and the release's name@version beside the file's own name (F10).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// F1 and F2 together: a pinned event upgrades only a positive advice; with nothing verified, the server's
// warnings pass and every other word (an "ours" look-alike above all) becomes a closed-set advice.
func TestCheckFileAdviceSets(t *testing.T) {
	server, stranger := testKit(t), testKit(t)
	file, sum := r5revFile(t)
	ours, _ := server.ReleaseEvent("alalanet-agent-linux-amd64@1.6.0", file, "", "package")
	theirs, _ := stranger.ReleaseEvent("alalanet-agent-linux-amd64@1.6.0", file, "", "package")
	pins := ReleasePins{Server: server.PK}
	for _, c := range []struct {
		server   string
		verified bool
		listed   bool
		want     string
	}{
		// a pinned event: every word becomes ours except a warning, which stays a warning (R5-3: R2-1)
		{"unknown_hash", true, true, "signed_by_alalanet"},
		{"signed_by_new_publisher", true, true, "signed_by_alalanet"},
		{"signed_by_established", true, true, "signed_by_alalanet"},
		{"signed_by_alalanet", true, true, "signed_by_alalanet"},
		{"caution_conflicting", true, true, "caution_conflicting"},
		{"caution_revoked", true, true, "caution_server_warning"},
		{"avoid_known_bad", true, true, "caution_server_warning"},
		{"do_not_install", true, true, "caution_server_warning"},
		{"caution_server_warning", true, true, "caution_server_warning"},
		{"something_new", true, true, "signed_by_alalanet"},
		{"signed_by_alalanet_and_audited", true, true, "signed_by_alalanet"},
		{"Caution_revoked", true, true, "signed_by_alalanet"},
		// nothing verifies: the closed set passes, a warning becomes the one fixed warning, the rest is taken back
		{"unknown_hash", false, true, "unknown_hash"},
		{"signed_by_new_publisher", false, true, "signed_by_new_publisher"},
		{"signed_by_established", false, true, "signed_by_established"},
		{"caution_conflicting", false, true, "caution_conflicting"},
		{"caution_revoked", false, true, "caution_server_warning"},
		{"avoid_known_bad", false, true, "caution_server_warning"},
		{"do_not_install", false, true, "caution_server_warning"},
		{"caution_none_this_is_the_official_build", false, true, "caution_server_warning"},
		{"caution_signed_by_alalanet", false, true, "caution_server_warning"},
		{"signed_by_alalanet", false, true, "signed_by_new_publisher"},
		{"signed_by_alalanet", false, false, "unknown_hash"},
		{"Caution_revoked", false, true, "signed_by_new_publisher"},
		{"caution_", false, true, "signed_by_new_publisher"},
		{"caution_revoked ", false, true, "signed_by_new_publisher"},
		{"ok", false, true, "signed_by_new_publisher"},
		{"", false, false, "unknown_hash"},
	} {
		var rels []map[string]any
		if c.listed {
			ev := theirs
			if c.verified {
				ev = ours
			}
			rels = append(rels, releaseEntry(ev, sum))
		}
		out := r5revCheck(t, pins, file, c.server, rels...)
		if out["advice"] != c.want {
			t.Errorf("server %q, verified %v, listed %v: advice %v, want %s", c.server, c.verified, c.listed, out["advice"], c.want)
		}
		if c.want != c.server && out["server_advice"] != c.server {
			t.Errorf("server %q: its advice is not kept beside ours: %v", c.server, out["server_advice"])
		}
	}
}

// F10: the release's name@version is shown at the top, compared with the name of the file the user gave;
// among several pinned releases of one hash, the one named like the file is the one shown.
func TestCheckFileNamesTheRelease(t *testing.T) {
	server := testKit(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "alalanet-agent-linux-amd64")
	_ = os.WriteFile(file, []byte("an old genuine binary"), 0o600)
	sum, _ := FileSHA256(file)
	old, _ := server.ReleaseEvent("alalanet-agent-linux-amd64@1.4.2", file, "", "package")
	other, _ := server.ReleaseEvent("something-else@2.0.0", file, "", "package")
	pins := ReleasePins{Server: server.PK}

	out := r5revCheck(t, pins, file, "signed_by_alalanet", releaseEntry(other, sum), releaseEntry(old, sum))
	rc, _ := out["release_check"].(map[string]any)
	if out["name_version"] != "alalanet-agent-linux-amd64@1.4.2" || rc["name_matches_file"] != true {
		t.Fatalf("the release named like the file is not the one shown: %v %v", out["name_version"], rc)
	}
	if note, _ := rc["name_note"].(string); note != "" {
		t.Fatalf("a matching name got a note: %q", note)
	}

	renamed := filepath.Join(dir, "agent.bin")
	_ = os.WriteFile(renamed, []byte("an old genuine binary"), 0o600)
	out = r5revCheck(t, pins, renamed, "signed_by_alalanet", releaseEntry(old, sum))
	rc, _ = out["release_check"].(map[string]any)
	note, _ := rc["name_note"].(string)
	if out["advice"] != "signed_by_alalanet" || out["name_version"] != "alalanet-agent-linux-amd64@1.4.2" || rc["name_matches_file"] != false ||
		!strings.Contains(note, "alalanet-agent-linux-amd64@1.4.2") || !strings.Contains(note, "agent.bin") {
		t.Fatalf("a name that differs from the file's is not said: %v %v", out["name_version"], rc)
	}

	// .exe is part of the file's name, not of the release's (release-sign strips it).
	exe := filepath.Join(dir, "alalanet-agent-windows-amd64.exe")
	_ = os.WriteFile(exe, []byte("w"), 0o600)
	wsum, _ := FileSHA256(exe)
	win, _ := server.ReleaseEvent("alalanet-agent-windows-amd64@1.6.0", exe, "", "package")
	out = r5revCheck(t, pins, exe, "signed_by_alalanet", releaseEntry(win, wsum))
	if rc, _ := out["release_check"].(map[string]any); rc["name_matches_file"] != true {
		t.Fatalf(".exe: %v", rc)
	}
	// Nothing verified: no name is claimed.
	out = r5revCheck(t, pins, file, "unknown_hash")
	if _, ok := out["name_version"]; ok {
		t.Fatalf("a name_version without a verified release: %v", out["name_version"])
	}
}
