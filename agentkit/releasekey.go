package agentkit

// alalanet's own releases (kind 30422: the alalanet-agent binaries and alalanet's skills) are decided here,
// on the machine that installs, from the release event's own signature and the release keys pinned below,
// apart from the server key's other work (ADR-0109 step 2, plan row R5). A server's word alone never makes
// a file "signed_by_alalanet": a compromised server would otherwise need no forged signature at all.
//
// The transition, by alalanet-agent version (the server's own rule, internal/app, follows the same pins):
//
//  1. The first alalanet-agent with this file ships with both keys: ReleasePinOffline set (one line: the
//     public key `make release-pubkey` prints on the owner's machine). No client trusts the server key
//     alone: while ReleasePinOffline is empty, `make release-agent` refuses to build. From here every
//     release is also signed offline (`make sign-release`), and the current files are signed offline once,
//     so that they stay alalanet's own after the flip.
//  2. ReleaseOfflineOnly = true (the next version; one line): the offline key alone. The server key stops
//     signing releases (sign-dl and the skills' signing at start), its old releases are no longer ours, and
//     the server retires it (internal/agents, retiredInCode) for the clients of step 1 that still pin it.
//
// The versions of each step are in docs/05-DECISIONS.md, ADR-0109 (round R5-2).

import (
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nbd-wtf/go-nostr"
)

const (
	// ReleasePinServer is the server key (= attest.ProductionServerKey; a test holds them equal). It is
	// written twice because this package travels to the public alalanet-agent repository alone.
	ReleasePinServer = "95ac63a6f99ce221d67af2ab5fe203d3650ee8bac486fe22e01ae74809a41ce2"
	// ReleasePinOffline is the owner's offline release key, x-only public key in lowercase hex. Its secret
	// half lives only on the owner's USB stick. The owner made it on 2026-11-19 (`make release-key`); this is
	// the line that command printed. From this build on both keys are pinned (step 1 above).
	ReleasePinOffline = "d2c016b004680a6889d0048ec1bdcf5015b09d2457e3571e9922082289a0183e"
	// ReleaseOfflineOnly is the flip: true trusts the offline key alone. Check refuses it without one.
	ReleaseOfflineOnly = false
)

// KindRelease is a signed release: name@version -> sha256 (the same kind as agents.KindRelease).
const KindRelease = 30422

// ReleasePins are the keys whose releases are alalanet's own.
type ReleasePins struct {
	Server      string // the server key: trusted for releases until OfflineOnly
	Offline     string // the owner's offline release key; empty until it exists
	OfflineOnly bool   // the flip: the offline key alone
}

// ProductionReleasePins are this build's pins.
func ProductionReleasePins() ReleasePins {
	return ReleasePins{Server: ReleasePinServer, Offline: ReleasePinOffline, OfflineOnly: ReleaseOfflineOnly}
}

func hexKey(s string) bool {
	if len(s) != 64 || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// Check refuses pins that cannot be meant: no key, a key that is not 64 lowercase hex, the flip without
// an offline key (that would trust nothing), or the same key in both places (the flip would change nothing).
func (p ReleasePins) Check() error {
	switch {
	case p.Server == "" && p.Offline == "":
		return errors.New("release pins: no key")
	case p.Server != "" && !hexKey(p.Server), p.Offline != "" && !hexKey(p.Offline):
		return errors.New("release pins: a key is not 64 lowercase hex (an x-only public key)")
	case p.OfflineOnly && p.Offline == "":
		return errors.New("release pins: the flip to the offline key alone, but no offline key is pinned")
	case p.Offline != "" && p.Offline == p.Server:
		return errors.New("release pins: the offline key is the server key")
	}
	return nil
}

// Keys lists the keys trusted now, the server key first.
func (p ReleasePins) Keys() []string {
	var ks []string
	if p.Server != "" && !p.OfflineOnly {
		ks = append(ks, p.Server)
	}
	if p.Offline != "" {
		ks = append(ks, p.Offline)
	}
	return ks
}

// Role names which pinned key pub is ("server" or "offline"), or "" when it is not trusted now. Pins that
// fail Check trust nothing.
func (p ReleasePins) Role(pub string) string {
	if pub == "" || p.Check() != nil {
		return ""
	}
	switch {
	case pub == p.Offline:
		return "offline"
	case pub == p.Server && !p.OfflineOnly:
		return "server"
	}
	return ""
}

// Accepts says whether a release signed by pub is alalanet's own under these pins.
func (p ReleasePins) Accepts(pub string) bool { return p.Role(pub) != "" }

// Release is what a verified release event says.
type Release struct {
	ID, Signer  string
	Key         string // "server" or "offline": which pinned key signed it
	NameVersion string
	SHA256      string
}

func tagValues(ev nostr.Event, name string) []string {
	var vs []string
	for _, tg := range ev.Tags {
		if len(tg) >= 2 && tg[0] == name {
			vs = append(vs, tg[1])
		}
	}
	return vs
}

// VerifyRelease checks one release event as a client must before it calls a file alalanet's own: the id is
// the event's NIP-01 hash, the BIP-340 signature is valid, the kind is 30422 with empty content, one d tag
// (name@version) and one x tag (sha256, 64 lowercase hex), the signer is pinned, and — when sha is given —
// x is that file's hash.
func VerifyRelease(ev nostr.Event, sha string, p ReleasePins) (Release, error) {
	if err := p.Check(); err != nil {
		return Release{}, err
	}
	if ev.Kind != KindRelease || ev.Content != "" {
		return Release{}, fmt.Errorf("not a release event (kind %d, content %d bytes)", ev.Kind, len(ev.Content))
	}
	if !hexKey(ev.ID) || ev.GetID() != ev.ID {
		return Release{}, errors.New("the release event's id is not its hash: the event was changed after signing")
	}
	if ok, err := ev.CheckSignature(); !ok || err != nil {
		return Release{}, errors.New("the release event's signature is not valid")
	}
	role := p.Role(ev.PubKey)
	if role == "" {
		return Release{}, fmt.Errorf("signed by %s, not by a release key pinned here (%s)", ev.PubKey, strings.Join(p.Keys(), ", "))
	}
	ds, xs := tagValues(ev, "d"), tagValues(ev, "x")
	if len(ds) != 1 || !strings.Contains(ds[0], "@") {
		return Release{}, errors.New("the release event has no single d tag name@version")
	}
	if len(xs) != 1 || !hexKey(xs[0]) {
		return Release{}, errors.New("the release event has no single x tag (sha256)")
	}
	if sha != "" && xs[0] != sha {
		return Release{}, fmt.Errorf("the release is of another file (sha256 %s, this file %s)", xs[0], sha)
	}
	return Release{ID: ev.ID, Signer: ev.PubKey, Key: role, NameVersion: ds[0], SHA256: xs[0]}, nil
}

// ReleaseEvent signs name@version = sha256(file) with the kit's key, offline: nothing is sent. SignRelease
// submits it; the owner's ceremony (`alalanetd release-sign`) writes it to a file instead.
func (k *Kit) ReleaseEvent(nameVersion, file, source, typ string) (nostr.Event, error) {
	sum, err := FileSHA256(file)
	if err != nil {
		return nostr.Event{}, err
	}
	return k.ReleaseEventOf(nameVersion, sum, source, typ)
}

// ReleaseEventOf is ReleaseEvent for a hash already computed (a skill's text).
func (k *Kit) ReleaseEventOf(nameVersion, sum, source, typ string) (nostr.Event, error) {
	tags := nostr.Tags{{"d", strings.ToLower(nameVersion)}, {"x", sum}}
	if source != "" {
		tags = append(tags, nostr.Tag{"r", source})
	}
	if typ != "" {
		tags = append(tags, nostr.Tag{"m", typ})
	}
	return k.Sign(nostr.Event{Kind: KindRelease, Tags: tags})
}

func (k *Kit) releasePins() ReleasePins {
	if k.Pins != nil {
		return *k.Pins
	}
	return ProductionReleasePins()
}

// relayedAdvice are the answers passed on as the server gave them: who signed, short of us, the conflict
// warning, and the one fixed warning below.
var relayedAdvice = map[string]bool{"unknown_hash": true, "signed_by_new_publisher": true, "signed_by_established": true,
	"caution_conflicting": true, serverWarningAdvice: true}

// serverWarningAdvice is how every other warning of the server is passed on, verified or not (R5-3): a
// warning is never dropped, and its own word, which a server writes as it likes, stays in server_advice
// and never becomes the advice (caution_none_this_is_the_official_build).
const serverWarningAdvice = "caution_server_warning"

var serverWarning = regexp.MustCompile(`^(caution|avoid|do_not)_[a-z0-9_]{1,64}$`)

// relayed says whether an advice is passed on as it is.
func relayed(advice string) bool { return relayedAdvice[advice] }

// adviceFor is the client's advice from the server's and whether a release verified here (R5 rounds 2, 3):
//   - verified: a warning stays a warning (caution_conflicting as it is, any other as the fixed one);
//     every other word, positive or not, becomes signed_by_alalanet (F1, R2-1);
//   - not verified: the closed set passes, a warning becomes the fixed one, anything else — an "ours"
//     look-alike above all — becomes signed_by_new_publisher (releases listed) or unknown_hash (F2).
func adviceFor(server string, verified, listed bool) string {
	switch {
	case server == "caution_conflicting" || server == serverWarningAdvice:
		return server
	case serverWarning.MatchString(server):
		return serverWarningAdvice
	case verified:
		return "signed_by_alalanet"
	case relayed(server):
		return server
	case listed:
		return "signed_by_new_publisher"
	}
	return "unknown_hash"
}

// ClientReleaseReady says whether pins are a client release's: valid, with the offline key pinned. No
// alalanet-agent ships trusting the server key alone (ADR-0109, round R5-2); `make release-agent` runs
// TestClientReleasePins, which checks this build's pins with it (R5-3, R2-5).
func ClientReleaseReady(p ReleasePins) error {
	if err := p.Check(); err != nil {
		return err
	}
	if p.Offline == "" {
		return errors.New("this build pins no offline release key (agentkit.ReleasePinOffline is empty): the first alalanet-agent that checks releases ships with both pins; pin the owner's key first, or build from a commit before R5")
	}
	return nil
}

// releaseName is the name a release of this file is expected under: the file's own name without .exe, as
// release-sign names it.
func releaseName(file string) string {
	return strings.ToLower(strings.TrimSuffix(filepath.Base(file), ".exe"))
}

// checkReleases decides signed_by_alalanet from the answer as alalanet sent it (raw: each event is
// checked as signed, before any cleaning) and writes the verdict into the cleaned answer out. Among
// several releases that verify, the one named like the file is shown (F10); its name@version goes to the
// top of the answer, with a note when it is not the file's.
func checkReleases(raw, out map[string]any, sha, file string, pins ReleasePins) {
	var found *Release
	want := releaseName(file)
	matches := func(r *Release) bool { n, _, _ := strings.Cut(r.NameVersion, "@"); return n == want }
	rs, _ := raw["releases"].([]any)
	for _, r := range rs {
		m, _ := r.(map[string]any)
		js, _ := m["event"].(string)
		var ev nostr.Event
		if js == "" || ev.UnmarshalJSON([]byte(js)) != nil {
			continue
		}
		if rel, err := VerifyRelease(ev, sha, pins); err == nil && (found == nil || !matches(found) && matches(&rel)) {
			found = &rel
		}
	}
	server, _ := out["advice"].(string)
	advice := adviceFor(server, found != nil, len(rs) > 0)
	// The fields this check writes are the client's alone: none of them is ever the server's (R2-2).
	delete(out, "name_version")
	delete(out, "server_advice")
	delete(out, "release_check")
	keys := make([]any, 0, 2)
	for _, k := range pins.Keys() {
		keys = append(keys, k)
	}
	rc := map[string]any{"verified": found != nil, "pinned_keys": keys,
		"note": "Checked on this machine: the release event's signature, its sha256 against this file and its signer against the release keys pinned in this alalanet-agent. alalanet's answer alone never makes a file signed_by_alalanet."}
	if found != nil {
		rc["event_id"], rc["name_version"], rc["signer"], rc["key"] = found.ID, found.NameVersion, found.Signer, found.Key
		rc["name_matches_file"] = matches(found)
		if !matches(found) {
			rc["name_note"] = "This file was released as " + found.NameVersion + ", not under its own name " + filepath.Base(file) +
				": check that this is the program and version you meant to install."
		}
		out["name_version"] = found.NameVersion
	}
	out["release_check"] = rc
	if advice != server {
		out["server_advice"] = server
		out["advice"] = advice
	}
}
