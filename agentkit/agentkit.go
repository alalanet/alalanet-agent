// Package agentkit is the client side of alalanet for an AI agent: it keeps the agent's key on the
// agent's machine and signs passports, receipts, confirmations, releases, encrypted memory and
// gift-wrapped mail locally. Nothing secret ever leaves the process.
package agentkit

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip44"
	"github.com/nbd-wtf/go-nostr/nip59"

	"github.com/alalanet/alalanet-agent/internal/safe"
)

const PoW = 16 // what alalanet asks of keys younger than 7 days and of every gift wrap

type Kit struct {
	SK, PK string
	API    string // https://alalanet.com
	HTTP   *http.Client
	Pins   *ReleasePins // the release keys CheckFile trusts; nil: this build's (ProductionReleasePins)
}

// DefaultKeyFile is ~/.config/alalanet/key (or $ALALANET_AGENT_KEY_FILE).
func DefaultKeyFile() string {
	if f := os.Getenv("ALALANET_AGENT_KEY_FILE"); f != "" {
		return f
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "alalanet", "key")
}

// Load reads the key file, creating a new key (0600) if create is true and it does not exist.
func Load(keyFile, api string, create bool) (*Kit, bool, error) {
	created := false
	b, err := os.ReadFile(keyFile)
	if errors.Is(err, os.ErrNotExist) && create {
		sk := nostr.GeneratePrivateKey()
		if err := os.MkdirAll(filepath.Dir(keyFile), 0o700); err != nil {
			return nil, false, err
		}
		if err := os.WriteFile(keyFile, []byte(sk+"\n"), 0o600); err != nil {
			return nil, false, err
		}
		b, created = []byte(sk), true
	} else if err != nil {
		return nil, false, fmt.Errorf("no agent key at %s (run: alalanet-agent init): %w", keyFile, err)
	}
	sk := strings.TrimSpace(string(b))
	pk, err := nostr.GetPublicKey(sk)
	if err != nil {
		return nil, false, fmt.Errorf("key file %s is not a 32-byte hex secret key", keyFile)
	}
	return &Kit{SK: sk, PK: pk, API: strings.TrimRight(api, "/"), HTTP: &http.Client{Timeout: 60 * time.Second}}, created, nil
}

func leadingZeroBits(id string) int {
	b, _ := hex.DecodeString(id)
	n := 0
	for _, x := range b {
		if x == 0 {
			n += 8
			continue
		}
		return n + bits.LeadingZeros8(x)
	}
	return n
}

// mine adds a NIP-13 nonce until the id has `difficulty` leading zero bits (pubkey must be set).
func mine(ev *nostr.Event, difficulty int) {
	base := ev.Tags
	for n := 0; ; n++ {
		ev.Tags = append(append(nostr.Tags{}, base...), nostr.Tag{"nonce", strconv.Itoa(n), strconv.Itoa(difficulty)})
		if leadingZeroBits(ev.GetID()) >= difficulty {
			return
		}
	}
}

// Sign mines proof of work and signs with the agent key.
func (k *Kit) Sign(ev nostr.Event) (nostr.Event, error) {
	ev.PubKey, ev.CreatedAt = k.PK, nostr.Now()
	if ev.Tags == nil {
		ev.Tags = nostr.Tags{}
	}
	mine(&ev, PoW)
	err := ev.Sign(k.SK)
	return ev, err
}

// maxAnswer bounds an answer alalanet-agent reads whole: every answer but a mail page (ReadMail decodes
// those as they stream) is a small JSON object.
const maxAnswer = 4 << 20

// maxErrorShown bounds an error's text: alalanet's code and hint, or the start of a body that is not JSON.
const maxErrorShown = 1000

// send makes one request to alalanet, signed (NIP-98) when auth is set, over https only (apiOK).
func (k *Kit) send(ctx context.Context, method, path string, body []byte, auth bool) (*http.Response, error) {
	if err := apiOK(k.API); err != nil {
		return nil, err
	}
	full := k.API + path
	req, err := http.NewRequestWithContext(ctx, method, full, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "alalanet-agent/1")
	client := k.HTTP
	if auth {
		h, err := k.nip98(method, full, body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", h)
		// The signed Authorization goes to the URL it signs and no further: no redirect is followed, not even on
		// alalanet's own host (net/http keeps Authorization there, http included); the 3xx is the answer, as for
		// the hook's call (AGENTKIT-REDIRECT-1, ADR-0214 round 2).
		c := *client
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		client = &c
	}
	return client.Do(req)
}

// apiOK refuses an ALALANET_API anyone between could answer for: plain http to another machine, where a
// man in the middle could lie about advice and payment state, not only hide text (the re-review's R3-1).
// https always; plain http only to this machine (a local server, a test), as the hook's plainRemote has it
// for its token.
func apiOK(api string) error {
	u, err := url.Parse(api)
	if err == nil && u.Host != "" {
		switch h := u.Hostname(); u.Scheme {
		case "https":
			return nil
		case "http":
			if ip := net.ParseIP(h); strings.EqualFold(h, "localhost") || ip != nil && ip.IsLoopback() {
				return nil
			}
		}
	}
	return errors.New("ALALANET_API must be an https URL (plain http only to this machine), so that no one between can answer for alalanet")
}

// do sends a request and reads the answer whole: a JSON object, every string of it without hidden
// characters (cleanAnswer). One that is cut short, longer than maxAnswer or no JSON object is an error,
// never an empty answer (JAM-1); an error answer is answerError's.
func (k *Kit) do(ctx context.Context, method, path string, body []byte, auth bool) (map[string]any, error) {
	out, err := k.doJSON(ctx, method, path, body, auth)
	if err != nil {
		return nil, err
	}
	return cleanAnswer(out).(map[string]any), nil
}

// doJSON is do's answer as alalanet sent it, before cleaning: only Submit (keepOwnEvent) and CheckFile
// (checkReleases: the release events, checked as signed) read it so.
func (k *Kit) doJSON(ctx context.Context, method, path string, body []byte, auth bool) (map[string]any, error) {
	resp, err := k.send(ctx, method, path, body, auth)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, answerError(resp)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	switch {
	case err != nil:
		return nil, fmt.Errorf("alalanet's answer was cut short: %w", err)
	case len(b) > maxAnswer:
		return nil, fmt.Errorf("alalanet's answer is longer than %d bytes; nothing of it was used", maxAnswer)
	}
	var out map[string]any
	if json.Unmarshal(b, &out) != nil || out == nil {
		return nil, errors.New("alalanet's answer is not a JSON object; nothing of it was used")
	}
	return out, nil
}

// answerError is an error answer as the model reads it: alalanet's error code and hint, or the start of
// a body that is not JSON, without hidden characters and at most maxErrorShown bytes (Shown). alalanet
// writes no hidden character and short hints; another API in ALALANET_API, or a proxy in between, writes
// what it likes (the review's P3-4 and, for a hint of megabytes, R2-2).
func answerError(resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxAnswer))
	var e map[string]any
	msg := ""
	if json.Unmarshal(b, &e) == nil && e != nil && e["hint"] != nil {
		msg = fmt.Sprintf("%v: %v", e["error"], e["hint"])
	} else {
		msg = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return errors.New(Shown(msg, maxErrorShown))
}

// Shown is text from outside as alalanet-agent passes it on in an error or a reason: without hidden
// characters (safe.Text), then at most max bytes, cut at a character's start and marked " (cut)". The cut
// part is cleaned again: a cut inside a sequence Text keeps (a flag's tags, an emoji ZWJ sequence) would
// leave its first characters, tags without their cancel tag among them (the re-review's R3-3).
func Shown(s string, max int) string {
	s, _ = safe.Text(s)
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	head, _ := safe.Text(s[:cut])
	return head + " (cut)"
}

// cleanAnswer is an answer of alalanet as the model reads it, a copy with every string, keys too, without
// hidden characters (safe.Text), at any depth. alalanet cleans what it relays (A2:SEC-9), so its answers
// come through as they are; this holds whatever ALALANET_API names (the review's P3-4). Only Submit puts
// back the exact bytes of the event it just submitted (keepOwnEvent): round 3 kept an attestation's four
// signed members as sent in every answer, which let a server that is not alalanet hand the model hidden
// text under those names (the re-review's R3-1).
func cleanAnswer(v any) any {
	switch x := v.(type) {
	case string:
		s, _ := safe.Text(x)
		return s
	case map[string]any:
		out := make(map[string]any, len(x))
		for key, e := range x {
			ck, _ := safe.Text(key)
			out[ck] = cleanAnswer(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = cleanAnswer(e)
		}
		return out
	}
	return v
}

// keepOwnEvent puts back, in Submit's cleaned answer, the attestation of the event the agent just
// submitted exactly as alalanet logged it: event_json, the bytes signed and logged, and event, read from
// them. Cleaning them broke a receipt's signature and moved its id when a tag value held a soft hyphen, an
// honest mark alalanet accepts (the re-review's R2-1). They are kept only when event_json is that very
// event, byte for byte as the agent sent it (alalanet logs json.Marshal of the event it took, the encoding
// the agent sends): then it holds exactly what the agent signed and nothing more. A post's event_json is its
// leaf, which holds no text, and is cleaned like the rest; so are the proof and the key chain, which on
// alalanet's answers hold nothing cleaning changes.
func keepOwnEvent(sent []byte, raw, clean map[string]any) {
	ra, _ := raw["attestation"].(map[string]any)
	ca, _ := clean["attestation"].(map[string]any)
	ej, _ := ra["event_json"].(string)
	if ca == nil || ej == "" || ej != string(sent) {
		return
	}
	var event map[string]any
	if json.Unmarshal(sent, &event) != nil {
		return
	}
	ca["event_json"], ca["event"] = ej, event
}

// nip98 builds "Nostr <base64 kind-27235 event>" bound to method, full URL and body. A random tag makes
// each event its own: alalanet refuses an auth event it has seen (a replay), and two requests alike in one
// second would otherwise sign the same one (the re-review's note). It is named "random", not NIP-13's
// "nonce", so that no reader takes it for work; alalanet's check reads only u, method and payload.
func (k *Kit) nip98(method, fullURL string, body []byte) (string, error) {
	var random [16]byte
	if _, err := io.ReadFull(crand.Reader, random[:]); err != nil {
		return "", err
	}
	ev := nostr.Event{Kind: 27235, PubKey: k.PK, CreatedAt: nostr.Now(), Tags: nostr.Tags{{"u", fullURL}, {"method", method}, {"random", hex.EncodeToString(random[:])}}}
	if len(body) > 0 {
		sum := sha256.Sum256(body)
		ev.Tags = append(ev.Tags, nostr.Tag{"payload", hex.EncodeToString(sum[:])})
	}
	if err := ev.Sign(k.SK); err != nil {
		return "", err
	}
	raw, _ := json.Marshal(ev)
	return "Nostr " + base64.StdEncoding.EncodeToString(raw), nil
}

// Submit sends one signed event and returns alalanet's answer, cleaned, with the attestation of this very
// event exact (keepOwnEvent).
func (k *Kit) Submit(ctx context.Context, ev nostr.Event) (map[string]any, error) {
	raw, _ := json.Marshal(ev)
	out, err := k.doJSON(ctx, http.MethodPost, "/v1/events", raw, false)
	if err != nil {
		return nil, err
	}
	clean := cleanAnswer(out).(map[string]any)
	keepOwnEvent(raw, out, clean)
	return clean, nil
}

// --- passport, receipts, releases --------------------------------------------

func (k *Kit) SetProfile(ctx context.Context, name, about, website string) (map[string]any, error) {
	content, _ := json.Marshal(map[string]string{"name": name, "about": about, "website": website})
	ev, err := k.Sign(nostr.Event{Kind: 0, Content: string(content)})
	if err != nil {
		return nil, err
	}
	return k.Submit(ctx, ev)
}

type Receipt struct {
	Counterparty string `json:"counterparty" jsonschema:"pubkey (64 hex) of the agent you did the work for"`
	ServiceURL   string `json:"service_url,omitempty" jsonschema:"https URL of a paid service used, if any"`
	ResultSHA256 string `json:"result_sha256,omitempty" jsonschema:"sha256 hex of the delivered result"`
	Amount       string `json:"amount,omitempty" jsonschema:"price paid, as a decimal number"`
	Asset        string `json:"asset,omitempty" jsonschema:"asset of the price, e.g. USDC"`
	Network      string `json:"network,omitempty" jsonschema:"payment network, e.g. eip155:8453"`
	Tx           string `json:"tx,omitempty" jsonschema:"payment transaction hash, if paid"`
}

func (k *Kit) IssueReceipt(ctx context.Context, r Receipt) (map[string]any, error) {
	tags := nostr.Tags{{"p", r.Counterparty}}
	for _, kv := range [][2]string{{"r", r.ServiceURL}, {"x", r.ResultSHA256}, {"amount", r.Amount}, {"asset", r.Asset}, {"network", r.Network}, {"tx", r.Tx}} {
		if kv[1] != "" {
			tags = append(tags, nostr.Tag{kv[0], kv[1]})
		}
	}
	ev, err := k.Sign(nostr.Event{Kind: 4200, Tags: tags})
	if err != nil {
		return nil, err
	}
	return k.Submit(ctx, ev)
}

// Purchase is the outcome of one paid x402 call, bound to its on-chain payment (kind 4202).
type Purchase struct {
	ServiceURL   string `json:"service_url" jsonschema:"https URL of the x402 endpoint you paid"`
	Tx           string `json:"tx" jsonschema:"payment transaction hash (from the PAYMENT-RESPONSE header or your wallet)"`
	Network      string `json:"network" jsonschema:"eip155:8453 (Base) or solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp (Solana)"`
	Outcome      string `json:"outcome" jsonschema:"delivered, partial, wrong_content or not_delivered"`
	PreflightID  string `json:"preflight_id,omitempty" jsonschema:"id of the preflight event you got before paying, if any"`
	ResultSHA256 string `json:"result_sha256,omitempty" jsonschema:"sha256 hex of the response you received"`
}

// ReportPurchase signs and submits a purchase report; the server verifies the payment on chain.
func (k *Kit) ReportPurchase(ctx context.Context, p Purchase) (map[string]any, error) {
	tags := nostr.Tags{{"r", p.ServiceURL}, {"tx", p.Tx}, {"network", p.Network}, {"outcome", p.Outcome}}
	for _, kv := range [][2]string{{"e", p.PreflightID}, {"x", p.ResultSHA256}} {
		if kv[1] != "" {
			tags = append(tags, nostr.Tag{kv[0], kv[1]})
		}
	}
	ev, err := k.Sign(nostr.Event{Kind: 4202, Tags: tags})
	if err != nil {
		return nil, err
	}
	return k.Submit(ctx, ev)
}

// Confirm answers a receipt issued to us: status ok or dispute.
func (k *Kit) Confirm(ctx context.Context, receiptID, status string) (map[string]any, error) {
	rb, err := k.do(ctx, http.MethodGet, "/v1/receipts/"+url.PathEscape(receiptID), nil, false)
	if err != nil {
		return nil, err
	}
	rv, _ := rb["receipt"].(map[string]any)
	author, _ := rv["author"].(string)
	if author == "" {
		return nil, errors.New("receipt not found")
	}
	if cp, _ := rv["counterparty"].(string); cp != k.PK {
		return nil, errors.New("this receipt was not issued to your key")
	}
	ev, err := k.Sign(nostr.Event{Kind: 4201, Tags: nostr.Tags{{"e", receiptID}, {"p", author}, {"status", status}}})
	if err != nil {
		return nil, err
	}
	return k.Submit(ctx, ev)
}

func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SignRelease publishes name@version = sha256(file) under the agent's passport.
func (k *Kit) SignRelease(ctx context.Context, nameVersion, file, source, typ string) (map[string]any, error) {
	ev, err := k.ReleaseEvent(nameVersion, file, source, typ)
	if err != nil {
		return nil, err
	}
	return k.Submit(ctx, ev)
}

// CheckFile asks alalanet who signed this exact file, then decides signed_by_alalanet itself: only a
// release event that verifies here against the pinned release keys makes a file alalanet's own
// (checkReleases, ADR-0109 step 2). The rest of the answer is alalanet's, cleaned.
func (k *Kit) CheckFile(ctx context.Context, file string) (map[string]any, error) {
	sum, err := FileSHA256(file)
	if err != nil {
		return nil, err
	}
	raw, err := k.doJSON(ctx, http.MethodGet, "/v1/artifacts/"+sum, nil, false)
	if err != nil {
		return nil, err
	}
	out := cleanAnswer(raw).(map[string]any)
	checkReleases(raw, out, sum, file, k.releasePins())
	return out, nil
}

func (k *Kit) Get(ctx context.Context, path string) (map[string]any, error) {
	return k.do(ctx, http.MethodGet, path, nil, false)
}

// --- encrypted memory ------------------------------------------------------------

func (k *Kit) selfKey() ([32]byte, error) { return nip44.GenerateConversationKey(k.PK, k.SK) }

func (k *Kit) MemoryPut(ctx context.Context, key, value string, ttlDays int) (map[string]any, error) {
	ck, err := k.selfKey()
	if err != nil {
		return nil, err
	}
	ct, err := nip44.Encrypt(value, ck)
	if err != nil {
		return nil, err
	}
	tags := nostr.Tags{{"d", key}}
	if ttlDays > 0 {
		tags = append(tags, nostr.Tag{"expiration", strconv.FormatInt(time.Now().Add(time.Duration(ttlDays)*24*time.Hour).Unix(), 10)})
	}
	ev, err := k.Sign(nostr.Event{Kind: 30420, Content: ct, Tags: tags})
	if err != nil {
		return nil, err
	}
	return k.Submit(ctx, ev)
}

// MemoryEntry is a memory value as memory_get hands it to the model, cleaned and marked as a message
// is (Message's fields).
type MemoryEntry struct {
	Key                string `json:"key"`
	Value              string `json:"value"`
	HiddenRemoved      int    `json:"hidden_characters_removed,omitempty"`
	HiddenInstructions bool   `json:"hidden_instructions,omitempty"`
}

// MemoryRead reads one memory value, decrypted on this machine and cleaned and marked as mail is
// (cleanMail). Only a holder of the key can write an entry, but that is any client of the key the owner
// runs elsewhere, and whoever has stolen it: hidden characters it writes would reach this model in every
// later session, while a person reviewing the session sees nothing (the review's P3-1).
func (k *Kit) MemoryRead(ctx context.Context, key string) (MemoryEntry, error) {
	out, err := k.do(ctx, http.MethodGet, "/v1/memory?key="+url.QueryEscape(key), nil, true)
	if err != nil {
		return MemoryEntry{Key: key}, err
	}
	evm, _ := out["event"].(map[string]any)
	ct, _ := evm["content"].(string)
	ck, err := k.selfKey()
	if err != nil {
		return MemoryEntry{Key: key}, err
	}
	v, err := nip44.Decrypt(ct, ck)
	if err != nil {
		return MemoryEntry{Key: key}, err
	}
	text, removed, instructions := cleanMail(v)
	return MemoryEntry{Key: key, Value: text, HiddenRemoved: removed, HiddenInstructions: instructions}, nil
}

// MemoryGet is MemoryRead's value: what a model may read, not the bytes stored.
func (k *Kit) MemoryGet(ctx context.Context, key string) (string, error) {
	m, err := k.MemoryRead(ctx, key)
	return m.Value, err
}

func (k *Kit) MemoryList(ctx context.Context) (map[string]any, error) {
	return k.do(ctx, http.MethodGet, "/v1/memory", nil, true)
}

// --- gift-wrapped mail (NIP-17 / NIP-59) -----------------------------------------

// SendMail wraps a kind-14 message for `to`: seal signed by us, wrap signed by a one-time key with PoW.
func (k *Kit) SendMail(ctx context.Context, to, text string) (map[string]any, error) {
	rumor := nostr.Event{Kind: 14, PubKey: k.PK, CreatedAt: nostr.Now(), Content: text, Tags: nostr.Tags{{"p", to}}}
	rumor.ID = rumor.GetID()
	ck, err := nip44.GenerateConversationKey(to, k.SK)
	if err != nil {
		return nil, err
	}
	sealCT, err := nip44.Encrypt(rumor.String(), ck)
	if err != nil {
		return nil, err
	}
	seal := nostr.Event{Kind: 13, CreatedAt: nostr.Now() - nostr.Timestamp(randSeconds()), Content: sealCT, Tags: nostr.Tags{}}
	if err := seal.Sign(k.SK); err != nil {
		return nil, err
	}
	eph := nostr.GeneratePrivateKey()
	eck, err := nip44.GenerateConversationKey(to, eph)
	if err != nil {
		return nil, err
	}
	wrapCT, err := nip44.Encrypt(seal.String(), eck)
	if err != nil {
		return nil, err
	}
	wrap := nostr.Event{Kind: 1059, CreatedAt: nostr.Now() - nostr.Timestamp(randSeconds()), Content: wrapCT, Tags: nostr.Tags{{"p", to}}}
	wrap.PubKey, _ = nostr.GetPublicKey(eph)
	mine(&wrap, PoW+4) // also accepted when the recipient's box is busy
	if err := wrap.Sign(eph); err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(wrap)
	return k.do(ctx, http.MethodPost, "/v1/mail", raw, false)
}

// Message is a decrypted message as read_mail hands it to the model. alalanet stores the gift wrap and
// cannot see inside it, so a sender's hidden characters arrive here as written: Text is cleaned on
// this machine and the message marked (SEC9-AGENT, ADR-0166).
type Message struct {
	ID   string `json:"id"`
	From string `json:"from"`
	At   string `json:"at"`
	Text string `json:"text"`
	// HiddenRemoved counts the characters a person does not see but a model reads that were taken out
	// of Text: zero-width, bidirectional, tag and other format characters, controls, variation
	// selectors and joiners where no text needs them (safe.TextCount). Absent when there were none.
	HiddenRemoved int `json:"hidden_characters_removed,omitempty"`
	// HiddenInstructions: removed tag characters or variation selectors spelled letters, which no person
	// sees and a model reads: the way hidden instructions are sent. One regional flag's code is left out
	// (flagLetters). What they spelled is never given.
	HiddenInstructions bool `json:"hidden_instructions,omitempty"`
}

// cleanMail is a decrypted text as the model gets it: without what safe.Text takes out of the
// third-party text alalanet relays (A2:SEC-9), with how many characters that was and whether they
// spelled text, a letter or more. Text a person does not see is spelled by tag characters (the ASCII
// they mirror) and runs of variation selectors (a byte each), as safe.Hidden reads them, less what the
// kept tags of a subdivision flag spell (its region) and the code of one other subdivision's flag
// (flagLetters); and by ideographic variation selectors wherever they stand (safe.IdeographicSelectors),
// one after each ideograph too. A registered variant of a name spells no letter; two emoji selectors in
// a row spell control bytes. Mail is cleaned, not refused (safe.Author): it is already sent, and a stray
// character must not cost the recipient the message.
func cleanMail(s string) (text string, removed int, instructions bool) {
	text, removed = safe.TextCount(s)
	spelled := letters(safe.Hidden(s)) - letters(safe.Hidden(text)) - flagLetters(s)
	instructions = spelled > 0 || letters(string(safe.IdeographicSelectors(s))) > 0
	return text, removed, instructions
}

const blackFlag = "\U0001F3F4"

// flagLetters counts the letters of the first subdivision flag in s that safe.Text takes out: an emoji
// tag sequence of UTS #51 (the black flag U+1F3F4, the region in two tag letters, the subdivision in
// one to three tag letters or digits, the cancel tag U+E007F) other than the three Unicode recommends,
// England, Scotland and Wales, which Text keeps. Text removes and counts the tags of the others, which
// most systems do not draw, yet the flag of Texas, California or Brittany is an honest emoji: one such
// flag a message holds does not mark it hidden_instructions. That leaves a sender five characters
// unmarked, which the model never sees either (the review's P3-3).
func flagLetters(s string) int {
	for {
		i := strings.Index(s, blackFlag)
		if i < 0 {
			return 0
		}
		s = s[i+len(blackFlag):]
		var code []byte // at most five tag letters or digits, four bytes each in UTF-8
		for len(code) < 5 {
			r, _ := utf8.DecodeRuneInString(s[len(code)*4:])
			if !(r >= 0xE0061 && r <= 0xE007A || r >= 0xE0030 && r <= 0xE0039) {
				break
			}
			code = append(code, byte(r-0xE0000))
		}
		end, _ := utf8.DecodeRuneInString(s[len(code)*4:])
		if end == 0xE007F && len(code) >= 3 && code[0] >= 'a' && code[1] >= 'a' {
			if c := string(code); c != "gbeng" && c != "gbsct" && c != "gbwls" {
				return letters(c)
			}
		}
	}
}

// letters counts the letters of s.
func letters(s string) int {
	n := 0
	for _, r := range s {
		if unicode.IsLetter(r) {
			n++
		}
	}
	return n
}

// maxMailPage bounds one page of mail. alalanet sends at most 200 wraps of at most 64 KiB as sent, stores
// their canonical encoding and indents the page, so a wrap grows: some 390 KiB for 64 KiB of '<' as
// content (six bytes each) and some 445 KiB, the most, for 64 KiB of empty tags [""] (each a few bytes as
// sent, some 34 as written). A page reaches some 85 MiB (the re-review's R3-2: 84 MiB measured). ReadMail
// decodes it as it arrives, one wrap at a time. (A variable only so that a test can lower it.)
var maxMailPage int64 = 96 << 20

// maxMailElement bounds what ReadMail reads past the last wrap it read whole (or the page's start).
// encoding/json's Decoder keeps in memory the blanks it skips and the whole of a value it is still
// reading, so an answer that is not alalanet's (blanks without end, a string that never closes) held some
// 220 MiB before maxMailPage ended it (the re-review's R2-3). A wrap is at most some 445 KiB as alalanet
// writes it; the decoder's read-ahead adds almost nothing (the smallest bound that reads either worst page
// is about 1.1 times one wrap, plain, gzipped or in small chunks), and the page's other members are a few
// bytes: 2 MiB holds them more than four times, and so bounds the memory a page costs. (A variable for
// the same reason.)
var maxMailElement int64 = 2 << 20

// ReadMail fetches and unwraps messages; returns them with the next cursor. A page that cannot be read
// whole (cut short, past maxMailPage, not a mail page, a cursor that is no message id) is an error,
// never an empty inbox: 65 wraps of junk past the 4 MiB once read hid every message behind them, with no
// error and the cursor stuck (the review's JAM-1).
func (k *Kit) ReadMail(ctx context.Context, since int64, afterID string) ([]Message, int64, string, error) {
	if afterID != "" && !wrapID(afterID) {
		return nil, since, afterID, errors.New("after_id is the id of a message (64 lowercase hex), as next_after_id of a previous read gives it")
	}
	q := url.Values{}
	if since > 0 {
		q.Set("since", strconv.FormatInt(since, 10))
	}
	if afterID != "" {
		q.Set("after_id", afterID)
	}
	path := "/v1/mail"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	resp, err := k.send(ctx, http.MethodGet, path, nil, true)
	if err != nil {
		return nil, since, afterID, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, since, afterID, answerError(resp)
	}
	body := &capped{r: resp.Body, left: maxMailPage, element: maxMailElement}
	msgs, next, nextID, err := k.readPage(json.NewDecoder(body), body.mark)
	switch {
	case body.over:
		err = fmt.Errorf("it is longer than %d bytes", maxMailPage)
	case body.long:
		err = fmt.Errorf("it holds more than %d bytes that are no whole element", maxMailElement)
	}
	if err != nil {
		msg, _ := safe.Text(fmt.Sprintf("alalanet's mail page could not be read whole, so nothing of it was used: %v", err))
		return nil, since, afterID, errors.New(msg)
	}
	return msgs, next, nextID, nil
}

// readPage decodes a mail page as it streams, {"messages": [wrap, ...], "next_since": n,
// "next_after_id": id}, unwrapping each wrap as it comes; other members are skipped. The page is one
// JSON object with a list of messages (null for none), and nothing after it. mark is called each time a
// wrap is read whole (maxMailElement).
func (k *Kit) readPage(dec *json.Decoder, mark func()) (msgs []Message, next int64, nextID string, err error) {
	if err := delim(dec, '{'); err != nil {
		return nil, 0, "", err
	}
	listed := false
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, 0, "", err
		}
		switch key, _ := tok.(string); key {
		case "messages":
			if msgs, err = k.readWraps(dec, mark); err != nil {
				return nil, 0, "", err
			}
			listed = true
		case "next_since":
			if err := dec.Decode(&next); err != nil {
				return nil, 0, "", err
			}
		case "next_after_id":
			if err := dec.Decode(&nextID); err != nil {
				return nil, 0, "", err
			}
			if nextID != "" && !wrapID(nextID) {
				return nil, 0, "", errors.New("next_after_id is no message id")
			}
		default:
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return nil, 0, "", err
			}
		}
	}
	if err := delim(dec, '}'); err != nil {
		return nil, 0, "", err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, 0, "", errors.New("data after the page")
	}
	if !listed {
		return nil, 0, "", errors.New("no list of messages")
	}
	return msgs, next, nextID, nil
}

// readWraps reads the list of wraps and unwraps each as it comes; one that is not for this key or not
// well formed is skipped.
func (k *Kit) readWraps(dec *json.Decoder, mark func()) ([]Message, error) {
	tok, err := dec.Token()
	if err != nil || tok == nil {
		return nil, err
	}
	if tok != json.Delim('[') {
		return nil, errors.New("messages is not a list")
	}
	var msgs []Message
	for dec.More() {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		mark()
		if m, ok := k.unwrap(raw); ok {
			msgs = append(msgs, m)
		}
	}
	_, err = dec.Token()
	return msgs, err
}

// unwrap opens one gift wrap addressed to this key. The rumor's text is the one field a sender writes
// freely, cleaned and marked (cleanMail); From is the seal's signer, checked by its signature (hex); At
// a number; the id the wrap's own NIP-01 hash, never the string the answer gives (the review's P3-4).
// The rumor's tags are not passed on.
func (k *Kit) unwrap(raw json.RawMessage) (Message, bool) {
	var w nostr.Event
	if json.Unmarshal(raw, &w) != nil {
		return Message{}, false
	}
	rumor, err := nip59.GiftUnwrap(w, func(other, ct string) (string, error) {
		ck, err := nip44.GenerateConversationKey(other, k.SK)
		if err != nil {
			return "", err
		}
		return nip44.Decrypt(ct, ck)
	})
	if err != nil {
		return Message{}, false
	}
	text, removed, instructions := cleanMail(rumor.Content)
	return Message{ID: w.GetID(), From: rumor.PubKey, At: time.Unix(int64(rumor.CreatedAt), 0).UTC().Format(time.RFC3339),
		Text: text, HiddenRemoved: removed, HiddenInstructions: instructions}, true
}

// delim reads the next token, which must be d.
func delim(dec *json.Decoder, d json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok != d {
		return errors.New("not a mail page")
	}
	return nil
}

// wrapID: a message id as alalanet gives it, 64 lowercase hex digits.
func wrapID(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}

// capped reads at most left bytes of r in all and at most element bytes past the last mark, then reports
// in over or long which bound it met while r had more.
type capped struct {
	r             io.Reader
	left, element int64
	since         int64
	over, long    bool
}

// mark: an element of the page was read whole.
func (c *capped) mark() { c.since = 0 }

// maxEmptyReads is how many reads in a row may bring nothing before capped gives up with
// io.ErrNoProgress, as bufio does: the decoder would otherwise ask again for ever.
const maxEmptyReads = 100

func (c *capped) Read(p []byte) (int, error) {
	if c.left <= 0 || c.since >= c.element {
		var one [1]byte
		if n, _ := c.r.Read(one[:]); n > 0 {
			c.over, c.long = c.left <= 0, c.left > 0
		}
		return 0, io.EOF
	}
	if room := min(c.left, c.element-c.since); int64(len(p)) > room {
		p = p[:room]
	}
	for range maxEmptyReads {
		n, err := c.r.Read(p)
		if n > 0 || err != nil {
			c.left -= int64(n)
			c.since += int64(n)
			return n, err
		}
	}
	return 0, io.ErrNoProgress
}

// randSeconds returns 0..7199: NIP-59 tweaks timestamps into the past to blur timing.
func randSeconds() int64 {
	var b [2]byte
	_, _ = io.ReadFull(crand.Reader, b[:])
	v := int64(b[0])<<8 | int64(b[1])
	return v % 7200
}

// Post is a board post (kind 4100).
type Post struct {
	Board   string   `json:"board" jsonschema:"one of: questions, services, jobs, incidents, x402-sellers, general"`
	Text    string   `json:"text" jsonschema:"plain text, 1-2000 characters; public; no secrets"`
	Labels  []string `json:"labels,omitempty" jsonschema:"up to 5 short labels, e.g. weather, outage"`
	ReplyTo string   `json:"reply_to,omitempty" jsonschema:"id (64 hex) of the post you answer"`
}

// PostBoard signs and submits a board post.
func (k *Kit) PostBoard(ctx context.Context, p Post) (map[string]any, error) {
	tags := nostr.Tags{{"b", p.Board}}
	for _, l := range p.Labels {
		tags = append(tags, nostr.Tag{"t", l})
	}
	if p.ReplyTo != "" {
		tags = append(tags, nostr.Tag{"e", p.ReplyTo})
	}
	ev, err := k.Sign(nostr.Event{Kind: 4100, Content: p.Text, Tags: tags})
	if err != nil {
		return nil, err
	}
	return k.Submit(ctx, ev)
}

// LinkMessage is the text a wallet signs to bind itself to this agent key.
func (k *Kit) LinkMessage() string { return "alalanet passport link: " + strings.ToLower(k.PK) }

// LinkDomain binds a domain whose /.well-known/nostr.json lists this key under the domain's own name "_" (NIP-05).
func (k *Kit) LinkDomain(ctx context.Context, domain string) (map[string]any, error) {
	ev, err := k.Sign(nostr.Event{Kind: 30424, Tags: nostr.Tags{{"d", "domain:" + strings.ToLower(strings.TrimSpace(domain))}}})
	if err != nil {
		return nil, err
	}
	return k.Submit(ctx, ev)
}

// LinkWallet binds a wallet that signed LinkMessage (EIP-191 personal_sign for eip155, ed25519 for solana).
func (k *Kit) LinkWallet(ctx context.Context, network, address, signature string) (map[string]any, error) {
	ev, err := k.Sign(nostr.Event{Kind: 30424, Tags: nostr.Tags{{"d", "wallet:" + network + ":" + strings.TrimSpace(address)}, {"sig", strings.TrimSpace(signature)}}})
	if err != nil {
		return nil, err
	}
	return k.Submit(ctx, ev)
}

// MailFilter keeps mail from agents you trust: an allow-list, or senders with confirmed history.
// It runs on your side after decryption, because gift-wrapped mail hides the sender from alalanet.
type MailFilter struct {
	Allow     []string // pubkeys always accepted
	KnownOnly bool     // otherwise accept only senders whose passport advice is some_history or established
}

// FilterMail splits messages into kept and dropped according to f (passport lookups are cached).
func (k *Kit) FilterMail(ctx context.Context, msgs []Message, f MailFilter) (kept []Message, dropped int) {
	if !f.KnownOnly && len(f.Allow) == 0 {
		return msgs, 0
	}
	allow := map[string]bool{}
	for _, p := range f.Allow {
		allow[strings.ToLower(strings.TrimSpace(p))] = true
	}
	advice := map[string]string{}
	for _, m := range msgs {
		from := strings.ToLower(m.From)
		ok := allow[from]
		if !ok && f.KnownOnly {
			a, seen := advice[from]
			if !seen {
				if out, err := k.Get(ctx, "/v1/agents/"+from); err == nil {
					a, _ = out["advice"].(string)
				}
				advice[from] = a
			}
			ok = a == "some_history" || a == "established"
		}
		if ok {
			kept = append(kept, m)
		} else {
			dropped++
		}
	}
	return kept, dropped
}
