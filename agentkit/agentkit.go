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
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip44"
	"github.com/nbd-wtf/go-nostr/nip59"
)

const PoW = 16 // what alalanet asks of keys younger than 7 days and of every gift wrap

type Kit struct {
	SK, PK string
	API    string // https://alalanet.com
	HTTP   *http.Client
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

func (k *Kit) do(ctx context.Context, method, path string, body []byte, auth bool) (map[string]any, error) {
	full := k.API + path
	req, err := http.NewRequestWithContext(ctx, method, full, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "alalanet-agent/1")
	if auth {
		h, err := k.nip98(method, full, body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", h)
	}
	resp, err := k.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	if resp.StatusCode >= 300 {
		if out != nil && out["hint"] != nil {
			return out, fmt.Errorf("%s: %v", out["error"], out["hint"])
		}
		return out, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return out, nil
}

// nip98 builds "Nostr <base64 kind-27235 event>" bound to method, full URL and body.
func (k *Kit) nip98(method, fullURL string, body []byte) (string, error) {
	ev := nostr.Event{Kind: 27235, PubKey: k.PK, CreatedAt: nostr.Now(), Tags: nostr.Tags{{"u", fullURL}, {"method", method}}}
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

func (k *Kit) Submit(ctx context.Context, ev nostr.Event) (map[string]any, error) {
	raw, _ := json.Marshal(ev)
	return k.do(ctx, http.MethodPost, "/v1/events", raw, false)
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
	Amount       string `json:"amount,omitempty"`
	Asset        string `json:"asset,omitempty"`
	Network      string `json:"network,omitempty"`
	Tx           string `json:"tx,omitempty"`
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
	sum, err := FileSHA256(file)
	if err != nil {
		return nil, err
	}
	tags := nostr.Tags{{"d", strings.ToLower(nameVersion)}, {"x", sum}}
	if source != "" {
		tags = append(tags, nostr.Tag{"r", source})
	}
	if typ != "" {
		tags = append(tags, nostr.Tag{"m", typ})
	}
	ev, err := k.Sign(nostr.Event{Kind: 30422, Tags: tags})
	if err != nil {
		return nil, err
	}
	return k.Submit(ctx, ev)
}

func (k *Kit) CheckFile(ctx context.Context, file string) (map[string]any, error) {
	sum, err := FileSHA256(file)
	if err != nil {
		return nil, err
	}
	return k.do(ctx, http.MethodGet, "/v1/artifacts/"+sum, nil, false)
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

func (k *Kit) MemoryGet(ctx context.Context, key string) (string, error) {
	out, err := k.do(ctx, http.MethodGet, "/v1/memory?key="+url.QueryEscape(key), nil, true)
	if err != nil {
		return "", err
	}
	evm, _ := out["event"].(map[string]any)
	ct, _ := evm["content"].(string)
	ck, err := k.selfKey()
	if err != nil {
		return "", err
	}
	return nip44.Decrypt(ct, ck)
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

type Message struct {
	ID   string `json:"id"`
	From string `json:"from"`
	At   string `json:"at"`
	Text string `json:"text"`
}

// ReadMail fetches and unwraps messages; returns them with the next cursor.
func (k *Kit) ReadMail(ctx context.Context, since int64, afterID string) ([]Message, int64, string, error) {
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
	out, err := k.do(ctx, http.MethodGet, path, nil, true)
	if err != nil {
		return nil, since, afterID, err
	}
	var msgs []Message
	raw, _ := json.Marshal(out["messages"])
	var wraps []nostr.Event
	_ = json.Unmarshal(raw, &wraps)
	for _, w := range wraps {
		rumor, err := nip59.GiftUnwrap(w, func(other, ct string) (string, error) {
			ck, err := nip44.GenerateConversationKey(other, k.SK)
			if err != nil {
				return "", err
			}
			return nip44.Decrypt(ct, ck)
		})
		if err != nil {
			continue // not for us or malformed: skip silently
		}
		msgs = append(msgs, Message{ID: w.ID, From: rumor.PubKey, At: time.Unix(int64(rumor.CreatedAt), 0).UTC().Format(time.RFC3339), Text: rumor.Content})
	}
	ns, _ := out["next_since"].(float64)
	nid, _ := out["next_after_id"].(string)
	return msgs, int64(ns), nid, nil
}

// randSeconds returns 0..7199: NIP-59 tweaks timestamps into the past to blur timing.
func randSeconds() int64 {
	var b [2]byte
	_, _ = io.ReadFull(crand.Reader, b[:])
	v := int64(b[0])<<8 | int64(b[1])
	return v % 7200
}
