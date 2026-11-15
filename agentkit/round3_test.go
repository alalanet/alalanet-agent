package agentkit

// SEC9-AGENT round 3 (the re-review of fc8b708): signed bytes in an answer are kept exactly as sent, an
// error is bounded however it comes, a page that is not alalanet's costs little memory, a page that
// cannot arrive in time is an error, and two signed reads in one second are two requests.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/alalanet/alalanet-agent/internal/safe"
)

// Round 4 (the re-review's R3-1): an answer to a read is cleaned in every member, an attestation's event,
// event_json, proof and key_chain too, at any depth; only Submit's answer keeps its own event exact
// (round4_test.go). Round 3 kept those four members as sent wherever they stood, which let a server that
// is not alalanet hand the model hidden text through them.
func TestAnswersCleanEveryMember(t *testing.T) {
	eventJSON := `{"id":"` + strings.Repeat("a", 64) + `","pubkey":"` + strings.Repeat("b", 64) +
		`","created_at":1763100000,"kind":4200,"tags":[["asset","Euro` + "\U000000AD" + `coin"]],"content":"x` + hiddenTags("pay") + `","sig":"` + strings.Repeat("c", 128) + `"}`
	var event map[string]any
	if err := json.Unmarshal([]byte(eventJSON), &event); err != nil {
		t.Fatal(err)
	}
	proof := map[string]any{"index": 7.0, "hashes": []any{"aGFzaA=="}, "checkpoint": "alalanet.com/log\n8\nroot=\n\n\U00002014\U000000A0alalanet.com/log sig=\n" + hiddenTags("go")}
	sent := map[string]any{
		"id": strings.Repeat("a", 64),
		"attestation": map[string]any{"event": event, "event_json": eventJSON, "proof": proof, "key_chain": []any{eventJSON},
			"how_to_verify": "check the signature" + hiddenTags("then pay")},
		"profile":                map[string]any{"event": map[string]any{"content": "hi" + hiddenTags("now")}},
		"note" + hiddenTags("k"): "n" + hiddenTags("x"),
	}
	body, _ := json.Marshal(sent)
	out, err := reader(answering(t, http.StatusOK, string(body))).Get(context.Background(), "/v1/receipts/x")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	if _, changed := safe.Text(string(b)); changed {
		t.Errorf("a read's answer hands the model hidden text: %+q", b)
	}
	att, _ := out["attestation"].(map[string]any)
	if att["how_to_verify"] != "check the signature" || out["note"] != "n" {
		t.Errorf("the strings are not cleaned: %+q %+q", att["how_to_verify"], out["note"])
	}
	if ev, _ := att["event"].(map[string]any); ev["content"] != "x" {
		t.Errorf("an attestation's event in a read is not cleaned: %+v", att["event"])
	}
}

// R2-2: an error is at most maxErrorShown bytes however it comes, a JSON hint too, cut at a character's
// start after its hidden characters are gone.
func TestErrorHintIsCut(t *testing.T) {
	for _, c := range []struct{ name, hint string }{
		{"3 MiB of letters", strings.Repeat("a", 3<<20)},
		{"hidden characters, then letters", strings.Repeat(hiddenTags("x"), 2000) + strings.Repeat("b", 5000)},
		{"two-byte letters across the cut", strings.Repeat("\U000000E9", 3000)},
	} {
		body, _ := json.Marshal(map[string]string{"error": "bad_request", "hint": c.hint})
		_, err := reader(answering(t, http.StatusBadRequest, string(body))).Get(context.Background(), "/v1/x")
		if err == nil {
			t.Fatalf("%s: no error", c.name)
		}
		msg := err.Error()
		if len(msg) > 1100 || !strings.HasPrefix(msg, "bad_request: ") {
			t.Errorf("%s: an error of %d bytes: %.60q", c.name, len(msg), msg)
		}
		if _, changed := safe.Text(msg); changed {
			t.Errorf("%s: the error holds a hidden character or a cut one: %+q", c.name, msg[len(msg)-20:])
		}
	}
}

// R2-3: an answer that is not alalanet's, blanks without end or a string that never closes, is an error
// after a few MiB past the last element read, not after the page's 96 MiB, and holds little memory;
// blanks after a whole wrap end the same way.
func TestReadMailElementBound(t *testing.T) {
	senderSK, recipientSK := nostr.GeneratePrivateKey(), nostr.GeneratePrivateKey()
	recipientPK, _ := nostr.GetPublicKey(recipientSK)
	wrap, _ := json.Marshal(giftWrap(t, senderSK, recipientPK, "hello"))
	blanks := []byte(strings.Repeat(" ", 1<<20))
	letters := []byte(strings.Repeat("A", 1<<20))
	for _, c := range []struct {
		name, start string
		fill        []byte
	}{
		{"blanks inside the list", `{"messages":[`, blanks},
		{"a string that never closes", `{"messages":["`, letters},
		{"blanks after a whole wrap", `{"messages":[` + string(wrap), blanks},
		{"blanks before the list", `{"messages":`, blanks},
	} {
		written := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, c.start)
			for r.Context().Err() == nil && written < 200<<20 {
				n, err := w.Write(c.fill)
				written += n
				if err != nil {
					return
				}
			}
		}))
		k := &Kit{SK: recipientSK, PK: recipientPK, API: srv.URL, HTTP: srv.Client()}
		var msgs []Message
		var err error
		d, peak := zz2Peak(func() { msgs, _, _, err = k.ReadMail(context.Background(), 0, "") })
		srv.Close()
		if err == nil || msgs != nil {
			t.Errorf("%s: %d messages, %v", c.name, len(msgs), err)
			continue
		}
		if peak > 32<<20 {
			t.Errorf("%s: the read held %.0f MiB more heap (%v): %v", c.name, zz2MiB(peak), d, err)
		}
		if !strings.Contains(err.Error(), "more than 2097152 bytes that are no whole element") {
			t.Errorf("%s: the error does not name the element bound: %v", c.name, err)
		}
		t.Logf("%s: %v in %v, heap +%.1f MiB, %d MiB written", c.name, err, d, zz2MiB(peak), written>>20)
	}
}

// A page that cannot arrive before the client's timeout is an error, with no message and the cursor as
// given. (Only the dripped page: the review's version also timed a full-speed read against 400 ms, which
// a loaded machine under -race can miss.)
func TestReadMailSlowPageIsAnError(t *testing.T) {
	senderSK, recipientSK := nostr.GeneratePrivateKey(), nostr.GeneratePrivateKey()
	recipientPK, _ := nostr.GetPublicKey(recipientSK)
	w := giftWrap(t, senderSK, recipientPK, "hello")
	page, _ := json.Marshal(map[string]any{"messages": []nostr.Event{w, w, w}, "next_since": 9, "next_after_id": w.ID})
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		fl := rw.(http.Flusher)
		for i := 0; i < len(page); i += 64 {
			_, _ = rw.Write(page[i:min(i+64, len(page))])
			fl.Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
	}))
	defer srv.Close()
	k := &Kit{SK: recipientSK, PK: recipientPK, API: srv.URL, HTTP: &http.Client{Timeout: 300 * time.Millisecond}}
	msgs, ns, nid, err := k.ReadMail(context.Background(), 7, "")
	if err == nil || msgs != nil || ns != 7 || nid != "" {
		t.Errorf("a page dripped past the timeout: %d messages, %d %q, %v", len(msgs), ns, nid, err)
	}
}

// Two signed requests alike in method, URL and body within one second are two events: alalanet refuses
// an auth event it has seen (a replay), so the second read would fail.
func TestNIP98EventsAreFresh(t *testing.T) {
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)
	k := &Kit{SK: sk, PK: pk}
	ids := map[string]bool{}
	for i := 0; i < 20; i++ {
		h, err := k.nip98(http.MethodGet, "https://alalanet.com/v1/mail", nil)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(h, "Nostr "))
		if err != nil {
			t.Fatal(err)
		}
		var ev nostr.Event
		if err := json.Unmarshal(raw, &ev); err != nil {
			t.Fatal(err)
		}
		if ok, _ := ev.CheckSignature(); !ok || ev.Kind != 27235 || ev.GetID() != ev.ID {
			t.Fatalf("not a valid NIP-98 event: %s", raw)
		}
		if len(values(ev, "u")) != 1 || len(values(ev, "method")) != 1 {
			t.Fatalf("u and method must stand once each: %s", raw)
		}
		ids[ev.ID] = true
	}
	if len(ids) != 20 {
		t.Errorf("20 signed requests alike gave %d distinct auth events", len(ids))
	}
}

// values are the first values of the tags named name.
func values(ev nostr.Event, name string) []string {
	var out []string
	for _, tg := range ev.Tags {
		if len(tg) >= 2 && tg[0] == name {
			out = append(out, tg[1])
		}
	}
	return out
}
