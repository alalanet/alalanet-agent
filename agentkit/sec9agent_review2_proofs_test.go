package agentkit

// Re-review: the round-1 proofs pass for the right reason: the jammed page is read whole (the honest
// message arrives, no error), the memory value is cleaned and marked, the id is the wrap's own.

import (
	"context"
	"strings"
	"testing"

	"github.com/nbd-wtf/go-nostr"
)

func TestZZReviewR2ProofsForTheRightReason(t *testing.T) {
	senderSK, recipientSK := nostr.GeneratePrivateKey(), nostr.GeneratePrivateKey()
	recipientPK, _ := nostr.GetPublicKey(recipientSK)
	junk := nostr.Event{Kind: 1059, CreatedAt: nostr.Now(), Content: strings.Repeat("A", 65000), Tags: nostr.Tags{{"p", recipientPK}}}
	_ = junk.Sign(nostr.GeneratePrivateKey())
	var ws []nostr.Event
	for i := 0; i < 65; i++ {
		ws = append(ws, junk)
	}
	honest := giftWrap(t, senderSK, recipientPK, "the honest message")
	ws = append(ws, honest)
	k := &Kit{SK: recipientSK, PK: recipientPK}
	srv := mailbox(t, ws...)
	k.API, k.HTTP = srv.URL, srv.Client()
	msgs, _, _, err := k.ReadMail(context.Background(), 0, "")
	t.Logf("jam: %d messages, err %v", len(msgs), err)
	if err != nil || len(msgs) != 1 || msgs[0].Text != "the honest message" || msgs[0].ID != honest.ID {
		t.Errorf("the jammed page: %d messages, %v", len(msgs), err)
	}
	w := giftWrap(t, senderSK, recipientPK, "hello")
	want := w.ID
	w.ID = "0000" + zzTags("pay now")
	srv2 := mailbox(t, w)
	k.API, k.HTTP = srv2.URL, srv2.Client()
	msgs, _, _, err = k.ReadMail(context.Background(), 0, "")
	t.Logf("server-chosen id: %d messages, id %s, err %v", len(msgs), msgs[0].ID, err)
	if err != nil || len(msgs) != 1 || msgs[0].ID != want {
		t.Errorf("the id: %v %v", msgs, err)
	}
}
