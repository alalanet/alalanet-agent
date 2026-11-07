package agentkit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFilterMail(t *testing.T) {
	good, spam, friend := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		adv := "unknown_key"
		if strings.HasSuffix(r.URL.Path, good) {
			adv = "established"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"advice": adv})
	}))
	defer srv.Close()
	k := &Kit{API: srv.URL, HTTP: srv.Client()}
	msgs := []Message{{From: good}, {From: spam}, {From: spam}, {From: friend}}
	kept, dropped := k.FilterMail(context.Background(), msgs, MailFilter{KnownOnly: true, Allow: []string{friend}})
	if len(kept) != 2 || dropped != 2 || kept[0].From != good || kept[1].From != friend {
		t.Fatalf("kept %+v dropped %d", kept, dropped)
	}
	if calls != 2 {
		t.Fatalf("passport lookups not cached: %d", calls)
	}
	if all, d := k.FilterMail(context.Background(), msgs, MailFilter{}); len(all) != 4 || d != 0 {
		t.Fatal("no filter must keep everything")
	}
}
