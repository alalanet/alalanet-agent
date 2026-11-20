package main

import (
	"net/http"
	"strings"
	"testing"
)

// Trial merge of reader-rows e020364 onto develop 74173c1 (hook.go conflict): a daily-limit or rate answer from the
// server must not drop the hold of the line's local files. The reviewer's proof, adopted in round 21 with the merge of
// develop 9a4193f.
func TestReview8MergeLimitKeepsLocalHold(t *testing.T) {
	dir := t.TempDir()
	zzWrite(t, dir, "r.txt", []byte(zzEvil))
	for _, mark := range []string{"daily-limit", "rate"} {
		f := &fakeHook{answer: func(w http.ResponseWriter) {
			w.Header().Set("Alalanet-Not-Checked", mark)
			_, _ = w.Write([]byte(`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"limit"}}`))
		}}
		srv := f.server(t)
		d, reason := codexDecision(t, runCodex(t, srv.URL, codexInputIn(dir, "pip install -r r.txt zz-req-pkg")))
		t.Logf("%s: %s %q", mark, d, reason)
		if d != "deny" || !strings.Contains(reason, "requirements file") {
			t.Errorf("%s: the local file's hold is lost: %s %q", mark, d, reason)
		}
	}
}
