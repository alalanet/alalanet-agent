package main

import (
	"strings"
	"testing"
	"time"

	"github.com/alalanet/alalanet-agent/internal/installread"
)

// Batch P3 review 5, R-1 (ADR-0159 round 39): a line answered on the machine (OwnShellAsk) skips the
// organisation's or repository's policy, which the hook applies to the server's answer for the same line.
// With `on_hold: packages: deny`, the server path answers deny ("not checked under a deny", policy_test.go);
// the local path answers ask. Before round 39 the same line went to the server and was denied.
func TestZZReviewLocalAskSkipsTheDenyPolicy(t *testing.T) {
	const line = "ls *(e#id#)"
	why, ok := installread.OwnShellAsk(line)
	if !ok {
		t.Fatalf("%q is not answered locally", line)
	}
	// What the hook's policy step gives to the very same verdict when it comes from the server.
	dir := workspace(t, "", denyHolds)
	pf := &policyFiles{managed: managedFile(t, "")}
	viaPolicy, _ := loadPolicy(pf, dir).applyNotes(verdict{Decision: "ask", Reason: why}, line, time.Now())
	t.Logf("the server's ask through the policy: %q", viaPolicy.Decision)

	// What the hook answers now: local, no policy.
	serverAsk := `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"` + why + `"}}`
	form, out, _, f := runWithPolicy(t, "claude-code", serverAsk, managedFile(t, ""), codexInputIn(dir, line), nil)
	t.Logf("hook answer: form=%s sent=%d out=%s", form, len(f.calls()), strings.TrimSpace(out))

	// The same policy on a line with a target that the server answers NOT CHECKED: deny.
	form2, _, _, _ := runWithPolicy(t, "claude-code", notChecked_, managedFile(t, ""), codexInputIn(dir, "npm i @acme/cli"), nil)
	t.Logf("a sent line under the same policy: form=%s", form2)

	if viaPolicy.Decision == "deny" && form != "deny" {
		t.Errorf("the repository's on_hold deny turns the server's answer into deny, but the locally answered line is %s", form)
	}
}
