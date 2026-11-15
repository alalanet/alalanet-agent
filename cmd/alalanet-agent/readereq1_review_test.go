package main

import "testing"

// Independent review of READER-EQ-1 round 4 (9024dd1): the agent's own filter embeds the reader, so on 7b53831 a
// split eval line is never sent to alalanet (Codex, Cursor, Copilot, Antigravity): the fix needs this binary too.
func TestZZReviewAgentSendsEval(t *testing.T) {
	for _, line := range []string{"eval 'npm i' zz-review-eq1-pkg", "eval 'npx -y' zz-review-eq1-pkg", "eval '-x; npm i zz-review-eq1-pkg'"} {
		if !isInstall(line) {
			t.Errorf("%q: not sent to alalanet", line)
		}
	}
}
