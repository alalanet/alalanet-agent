package installread

// Independent re-review of rt1-codex, round 2 (8695847), 2026-11-14: the shared reader. The test FAILS on the
// reviewed code (a gap older than this branch; recorded because the adapter now relies on this reader alone).

import (
	"slices"
	"testing"
)

// Out of scope (P3 for the server): npm, pnpm, Yarn and bun read `create` and `init` only as the first word after
// the program, so an option before it — here a folder — leaves the scaffolder the command runs (create-vite)
// unchecked: no target, no reason. Before db0946d the same lines with a stray x, exec or dlx word acted on a wrong
// target by accident; now they are silent (17 of the reviewer's 40,233 differential inputs went from acting to
// silence, every one a wrong target before).
func TestReviewRT1R2_ScaffolderAfterAnOption(t *testing.T) {
	for _, line := range []string{"npm --prefix web create vite@latest my-app", "pnpm --dir web create vite", "npm -w web init vite"} {
		targets, unread, _, _ := parseInstallLineFull(line)
		if !slices.ContainsFunc(targets, func(s string) bool { return s == "npm:create-vite@latest" || s == "npm:create-vite" }) && len(unread) == 0 {
			t.Errorf("%q: targets %q, unread %q — the scaffolder runs unchecked", line, targets, unread)
		}
	}
}
