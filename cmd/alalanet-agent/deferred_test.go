package main

import (
	"os"
	"strings"
	"testing"
)

// ADR-0156 (round 3, the re-review's P3-6): post_board's description still says "the transparency log keeps
// the post id and signature"; the log keeps the post's leaf (agents.PostLeaf: its id, the author's key, the
// time, the kind and the signature). This main.go is being reworked on branch rt1-codex, so the text is
// corrected once that branch has landed. This test is what holds it to that: it turns red as soon as
// main.go has rt1-codex's hook subcommand while the old text is still there, and once the text is changed
// it requires the new one to name the leaf.
func TestPostBoardTextOnceRT1Lands(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	desc := reviewS7ToolDescription(t, "post_board")
	old := strings.Contains(desc, "the transparency log keeps the post id and signature")
	switch {
	case old && strings.Contains(string(src), `case "hook":`):
		t.Errorf("rt1-codex's hook subcommand is in main.go and post_board still says %q: name the leaf now (its id, the author's key, the time, the kind and the signature; ADR-0156)",
			"the transparency log keeps the post id and signature")
	case !old:
		for _, w := range []string{"id", "author", "time", "kind", "signature"} {
			if !strings.Contains(desc, w) {
				t.Errorf("post_board's new text does not name the leaf's %s: %q", w, desc)
			}
		}
	}
}
