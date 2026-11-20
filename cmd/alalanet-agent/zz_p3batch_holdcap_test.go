package main

import (
	"fmt"
	"strings"
	"testing"
)

// Batch P3 review (HOOK-REASONS-CAP, ca87512, meets REPO-POL-1): the server now names at most ten held items and
// ends the part with "; and N more". A repository exception reads the HOLD part item by item (heldTargets); a cut
// list must never read as complete, or an exception covering the ten shown would lift a hold on the eleventh.
func TestP3BatchCappedHoldIsNeverReadAsComplete(t *testing.T) {
	var items []string
	for i := 0; i < 11; i++ {
		items = append(items, fmt.Sprintf("npm:zz-p3b-%d@1.0.0 — new_package", i))
	}
	// the server's text for 11 held items (internal/app hookList: the first ten, then "; and 1 more")
	capped := "alalanet install_check: HOLD. " + strings.Join(items[:10], "; ") + "; and 1 more. Install only if the user confirms."
	if got, ok := heldTargets(capped); ok {
		t.Errorf("a capped HOLD read as complete: %d items", len(got))
	}
	whole := "alalanet install_check: HOLD. " + strings.Join(items[:10], "; ") + ". Install only if the user confirms."
	if got, ok := heldTargets(whole); !ok || len(got) != 10 {
		t.Errorf("ten held items: ok %v, %d items; want all ten read", ok, len(got))
	}
}
