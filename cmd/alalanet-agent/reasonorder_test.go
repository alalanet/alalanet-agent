package main

import (
	"fmt"
	"testing"
)

// reasonRuns: how many runs the order tests make; a map's order differs between runs of one process.
const reasonRuns = 100

func sameEveryRun(t *testing.T, name, want string, read func() string) {
	t.Helper()
	seen := map[string]int{}
	for range reasonRuns {
		seen[read()]++
	}
	if len(seen) != 1 || seen[want] != reasonRuns {
		t.Errorf("%s: %d runs gave %v, want %q every run", name, reasonRuns, seen, want)
	}
}

// READER-REASON-ORDER-1 (ADR-0159 round 48): bun.lock names a nested package parent/name, and the name may be a
// scoped one (p/@x/b). With targets b and @x/b both suffixes match; the map's order picked either, and when it picked
// b the registry's own @x/b entry read as another package — a hold on some runs only. The longest name is the one the
// key nests.
func TestBunTargetNestedScopedSameEveryRun(t *testing.T) {
	const lock = `{"packages":{"p/@x/b":["@x/b@1.0.0",""],"q/b":["b@2.0.0",""],},}`
	sameEveryRun(t, "bunTarget(p/@x/b)", "@x/b", func() string {
		c := &regCheck{npmNames: map[string]bool{"b": true, "@x/b": true}}
		return c.bunTarget("p/@x/b")
	})
	sameEveryRun(t, "bunLock", "", func() string {
		c := &regCheck{npmNames: map[string]bool{"b": true, "@x/b": true}}
		c.bunLock("bun.lock", []byte(lock))
		return c.why
	})
	// a nested entry that is not the target's own still moves it, on every run
	sameEveryRun(t, "bunLock, moved", "bun.lock resolves a target outside the public registry", func() string {
		c := &regCheck{npmNames: map[string]bool{"b": true, "@x/b": true}}
		c.bunLock("bun.lock", []byte(`{"packages":{"p/@x/b":["@x/b@github:evil/x",""]}}`))
		return c.why
	})
}

// A startup file's source word is placed with the variables the file set before. A name that begins another
// ($Z, $ZZ) was replaced in the map's order: $ZZ/$Z read as /b/a when ZZ went first and as no path when Z did, so
// the file it sources was pinned on some runs only. The longer name is replaced first.
func TestStartupRefsVariablesSameEveryRun(t *testing.T) {
	text := []byte("Z=/a\nZZ=/b\n. $ZZ/$Z\n. ${Z}/x\n. \"$ZZ\"\n")
	sameEveryRun(t, "startupRefs", "[{/b/a 1 false} {/a/x 1 false} {/b 1 false}]", func() string {
		c := &regCheck{home: "/h"}
		return fmt.Sprint(c.startupRefs("/h/.zshrc", text, false))
	})
}

// The key's last name, not a suffix: bun.lock joins a dependency path's names with /, and a scoped name keeps its
// own slash, so the name a key gives is its last segment, or its last two when the one before starts with @. A
// suffix match read @x/x as the unscoped target x and held a lock that installs @x/x next to x (the review of
// f91add7c, its last finding).
func TestBunTargetLastName(t *testing.T) {
	names := map[string]bool{"b": true, "@x/b": true, "x": true, "@p/q": true}
	for k, want := range map[string]string{
		"p/@x/b": "@x/b", "@x/b": "@x/b", "b": "b", "p/b": "b", "@p/q/b": "b", "@p/q/@x/b": "@x/b", "@x/p/b": "b",
		"q/x/b": "b", "p/x": "x", "@x/x": "", "x/@x/b/c": "", "P/@X/B": "@x/b", "@p/q": "@p/q", "p/@p/q": "@p/q",
		"@x": "", "": "", "p/": "", "/b": "b", "@x/": "",
	} {
		sameEveryRun(t, "bunTarget("+k+")", want, func() string { return (&regCheck{npmNames: names}).bunTarget(k) })
	}
	sameEveryRun(t, "bunLock, @x/x beside target x", "", func() string {
		c := &regCheck{npmNames: map[string]bool{"x": true}}
		c.bunLock("bun.lock", []byte(`{"packages":{"x":["x@1.0.0",""],"@x/x":["@x/x@github:o/r",""]}}`))
		return c.why
	})
}
