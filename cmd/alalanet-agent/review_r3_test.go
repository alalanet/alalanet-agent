package main

// Review of VERIFY-AUTO-1 round 3 (99e0418): spellings the round-2 rule held and the narrowed rule may not.

import "testing"

func TestReviewR3NarrowedRuleSpellings(t *testing.T) {
	word := "appro" + "ve"
	held := map[int]bool{4: true, 5: true, 6: true} // round 4 (P3-4): the first four are the stated limit, the last two honest
	for i, line := range []string{
		"A=mcp-; alalanet-agent ${A}" + word + " docs",
		"A=mcp-; B=" + word + "; alalanet-agent $A$B docs",
		`alalanet-agent "$(printf mcp-%s ` + word + `)" docs`,
		"alalanet-agent $(printf %s-%s mcp " + word + ") docs",
		"alalanet-agent mcp-$(echo " + word + ") docs",
		"alalanet-agent `echo mcp-" + word + "` docs",
		"X=alalanet-agent; $X mcp-$Y docs",
		"alalanet-agent mcp-verify && gh pr review 3 --" + word,
		`git commit -m "alalanet-agent: mcp approve flow"`,
	} {
		t.Logf("%-62s held=%v", line, approvesMCP(line))
		if approvesMCP(line) != held[i] {
			t.Errorf("%q: held %v, want %v", line, approvesMCP(line), held[i])
		}
	}
}
