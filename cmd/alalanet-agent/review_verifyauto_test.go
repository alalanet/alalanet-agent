package main

// Review of VERIFY-AUTO-1 step 1 (a7aeeda): the install hook holds mcp-approve sent through the agent's shell
// "wherever it stands in the line (through a variable, a wrapper, script)" (ADR-0181 point 3). Lines a shell runs as
// mcp-approve without the literal word.

import "testing"

func TestReviewApproveHoldThroughShellSpellings(t *testing.T) {
	word := "appro" + "ve"
	for _, line := range []string{
		"X=" + word + "; alalanet-agent mcp-$X docs",
		"alalanet-agent mcp-\"" + word + "\" docs",
		"alalanet-agent mcp-appro\\ve docs",
		"alalanet-agent \"mcp\"-" + word + " docs",
		"script -q /dev/null sh -c 'alalanet-agent mcp-$0 docs' " + word,
	} {
		for runtime := range hookRuntimes {
			f := reviewDeny()
			srv := f.server(t)
			out := runRuntime(t, runtime, srv.URL, shellForms(line)["codex Bash"])
			if got := form5(t, runtime, out); got != "hold" {
				t.Errorf("hook %s, %q: %s (a shell runs this as mcp-approve)", runtime, line, got)
			}
		}
	}
}
