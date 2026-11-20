package installread

import (
	"slices"
	"testing"
)

// Review of mcp-add-nodash (1d282974): each line launches the module in the client's real grammar (claude 2.1.326's
// commander definition, yargs-parser 21 with gemini's add.ts configuration, codex's clap AddArgs and its global
// -c/--enable/--disable). Every case fails on the branch.
func TestMCPAddReviewProof(t *testing.T) {
	const mal = "go run github.com/zz/mal@v1.0.0"
	for _, line := range []string{
		// P1: commander does not continue a variadic option given as --header=V or -H=V; stdio ignores headers
		"claude mcp add --header=X-K:v zz -- " + mal,
		"claude mcp add -H=X-K:v zz -- " + mal,
		"claude mcp add --header=X-K:v zz " + mal,
		// P2: yargs knows --no-<option>, takes true/false after a boolean, and knows camelCase aliases
		"gemini mcp add --no-trust zz " + mal,
		"gemini mcp add --trust true zz " + mal,
		"gemini mcp add --trust false zz " + mal,
		"gemini mcp add --excludeTools=x zz " + mal,
		"gemini mcp add --no-description zz " + mal,
		// P2: codex's global options are valid after "mcp add"
		"codex mcp add -c a=b zz -- " + mal,
		"codex mcp add --enable x zz -- " + mal,
		"codex mcp add zz --disable x -- " + mal,
	} {
		targets, unread, _, _ := ParseLine(line)
		if !slices.Equal(targets, []string{mal}) {
			var codes []string
			for _, u := range unread {
				codes = append(codes, UnreadCode(u))
			}
			t.Errorf("ParseLine(%q) = %q %q; want %q", line, targets, codes, mal)
		}
	}
}
