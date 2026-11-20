package installread

import (
	"strings"
	"testing"
)

// The re-review of home-config-env round 3 (2026-11-18): its proof tests, adopted.

// P3-1: the tokenizer's mark leaves the reader in an MCP add's launch target for the Go names: install_check and the
// hook show it, and the target read again carries it inside quotes.
func TestHomeReview3ProofMarkInMCPAddTarget(t *testing.T) {
	for _, line := range []string{
		`claude mcp add x -e GOFLAGS='$X' -- npx -y left-pad`, `claude mcp add x -e GOPROXY=\$P -- npx -y left-pad`,
		`claude mcp add x -e GOPATH=~"" -- npx -y left-pad`,
	} {
		tg, un, _, s := ParseLine(line)
		for _, x := range append(append(append([]string{}, tg...), un...), HookExtra(line, tg, un, s)...) {
			if strings.Contains(x, "\ue000") {
				t.Errorf("%q: the mark is in %q", line, x)
			}
		}
	}
}

// P3-2: a quoted ~ after a list's ":" stays literal in bash (checked in a container: XDG_CONFIG_DIRS=/etc:~"" is
// "/etc:~"; '/etc:~' and "/etc:~/x" the same); the element reads as the home.
func TestHomeReview3ProofListTildeAfterColon(t *testing.T) {
	for _, line := range []string{`XDG_CONFIG_DIRS=/etc:~"" uv pip install requests`, `XDG_CONFIG_DIRS='/etc:~' uv pip install requests`,
		`XDG_CONFIG_DIRS="/etc:~/x" uv pip install requests`, `XDG_CONFIG_DIRS=/etc:\~ uv pip install requests`} {
		if !homeR3Holds(line) {
			t.Errorf("%q reads clean", line)
		}
	}
	if homeR3Holds(`XDG_CONFIG_DIRS=/etc:~ uv pip install requests`) {
		t.Error("an unquoted ~ after : (bash expands it) holds")
	}
}

func homeR3Holds(line string) bool {
	tg, un, _, s := ParseLine(line)
	return len(un)+len(HookExtra(line, tg, un, s)) > 0
}
