package installread

import (
	"slices"
	"testing"
)

// N1 (review of READER-ESCAPE-1 round 2): bash reads $"…" as "…" (a string no catalogue translates is itself), and runs
// each of these as npm i mcp-server-fetch (the review's trace oracle); dash and zsh run a program named $npm. Base and
// both heads were silent. The stored sample carries $"…" respellings with bash's verdicts.
func TestReaderEscapeBashLocaleQuote(t *testing.T) {
	for _, line := range []string{
		`$"npm" i mcp-server-fetch`, `npm $"i" mcp-server-fetch`, `$""npm i mcp-server-fetch`, `n$"pm" i mcp-server-fetch`,
		`bash -c '$"npm" i mcp-server-fetch'`, `npm i $"mcp-server-fetch"`,
	} {
		if tg, _, _, _ := ParseLine(line); !slices.Equal(tg, []string{"npm:mcp-server-fetch"}) {
			t.Errorf("%q: targets %q, want npm:mcp-server-fetch", line, tg)
		}
	}
	// what $"…" holds is still read: a substitution in it is one
	if _, _, _, subst := ParseLine(`npm i $"$(cat pkg)"`); !subst {
		t.Error(`npm i $"$(cat pkg)": no substitution`)
	}
}
