package installread

import (
	"slices"
	"testing"
)

// Independent re-review of READER-VAR-OPT-1 T1 (b5eeb63 on cf45789), 2026-11-15.

// U1 (P3, test strength). TestEighthReviewBoundaries (internal/app) pinned that the second reader does not take
// nodejs.org, Node's own mirror, as a public place for a non-Node source variable, with PIP_FIND_LINKS. Since the first
// reader reads PIP_FIND_LINKS too, that case accepts the reason from either reader, and the mutant "nodejs.org is
// public for every source variable" (sourceWhy: !nodeMirrorHosts[lh] for !(mirror && nodeMirrorHosts[lh])) survives
// every installread and app test. A source variable only the second reader reads keeps the boundary pinned.
func TestReviewR5NodeMirrorIsNoSourceForOthers(t *testing.T) {
	want := "installs from a custom registry or index (nodejs.org): alalanet judges packages on the public registries only"
	for _, line := range []string{
		"UV_PYTHON_INSTALL_MIRROR=https://nodejs.org/dist/ uv python install 3.12",
		"JSR_URL=https://nodejs.org/dist/ deno add jsr:@std/path",
	} {
		tg, un, _, s := ParseLine(line)
		if got := HookExtra(line, tg, un, s); !slices.Contains(got, want) {
			t.Errorf("%q: second reader %q, want %q", line, got, want)
		}
	}
}
