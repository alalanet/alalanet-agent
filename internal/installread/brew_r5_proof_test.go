package installread

import (
	"slices"
	"testing"
)

// ECO-1-BREW round 5: the re-review's proofs, adopted as they are (d/ir_zz_brewr4_proof_test.go). Proofs of the re-review of ECO-1-BREW round 4 (review-1117/eco1-brew-r4): each line runs the package or installs the
// tap on Homebrew 7.0.14, so the reader must give the target or a reason — never nothing.
func zzR4Read(t *testing.T, want string, lines ...string) {
	t.Helper()
	for _, l := range lines {
		tg, codes := codesOn(l)
		if !slices.Contains(tg, want) && len(codes) == 0 {
			t.Errorf("%s\n\tread as nothing (targets %v); Homebrew runs %s", l, tg, want)
		}
	}
}

// P2-1: brew sh FILE runs the user's shell with FILE (dev-cmd/sh.rb: safe_system(preferred_path, named.first)); "-" is
// a named word for OptionParser, and the shell given "-" or /dev/stdin reads its standard input as the script, as
// bash - and bash /dev/stdin do (both read as script_not_read).
func TestReviewR4ShStdinFile(t *testing.T) {
	zzR4Read(t, "npm:zz-evil-pkg",
		`brew sh - <<< 'npx -y zz-evil-pkg'`,
		`brew sh /dev/stdin <<< 'npx -y zz-evil-pkg'`,
		`echo 'npx -y zz-evil-pkg' | brew sh -`,
		`echo 'npx -y zz-evil-pkg' | brew sh -- -`,
		`echo 'npx -y zz-evil-pkg' | brew sh /dev/fd/0`,
	)
}

// P2-2: brew alias defined from a variable (cmd/alias.rb splits the one named word at "="): the line does not show the
// alias, and its use installs what the variable names.
func TestReviewR4AliasVariable(t *testing.T) {
	zzR4Read(t, "github:u/homebrew-r",
		`brew alias "$A" && brew e u/r/x`,
		`brew alias $A && brew e u/r/x`,
		`brew alias "${A}" && brew e u/r/x`,
	)
}
