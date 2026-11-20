package installread

import (
	"slices"
	"testing"
)

// ECO-1-BREW round 4: the re-review's proofs, adopted as they are (h/ir_zz_brewr3_proof_test.go). Proofs of the re-review of ECO-1-BREW round 3 (review-1117/eco1-brew-r3). Each line runs the package or the tap on
// Homebrew 7.0.14 (cli/parser.rb's parse_remaining on Ruby's OptionParser: optmodel.txt; aliases/alias.rb; dev-cmd/sh.rb
// with utils/shell.rb), so the reader must give the target or a reason — never nothing.
func zzR3Read(t *testing.T, want string, lines ...string) {
	t.Helper()
	for _, l := range lines {
		tg, codes := codesOn(l)
		if !slices.Contains(tg, want) && len(codes) == 0 {
			t.Errorf("%s\n\tread as nothing (targets %v); Homebrew runs %s", l, tg, want)
		}
	}
}

// P1-1: Homebrew's parser takes an unambiguous prefix of a long option, a short cluster ending in a value option, and
// the last value of a repeated flag.
func TestReviewR3OptionParser(t *testing.T) {
	zzR3Read(t, "npm:zz-evil-pkg",
		`brew sandbox-exec --den /tmp/s -- npx -y zz-evil-pkg`,
		`brew sandbox-exec --de /tmp/s -- npx -y zz-evil-pkg`,
		`brew sandbox-exec --verb /tmp/s -- npx -y zz-evil-pkg`,
		`brew sandbox-exec /tmp/s --den -- npx -y zz-evil-pkg`,
		`brew sh -vc 'npx -y zz-evil-pkg'`,
		`brew sh -rc 'npx -y zz-evil-pkg'`,
		`brew sh -dvc 'npx -y zz-evil-pkg'`,
		`brew sh '-vcnpx -y zz-evil-pkg'`,
		`brew sh --cm 'npx -y zz-evil-pkg'`,
		`brew sh '--c=npx -y zz-evil-pkg'`,
		`brew sh -c true -c 'npx -y zz-evil-pkg'`,
		`brew sh --cmd=true '--cmd=npx -y zz-evil-pkg'`,
		`brew benchmark --exe -- 'npx -y zz-evil-pkg'`,
		`brew benchmark --e -- 'npx -y zz-evil-pkg'`,
		`brew bundle --fil Brewfile exec -- npx -y zz-evil-pkg`,
		`brew bundle exec --sand /tmp/s -- npx -y zz-evil-pkg`,
	)
	zzR3Read(t, "github:u/homebrew-r",
		`brew prof --sta install u/r/x`,
		`brew prof --tim install u/r/x`,
		`brew debugger --op install u/r/x`,
	)
}

// P1-2: hyperfine's own options run commands too (brew benchmark --exec passes every word after "--").
func TestReviewR3Hyperfine(t *testing.T) {
	zzR3Read(t, "npm:zz-evil-pkg",
		`brew benchmark --exec -- '--prepare=npx -y zz-evil-pkg' true`,
		`brew benchmark --exec -- '-pnpx -y zz-evil-pkg' true`,
		`brew benchmark --exec -- '--setup=npx -y zz-evil-pkg' true`,
		`brew benchmark --exec -- '--conclude=npx -y zz-evil-pkg' true`,
		`brew benchmark --exec -- '--cleanup=npx -y zz-evil-pkg' true`,
	)
}

// P1-3: an alias defined and used on one line, and an alias's command, which alias.rb writes into a bash script
// ("#{command} $*", "brew " in front unless it starts with ! or %).
func TestReviewR3Alias(t *testing.T) {
	zzR3Read(t, "github:u/homebrew-r",
		`brew alias i=install && brew i u/r/x`,
		`brew alias i=install; brew i u/r/x`,
	)
	zzR3Read(t, "npm:zz-evil-pkg",
		`brew alias e='!npx -y' && brew e zz-evil-pkg`,
		`brew alias e='%npx -y' && brew e zz-evil-pkg`,
		`brew alias e='!sh -c' && brew e 'npx -y zz-evil-pkg'`,
		`brew alias i='install wget; npx -y zz-evil-pkg' && brew i`,
	)
}

// P2-1: brew's shells read their standard input as a script, as sh does (dev-cmd/sh.rb without -c or FILE runs
// Utils::Shell.shell_with_prompt; bundle sh the same; exec, sandbox-exec and bundle exec run the shell named).
func TestReviewR3StdinShell(t *testing.T) {
	zzR3Read(t, "npm:zz-evil-pkg",
		`echo 'npx -y zz-evil-pkg' | brew sh`,
		`brew sh <<< 'npx -y zz-evil-pkg'`,
		`echo 'npx -y zz-evil-pkg' | brew bundle sh`,
		`echo 'npx -y zz-evil-pkg' | brew x bash`,
		`echo 'npx -y zz-evil-pkg' | brew sandbox-exec /tmp/s -- bash`,
		`echo 'npx -y zz-evil-pkg' | brew bundle exec -- bash`,
	)
}
