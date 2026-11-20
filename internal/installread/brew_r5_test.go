package installread

import (
	"slices"
	"testing"
)

// ECO-1-BREW round 5 (re-review review-1117/eco1-brew-r4). P2-1: brew sh FILE runs the user's shell with FILE
// (dev-cmd/sh.rb: safe_system(preferred_path, named.first)); "-" is a named word for OptionParser and "--" before it is
// removed (split_non_options), and a shell given "-", /dev/stdin, /dev/fd/0 or /proc/self/fd/0 reads its input as the
// script, as the reader takes bash - and bash /dev/stdin. P2-2: brew alias splits its one named word at "="
// (cmd/alias.rb): a word the line does not show defines what the line does not show. Placeholders only.
func TestBrewRound5(t *testing.T) {
	for line, code := range map[string]string{
		// P2-1: every spelling of standard input as sh's FILE, every option before it, every way to reach brew sh
		"brew sh - <<< 'npx -y zz-evil-pkg'":                  "script_not_read",
		"brew sh /dev/stdin <<< 'npx -y zz-evil-pkg'":         "script_not_read",
		"echo 'npx -y zz-evil-pkg' | brew sh -":               "script_not_read",
		"echo 'npx -y zz-evil-pkg' | brew sh -- -":            "script_not_read",
		"echo 'npx -y zz-evil-pkg' | brew sh /dev/fd/0":       "script_not_read",
		"echo 'npx -y zz-evil-pkg' | brew sh /proc/self/fd/0": "script_not_read",
		"echo 'npx -y zz-evil-pkg' | brew sh -- /dev/stdin":   "script_not_read",
		"echo 'npx -y zz-evil-pkg' | brew sh -r -":            "script_not_read",
		"echo 'npx -y zz-evil-pkg' | brew sh --env=std -":     "script_not_read",
		"echo 'npx -y zz-evil-pkg' | brew sh -v /dev/stdin":   "script_not_read",
		"echo 'npx -y zz-evil-pkg' | brew sh - x":             "script_not_read",
		"echo 'npx -y zz-evil-pkg' | brew as-brew-user sh -":  "script_not_read",
		"echo 'npx -y zz-evil-pkg' | brew x -- brew sh -":     "script_not_read",
		"echo 'npx -y zz-evil-pkg' | brew -v sh /dev/stdin":   "script_not_read",
		"echo 'npx -y zz-evil-pkg' | brew debugger -- sh -":   "script_not_read",
		// P2-2: a variable in alias's word, in every quoting and position
		`brew alias "$A" && brew e u/r/x`:   "variable_argument",
		`brew alias $A && brew e u/r/x`:     "variable_argument",
		`brew alias "${A}" && brew e u/r/x`: "variable_argument",
		`brew alias "$A"`:                   "variable_argument",
		`brew alias --edit "$A"`:            "variable_argument",
		`brew alias "$N=install"`:           "variable_argument",
		`brew alias "e=install $T/x"`:       "variable_argument",
		`brew alias e=$V && brew e u/r/x`:   "variable_argument",
		"brew alias `cat f`":                "variable_argument",
		`brew as-brew-user alias "$A"`:      "variable_argument",
		`brew alias -- "$A"`:                "variable_argument",
	} {
		if _, codes := codesOn(line); !slices.Contains(codes, code) {
			t.Errorf("%q: codes %v, want %s", line, codes, code)
		}
	}
	// a here-document's lines are read as the line's own commands (the reader's rule): the target
	if tg, _ := codesOn("brew sh /dev/stdin <<EOF\nnpx -y zz-evil-pkg\nEOF"); !slices.Contains(tg, "npm:zz-evil-pkg") {
		t.Errorf("brew sh /dev/stdin <<EOF: targets %v, want npm:zz-evil-pkg", tg)
	}
	// nothing: sh with a FILE of its own, with a -c script, with no input shown; aliases the line shows whole
	for _, line := range []string{
		"echo 'npx -y zz-evil-pkg' | brew sh ./x.sh", "echo 'npx -y zz-evil-pkg' | brew sh -c 'echo hi' -",
		"brew sh -", "brew sh /dev/stdin", "echo 'npx -y zz-evil-pkg' | brew sh x.sh -", "brew alias", "brew alias zz",
		"brew alias zz='install wget'", "brew alias --edit zz", `brew alias --help "$A"`, `brew alias -h "$A"`,
		`brew alias zz "$A"`, // two named words: cmd/alias.rb takes one (named_args max: 1), Homebrew refuses the line
	} {
		if tg, codes := codesOn(line); len(tg) > 0 || len(codes) > 0 {
			t.Errorf("%q: targets %v codes %v, want none", line, tg, codes)
		}
	}
}
