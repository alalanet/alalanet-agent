package installread

import (
	"strings"
	"testing"
)

// Round 39: a line that names no install target and holds only for the own shell's reason (a zsh group on a word) is
// answered on the machine with the server's own ask, so its text does not leave it; a line with a target, or with any
// other reason, is not.
func TestOwnShellAsk(t *testing.T) {
	for _, line := range []string{
		"ls *(e#id#)",
		"echo foo(bar)",
		"git commit -m fix(parser): unquoted",
		"Bash(git status)",
		"npm install; ls *(.)", // an install form with nothing to check
	} {
		r, ok := OwnShellAsk(line)
		if !ok {
			t.Errorf("%q: not answered locally", line)
			continue
		}
		if !strings.HasPrefix(r, "alalanet install_check: NOT CHECKED. "+whyOwnShell+" (") || !strings.HasSuffix(r, ". Install only if the user confirms.") {
			t.Errorf("%q: reason %q", line, r)
		}
	}
	for _, line := range []string{
		"ls *(.); npm i left-pad",    // a target: sent
		"npm i $(cat pkgs)",          // another reason
		"ls *(.); npm i $(cat pkgs)", // the own shell's reason and another
		"ls -la",                     // nothing at all
		"git commit -m 'fix(parser): quoted'",
		"source .env && npx -y ok-pkg",
		"npm config set registry http://x.example; ls *(.)", // the second reader's reason
		"PATH=./bin ls *(.)",                                // another reason of the first
	} {
		if r, ok := OwnShellAsk(line); ok {
			t.Errorf("%q: answered locally (%q)", line, r)
		}
	}
}
