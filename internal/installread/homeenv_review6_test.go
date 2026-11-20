package installread

import (
	"strings"
	"testing"
)

// Reviewer's proof (home-p6, ADR-0243 round 6; adopted in round 7). A search-path entry ~X with any X but the empty one is not the home:
// ~+x, ~-lead (literal in bash and dash under nss_files; another user's home where a name service has them), ~+, ~0
// (the current folder in bash and zsh), ~1 (literal, or user 1's home): every one is a folder the project can ship.
// Held at develop 68f50cfa for ~+x, ~-lead; released by round 6 (P2-1); ~+, ~-, ~N read clean at develop too (P2-2).
func TestRvHome6SearchPathTilde(t *testing.T) {
	for _, line := range []string{
		"PATH=~+x/bin:/usr/bin go install example.com/x@latest",
		"PATH=~-lead/bin:/usr/bin cargo install x",
		"export PATH=~+x/bin:/usr/bin && go install example.com/x@latest",
		"env LD_LIBRARY_PATH=~+x go install example.com/x@latest",
		"set PATH=~+x && go install example.com/x@latest",
		"PATH=~+/bin:/usr/bin go install example.com/x@latest",
		"PATH=~0/bin:/usr/bin go install example.com/x@latest",
		"PATH=~0/bin:/usr/bin npm i x",
		"PATH=~1/bin:/usr/bin npx -y x",
		"claude mcp add s -e PATH=~0/bin:/usr/bin -- npx -y y",
		"env NODE_PATH=~12 npm i x",
	} {
		tg, un, _, s := ParseLine(line)
		if ex := HookExtra(line, tg, un, s); len(un)+len(ex) == 0 {
			t.Errorf("%s: reads clean; the entry's folder is the project's or another user's", line)
		}
	}
}

// P3-1: a fully quoted assignment-shaped word is no assignment in bash either ("HOME=~/x" stays ~/x): the note must
// not say bash would use a home.
func TestRvHome6QuotedWordNote(t *testing.T) {
	for _, line := range []string{`env "HOME=~/x" npm i x`, `claude mcp add s -e "HOME=~u" -- npx -y y`, `sudo 'HOME=~/x' npm i x`} {
		tg, un, _, s := ParseLine(line)
		all := strings.Join(append(un, HookExtra(line, tg, un, s)...), " | ")
		if all == "" {
			t.Errorf("%s: not held", line)
		}
		if strings.Contains(all, "bash, outside POSIX mode, would use") {
			t.Errorf("%s: the note says bash would expand a quoted word: %s", line, all)
		}
	}
}
