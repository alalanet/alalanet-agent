package installread

import "testing"

// Re-review 21 of READER-EXPANSION-ENV-1 round 33 (reader-env 72e2f9c3): the command's name is still not literal.
// Each line ran the planted pip in a real shell (r21-proofs/shell/: host.out is bash 3.2.57 and zsh 5.9 on the Mac,
// bash52.out is bash 5.2.15 in the pinned golang image).
func TestReview21MissedAssigns(t *testing.T) {
	for _, tc := range []struct{ shells, line string }{
		// a quoted word with a / counts as a path ("$VENV/bin/pip"), but the / may sit in an expansion's word that
		// expands to nothing: "${NOPE:+/}eval" is eval
		{"bash zsh", "x=PATH=./bin; \"${NOPE:+/}eval\" \"$x\"; pip install zz-pkg"},
		{"bash", "x=PATH=./bin; \"e${NOPE:+/}val\" \"$x\"; pip install zz-pkg"},
		{"bash", "x=PATH=./bin; \"${NOPE+/}eval\" \"$x\"; pip install zz-pkg"},
		// zsh's glob qualifiers take modifiers: a path pattern with (:s:…:…:) or (:t) names any word, a builtin's
		// too; a pattern with a / is never checked against the builtins' names
		{"zsh", "x=PATH=./bin; /bin/ls(:s:/bin/ls:eval:) \"$x\"; pip install zz-pkg"},
		{"zsh", "x=PATH=./bin; ./e?al(:t) \"$x\"; pip install zz-pkg"}, // a folder with a file named eval
	} {
		tg, un, _, s := ParseLine(tc.line)
		if len(un)+len(HookExtra(tc.line, tg, un, s)) == 0 {
			t.Errorf("%s: %q: silent", tc.shells, tc.line)
		}
	}
}

// Tool homes their installers set, newly held as a command's name (silent at 0880f3fb): pnpm's, bun's, pyenv's, nvm's
// and Volta's own install instructions export them.
func TestReview21NewHolds(t *testing.T) {
	for _, line := range []string{
		"$PNPM_HOME/pnpm add zz-pkg",
		"$BUN_INSTALL/bin/bun add zz-pkg",
		"$PYENV_ROOT/shims/pip install zz-pkg",
		"$NVM_BIN/npm i zz-pkg",
		"$VOLTA_HOME/bin/npm i zz-pkg",
	} {
		tg, un, _, s := ParseLine(line)
		if ex := HookExtra(line, tg, un, s); len(un)+len(ex) > 0 {
			t.Errorf("%q: held %q %q", line, un, ex)
		}
	}
}
