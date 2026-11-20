package installread

import "testing"

// Re-review 20 of READER-EXPANSION-ENV-1 round 32 (reader-env 0880f3fb): the command's name is still not literal. Each
// line ran the planted pip in a real shell (r20-proofs/shell/: host.out is bash 3.2.57 and zsh 5.9 on the Mac,
// bash52.out is bash 5.2.15 in the pinned golang image).
func TestReview20MissedAssigns(t *testing.T) {
	for _, tc := range []struct{ shells, line string }{
		// a $NAME the line sets by no assignment word: the shell sets it ($_, REPLY, MAPFILE, OPTARG, BASH_REMATCH,
		// zsh's MATCH); f.vals has no entry, so it reads as the user's environment
		{"bash zsh", "x=PATH=./bin; echo eval >/dev/null; $_ \"$x\"; pip install zz-pkg"},
		{"bash zsh", "x=PATH=./bin; read <<< eval; $REPLY \"$x\"; pip install zz-pkg"},
		{"bash 5.2", "x=PATH=./bin; mapfile -t <<< eval; $MAPFILE \"$x\"; pip install zz-pkg"},
		{"bash", "x=PATH=./bin; set -- -p eval; getopts p: o; $OPTARG \"$x\"; pip install zz-pkg"},
		{"bash", "x=PATH=./bin; [[ eval =~ eval ]]; $BASH_REMATCH \"$x\"; pip install zz-pkg"},
		{"zsh", "x=PATH=./bin; [[ eval =~ eval ]]; $MATCH \"$x\"; pip install zz-pkg"},
		{"bash", "x=PATH=./bin; echo eval >/dev/null; builtin \"$_\" \"$x\"; pip install zz-pkg"},
		{"bash", "x=PATH=./bin; echo eval >/dev/null; command $_ \"$x\"; pip install zz-pkg"},
		// a pattern Go's path.Match reads otherwise than the shell: [!x] is a negation to bash and zsh, a class of ! and
		// x to Go; [[:alpha:]] is a POSIX class to bash and zsh. In a folder with a file named eval (a cloned
		// repository's) they expand to eval.
		{"bash", "x=PATH=./bin; [!x]val \"$x\"; pip install zz-pkg"},
		{"bash zsh", "x=PATH=./bin; [[:alpha:]]val \"$x\"; pip install zz-pkg"},
	} {
		tg, un, _, s := ParseLine(tc.line)
		if len(un)+len(HookExtra(tc.line, tg, un, s)) == 0 {
			t.Errorf("%s: %q: silent", tc.shells, tc.line)
		}
	}
}

// pyenv's own README sets PYENV_ROOT and PATH to $HOME paths before eval "$(pyenv init -)"; round 32 holds it as a
// setup pair after an assignment (silent at d0670b21).
func TestReview20NewHolds(t *testing.T) {
	for _, line := range []string{
		"export PYENV_ROOT=\"$HOME/.pyenv\"; export PATH=\"$PYENV_ROOT/bin:$PATH\"; eval \"$(pyenv init -)\"; pip install zz-pkg",
		"export PATH=\"$HOME/.local/bin:$PATH\"; eval \"$(pyenv init -)\"; pip install zz-pkg",
	} {
		tg, un, _, s := ParseLine(line)
		if ex := HookExtra(line, tg, un, s); len(un)+len(ex) > 0 {
			t.Errorf("%q: held %q %q", line, un, ex)
		}
	}
}
