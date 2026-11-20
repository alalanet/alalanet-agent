package installread

import "testing"

// Re-review 19 of READER-EXPANSION-ENV-1 round 31 (reader-env d0670b21): lines that still set PATH in the shell that
// runs the install and pass both readers. Each ran the planted pip in a real shell (r19-proofs/shell/: host2.out is
// bash 3.2.57 and zsh 5.9 on the Mac, bash52.out is bash 5.2.15 in the pinned golang image); for npm view, a fake npm
// prints what a registry package can put in the field (e2e/fakepm/npm).
func TestReview19MissedAssigns(t *testing.T) {
	for _, tc := range []struct{ shells, line string }{
		// brace expansion names a builtin: {eval,} is eval to bash, but no builtin's name to the allowlist (mayName
		// reads * ? [ ( only)
		{"bash", "x=PATH=./bin; {eval,} \"$x\"; pip install zz-pkg"},
		// a package manager's output as the command's name (pmOnly): npm view prints a registry package's field
		{"bash zsh", "x=PATH=./bin; $(npm view eval name) \"$x\"; pip install zz-pkg"},
		{"bash zsh", "$(npm view eval name) P\\ATH=./bin; pip install zz-pkg"},
		{"bash zsh", "$(npm view attacker-pkg description); pip install zz-pkg"}, // description: export PATH=./bin
		// zsh's - bullet: a first word that is one substitution counts as prose (mdBullet), and zsh runs its output
		{"zsh", "true\n- $(printf eval) P\\ATH=./bin `true`\npip install zz-pkg"},
		{"zsh", "x=PATH=./bin; true\n- $(printf eval) \"$x\" `true`\npip install zz-pkg"},
	} {
		tg, un, _, s := ParseLine(tc.line)
		if len(un)+len(HookExtra(tc.line, tg, un, s)) == 0 {
			t.Errorf("%s: %q: silent", tc.shells, tc.line)
		}
	}
}

// A setup pair's output follows the tool's root variable, which the line may set: pyenv init - prints
// export PATH="<PYENV_ROOT>/shims:${PATH}" (pyenv README, "Environment variables": PYENV_ROOT "defines the directory
// under which Python versions and shims reside"; rbenv and nodenv the same with RBENV_ROOT and NODENV_ROOT). The tools
// are not on the reviewer's machine: these lines follow their documentation.
func TestReview19SetupRoot(t *testing.T) {
	for _, line := range []string{
		"export PYENV_ROOT=./evil; eval \"$(pyenv init -)\"; pip install zz-pkg",
		"PYENV_ROOT=./evil; eval \"$(pyenv init -)\"; pip install zz-pkg",
		"export NODENV_ROOT=./evil; eval \"$(nodenv init -)\"; npm i zz-pkg",
	} {
		tg, un, _, s := ParseLine(line)
		if len(un)+len(HookExtra(line, tg, un, s)) == 0 {
			t.Errorf("%q: silent", line)
		}
	}
}

// Honest lines round 31 newly holds (silent at 5d2d2330): pyenv-virtualenv's and fnm's own README setup lines, and a
// -c script whose only expansions are of the user's environment ($HOME, $DIR) the line does not set.
func TestReview19NewHolds(t *testing.T) {
	for _, line := range []string{
		"eval \"$(pyenv virtualenv-init -)\" && pip install zz-pkg",
		"eval \"$(fnm env --use-on-cd --shell bash)\" && npm i zz-pkg",
		"bash -c \"source $HOME/.nvm/nvm.sh && npm i -g zz-pkg\"",
		"sh -c \"cd $DIR && npm install zz-pkg\"",
	} {
		tg, un, _, s := ParseLine(line)
		if ex := HookExtra(line, tg, un, s); len(un)+len(ex) > 0 {
			t.Errorf("%q: held %q %q", line, un, ex)
		}
	}
}
