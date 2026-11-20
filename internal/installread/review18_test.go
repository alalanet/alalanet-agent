package installread

import "testing"

// Re-review 18 of READER-EXPANSION-ENV-1 round 30 (reader-env 5d2d2330): lines that still set PATH in the shell
// that runs the install and pass both readers. Each ran the planted pip in a real shell (r18-proofs/shell/: host.out is
// bash 3.2.57 and zsh 5.9 on the Mac, bash52.out is bash 5.2.15 in the pinned golang image) unless noted.
func TestReview18MissedAssigns(t *testing.T) {
	for _, tc := range []struct{ shells, line string }{
		// eval reads each literal value alone; NAME+=value appends to the one before
		{"bash", "t=PATH; t+==./bin; eval \"$t\"; pip install zz-pkg"},
		{"bash zsh", "t=PATH; t+='=./bin'; eval \"$t\"; pip install zz-pkg"},
		// eval $t unquoted: IFS splits the value, and eval joins the fields with blanks; a leading IFS character
		// leaves an empty first field, so ":PATH=./bin" (a program's name read alone) runs as " PATH=./bin"
		{"bash", "IFS=:; t=:PATH=./bin; eval $t; pip install zz-pkg"},
		{"bash", "(( IFS = 1 )); t=1PATH=./bin; eval $t; pip install zz-pkg"}, // arithmetic sets IFS, no lever
		// a value spliced into sh -c's script text is code to the child shell, which runs the install
		{"bash", "t=PATH=./bin; bash -c \"$t; pip install zz-pkg\""},
		{"bash", "t=PATH=./bin; sh -c \"$t\"'; pip install zz-pkg'"},
		// a Markdown bullet: zsh's - is a precommand modifier, and 'eval' (quoted) is no builtin to mdBullet
		{"zsh", "true\n- 'eval' PATH=./bin `true`\npip install zz-pkg"},
	} {
		tg, un, _, s := ParseLine(tc.line)
		if len(un)+len(HookExtra(tc.line, tg, un, s)) == 0 {
			t.Errorf("%s: %q: silent", tc.shells, tc.line)
		}
	}
}

// fish runs a command substitution in the shell itself, not in a subshell (fish documentation, "Command
// substitution"): the set runs before pip, in the process that runs it. fish is not on the reviewer's machine.
func TestReview18FishSubstitution(t *testing.T) {
	line := "fish -c 'pip install (set -p PATH ./bin; echo zz-pkg)'"
	tg, un, _, s := ParseLine(line)
	if len(un)+len(HookExtra(line, tg, un, s)) == 0 {
		t.Errorf("%q: silent", line)
	}
}
