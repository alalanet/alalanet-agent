package installread

import (
	"slices"
	"testing"
)

// Batch P3 review (ENV-HASH-ASK, 48a4351): with the ask on any # gone, a # alalanet reads as a comment must be one
// env reads as a comment too (GNU coreutils build_argv: '#' only while ss.sep; FreeBSD/macOS split_spaces: only
// when !in_arg; uutils: only in the delimiter state). Each line below runs an install of zz-p3b-evil under GNU env;
// the reader must name it, never read it as a comment.
func TestP3BatchEnvHashNeverHidesAnInstall(t *testing.T) {
	for _, line := range []string{
		`env -S 'npm i zz-p3b-good \_#x' zz-p3b-evil`,    // \_ separates; the comment ends the value; the rest follows
		`env -S 'npm i zz-p3b-good "#x" zz-p3b-evil'`,    // # inside double quotes is a letter
		`env -S "npm i zz-p3b-good ''#x zz-p3b-evil"`,    // an empty quote starts the word: # is a letter
		`env -S 'npm i zz-p3b-good \#x zz-p3b-evil'`,     // \# is a letter
		`env -S 'npm i zz-p3b-good a#x zz-p3b-evil'`,     // # inside a word is a letter
		"env -S 'npm i zz-p3b-good\t#x' zz-p3b-evil",     // a tab before # makes a comment; the rest follows
		`env -S '-S#x npm i zz-p3b-evil'`,                // a nested -S whose value is a comment: env runs the rest
		`env -S '#x' npm i zz-p3b-evil`,                  // the whole value a comment: the words after it run
		`env -S 'npm i zz-p3b-good #x' -- zz-p3b-evil`,   // the words after the value follow the comment
		`env -S 'npm i zz-p3b-good' -S '#x' zz-p3b-evil`, // a second -S after the command is npm's argument
	} {
		tg, unread, _, _ := ParseLine(line)
		if !slices.Contains(tg, "npm:zz-p3b-evil") && len(unread) == 0 {
			t.Errorf("%q: targets %q, no reason; env installs zz-p3b-evil", line, tg)
		}
	}
	// What env reads as a comment installs nothing: no target and no reason (the round's ordinary cases).
	for _, line := range []string{`env -S 'echo hi # npm i zz-p3b-evil'`, `env -S 'true \_# npm i zz-p3b-evil'`} {
		tg, unread, _, _ := ParseLine(line)
		if len(tg) != 0 || len(unread) != 0 {
			t.Errorf("%q: targets %q, unread %q; want nothing", line, tg, unread)
		}
	}
}
