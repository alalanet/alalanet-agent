package installread

import "testing"

// Re-review 22 of READER-EXPANSION-ENV-1 round 34 (reader-env c8e9fb10): zsh modifiers after a qualifier whose
// argument qualMod's character set does not take (L+0, m+0: a + and digits; g{wheel}: braces). Each line ran the planted
// pip in zsh 5.9 on the Mac (r22-proofs/shell/host.out); /bin/ls exists everywhere, no file of the folder is needed.
func TestReview22ModifierAfterQualifier(t *testing.T) {
	for _, line := range []string{
		"x=PATH=./bin; /bin/ls(L+0:s:/bin/ls:eval:) \"$x\"; pip install zz-pkg",
		"x=PATH=./bin; /bin/ls(m+0:s:/bin/ls:eval:) \"$x\"; pip install zz-pkg",
		"x=PATH=./bin; /bin/ls(.L+0:t:s/ls/eval/) \"$x\"; pip install zz-pkg",
		"x=PATH=./bin; /bin/ls(g{wheel}:s:/bin/ls:eval:) \"$x\"; pip install zz-pkg",
	} {
		tg, un, _, s := ParseLine(line)
		if len(un)+len(HookExtra(line, tg, un, s)) == 0 {
			t.Errorf("zsh: %q: silent", line)
		}
	}
}
