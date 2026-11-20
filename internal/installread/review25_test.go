package installread

import "testing"

// Re-review 25 of ADR-0159 round 37 (reader-ag b78707d5), adopted in round 38 (bodies unchanged).

// P2-AG closed: review 24's seven lines; the hook now sends each (a target, or a reason).
func TestReview25HashInWordSent(t *testing.T) {
	for _, line := range []string{
		"echo x}#y; pip install real-pkg",
		"echo a{#,b}; pip install real-pkg",
		"echo *(#|); pip install real-pkg",
		"ls a(|#) && npm i real-pkg",
		"echo a(#qe:id:); pip install real-pkg",
		"ls *(#q.); pip install real-pkg",
		"echo a(#i); npm i real-pkg",
	} {
		tg, un, _, s := ParseLine(line)
		if len(tg)+len(un)+len(HookExtra(line, tg, un, s)) == 0 {
			t.Errorf("%q: not sent", line)
		}
	}
}

// P2-AH (new in round 37): a # right after a subshell's ( or ) starts a comment in bash and zsh, but the splitter now
// reads it as a word; a \ at the comment's end then joins the next line, and the install on it vanishes. Develop
// 3585cc80 sends each; bash 3.2 and zsh 5.9 ran the next line (r25/shell/agbs.json).
func TestReview25CommentAfterSubshellParen(t *testing.T) {
	for _, line := range []string{
		"(true)#\\\nnpm i evil-pkg",
		"(cd a)# build it, see C:\\\nnpm i evil-pkg",
		"(#\\\nnpm i evil-pkg\n)",
		"(# note \\\nnpm i evil-pkg\n)",
		"x=$(true)\n(true)#\\\npip install evil-pkg",
		"(true)#x\\\npip install evil-pkg",
	} {
		tg, un, _, s := ParseLine(line)
		if len(tg)+len(un)+len(HookExtra(line, tg, un, s)) == 0 {
			t.Errorf("%q: not sent", line)
		}
	}
}
