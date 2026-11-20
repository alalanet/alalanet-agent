package installread

import "testing"

// Re-review 23 of READER-EXPANSION-ENV-1 round 35 (reader-env 52623aef): a zsh qualifier after one that takes an
// argument (m+0) runs code (e with any delimiter but :), or prepends a word (P). Each ran the planted pip in zsh 5.9 on
// the Mac (r23-proofs/shell/host.out); the P line in a folder with a file named PATH=evil and evil/pip, as a cloned
// repository can hold.
func TestReview23QualifierAfterArgument(t *testing.T) {
	for _, line := range []string{
		"/bin/ls(m+0e#export PA''TH=./bin#) >/dev/null; pip install zz-pkg",
		"/bin/ls(m+0e^export PA''TH=./bin^) >/dev/null; pip install zz-pkg",
		"[P]ATH?evil(P.export.); pip install zz-pkg",
	} {
		tg, un, _, s := ParseLine(line)
		if len(un)+len(HookExtra(line, tg, un, s)) == 0 {
			t.Errorf("zsh: %q: silent", line)
		}
	}
}

// Round 36 (P2-AF): every unquoted group attached to a word holds, wherever zsh reads glob qualifiers — the command's
// name, an argument, a redirection's target, an array's element, a for list, and the word of an unquoted
// ${NAME:-word} (-, :+, +) and a Markdown bullet's prose (TestReaderOwnShell). Only a group that is a plain http:// or https:// address is let through: zsh refuses it
// ("unknown file attribute: h"; with NO_BARE_GLOB_QUAL "bad pattern"; sh emulation leaves it literal), bash refuses the
// line. Each "ran" line ran the planted pip in zsh 5.9 on the Mac (work-1116/reader-af/shell/host36.out).
func TestReaderAttachedGroupHolds(t *testing.T) {
	held := func(line string) bool {
		tg, un, _, s := ParseLine(line)
		return len(un)+len(HookExtra(line, tg, un, s)) > 0
	}
	for _, line := range []string{
		// ran
		"echo /bin/ls(m+0e#export PA''TH=./bin#) >/dev/null; pip install zz-pkg",
		": /bin/ls(L+0e^export PA''TH=./bin^); pip install zz-pkg",
		"echo ${x:-/bin/ls(m+0e#export PA''TH=./bin#)} >/dev/null; pip install zz-pkg",
		"echo ${x-/bin/ls(e#export PA''TH=./bin#)} >/dev/null; pip install zz-pkg",
		"y=1; echo ${y:+/bin/ls(e#export PA''TH=./bin#)} >/dev/null; pip install zz-pkg",
		"echo ${x:-\"/bin/ls\"(e#export PA''TH=./bin#)} >/dev/null; pip install zz-pkg",
		"echo /bin/l?(e#export PA''TH=./bin#) >/dev/null; pip install zz-pkg",
		"x=(/bin/ls(m+0e#export PA''TH=./bin#)); pip install zz-pkg",
		"for f in /bin/ls(m+0e#export PA''TH=./bin#); do :; done; pip install zz-pkg",
		// the qualifiers alalanet does not model: any attached group holds
		"/bin/ls(m+0e'export PA\"TH\"=./bin') >/dev/null; pip install zz-pkg",
		"/bin/ls(m+0e<export PA''TH=./bin>) >/dev/null; pip install zz-pkg",
		"pip install zz-pkg(P.--index-url=x.)",
		"pip install zz-pkg >zz(N)",
		"echo a(N)(e#x#); pip install zz-pkg",
		"[plugin-init](packages/plugin-init) x; pip install zz-pkg",
		"Bash(npx -y:*)",
		"func(x: int) pip install zz-pkg",
		"[x](https://a.example/b_(c)) pip install zz-pkg", // a group inside the address: not a plain one
		"[x](https://a.example/$(id)) pip install zz-pkg",
		"[x](https://a.example)(e#x#) pip install zz-pkg", // the address is let through, the group after it is not
		"[x](ftp://a.example) pip install zz-pkg",
		"/bin/ls(.://x) x; pip install zz-pkg",
		"/bin/ls(P://::s:/bin/ls:eval:) x; pip install zz-pkg",
		"[x](https://a.example/$HOME) pip install zz-pkg",
		"[x](https://a.example/'b') pip install zz-pkg",
		"[x](https://a.example/\\b) pip install zz-pkg",
		"Bash(https://a.example b) pip install zz-pkg",
		"/bin/ls(e#true#https://x) x; pip install zz-pkg",
		"[x](https:x) pip install zz-pkg",
	} {
		if !held(line) {
			t.Errorf("%q: silent", line)
		}
	}
	for _, line := range []string{
		"[x](https://example.org) ; echo after; pip install zz-pkg",
		"[Docs](https://example.org/docs) pip install zz-pkg",
		"See [the guide](https://example.org/guide) and run pip install zz-pkg",
		"[a/b](http://x.example/a#c) pip install zz-pkg",
		"echo \"${x:-/bin/ls(e#x#)}\"; pip install zz-pkg", // in double quotes zsh does not glob
		"pip install zz-pkg (optional)",
		"npx -y zz-pkg --opt key:value",
		"docker run -v $(pwd):/app img && npm i zz-pkg",
		"echo $(date +%H:%M) && pip install zz-pkg",
		"(cd a && pip install zz-pkg)",
		"python -c 'print(1)' && pip install zz-pkg",
		"pip install \"zz-pkg(>=1.0)\"",
		"X=(a b); pip install zz-pkg",
	} {
		if held(line) {
			tg, un, _, s := ParseLine(line)
			t.Errorf("%q: held %q %q", line, un, HookExtra(line, tg, un, s))
		}
	}
}
