package installread

import (
	"slices"
	"testing"
)

// Re-review 24 of ADR-0159 round 36 (reader-af 76679770), adopted in round 37 (bodies unchanged).

// P2-AF closed: every line ran its code in zsh 5.9 (r24/shell/f1.txt, f2.txt); each must hold.
func TestReview24AttachedGroupsHold(t *testing.T) {
	for _, line := range []string{
		"/bin/ls(m+0e#export PA''TH=./bin#) >/dev/null; pip install zz-pkg",
		"/bin/ls(m+0e^export PA''TH=./bin^) >/dev/null; pip install zz-pkg",
		"[P]ATH?evil(P.export.); pip install zz-pkg",
		"echo {a,b}(e#id#); pip install zz-pkg",
		"echo >a(e#id#); pip install zz-pkg",
		"x=(a(e#id#)); pip install zz-pkg",
		"for f in a(e#id#); do :; done; pip install zz-pkg",
		"echo ${x:-a(e#id#)}; pip install zz-pkg",
		"echo ~(e#id#); pip install zz-pkg",
		"echo $(echo a)(e#id#); pip install zz-pkg",
		"echo a(e\\#id\\#); pip install zz-pkg",
	} {
		tg, un, _, s := ParseLine(line)
		if len(un)+len(HookExtra(line, tg, un, s)) == 0 {
			t.Errorf("zsh: %q: silent", line)
		}
	}
}

// READER-NPX-SC-1 against live npx 10.8.2 (empty npmrc, offline; r24/realnpm/npx-call-10.8.2.txt): every spelling
// that ran the call string holds. (-cy, -cs, --cal, --call-abc did not run it: npm read the string as a package.)
func TestReview24NpmCallMatchesNpm(t *testing.T) {
	for _, line := range []string{
		"npx -c 'echo RAN'", "npx -sc 'echo RAN'", "npx -yc 'echo RAN'", "npx --call 'echo RAN'",
		"npx --c 'echo RAN'", "npx --sc 'echo RAN'", "npx -yyc 'echo RAN'",
		"npm_config_call='sh x.sh' npx", "NPM_CONFIG_CALL='sh x.sh' npx", "export npm_config_call='sh x.sh'; npx",
	} {
		tg, un, _, s := ParseLine(line)
		if len(un)+len(HookExtra(line, tg, un, s)) == 0 {
			t.Errorf("npm 10.8.2 runs the call: %q: no hold (targets %q)", line, tg)
		}
	}
}

// P2-AG: the first reader (line.go) starts a comment at a # right after { } ( ), which end its word, so the install
// after it vanishes and the hook never sends the line. bash 3.2 and zsh 5.9 with default options ran the command after
// each of the first four (r24/shell/f5.txt, f4.txt); the (#q…) forms run under zsh's extendedglob.
func TestReview24HashAfterGroup(t *testing.T) {
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
			t.Errorf("%q: the install is not read and nothing holds", line)
		}
	}
}

// Round 37 (P2-AG): a # starts a comment only where a word starts — the line's start, after a blank, ;, & or | — in
// the first reader's splitter (line.go) and in the substitution splitter (subst.go); a word that goes on after { } ( )
// keeps its #. bash 3.2 and zsh 5.9 ran the command after each "ran" line (work-1116/reader-ag/shell/hash.out). A
// zsh group's hold stands on a line that installs nothing: the group's code may be the install.
func TestReaderHashInWord(t *testing.T) {
	read := func(line string) ([]string, int) {
		tg, un, _, s := ParseLine(line)
		return tg, len(un) + len(HookExtra(line, tg, un, s))
	}
	for _, line := range []string{
		// ran
		"v=$(echo a{#,b}); npm i evil-pkg",
		"echo $(echo x}#y) && npm i evil-pkg",
		"echo $(ls *(#q.)) && pip install real-pkg",
		// a zsh group's code, on a line with no install of its own
		"ls /bin/ls(e#npm i evil-pkg#)",
		"echo a(#qe:npm i evil-pkg:)",
		"echo ${x:-a(e#npm i evil-pkg#)}",
		"let i=1; ls *(e#npm i evil-pkg#)", // another construct held first
		"ls /bin/ls(e#n''pm i evil-pkg#)",  // the words hidden
		"ls /bin/ls(e#NPM i evil-pkg#)",    // macOS finds NPM
		"echo $(ls a(|#)) && npm i evil-pkg",
	} {
		if tg, n := read(line); len(tg)+n == 0 {
			t.Errorf("%q: the install is not read and nothing holds", line)
		}
	}
	for line, want := range map[string]string{
		"echo x}#y; pip install real-pkg": "pypi:real-pkg",
		"echo a{#,b}; npm i real-pkg":     "npm:real-pkg",
		"echo x;#c\nnpm i real-pkg":       "npm:real-pkg",
		"(#c\nnpm i real-pkg)":            "npm:real-pkg",
	} {
		if tg, _ := read(line); !slices.Contains(tg, want) {
			t.Errorf("%q: targets %q, want %s", line, tg, want)
		}
	}
	// after the group closes, a # after a blank is a comment (the line holds for its group: round 38)
	if tg, _ := read("ls a(x) # ; npm i evil-pkg"); len(tg) != 0 {
		t.Errorf("comment after a group: targets %q", tg)
	}
	// an array's ( opens no group on a word: the # after a blank in it is a comment (the line holds for the array)
	if tg, _ := read("a=(x # ; npm i evil-pkg\n)"); len(tg) != 0 {
		t.Errorf("array with a comment: targets %q", tg)
	}
	for _, line := range []string{
		"echo x #npm i evil-pkg",  // a comment after a blank
		"echo x;#npm i evil-pkg",  // after ;
		"echo x|#npm i evil-pkg",  // after |
		"echo x&&#npm i evil-pkg", // after &
		"#npm i evil-pkg",
		"ls -la; echo done",
		"echo \"a(e#x#)\"",
		// a comment hides the separator after it
		"# ; npm i evil-pkg",
		"echo x # ; npm i evil-pkg",
		"echo x\t# ; npm i evil-pkg",
		"echo x\r# ; npm i evil-pkg",
		"echo x\n# ; npm i evil-pkg",
		"echo x;# ; npm i evil-pkg",
		"echo x|# ; npm i evil-pkg",
		"echo x&&# ; npm i evil-pkg",
		"echo a(b\n# ; npm i evil-pkg",
		"echo $(echo x # ; npm i evil-pkg\n)",
		"echo $(npm -v); let i=1",
		"(( i++ )); echo $[1]", // (( and $(( are no groups on a word
		"echo $((1+2)); echo $[1]",
	} {
		if tg, n := read(line); len(tg)+n != 0 {
			t.Errorf("%q: targets %q, %d reasons; want nothing", line, tg, n)
		}
	}
}

// Round 37: the two releases review 24 offered (a Markdown link whose target has a /; a PowerShell line led by a
// [Type]:: token) are not made. zsh runs a group of either shape when it is a code qualifier: [x](e.docs/run.) ran a
// repository's docs/run, and [Environment]::GetEnvironmentVariable(e#…#) ran its code when a file n::Get… matched
// (work-1116/reader-ag/shell/release.out). These hold.
func TestReaderGroupReleasesNotMade(t *testing.T) {
	for _, line := range []string{
		"[x](e.docs/run.) pip install zz-pkg",
		"See [x](e.docs/run.) then pip install zz-pkg",
		"[Environment]::GetEnvironmentVariable(e#npm i zz-evil#); npx -y ok-pkg",
		"$env:Path = [Environment]::GetEnvironmentVariable(e#npm i zz-evil#); npx -y ok-pkg",
		"[guide](install/pypi.md) pip install zz-pkg",
		"set PATH=%ProgramFiles(x86)%\\nodejs;%PATH% && npx -y ok-pkg",
		"[Quickstart](#quickstart) pip install zz-pkg",
	} {
		tg, un, _, s := ParseLine(line)
		if len(un)+len(HookExtra(line, tg, un, s)) == 0 {
			t.Errorf("%q: silent", line)
		}
	}
}

// Round 37: the substitution splitter (subst.go, unnest) starts a comment where splitShell does — not after { } ( ), nor
// inside a group on a word — so a substitution ends where the shell ends it.
func TestReaderHashInWordSubst(t *testing.T) {
	for line, want := range map[string][]string{
		"echo $(echo x}#y) && npm i z": {"echo ${_s} && npm i z", "echo x}#y"},
		"echo $(ls a(|#)) && npm i z":  {"echo ${_s} && npm i z", "ls a(|#)"},
		"echo `ls a(|#)` && npm i z":   {"echo ${_s} && npm i z", "ls a(|#)"},
		"echo $(echo x|#y) && npm i z": {"echo ${_s}", "echo x|#y) && npm i z"}, // a comment after |
		"echo $(echo x #y) && npm i z": {"echo ${_s}", "echo x #y) && npm i z"}, // after a blank
		"echo $(a=(x #c) ; npm i z)":   {"echo ${_s}", "a=(x #c) ; npm i z)"},   // an array is no group on a word
		"echo $(ls a(x) #c) ; npm i z": {"echo ${_s}", "ls a(x) #c) ; npm i z"}, // after the group closes
		"ls a(x) #c $(npm i z)":        nil,                                     // the substitution is in a comment
		"ls a(x\n#c $(npm i z)":        nil,                                     // a line break ends the group
	} {
		if got, _ := unnest(line); !slices.Equal(got, want) {
			t.Errorf("unnest(%q) = %q, want %q", line, got, want)
		}
	}
	for _, line := range []string{
		"ls a((x)|#) && npm i real-pkg", // a group in a group
		"ls /bin/ls(e#$x i evil-pkg#)",  // an expansion hides the words
		"ls /bin/ls(e#`cat f` i evil-pkg#)",
	} {
		tg, un, _, s := ParseLine(line)
		if len(tg)+len(un)+len(HookExtra(line, tg, un, s)) == 0 {
			t.Errorf("%q: silent", line)
		}
	}
	// an address names no install it runs: with another hold on the line, it does not make the hold stand
	if _, un, _, _ := ParseLine("echo $[1]; echo [x](https://github.com/npm/cli)"); len(un) != 0 {
		t.Errorf("an address group: %q", un)
	}
}
