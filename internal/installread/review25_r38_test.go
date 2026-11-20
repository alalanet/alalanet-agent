package installread

import (
	"slices"
	"testing"
)

// Round 38 (P2-AH): a # right after a subshell's ( or ), or right after $(, starts a comment in bash and zsh; after a
// group's ) (a(|#)) and after $( … )'s ) (echo $(true)#c printed #c) it is part of the word. After an array's ) bash
// reads a word and zsh a comment: the reader reads the word, and a \ at its line's end continues nothing, so the next
// line is read as zsh runs it. Each "ran" line ran the install in bash 3.2 and zsh 5.9, in a temp dir whose PATH held
// a fake npm (work-1116/reader-ag/r38/probe.json).
func TestReaderCommentAfterSubshell(t *testing.T) {
	for _, line := range []string{
		// ran
		"(true)#c\nnpm i evil-pkg",
		"(#c\nnpm i evil-pkg)",
		"echo $(#c\nnpm i evil-pkg)",
		"echo $(true)#c; npm i evil-pkg",
		"cat <(true)#c; npm i evil-pkg",
		"a=(#c\nx); npm i evil-pkg",
		"a=(x)#c; npm i evil-pkg",  // bash
		"a=(x)#\\\nnpm i evil-pkg", // zsh
		"case x in x)#c\nnpm i evil-pkg;; esac",
		"case x in x)#\\\nnpm i evil-pkg;; esac",
		"f() (true)#c\nnpm i evil-pkg",
	} {
		if tg, _, _, _ := ParseLine(line); !slices.Contains(tg, "npm:evil-pkg") {
			t.Errorf("%q: targets %q, want npm:evil-pkg", line, tg)
		}
	}
	for _, line := range []string{
		"(true)#c npm i evil-pkg",
		"(#c ; npm i evil-pkg\n)",
		"echo $(true)#c\\\nnpm i evil-pkg", // one word, continued: echo #cnpm i evil-pkg
		"a=(x)#c\necho \\\nnpm i evil-pkg", // the ambiguity ends with its line: echo npm i evil-pkg
	} {
		if tg, _, _, _ := ParseLine(line); len(tg) != 0 {
			t.Errorf("%q: targets %q, want none (a comment)", line, tg)
		}
	}
	for line, want := range map[string][]string{
		"echo $(#c) && npm i z":        {"echo ${_s}", "#c) && npm i z"}, // a comment right after $(
		"echo $( (true)#c ) ; npm i z": {"echo ${_s}", "(true)#c ) ; npm i z"},
		"echo $(a=(x)#c); npm i z":     {"echo ${_s}; npm i z", "a=(x)#c"},
		"echo $(echo a(#q)) ; npm i z": {"echo ${_s} ; npm i z", "echo a(#q)"},
		"echo `#c` ; npm i z":          {"echo ${_s} ; npm i z", "#c"},
		"(true)#c $(npm i z)":          nil,
		"(#c $(npm i z)":               nil,
		"a=(x)#c $(npm i z)":           {"a=(x)#c ${_s}", "npm i z"},
		"echo $(true)#c $(npm i z)":    {"echo ${_s}#c ${_s}", "true", "npm i z"},
	} {
		if got, _ := unnest(line); !slices.Equal(got, want) {
			t.Errorf("unnest(%q) = %q, want %q", line, got, want)
		}
	}
}

// Round 38: a group's text hides an install program's name in more ways than a word list can see — e's delimiter may
// be a letter (*(eznpm i xz) ran npm in zsh 5.9), an alias or a function the line defines, a glob, a brace, any program
// the first reader reads (claude, code …). Any group on a word makes the own shell's hold stand with no install.
func TestReaderGroupMayInstallDodges(t *testing.T) {
	for _, line := range []string{
		"alias q=npm; ls *(e#q i evil-pkg#)",
		"q() { npm \"$@\"; }; ls *(e#q i evil-pkg#)",
		"ls *(e#/usr/bin/n?m i evil-pkg#)",
		"ls *(e#{n,}pm i evil-pkg#)",
		"x=npm; ls *(e#$x i evil-pkg#)",
		"ls *(e#./node_modules/.bin/npx -y evil-pkg#)",
		"ls *(e#code --install-extension evil.ext#)",
		"ls *(e#claude mcp add x -- evil#)",
		"ls *(e#python3 -m pip install evil-pkg#)",
		"ls *(eznpm i evil-pkgz)",
		"let i=1; ls *(N)",
		"ls *(e#id#)",
		"Bash(git status)",
		"ls *(e#pip3.12 install evil-pkg#)",
	} {
		tg, un, _, s := ParseLine(line)
		if len(tg)+len(un)+len(HookExtra(line, tg, un, s)) == 0 {
			t.Errorf("%q: silent", line)
		}
	}
}
