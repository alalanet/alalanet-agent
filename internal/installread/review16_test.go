package installread

import "testing"

// Re-review 16 of READER-EXPANSION-ENV-1 round 28 (reader-env 8576b6ec): lines that still assign PATH in the line's
// own shell and pass both readers. Each was run in a real shell (r16-proofs/shell/: host.out is bash 3.2.57 and zsh
// 5.9 on the Mac, bash52.out is bash 5.2.15 in the pinned golang image), and a planted ./1/pip or ./bin/pip ran
// unless noted.
func TestReview16MissedAssigns(t *testing.T) {
	silent := func(line string) bool {
		tg, un, _, s := ParseLine(line)
		return len(un)+len(HookExtra(line, tg, un, s)) == 0
	}
	for _, tc := range []struct{ shells, prefix string }{
		// rule 1's count, gamed: a judged word counted twice, or a judged word whose name the raw text does not show
		{"bash zsh", "echo -e PATH=x; : $[PATH=1]"},    // echo's words and the -e word: PATH judged twice
		{"bash", "echo --env=PATH=x; : $[PATH=1]"},     // echo's words and --env=: twice
		{"bash", "export \"PATH\"=$PATH; : $[PATH=1]"}, // the judged word is PATH=$PATH; the raw text has "PATH"=
		{"bash", "export \"PATH\"=$PATH; declare -i n=PATH=1"},
		{"bash", "echo PA''TH=x; [[ PATH=1 -eq 1 ]]"}, // echo's word counts PATH, the raw text does not
		// echo is not text: the shell expands its words, and arithmetic in them assigns
		{"bash zsh", "echo $[PATH=1] >/dev/null"},
		{"bash", "x=abc; echo ${x: PATH=1} >/dev/null"},
		{"bash", "x=abc; echo \"${x:0:PATH=1}\" >/dev/null"},
		// a quoted or escaped character in the name: the raw text has no PATH=, the shell removes the quote
		{"bash zsh", "[[ PA\"\"TH=1 -eq 1 ]]"},
		{"bash", "[[ P\\ATH=1 -eq 1 ]]"},
		{"bash", "declare -i n=PA''TH=1"},
		{"bash", "x=PA''TH=1; (( x ))"},
		{"zsh", "printf %d PA''TH=1 >/dev/null"},
		// a name built from an expansion: rule 2 reads only a whole $n or ${n}
		{"bash zsh", "a=PA; read ${a}TH <<< ./bin"},
		{"bash", "a=PA; printf -v ${a}TH ./bin"},
		{"bash zsh", "a=PA; (( ${a}TH = 1 ))"},
		{"bash", "a=PA; let ${a}TH=1"},
		{"bash 5.2", "a=PA; declare -n r=${a}TH; r=./bin"},
		{"bash", "a=PA; [[ ${a}TH=1 -eq 1 ]]"},
		// an option's name joined to its letter: rule 3 reads a bare word only
		{"zsh", "print -rvPATH ./bin"},
		{"bash 5.2", "read -aPATH <<< ./bin"},    // PATH=[./bin] (bash52.out)
		{"bash 5.2", "sleep 0 & wait -n -pPATH"}, // PATH=[a pid] (bash52.out)
		// zsh's set -A on the tied array: set is on the harmless list, and path is read only as path=
		{"zsh", "set -A path ./bin $path"},
	} {
		if line := tc.prefix + "; pip install zz-pkg"; silent(line) {
			t.Errorf("%s: %q: silent", tc.shells, line)
		}
	}
}

// Honest lines that round 28 newly holds: silent at 84515a8a, held at 8576b6ec (r16-proofs/probe-*.txt). A make
// variable, a remote system's setting, a file's text and a program's own code set nothing in the line's shell.
func TestReview16NewFalseHolds(t *testing.T) {
	for _, line := range []string{
		"make install PREFIX=$HOME/.local && pip install zz-pkg",
		"make test PYTHON=python3 && pip install zz-pkg",
		"conda env config vars set PYTHONPATH=$PWD && pip install zz-pkg",
		"printf 'PATH=%s\\n' \"$PATH\" >> \"$GITHUB_ENV\" && pip install zz-pkg",
		"sed -i 's/^PATH=.*//' .env && pip install zz-pkg",
		"node -e \"process.env.NODE_OPTIONS='--x'\" && npm i zz-pkg",
		"kubectl set env deploy/x NODE_OPTIONS=--max-old-space-size=4096 && npm i zz-pkg",
		"docker build --build-arg PIP_INDEX_URL=https://pypi.org/simple . && pip install zz-pkg",
		"for v in PATH PYTHONPATH; do echo ${!v}; done; pip install zz-pkg",
	} {
		tg, un, _, s := ParseLine(line)
		if ex := HookExtra(line, tg, un, s); len(un)+len(ex) > 0 {
			t.Errorf("%q: held %q %q", line, un, ex)
		}
	}
}
