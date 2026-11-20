package installread

import "testing"

// Re-review 17 of READER-EXPANSION-ENV-1 round 29 (reader-env cee05d61, the own-shell allowlist): lines that still set
// PATH in the shell that runs the install and pass both readers. POSIX lines were run in a real shell
// (r17-proofs/shell/: host.out is bash 3.2.57 and zsh 5.9 on the Mac, bash52*.out is bash 5.2.15 in the pinned golang
// image, zsh-2.out is zsh 5.9) and a planted ./1/pip or ./bin/pip ran.
func TestReview17MissedAssigns(t *testing.T) {
	silent := func(line string) bool {
		tg, un, _, s := ParseLine(line)
		return len(un)+len(HookExtra(line, tg, un, s)) == 0
	}
	for _, tc := range []struct{ shells, prefix string }{
		// eval and trap run a value the line gives as code: valueKind only asks whether its first word names a builtin
		{"bash zsh", "t=PATH=./bin; eval \"$t\""},
		{"bash", "t=PATH=./bin; trap \"$t\" DEBUG"}, // the DEBUG trap runs before pip
		{"bash", "for x in PATH=./bin; do eval $x; done"},
		{"bash 5.2", "t='$[PATH=1]'; eval \"$t\""},
		{"bash 5.2", "t='x=$[PATH=1]'; eval $t"},
		// a subscript in single quotes, which is arithmetic: lineArith skips single quotes, the allowlist reads the
		// word as a name argument
		{"bash 5.2", "test -v 'a[PATH=1]'"},
		{"bash 5.2", "[ -v 'a[PATH=1]' ]"},
		{"bash 5.2", "[[ -v 'a[PATH=1]' ]]"},
		{"bash zsh", "read 'a[PATH=1]' <<< x"},
		{"bash 5.2", "declare 'a[PATH=1]=x'"},
		// zsh's printf with an argument number before the conversion: numericConv does not match %1$d
		{"zsh", "printf '%1$d' 'PATH=1' >/dev/null"},
		{"zsh", "printf '%2$d %1$d' 1 'PATH=1' >/dev/null"},
	} {
		if line := tc.prefix + "; pip install zz-pkg"; silent(line) {
			t.Errorf("%s: %q: silent", tc.shells, line)
		}
	}
}

// Scripts of the shells the allowlist leaves out (question 2): the install runs inside them, after they set PATH.
// csh ran on the Mac (shell/csh.out); fish, cmd.exe and Windows PowerShell are not on the reviewer's machine, and the
// lines follow their documentation: fish's set -p / --prepend and fish_add_path -P prepend to $PATH, cmd's PATH
// command sets PATH, [Environment]::SetEnvironmentVariable's default scope is the process, and sc is Windows
// PowerShell's alias of Set-Content.
func TestReview17ForeignScripts(t *testing.T) {
	for _, line := range []string{
		"csh -c 'setenv PATH ./bin; pip install zz-pkg'",
		"fish -c 'set -p PATH ./bin; pip install zz-pkg'",
		"fish -c 'set --prepend PATH ./bin; pip install zz-pkg'",
		"fish -c 'fish_add_path -P ./bin; pip install zz-pkg'",
		"cmd /c \"path .\\bin & pip install zz-pkg\"",
		"powershell -c 'sc env:PATH ./bin; pip install zz-pkg'",
		"pwsh -c '[Environment]::SetEnvironmentVariable(\"PA\"+\"TH\", \"./bin\"); pip install zz-pkg'",
	} {
		tg, un, _, s := ParseLine(line)
		if len(un)+len(HookExtra(line, tg, un, s)) == 0 {
			t.Errorf("%q: silent", line)
		}
	}
}

// Honest lines round 29 newly holds that a narrow widening keeps silent (question 3): case, arithmetic and the
// name-setting builtins on a literal name that is no lever, and a Markdown bullet. Silent at 8576b6ec.
func TestReview17NarrowWidening(t *testing.T) {
	for _, line := range []string{
		"case \"$OSTYPE\" in darwin*) brew install x;; esac; pip install zz-pkg",
		"(( i++ )); pip install zz-pkg",
		"let n=1; pip install zz-pkg",
		"mapfile -t reqs < reqs.txt; pip install zz-pkg",
		"printf -v now '%(%s)T' -1; pip install zz-pkg",
		"getopts h opt; pip install zz-pkg",
		"* Requires the optional `chdb` extra: `pip install 'mcp-clickhouse[chdb]'",
	} {
		tg, un, _, s := ParseLine(line)
		if ex := HookExtra(line, tg, un, s); len(un)+len(ex) > 0 {
			t.Errorf("%q: held %q %q", line, un, ex)
		}
	}
}
