package installread

import (
	"strings"
	"testing"
)

// Reviewer's proofs (home-p7, ADR-0243 round 7; adopted in round 8 without B and S, which are READER-ESCAPE-1's). Each line's truth in bash, dash and zsh, and with the real pip, node
// and pwsh, is in h/q/out-t7.txt, h/q/out-pwsh.txt and h/q/q-truth.json. One subtest a finding:
//
//	R1 (regression): held at develop 4f06c4aa, clean at the merge;
//	R2, B, D, E, G, S: clean at develop and at the merge.
func TestRvHome7(t *testing.T) {
	read := func(line string) (targets, reasons []string) {
		tg, un, _, s := ParseLine(line)
		return tg, append(un, HookExtra(line, tg, un, s)...)
	}
	holds := func(t *testing.T, lines ...string) {
		t.Helper()
		for _, line := range lines {
			if _, why := read(line); len(why) == 0 {
				t.Errorf("%s: reads clean", line)
			}
		}
	}
	// pip and uv take a bare value for a file or folder of the current directory first (cwdFirst): pip 23.0.1 runs the
	// planted ~m$/bin/python in bash, dash and zsh. cwdFirst leaves out a value with $ or %; develop held these through
	// round 5's ./~m$.
	t.Run("R1 a ~name with $ or % for a lever that looks in the current folder first", func(t *testing.T) {
		holds(t, `UV_PYTHON=~m$ uvx x`, `UV_PYTHON=~a%b uvx x`, `PIP_PYTHON=~m$ pip install requests`, `PIP_PYTHON=~a%b pip install requests`)
	})
	// every shell keeps the ~ of a fully quoted word; dash and zsh run the planted ./~/a b/npm, bash one process down
	t.Run("R2 a quoted assignment word with a space or an operator", func(t *testing.T) {
		holds(t, `export "PATH=~/a b:/usr/bin" && npm i x`, `export "HOME=~/a b" && npm i x`, `declare -x "PATH=~/a b:/usr/bin"; npm i x`,
			`export 'HOME=~/a;b' && npm i x`)
	})
	t.Run("R2 the note on a quoted word with a space", func(t *testing.T) {
		for _, line := range []string{`env "HOME=~/a b" npm i x`, `claude mcp add s -e "PATH=~/a b:/usr/bin" -- npx -y y`} {
			if _, why := read(line); strings.Contains(strings.Join(why, " | "), "would use") {
				t.Errorf("%s: the note says bash expands a quoted word: %s", line, strings.Join(why, " | "))
			}
		}
	})
	// no shell expands an MCP entry's value (round 2, P2-1): node's spawn with PATH=~/bin:… runs ./~/bin/npx
	t.Run("D an MCP entry's search path with ~", func(t *testing.T) {
		for _, kv := range [][2]string{{"PATH", "~/bin:/usr/bin"}, {"NODE_PATH", "~/lib"}, {"PYTHONPATH", "/usr/lib:~/lib"}, {"LD_LIBRARY_PATH", "~/lib"}} {
			env := map[string]string{kv[0]: kv[1]}
			if len(EnvUnread(env))+len(ServerExtraCodes("npx", []string{"-y", "left-pad"}, env, nil)) == 0 {
				t.Errorf("MCP entry %s=%s: no reason", kv[0], kv[1])
			}
		}
	})
	// PowerShell 7.4 on Linux keeps the ~ of a string; a child runs ./~/bin/npm
	t.Run("E a PowerShell value that is a : list", func(t *testing.T) {
		holds(t, `$env:PATH = "/usr/bin:~/bin"; npm i x`, `$env:NODE_PATH = "/usr/lib:~/lib"; npm i x`)
	})
	// bash, dash and zsh run the planted ./%P%/go
	t.Run("G a %NAME% entry of a search path in a POSIX line", func(t *testing.T) {
		holds(t, `PATH=%P%:/usr/bin go install example.com/x@latest`, `PATH=%P:~+x/bin:/usr/bin go install example.com/x@latest`)
	})
}
