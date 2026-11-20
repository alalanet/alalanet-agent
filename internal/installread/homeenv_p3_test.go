package installread

import (
	"strings"
	"testing"
)

// The P3 round of HOME-CONFIG-ENV-1 (ADR-0243 round 4), P3-3: every path variable the readers know holds on a literal
// ~ (or a single-quoted $) by the same tokenizer rule as HOME — the go command's folders, the second reader's paths
// and search paths, interpreters and programs — on a line, after env, and through an MCP add's -e. A literal ~ is a
// folder of that name under the current one, so GOMODCACHE='~/m' is a module cache from the repository.
func TestPathLiteralTildeEveryVariable(t *testing.T) {
	type c struct{ name, cmd string }
	vars := []c{
		{"GOMODCACHE", "go install golang.org/x/tools/cmd/goimports@v0.30.0"}, {"GOPATH", "go install golang.org/x/tools/cmd/goimports@v0.30.0"},
		{"GOCACHE", "go install golang.org/x/tools/cmd/goimports@v0.30.0"}, {"GOROOT", "go install golang.org/x/tools/cmd/goimports@v0.30.0"},
		{"CCACHE_DIR", "go install golang.org/x/tools/cmd/goimports@v0.30.0"}, {"PKG_CONFIG_PATH", "go install golang.org/x/tools/cmd/goimports@v0.30.0"},
		{"NODE_EXTRA_CA_CERTS", "npx -y left-pad"}, {"PYTHONUSERBASE", "pip install requests"}, {"PYTHONPATH", "pip install requests"},
		{"NODE_PATH", "npx -y left-pad"}, {"PATH", "npx -y left-pad"}, {"SSL_CERT_FILE", "pip install requests"}, {"PIP_CERT", "pip install requests"},
		{"UV_PYTHON_INSTALL_DIR", "uv pip install requests"}, {"PIPX_HOME", "pipx install black"}, {"COREPACK_HOME", "npx -y left-pad"},
		{"npm_config_cafile", "npm i left-pad"}, {"VIRTUAL_ENV", "uv pip install requests"}, {"UV_PYTHON", "uv pip install requests"},
	}
	vals := []string{`'~/x'`, `~""/x`, `\~/x`, `"~"/x`, `'$X/x'`}
	n := 0
	for _, v := range vars {
		for _, val := range vals {
			for _, f := range []string{"%s=%s %s", "export %s=%s; %s", "env %s=%s %s"} {
				line := strings.Replace(strings.Replace(strings.Replace(f, "%s", v.name, 1), "%s", val, 1), "%s", v.cmd, 1)
				n++
				if !homeR3Holds(line) {
					t.Errorf("%q reads clean", line)
				}
			}
		}
		if line := v.name + "=~/x " + v.cmd; homeR3Holds(line) && v.name != "PATH" && v.name != "NODE_PATH" && v.name != "PYTHONPATH" {
			_, un, _, _ := ParseLine(line)
			t.Errorf("%q holds (the shell expands that ~): %v", line, un)
		}
	}
	// through an MCP add's -e: the launch target carries the folder as it is (install_check judges it: app's
	// TestPathLiteralTildeMCPAdd)
	for _, line := range []string{"claude mcp add x -e GOMODCACHE='~/m' -- go run golang.org/x/tools/cmd/goimports@v0.30.0",
		`claude mcp add x -e GOMODCACHE=~""/m -- go run golang.org/x/tools/cmd/goimports@v0.30.0`} {
		n++
		if tg, _, _, _ := ParseLine(line); len(tg) != 1 || !strings.Contains(tg[0], "GOMODCACHE=./~") {
			t.Errorf("%q: target %q", line, tg)
		}
	}
	if n < 270 {
		t.Errorf("%d lines tried", n)
	}
}

// P3-2: every element of a list after an unquoted ":" by the same rule (bash expands ~ after each ":" of an
// assignment), and nothing of a single folder's value after a ":" (HOME=~:x is /root:x, one absolute path).
func TestListLiteralTildeAfterColon(t *testing.T) {
	for _, line := range []string{`PATH=/usr/bin:~""/bin npx -y left-pad`, `GOPATH=/go:'~/g' go install golang.org/x/tools/cmd/goimports@v0.30.0`,
		`PYTHONPATH=/a:\~/b pip install requests`, `XDG_CONFIG_DIRS=/etc:"~"/x uv pip install requests`} {
		if !homeR3Holds(line) {
			t.Errorf("%q reads clean", line)
		}
	}
	for _, line := range []string{"XDG_CONFIG_DIRS=/etc:~/.config pip install requests", "HOME=~:x npm i left-pad", `HOME=/home/u:'~' npm i left-pad`,
		"GOPATH=/go:~/go go install golang.org/x/tools/cmd/goimports@v0.30.0"} {
		if homeR3Holds(line) {
			t.Errorf("%q holds", line)
		}
	}
}

// P3-1: no private-use character, and no mark of any kind, ever reaches a target, a reason or what Commands reports: a
// literal start is written as the folder it is (./~, ./$X).
func TestNoMarkAnywhere(t *testing.T) {
	for _, line := range []string{`claude mcp add x -e GOFLAGS='$X' -- npx -y left-pad`, `claude mcp add x -e GOPATH=~"" -- npx -y left-pad`,
		`HOME=""~ npm i left-pad`, `GOMODCACHE='~/m' go install golang.org/x/tools/cmd/goimports@v0.30.0`, `PATH=/a:~""/b npx -y left-pad`,
		`claude mcp add x -e GOMODCACHE='~/m' -- go run golang.org/x/tools/cmd/goimports@v0.30.0`} {
		tg, un, _, s := ParseLine(line)
		all := append(append(append([]string{}, tg...), un...), HookExtra(line, tg, un, s)...)
		for _, c := range Commands(line) {
			all = append(append(all, c.Assigns...), c.Words...)
		}
		for _, x := range all {
			if strings.ContainsFunc(x, func(r rune) bool { return r >= 0xe000 && r <= 0xf8ff }) {
				t.Errorf("%q: a private-use character in %q", line, x)
			}
		}
	}
}

// Attacking round 4: a literal ~ reaches a path variable through another variable the line sets (its expansion is not
// tilde-expanded again), in both readers' bindings; another variable's literal $ is left as it is.
func TestLiteralTildeThroughAVariable(t *testing.T) {
	for _, line := range []string{"D='~/b'; PATH=$D:/usr/bin npx -y left-pad", `D=~""/c; HOME=$D npm i left-pad`,
		"D='~/m'; GOMODCACHE=$D go install golang.org/x/tools/cmd/goimports@v0.30.0", `D=\~/b; export PYTHONPATH=$D; pip install requests`} {
		if !homeR3Holds(line) {
			t.Errorf("%q reads clean", line)
		}
	}
	for _, line := range []string{"D=~/b; PATH=$D:/usr/bin npx -y left-pad", "U='$X'; npm i left-pad"} {
		if homeR3Holds(line) {
			t.Errorf("%q holds", line)
		}
	}
	for _, c := range Commands("U='$X' npm i left-pad") {
		for _, a := range c.Assigns {
			if a != "U=$X" {
				t.Errorf("another variable's literal $ was written as a folder: %q", a)
			}
		}
	}
}

// Round 4's mutants: two literal elements of one list are both written as folders, in place; a single file's value
// after a ":" is one path (NODE_EXTRA_CA_CERTS=/etc/ca.pem:'~' is the file "/etc/ca.pem:~").
func TestLiteralTildeTwoElements(t *testing.T) {
	for _, c := range Commands(`PATH='~/a':'~/b':/usr/bin npx -y left-pad`) {
		if len(c.Assigns) == 1 && c.Assigns[0] != "PATH=./~/a:./~/b:/usr/bin" {
			t.Errorf("assigns %q", c.Assigns)
		}
	}
	if homeR3Holds(`NODE_EXTRA_CA_CERTS=/etc/ca.pem:'~' npx -y left-pad`) {
		t.Error("a single file's value after a : was taken as a list")
	}
}

// bash in a container (work-1116/home-p3/tilde/out.txt): X="/etc:"~ is "/etc:~" (a quoted ":" leaves the next ~
// literal), P=~:'/opt/bin' is "/root:/opt/bin" (the tilde-prefix ends at the ":"). And a literal start reads as the
// folder it is: a folder of the project, not a variable's.
func TestLiteralTildeColonEdges(t *testing.T) {
	if !homeR3Holds(`XDG_CONFIG_DIRS="/etc:"~ uv pip install requests`) {
		t.Error(`XDG_CONFIG_DIRS="/etc:"~ reads clean`)
	}
	if homeR3Holds(`PATH=~:'/opt/bin' npx -y left-pad`) {
		t.Error(`PATH=~:'/opt/bin' holds`)
	}
	_, un, _, _ := ParseLine(`HOME='$HOME/x' npm i left-pad`)
	if len(un) != 1 || !strings.Contains(un[0], whyDirRelative) {
		t.Errorf("HOME='$HOME/x': %q", un)
	}
}
