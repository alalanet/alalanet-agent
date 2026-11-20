package installread

import (
	"strings"
	"testing"
)

func homeP8Reasons(line string) string {
	tg, un, _, s := ParseLine(line)
	return strings.Join(append(append([]string{}, un...), HookExtra(line, tg, un, s)...), " | ")
}

// ADR-0243 round 8, R1: a lever's value whose first element has a tilde-prefix (~name, ~+, ~-, ~0) is held whatever
// the lever (a program, an interpreter, a virtualenv, a path), as the owner's rule says; the home (~, ~/…) keeps the
// lever's own rule.
func TestHomeP8LeverTildeFirstElement(t *testing.T) {
	for _, line := range []string{
		"UV_PYTHON=~m$ uvx x", "PIP_PYTHON=~a%b pip install requests", "PYTHON=~root npm i x", "GIT_SSH=~x@y npm i x",
		"MAKE=~u npm i x", "UV_PYTHON=~+ uvx x", "PYTHON=~0 npm i x", "VIRTUAL_ENV=~u/venv pip install requests",
		"npm_config_script_shell=~1 npm i x", "env PIPX_DEFAULT_PYTHON=~nouser pipx install x", "PIPX_DEFAULT_PYTHON=~=3.12 pipx install x",
		"claude mcp add s -e UV_PYTHON=~m$ -- uvx x",
	} {
		if r := homeP8Reasons(line); r == "" {
			t.Errorf("%q reads clean", line)
		} else if !strings.Contains(r, whyDirUser) && !strings.Contains(r, whyDirRelative) && !strings.Contains(r, "points at ./~") {
			t.Errorf("%q: the reason does not say which folder: %s", line, r)
		}
	}
	// a version request is no folder (uvx --python '~=3.12.0' some-tool: the corpus line of round 8)
	for _, line := range []string{"PYTHON=~/bin/python3 npm i x", "UV_PYTHON=3.12 uvx x", "PYTHON=python3 npm i x", "GIT_SSH=ssh npm i x",
		"uvx --python '~=3.12.0' some-tool", "UV_PYTHON=~=3.12 uvx x", "uv run --python ~=3.11 pytest"} {
		if r := homeP8Reasons(line); r != "" {
			t.Errorf("%q: %s", line, r)
		}
	}
}

// R2: a quoted word with a space or an operator is the assignment where an assignment stands (after export, declare,
// typeset, readonly, local, env, sudo, an MCP add's -e) — its value as the shell assigns it, every ~ literal: held, no
// bash note — and a script where a script stands (sh -c, bash -c, eval): read again as a line, as before.
func TestHomeP8QuotedWordWithSpace(t *testing.T) {
	for _, line := range []string{`export "PATH=~/a b:/usr/bin" && npm i x`, `declare -x "PATH=~/a b:/usr/bin"; npm i x`,
		`export 'HOME=~/a;b' && npm i x`, `typeset -x "HOME=~/a b"; npm i x`, `readonly "PATH=~/a b:/usr/bin" && npm i x`,
		`env "HOME=~/a b" npm i x`, `sudo "PATH=~/a b:/usr/bin" npm i x`, `claude mcp add s -e "PATH=~/a b:/usr/bin" -- npx -y y`,
		`env "NPM_CONFIG_USERCONFIG=~/a b/.npmrc" npm i x`, `export "PATH=/usr/bin:~/a b" && npm i x`} {
		r := homeP8Reasons(line)
		if r == "" {
			t.Errorf("%q reads clean", line)
		}
		if strings.Contains(r, "would use") {
			t.Errorf("%q: the bash note on a quoted word: %s", line, r)
		}
	}
	// a script: the shell assigns HOME=~ there, the home (clean as before); the note of an unquoted word stays
	for _, line := range []string{`sh -c "HOME=~ npm i x"`, `bash -c "PATH=~/bin:/usr/bin npm i x"`, `eval "HOME=~/x npm i x"`} {
		if r := homeP8Reasons(line); r != "" {
			t.Errorf("%q: %s", line, r)
		}
	}
	if r := homeP8Reasons(`env HOME=~/x npm i x`); !strings.Contains(r, whyArgTildeNote) {
		t.Errorf("the unquoted word lost its note: %s", r)
	}
}

// D: an MCP entry's value reaches the server as written: a ~ element of a search path or a path lever is the folder
// ./~ of the server's working folder, with round 2's reason.
func TestHomeP8EntryTilde(t *testing.T) {
	for _, kv := range [][2]string{{"PATH", "~/bin:/usr/bin"}, {"PATH", "/usr/bin:~/bin"}, {"NODE_PATH", "~/lib"}, {"PYTHONPATH", "/usr/lib:~/lib"},
		{"LD_LIBRARY_PATH", "~/lib"}, {"NODE_EXTRA_CA_CERTS", "~/ca.pem"}, {"UV_PYTHON", "~/py/bin/python"}, {"VIRTUAL_ENV", "~/x/bin"}} {
		env := map[string]string{kv[0]: kv[1]}
		un, codes := EnvUnread(env), ServerExtraCodes("npx", []string{"-y", "left-pad"}, env, nil)
		if len(un)+len(codes) == 0 {
			t.Errorf("entry %s=%s: no reason", kv[0], kv[1])
		}
	}
	// a folder named as a virtualenv (venv, .venv) is the project's own for the lever (lvVenv), ./~/venv as ./venv
	if len(ServerExtraCodes("npx", []string{"-y", "left-pad"}, map[string]string{"VIRTUAL_ENV": "./venv"}, nil)) != 0 {
		t.Error("an entry's ./venv held: the venv lever's rule changed")
	}
	e := newExtraParse()
	e.pm++
	e.entryEnv = true
	e.env("PATH", "/usr/bin:~/bin")
	if r := strings.Join(e.reasons(), " | "); !strings.Contains(r, "./~/bin") || !strings.Contains(r, whyDirLiteral) {
		t.Errorf("the entry's reason: %s", r)
	}
	for _, kv := range [][2]string{{"PATH", "/usr/bin:/bin"}, {"NODE_PATH", "/opt/lib"}} {
		if env := map[string]string{kv[0]: kv[1]}; len(EnvUnread(env))+len(ServerExtraCodes("npx", []string{"-y", "left-pad"}, env, nil)) != 0 {
			t.Errorf("entry %s=%s held", kv[0], kv[1])
		}
	}
}

// G: in a POSIX line a %…% element is a folder of that name, and cmd's %NAME:~n,m% exception is cmd's alone; cmd's
// and PowerShell's own values keep their reading.
func TestHomeP8PercentInPosixLine(t *testing.T) {
	for _, line := range []string{"PATH=%P%:/usr/bin go install example.com/x@latest", "PATH=%P:~+x/bin:/usr/bin go install example.com/x@latest",
		"export PATH=%P%:/usr/bin && go install example.com/x@latest", "env PATH=/usr/bin:%P% go install example.com/x@latest",
		`PATH="%P%;/usr/bin" go install example.com/x@latest`} {
		if homeP8Reasons(line) == "" {
			t.Errorf("%q reads clean", line)
		}
	}
	if untrustedPathIn("%PATH:~0,3%", true) || !untrustedPathIn("%P:~+x/bin", false) || !untrustedPathIn("%P%:/usr/bin", false) || untrustedPathIn("%P%;C:\\x", true) {
		t.Error("untrustedPathIn: the cmd exception in the wrong place")
	}
	// a Windows-looking value of a POSIX line (a backslash and %NAME%) keeps the Windows reading, as the second reader's
	for _, line := range []string{"set PATH=%PATH%;C:\\tools && go install example.com/x@latest", `PATH="C:\tools;%PATH%" npx -y x`,
		`PATH='%USERPROFILE%\bin' npx -y ok-pkg`} {
		if r := homeP8Reasons(line); r != "" {
			t.Errorf("%q: %s", line, r)
		}
	}
	// with a slash the value is POSIX-shaped, and a POSIX line is the only shell's that runs it (cmd and PowerShell take
	// no NAME=value prefix): bash, dash and zsh set PATH to %P%bin:/usr/bin (oracle, READER-ESCAPE-1 round 3), a
	// folder of the current directory first
	const rel = "runs with an environment that loads other code (PATH points at %P%bin:/usr/bin)"
	if r := homeP8Reasons(`PATH=%P%\bin:/usr/bin go install example.com/x@latest`); r != rel {
		t.Errorf("PATH=%%P%%\\bin:/usr/bin: %q, want exactly %q", r, rel)
	}
	if r := homeP8Reasons("set PATH=%PATH:~0,3%;%PATH% && npx -y ok-pkg"); strings.Count(r, " | ") != 0 || r == "" {
		t.Errorf("cmd's substring: %s", r)
	}
}

// E: PowerShell on Linux keeps a string's ~ and takes a list at ":" when it has no ";": each element is judged; cmd's
// value is one Windows path there.
func TestHomeP8PowerShellColonList(t *testing.T) {
	for _, line := range []string{`$env:PATH = "/usr/bin:~/bin"; npm i x`, `$env:NODE_PATH = "/usr/lib:~/lib"; npm i x`,
		`$env:PATH="/usr/bin:~/bin"; npm i x`, `$env:PYTHONPATH = "/usr/lib:~u/lib"; pip install requests`} {
		if homeP8Reasons(line) == "" {
			t.Errorf("%q reads clean", line)
		}
	}
	for _, line := range []string{`$env:PATH = "/usr/bin:/bin"; npm i x`, `$env:PATH = "C:\tools;C:\bin"; npm i x`} {
		if r := homeP8Reasons(line); r != "" {
			t.Errorf("%q: %s", line, r)
		}
	}
}

// R2 and D through each reader alone: go lines have only the first reader; a here-document's line keeps its quoted
// word's value; an MCP entry's reason says why in both readers.
func TestHomeP8EachReader(t *testing.T) {
	for _, line := range []string{`export "PATH=~/a b:/usr/bin" && go install example.com/x@latest`,
		`env "PATH=~/a b:/usr/bin" go install example.com/x@latest`, "bash <<'EOF'\nexport \"PATH=~/a b:/usr/bin\" && go install example.com/x@latest\nEOF"} {
		if _, un, _, _ := ParseLine(line); len(un) == 0 {
			t.Errorf("%q: the first reader reads it clean", line)
		}
	}
	if un := strings.Join(EnvUnread(map[string]string{"PATH": "~/bin:/usr/bin"}), " | "); !strings.Contains(un, "./~/bin") || !strings.Contains(un, whyDirLiteral) {
		t.Errorf("EnvUnread: %s", un)
	}
	e := newExtraParse()
	e.pm++
	e.entryEnv = true
	e.env("HOME", "~/x")
	if r := strings.Join(e.reasons(), " | "); !strings.Contains(r, "to ~/x: "+whyDirLiteral) {
		t.Errorf("an entry's HOME: %s", r)
	}
}

// G: the POSIX lines of the ninth review's table (app installmut9_test.go, installwin9_test.go), whose reason the second
// reader gave alone, get the same reason from the first reader now.
func TestHomeP8FirstReaderPercent(t *testing.T) {
	for line, want := range map[string]string{
		"set FOO=bar && PATH=%evil% npx -y ok-pkg":                     "PATH points at %evil%",
		"set PATH=%PATH%;C:\\tools && env PATH=%PATH% npx -y ok-pkg":   "PATH points at %PATH%",
		`echo "set PATH=%PATH%;C:\tools" && PATH=%evil% npx -y ok-pkg`: "PATH points at %evil%",
		`$env:PATH = "C:\tools;$env:PATH"; PATH=%PATH% npx -y ok-pkg`:  "PATH points at %PATH%",
		`PATH=%PATH% npx -y ok-pkg`:                                    "PATH points at %PATH%",
		`PATH=%x%:$PATH npx -y ok-pkg`:                                 "PATH points at %x%:$PATH",
	} {
		_, un, _, _ := ParseLine(line)
		if len(un) != 1 || un[0] != whyLoads+" ("+want+")" {
			t.Errorf("%q: %q", line, un)
		}
	}
}
