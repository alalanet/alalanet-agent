package installread

import (
	"slices"
	"strings"
	"testing"
)

// READER-ESCAPE-1 (home-p7 review, findings S and B; P1, live on 71a26345). A backslash before an ordinary character
// is dropped by bash, dash and zsh, so the reader must read the word the shell hands over, not the raw one. The red
// proof at the base: every line here read clean (no target, no reason) although it installs. A Windows path keeps its
// backslashes, so an honest C:\…\npm.cmd still resolves. The oracle proof of the shells' reading is in
// work-1118/reader-escape (metamorph), and the whole-class sweep is TestMetamorphSweep.
func readEscape(line string) (targets, reasons []string) {
	tg, un, _, s := ParseLine(line)
	return tg, append(un, HookExtra(line, tg, un, s)...)
}

func TestReaderEscapeSubcommand(t *testing.T) {
	// S: an escaped subcommand or runner verb. Each installs; the base read nothing.
	installs := map[string]string{
		`pip in\stall requests`:                "pypi:requests",
		`uv pip in\stall requests`:             "pypi:requests",
		`npm \i left-pad`:                      "npm:left-pad",
		`npm \install left-pad`:                "npm:left-pad",
		`yarn \add left-pad`:                   "npm:left-pad",
		`pnpm \add left-pad`:                   "npm:left-pad",
		`bun \add left-pad`:                    "npm:left-pad",
		`npm i\nstall mcp-server-fetch`:        "npm:mcp-server-fetch",
		`p\ip install requests`:                "pypi:requests",
		`pip install req\uests`:                "pypi:requests",
		`'pip' 'install' 'requests'`:           "pypi:requests",
		`"npm" "i" "left-pad"`:                 "npm:left-pad",
		`np\m i left-pad`:                      "npm:left-pad",
		`i""n'st'all requests via pip`:         "",              // a prose word, not a command: no install (consistency only)
		"pip in\\\nstall requests":             "pypi:requests", // a line continuation inside the verb
		`pip $'in'stall requests`:              "pypi:requests",
		`claude mcp \add s -- npx -y left-pad`: "npx -y left-pad",
		`npm \exec cowsay`:                     "", // exec with nothing named: an install form, no target
	}
	for line, want := range installs {
		tg, _ := readEscape(line)
		if want == "" {
			continue
		}
		if !slices.Contains(tg, want) {
			t.Errorf("%q: targets %v, want %s", line, tg, want)
		}
	}
	// npm \exec cowsay runs cowsay from the registry: a target or a hold, never nothing.
	if tg, why := readEscape(`npm \exec cowsay`); len(tg)+len(why) == 0 {
		t.Errorf("npm \\exec cowsay: read clean")
	}
}

func TestReaderEscapeAssignmentName(t *testing.T) {
	// B: an escaped character in a variable's name or its "=". The shell drops the backslash and makes the
	// assignment, so the escaped line must read exactly as the plain one; the base read the escaped form clean.
	// Each pair is {escaped, plain}.
	for _, p := range [][2]string{
		{`env NODE\_OPTIONS=--require=./x.js npx -y x`, `env NODE_OPTIONS=--require=./x.js npx -y x`},
		{`export \NODE_OPTIONS=--require=./x.js && npx -y x`, `export NODE_OPTIONS=--require=./x.js && npx -y x`},
		{`export \PATH=./bin:/usr/bin && npm i x`, `export PATH=./bin:/usr/bin && npm i x`},
		{`env \PATH=./bin:/usr/bin npm i x`, `env PATH=./bin:/usr/bin npm i x`},
		{`sudo \PATH=./bin:/usr/bin npm i x`, `sudo PATH=./bin:/usr/bin npm i x`},
		{`export H\OME=/tmp/x && npm i x`, `export HOME=/tmp/x && npm i x`},
		{`claude mcp add s -e \PATH=./bin:/usr/bin -- npx -y y`, `claude mcp add s -e PATH=./bin:/usr/bin -- npx -y y`},
		{`NODE\_OPTIONS=--require=./x.js npm i x`, `NODE_OPTIONS=--require=./x.js npm i x`},
	} {
		etg, ewhy := readEscape(p[0])
		ptg, pwhy := readEscape(p[1])
		if !slices.Equal(etg, ptg) || len(ewhy) != len(pwhy) {
			t.Errorf("%q reads %v/%d, but its plain twin %q reads %v/%d", p[0], etg, len(ewhy), p[1], ptg, len(pwhy))
		}
	}
	// An escaped "=" is no assignment to the shell's tilde rule: bash, dash and zsh set HOME to a literal ~ for
	// export HOME\=~ and to the home for export HOME=~ (oracle r10-oracle:1, round 3), so the escaped line is held for
	// the config folder ./~ and its plain twin is not.
	const tildeHome = "installs with a custom registry or config file alalanet cannot see (HOME moves the package managers' config to ./~: a folder of the project or the current directory)"
	if _, why := readEscape(`export HOME\=~ && npm i x`); !slices.Equal(why, []string{tildeHome}) {
		t.Errorf("export HOME\\=~: %q, want exactly %q", why, tildeHome)
	}
	if _, why := readEscape(`export HOME=~ && npm i x`); len(why) != 0 {
		t.Errorf("export HOME=~: %q, want none", why)
	}
	// NODE_OPTIONS=--require and a relative PATH set through an escaped name are still levers: held, with the install.
	for _, line := range []string{
		`env NODE\_OPTIONS=--require=./x.js npx -y x`,
		`export \PATH=./bin:/usr/bin && npm i x`,
	} {
		if tg, why := readEscape(line); len(tg) == 0 || len(why) == 0 {
			t.Errorf("%q: targets %v, reasons %v; want an install and a hold", line, tg, why)
		}
	}
}

func TestReaderEscapeWindowsPathKept(t *testing.T) {
	// A Windows path keeps its backslashes, so it still resolves; a bare name with a backslash does not (the shell
	// runs npm.cmd, so does the reader).
	cmds := Commands(`C:\Users\me\AppData\npm.cmd install left-pad`)
	if len(cmds) == 0 || cmds[0].Prog != "npm" {
		t.Errorf(`C:\…\npm.cmd: program %v, want npm`, cmds)
	}
	cmds = Commands(`.\node_modules\.bin\npx.cmd cowsay`)
	// .\ is ambiguous (a POSIX shell strips the backslash), so this reads POSIX; its consistency is the sweep's.
	_ = cmds
	// np\m.cmd is not a path: the shell runs npm.cmd.
	if cmds := Commands(`np\m.cmd install left-pad`); len(cmds) == 0 || cmds[0].Prog != "npm" {
		t.Errorf(`np\m.cmd: program %v, want npm`, cmds)
	}
}

func TestReaderEscapeDriveIsNotEscape(t *testing.T) {
	// splitShell must not drop the backslashes of a drive path even though U, A, m are ordinary characters.
	if !strings.Contains(splitShell(`C:\Users\me\npm.cmd`).segs[0].words[0], `\`) {
		t.Error(`C:\Users\me\npm.cmd lost its backslashes`)
	}
	if w := splitShell(`np\m`).segs[0].words[0]; w != "npm" {
		t.Errorf(`np\m = %q, want npm`, w)
	}
}

// Each Windows-path shape keeps its backslashes and resolves, so removing any one of looksWindowsPath's rules changes
// a reading (the mutants M05-M07). A plain name with a backslash does not, and .\x is POSIX (the oracle).
func TestReaderEscapeWindowsShapes(t *testing.T) {
	prog := func(line string) string {
		c := Commands(line)
		if len(c) == 0 {
			return ""
		}
		return c[0].Prog
	}
	// a drive or UNC path reaches the program through its last backslash (the whole word keeps them); a %VAR%\,
	// %~dp0\, $env:\ or ~\ path to an installer is read through the union second reading
	for line, want := range map[string]string{
		`C:\tools\npm.cmd i left-pad`:              "npm",
		`\\build01\share\tools\npm.cmd i left-pad`: "npm",
	} {
		if got := prog(line); got != want {
			t.Errorf("program of %q = %q, want %q", line, got, want)
		}
	}
	for _, line := range []string{
		`%USERPROFILE%\.local\bin\npm.cmd i x`, `%~dp0node_modules\.bin\npm.cmd i x`,
		`$env:LOCALAPPDATA\npm\npm.cmd i x`, `~\bin\npm.cmd i x`,
	} {
		if tg, _, _, _ := ParseLine(line); !slices.Contains(tg, "npm:x") {
			t.Errorf("%q: targets %v, want npm:x read through the Windows path", line, tg)
		}
	}
}

// A word with a colon but no drive shape (x:a\b) is POSIX: the backslash is dropped (mutant M04 widened the drive rule to
// any second-character colon). ShellFields drops empty words: they are no program, verb or "--" (mutant M09).
func TestReaderEscapeEdges(t *testing.T) {
	if w := splitShell(`x:a\b`).segs[0].words[0]; w != "x:ab" {
		t.Errorf(`x:a\b = %q, want x:ab`, w)
	}
	if got := ShellFields(`npm "" i ''`); !slices.Equal(got, []string{"npm", "i"}) {
		t.Errorf(`ShellFields(npm "" i '') = %q, want [npm i]`, got)
	}
}

// windowsWord puts the dropped backslashes back and moves the quoted parts' offsets past them, in one pass: the escapes
// it puts back are no escapes there (mutants M17-M19). "C:ab" + backslashes before offsets 2 and 4 is C:\ab\c.
func TestReaderEscapeWindowsWordOffsets(t *testing.T) {
	raw, segs, ok := windowsWord("C:abc", []int{2, 4}, [][3]int{{2, 3, 3}, {3, 4, 1}, {4, 5, 3}})
	if !ok || raw != `C:\ab\c` {
		t.Fatalf("raw %q ok %v, want C:\\ab\\c", raw, ok)
	}
	if want := [][3]int{{4, 5, 1}}; !slices.Equal(segs, want) {
		t.Errorf("segs %v, want %v", segs, want)
	}
	if w := splitShell(`\\build01\share\x.cmd`).segs[0].words[0]; !strings.HasPrefix(w, `\\`) {
		t.Errorf(`UNC word = %q, want a \\ prefix`, w)
	}
}
