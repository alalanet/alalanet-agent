package installread

import (
	"strings"
	"testing"
)

// Round 3 (HOME-CONFIG-ENV-1), attacking its own rule: every spelling in which bash, zsh or dash leaves the ~ of an
// assignment's value literal (the re-review's container checks, tilde/out.txt, and the rule: a quoted or escaped
// character anywhere in the tilde-prefix, or an empty quote next to it, stops tilde expansion), through every way a
// line sets the variable; and the spellings in which the shell expands it, which stay clean.
func TestHomeLiteralTildeEverySpelling(t *testing.T) {
	values := []string{`"~"`, `'~'`, `"~/x"`, `"~"/x`, `~"/x"`, `~"x"`, `""~`, `''~`, `~""`, `~''`, `$'~'`, `$"~"`, `\~`, `\~/x`,
		`~\/x`, `~\x`, `""~/x`, `~''/x`, `'~'/x`}
	forms := []string{"%s npm i left-pad", "export %s; npm i left-pad", "declare -x %s; npm i left-pad", "readonly %s; npm i left-pad",
		"typeset -x %s; npm ci", "%s pip install requests", "(%s; npm i left-pad)", "%s; npm i left-pad"}
	n := 0
	for _, name := range []string{"HOME", "XDG_CONFIG_HOME", "APPDATA", "PREFIX"} {
		for _, v := range values {
			for _, f := range forms {
				line := strings.Replace(f, "%s", name+"="+v, 1)
				n++
				if !homeR2Holds(line) {
					t.Errorf("%q reads clean", line)
				}
			}
		}
	}
	// argument words: env, sudo and their options, env -S (env expands nothing), an MCP add's -e, cmd's set, PowerShell
	for _, line := range []string{
		"env HOME=~ npm i left-pad", "env -i HOME=~ npm i left-pad", "env -u X HOME=~/x npm i left-pad", "sudo HOME=~ npm i left-pad",
		"sudo -E HOME=~ npm i left-pad", "nohup env HOME=~ npm i left-pad", "command env HOME=~ npm i left-pad", "exec env HOME=~ npm i left-pad",
		"time env XDG_CONFIG_HOME=~/c pip install requests", `env -S 'HOME=~ npm i left-pad'`, `env -S"HOME=~ npm i left-pad"`,
		`env --split-string='HOME=~/x npm i left-pad'`,
		"claude mcp add x -e HOME=~ -- npx -y left-pad", "claude mcp add x --env HOME=~ -- npx -y left-pad",
		"claude mcp add x --env=HOME=~ -- npx -y left-pad", "claude mcp add x -eHOME=~ -- npx -y left-pad",
		"codex mcp add x --env HOME=~ -- npx -y left-pad", "gemini mcp add x -e HOME=~ npx -y left-pad",
		"cmd /c set HOME=~ && npm i left-pad", `set "HOME=~" && npm i left-pad`, "set APPDATA=~ && pip install requests",
		`$env:HOME = "~"; npm i left-pad`, `$env:HOME='~'; npm i left-pad`, `${env:HOME} = '~'; npm i left-pad`,
		"Set-Item env:HOME ~; npm i left-pad", `Set-Item -Path Env:HOME -Value '~'; npm i left-pad`, "si env:HOME ~; npm i left-pad",
		"New-Item -Path Env:HOME -Value ~; npm i left-pad", `[Environment]::SetEnvironmentVariable('HOME','~'); npm i left-pad`,
	} {
		n++
		if !homeR2Holds(line) {
			t.Errorf("%q reads clean", line)
		}
	}
	// the shell expands these: the home, clean; and a line that only prints or mentions a quoted ~ costs nothing now
	for _, line := range []string{
		"HOME=~ npm i left-pad", "HOME=~/x npm i left-pad", `HOME=~/"x" npm i left-pad`, `HOME=~/'x' npm i left-pad`,
		`HOME=~/\x npm i left-pad`, "export HOME=~/x; npm i left-pad", `HOME="$HOME" npm i left-pad`, "HOME=${HOME}/x npm i left-pad",
		"XDG_CONFIG_HOME=~/.config pip install requests", "PREFIX=~/.npm-global npm i -g left-pad",
		`echo HOME="~" && npm i left-pad`, `git commit -m "HOME='~'" && npm ci`, "# HOME=\"~\"\nnpm ci", `HOME="~" make`, `printf 'HOME=~\n'; npm ci`,
	} {
		if homeR2Holds(line) {
			tg, un, _, s := ParseLine(line)
			t.Errorf("%q holds: %v %v", line, un, HookExtra(line, tg, un, s))
		}
	}
	if n < 600 {
		t.Errorf("%d lines tried", n)
	}
}

// The mark the tokenizer puts on a literal ~ never reaches what the walk reports of a command (Commands' Assigns).
func TestHomeTildeMarkStaysInside(t *testing.T) {
	for _, c := range Commands(`HOME=""~ npm i left-pad`) {
		for _, a := range c.Assigns {
			if strings.Contains(a, "\ue000") {
				t.Errorf("Commands shows the mark: %q", a)
			}
		}
	}
}

// Round 3, P3-1: a UNC path on another host in an MCP entry holds; the local device paths pass.
func TestHomeEntryUNC(t *testing.T) {
	for v, held := range map[string]bool{
		`\\evil.example\share`: true, `\\?\UNC\evil.example\share`: true, `\\evil.example@SSL\DavWWWRoot\cfg`: true, "//evil.example/share": true,
		`\\?\UNC\EVIL\x`: true, `\\?\C:\Users\me`: false, `\\.\C:\Users\me`: false, `C:\Users\me`: false, `\\?\`: false,
	} {
		if got := len(EnvUnread(map[string]string{"APPDATA": v})) > 0; got != held {
			t.Errorf("entry APPDATA=%q: held %v, want %v", v, got, held)
		}
	}
}

// Round 3, P3-2, not taken: npm's --prefix moves the global config to ${prefix}/etc/npmrc (@npmcli/config: globalconfig
// defaults to globalPrefix/etc/npmrc, and a --prefix on the command line sets both prefixes), but it moves the local
// prefix too, whose .npmrc npm reads as the project's config whatever the global one says: a folder the line names
// with --prefix gives a repository nothing it does not have with that folder's own .npmrc. PREFIX (the environment)
// moves the global prefix alone, and holds. The earlier reviews' decisions stand (installextra_test.go: "npx --prefix
// ./x -y ok-pkg", "a folder is no reason on a command line"); holding --prefix cost 138 lines of the corpus.
func TestHomeNpmPrefixFlagStaysAsDecided(t *testing.T) {
	for _, line := range []string{"npm i -g left-pad --prefix ./x", "npm --prefix ./app install", "npx --prefix /tmp/x -y ok-pkg"} {
		if homeR2Holds(line) {
			t.Errorf("%q holds", line)
		}
	}
	if !homeR2Holds("PREFIX=./x npm i -g left-pad") {
		t.Error("PREFIX=./x reads clean")
	}
}

// Round 3's mutants: each reader holds on its own (the line reader for POSIX lines, env -S and cmd's set), the mark
// never shows in a reason, and a word's quoting never leaks into the next word.
func TestHomeLiteralTildeEachReader(t *testing.T) {
	for _, line := range []string{`HOME=""~ npm i left-pad`, `HOME='$HOME/x' npm i left-pad`, `env -S 'HOME=~ npm i left-pad'`,
		"set HOME=~ && npm i left-pad", "env HOME=~ npm i left-pad", "fish -c 'HOME=~ npm i left-pad'"} {
		if first, _ := homeCodes(line); len(first) == 0 {
			t.Errorf("%q: the line reader reads it clean", line)
		}
	}
	for _, line := range []string{`HOME=""~ npm i left-pad`, `HOME=~"" npm i left-pad`, "claude mcp add x -e HOME=\"\"~ -- npx -y left-pad"} {
		tg, un, _, s := ParseLine(line)
		for _, r := range append(un, HookExtra(line, tg, un, s)...) {
			if strings.Contains(r, "\ue000") {
				t.Errorf("%q: the mark shows in %q", line, r)
			}
		}
	}
	for _, line := range []string{`ABCD="a" HOME=~ npm i left-pad`, `ABCDEF="a" HOME=~ npm i left-pad`, `ABCDEFGHIJ='a' XDG_CONFIG_HOME=~/.config pip install requests`,
		`X="a"; HOME=~ npm i left-pad`} {
		if homeR2Holds(line) {
			t.Errorf("%q holds: a quote of an earlier word marked this one", line)
		}
	}
}
