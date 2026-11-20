package installread

import (
	"slices"
	"testing"
)

// The re-review of home-config-env round 2 (2026-11-18): its proof tests, adopted.

func homeR2Holds(line string) bool {
	tg, un, _, s := ParseLine(line)
	return len(un)+len(HookExtra(line, tg, un, s)) > 0
}

// P2-1: quotings that leave a literal ~ (checked in bash in a container: each prints "~" or "~/x"), and ~ in an argument
// word, which zsh (macOS's default shell), dash and bash --posix never expand and env -S never expands at all.
func TestHomeReview2ProofLiteralTildeOnLines(t *testing.T) {
	for _, line := range []string{
		`HOME=""~ npm i left-pad`, `HOME=''~ npm i left-pad`, `HOME=~"" npm i left-pad`, `HOME=~'' npm i left-pad`, `HOME=~\/x npm i left-pad`,
		`HOME=$'~' npm i left-pad`, `HOME=~"/x" npm i left-pad`, `export HOME=""~; npm i left-pad`, `XDG_CONFIG_HOME=~"" pip install requests`,
		`env -S 'HOME=~ npm i left-pad'`, `env HOME=~ npm i left-pad`, `sudo HOME=~ npm i left-pad`, `claude mcp add x -e HOME=~ -- npx -y left-pad`,
		`Set-Item env:HOME ~; npm i left-pad`, `Set-Item -Path Env:HOME -Value '~'; npm i left-pad`,
	} {
		if !homeR2Holds(line) {
			t.Errorf("%q reads clean", line)
		}
	}
}

// P3-1: a share on another host (\\host\share, \\?\UNC\host\share) is a folder the line does not show, served by that
// host; the line forms hold already, an MCP entry's value does not.
func TestHomeReview2ProofUNCEntry(t *testing.T) {
	for _, v := range []string{`\\evil.example\share`, `\\?\UNC\evil.example\share`, `\\evil.example@SSL\DavWWWRoot\cfg`} {
		env := map[string]string{"APPDATA": v}
		if len(EnvUnread(env)) == 0 && !slices.Contains(ServerExtraCodes("npx", []string{"-y", "left-pad"}, env, nil), "custom_registry") {
			t.Errorf("entry APPDATA=%q reads clean", v)
		}
	}
}
