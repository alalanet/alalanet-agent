package installread

import (
	"slices"
	"testing"
)

// The review of home-config-env (2026-11-17, P2-1, P3-1, P3-2): its proof tests, adopted. Each case is a folder the repository can hold.
func TestHomeReviewProofHomeTildeNumber(t *testing.T) {
	// bash and zsh expand ~0 (and ~N after pushd) in an assignment to the current folder, as ~+ (checked in a
	// throwaway container: HOME=~0 bash -c 'echo $HOME' prints the cwd)
	for _, line := range []string{"HOME=~0 npm i left-pad", "HOME=~0/x npm i left-pad", "XDG_CONFIG_HOME=~0 pip install requests", "pushd . && HOME=~1 npm i left-pad"} {
		tg, un, _, s := ParseLine(line)
		if len(un)+len(HookExtra(line, tg, un, s)) == 0 {
			t.Errorf("%q reads clean", line)
		}
	}
}

func TestHomeReviewProofHomeEntryLiteral(t *testing.T) {
	// an MCP entry's env is not shell-expanded: "~" and "$HOME" are folders named so under the server's working folder
	for _, v := range []string{"~", "~/x", "$HOME", "$HOME/x"} {
		env := map[string]string{"HOME": v}
		if len(EnvUnread(env)) == 0 && !slices.Contains(ServerExtraCodes("npx", []string{"-y", "left-pad"}, env, nil), "custom_registry") {
			t.Errorf("entry HOME=%q reads clean", v)
		}
	}
}

func TestHomeReviewProofGoDirCwdAlias(t *testing.T) {
	// develop's goDirWhy (eco1-go) has no path.Clean: /proc/./self/cwd, //proc/self/cwd and ~0 pass where /proc/self/cwd holds
	for _, line := range []string{
		"GOMODCACHE=/proc/./self/cwd/m go install golang.org/x/tools/cmd/goimports@v0.30.0",
		"GOMODCACHE=//proc/self/cwd/m go install golang.org/x/tools/cmd/goimports@v0.30.0",
		"GOPATH=/proc//self/cwd go install golang.org/x/tools/cmd/goimports@v0.30.0",
		"GOMODCACHE=~0/m go install golang.org/x/tools/cmd/goimports@v0.30.0",
	} {
		tg, un, _, s := ParseLine(line)
		if len(un)+len(HookExtra(line, tg, un, s)) == 0 {
			t.Errorf("%q reads clean", line)
		}
	}
}

// Round 2, P2-1: an MCP entry's values reach the server as written — no shell expands ~, $NAME or %NAME% there — so
// only an absolute folder and the clients' own home forms (${HOME}, ${env:HOME}, ${env:USERPROFILE}, ${userHome}) are
// the user's; anything else is a folder named so under the server's working folder, or a variable's.
func TestHomeEntryValues(t *testing.T) {
	for v, held := range map[string]bool{
		"~": true, "~/x": true, "$HOME": true, "$HOME/x": true, "%USERPROFILE%": true, `%USERPROFILE%\x`: true, "$env:USERPROFILE": true,
		"${HOME:-/root}": true, "${CLAUDE_PROJECT_DIR}": true, "${TMPDIR}": true, ".": true, "h": true, "~0": true, "/tmp/h": true,
		"${HOME}/../x": true, "${HOMEX}": true, "${HOME}x": true,
		"/home/u": false, "/root": false, `C:\Users\me`: false, "C:/Users/me": false, "${HOME}": false, "${HOME}/.config": false,
		"${env:HOME}": false, `${env:USERPROFILE}\AppData\Roaming`: false, "${userHome}": false, "${userHome}/x": false, "": false,
	} {
		env := map[string]string{"HOME": v}
		first := len(EnvUnread(env)) > 0
		second := slices.Contains(ServerExtraCodes("npx", []string{"-y", "left-pad"}, env, nil), "custom_registry")
		if first != held || second != held {
			t.Errorf("entry HOME=%q: line reader %v, second reader %v; want %v", v, first, second, held)
		}
	}
	// the same values on a shell line are the shell's: ~ and $HOME are the home there
	for _, l := range []string{"HOME=~ npm i left-pad", "HOME=$HOME/x npm i left-pad", "HOME=${HOME} npm i left-pad"} {
		tg, un, _, s := ParseLine(l)
		if n := len(un) + len(HookExtra(l, tg, un, s)); n != 0 {
			t.Errorf("%q: held on a line", l)
		}
	}
}

// Round 2, P3-3: LOCALAPPDATA (pnpm's config on Windows), XDG_CONFIG_DIRS (pip's and uv's system config, a list) and
// PREFIX (npm's $PREFIX/etc/npmrc) move package-manager config too: the same rule.
func TestHomeConfigEnvMoreFolders(t *testing.T) {
	for _, l := range []string{
		"LOCALAPPDATA=$GITHUB_WORKSPACE pnpm add left-pad", `LOCALAPPDATA=.\cfg pnpm add left-pad`, "XDG_CONFIG_DIRS=$CI_PROJECT_DIR pip install requests",
		"XDG_CONFIG_DIRS=/etc/xdg:./cfg uv pip install requests", "PREFIX=$GITHUB_WORKSPACE npm i left-pad", "PREFIX=. npm i left-pad",
	} {
		first, both := homeCodes(l)
		if !slices.Contains(first, "custom_registry") || slices.Contains(both, "environment_override") {
			t.Errorf("%q: %v / %v, want custom_registry", l, first, both)
		}
	}
	for _, l := range []string{`LOCALAPPDATA=C:\Users\me\AppData\Local pnpm add left-pad`, "XDG_CONFIG_DIRS=/etc/xdg:/usr/share pip install requests",
		"PREFIX=/usr/local npm i -g left-pad", "PREFIX=$HOME/.local npm i -g left-pad", "PREFIX=. make install"} {
		if _, both := homeCodes(l); len(both) > 0 {
			t.Errorf("%q: %v, want no reason", l, both)
		}
	}
}

// Round 2, the class of P2-1 on a shell line: a quoted or escaped ~ and a single-quoted $NAME are not expanded, and
// PowerShell and cmd never expand ~ in a value: the folder is one named so under the current one.
func TestHomeQuotedTilde(t *testing.T) {
	for _, l := range []string{`HOME="~" npm i left-pad`, `HOME='~' npm i left-pad`, `HOME=\~ npm i left-pad`, `HOME="~/x" npm i left-pad`,
		`HOME='$HOME/x' npm i left-pad`, `export XDG_CONFIG_HOME='~/.config'; pip install requests`, `$env:APPDATA = "~\cfg"; pip install requests`,
		`set HOME=~&& npm i left-pad`} {
		// the first reader for a POSIX line, the second for PowerShell's and cmd's (round 3: the word's rule)
		if _, both := homeCodes(l); !slices.Contains(both, "custom_registry") {
			t.Errorf("%q: %v, want custom_registry", l, both)
		}
	}
	// (the raw line is matched: echo HOME="~" && npm i x holds too, as P3-4's line-wide hold)
	for _, l := range []string{"HOME=~ npm i left-pad", `HOME="$HOME/x" npm i left-pad`, `HOME=~/"x" npm i left-pad`, `HOME="~" make`} {
		if _, both := homeCodes(l); len(both) > 0 {
			t.Errorf("%q: %v, want no reason", l, both)
		}
	}
}

// Round 2's mutants: a cleaned temporary folder, a client form in another case, install_check's own reading of an MCP
// entry (LaunchExtraWhy), and the entry's command line read as a shell's after its env.
func TestHomeRound2Edges(t *testing.T) {
	for v, want := range map[string]string{"/var//tmp/x": whyDirTemp, "/dev//shm": whyDirTemp} {
		if got := dirWhy(v); got != want {
			t.Errorf("dirWhy(%q) = %q, want %q", v, got, want)
		}
	}
	for _, v := range []string{"${env:home}/x", "${userhome}", "${Home}"} {
		if len(EnvUnread(map[string]string{"HOME": v})) == 0 {
			t.Errorf("entry HOME=%q: a client form in another case is no client's home", v)
		}
	}
	if code, _ := LaunchExtraWhy(`{"command":"npx","args":["-y","left-pad"],"env":{"HOME":"~"}}`); code != "custom_registry" {
		t.Errorf("install_check of an entry with HOME=~: %q", code)
	}
	if code, why := LaunchExtraWhy(`{"command":"bash","args":["-c","HOME=$HOME/x npm i left-pad"],"env":{"PATH":"/usr/bin:/bin"}}`); code == "custom_registry" {
		t.Errorf("an entry's shell line read as an entry value: %q", why)
	}
}
