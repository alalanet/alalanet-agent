package installread

import (
	"slices"
	"strings"
	"testing"
)

// HOME-CONFIG-ENV-1 (eco1-go review P3-4): HOME, USERPROFILE, XDG_CONFIG_HOME and APPDATA move where the package
// managers read their user config — npm ~/.npmrc, pnpm and Yarn and bun theirs under HOME, pip
// $XDG_CONFIG_HOME/pip/pip.conf or %APPDATA%\pip\pip.ini, uv $XDG_CONFIG_HOME/uv/uv.toml or %APPDATA%\uv\uv.toml —
// so a line that points one of them at a folder the repository may ship (relative, ./, $PWD, .., a temporary folder,
// a variable other than $HOME) installs with a registry or scripts alalanet cannot see. Such a line holds as
// custom_registry, by both readers, at any install they read; a line with no install stays silent. An absolute
// folder is not judged by its name (the rule of eco1-go round 4: a folder the line names absolutely is one an
// attacker would have to control already).

var homeHeld = []string{
	"HOME=. npm i left-pad",
	"HOME=$PWD npm i left-pad",
	"HOME=${PWD} pnpm add left-pad",
	"HOME=./h yarn add left-pad",
	"HOME=.. bun add left-pad",
	"HOME=h npm i left-pad",
	"XDG_CONFIG_HOME=./cfg pip install requests",
	"XDG_CONFIG_HOME=$PWD/cfg uv pip install requests",
	"XDG_CONFIG_HOME=cfg uv tool install ruff",
	"XDG_CONFIG_HOME=./cfg pipx install black",
	"USERPROFILE=. npm i left-pad",
	`APPDATA=.\cfg pip install requests`,
	`APPDATA=%CD%\cfg pip install requests`,
	"HOME=/tmp/h npm i left-pad",
	"HOME=/var/tmp/h npm i left-pad",
	"HOME=$TMPDIR npm i left-pad",
	"HOME=$CI_PROJECT_DIR npm ci",
	"HOME=$HOME/../../tmp/x npm i left-pad",
	"HOME=/home/u/../../srv/x npm i left-pad",
	"HOME=~+ npm i left-pad",
	"HOME=~-/x npm i left-pad",
	"HOME=/proc/self/cwd npm i left-pad",
	"export HOME=.; npm i left-pad",
	"export XDG_CONFIG_HOME=./c && pipx install black",
	"HOME=. npx -y left-pad",
	"env HOME=. npm i left-pad",
	"HOME=. npm install",
	"HOME=. python -m pip install requests",
	// a later absolute folder does not clear an earlier one; Windows names in any case (cmd's set, PowerShell)
	"HOME=. XDG_CONFIG_HOME=/etc/xdg npm i left-pad",
	`set appdata=.\cfg && pip install requests`,
}

var homeClean = []string{
	"HOME=/home/u npm i left-pad",
	"HOME=$HOME npm i left-pad",
	"HOME=${HOME}/proj npm i left-pad",
	"HOME=~ npm i left-pad",
	"HOME=~/sandbox npm i left-pad",
	"XDG_CONFIG_HOME=$HOME/.config pip install requests",
	"XDG_CONFIG_HOME=/etc/xdg pip install requests",
	"XDG_CONFIG_HOME=/workspace/.config uv pip install requests",
	`APPDATA=C:\Users\me\AppData\Roaming pip install requests`,
	`APPDATA=%USERPROFILE%\AppData\Roaming pip install requests`,
	`USERPROFILE=C:\Users\me npm i left-pad`,
	"HOME=/workspace npm ci",
	// no install: silent
	"HOME=. make",
	"HOME=. ls && echo ok",
	"XDG_CONFIG_HOME=./cfg nvim",
	"HOME=$PWD git status",
	"export HOME=.; make test",
	// PowerShell's own reading of a Windows folder
	`$env:APPDATA = "C:\Users\me\AppData\Roaming"; pip install requests`,
	`$env:HOME = "$env:USERPROFILE\x"; npm i left-pad`,
}

func homeCodes(line string) (first, both []string) {
	tg, un, _, s := ParseLine(line)
	for _, u := range un {
		first = append(first, UnreadCode(u))
	}
	both = slices.Clone(first)
	for _, x := range HookExtra(line, tg, un, s) {
		both = append(both, ExtraCode(x))
	}
	return first, both
}

func TestHomeConfigEnvHolds(t *testing.T) {
	for _, l := range homeHeld {
		first, both := homeCodes(l)
		if !slices.Contains(first, "custom_registry") {
			t.Errorf("%q: the line reader gives %v, want custom_registry", l, first)
		}
		if slices.Contains(both, "environment_override") {
			t.Errorf("%q: the second reader still calls it environment_override: %v", l, both)
		}
	}
	for _, l := range homeClean {
		if _, both := homeCodes(l); len(both) > 0 {
			t.Errorf("%q: %v, want no reason", l, both)
		}
	}
	// The reason names the variable, where it points and why.
	_, un, _, _ := ParseLine("HOME=$PWD npm i left-pad")
	if len(un) != 1 || !strings.Contains(un[0], "HOME") || !strings.Contains(un[0], "$PWD") || !strings.Contains(un[0], "config file alalanet cannot see") {
		t.Errorf("HOME=$PWD: %q", un)
	}
}

// An MCP entry's environment (install_check's EnvUnread) and a repository config's server (check_repo_config,
// ServerExtraCodes): an entry is a launch, so the folder alone decides.
func TestHomeConfigEnvInEntries(t *testing.T) {
	for _, c := range []struct {
		env  map[string]string
		held bool
	}{
		{map[string]string{"HOME": "."}, true},
		{map[string]string{"XDG_CONFIG_HOME": "./cfg"}, true},
		{map[string]string{"APPDATA": `.\cfg`}, true},
		{map[string]string{"USERPROFILE": "${PWD}"}, true},
		{map[string]string{"HOME": "/tmp/h"}, true},
		{map[string]string{"HOME": "$TMPDIR"}, true},
		{map[string]string{"HOME": "/srv/../x"}, true},
		{map[string]string{"HOME": "//proc/./self/cwd"}, true},
		{map[string]string{"HOME": "/home/u"}, false},
		{map[string]string{"XDG_CONFIG_HOME": "/home/u/.config"}, false},
		{map[string]string{"APPDATA": `C:\Users\me\AppData\Roaming`}, false},
	} {
		un := EnvUnread(c.env)
		got := len(un) > 0 && UnreadCode(un[0]) == "custom_registry"
		if got != c.held || !c.held && len(un) > 0 {
			t.Errorf("EnvUnread(%v) = %q, want held %v", c.env, un, c.held)
		}
		codes := ServerExtraCodes("npx", []string{"-y", "left-pad"}, c.env, nil)
		if c.held != slices.Contains(codes, "custom_registry") || slices.Contains(codes, "environment_override") || !c.held && len(codes) > 0 {
			t.Errorf("ServerExtraCodes(%v) = %v, want custom_registry %v", c.env, codes, c.held)
		}
	}
}

// The second reader also holds what its own path reading holds besides homeDirWhy: a value past maxPathValue.
func TestHomeConfigEnvLongValue(t *testing.T) {
	long := "/" + strings.Repeat("a", maxPathValue+10)
	if codes := ServerExtraCodes("npx", []string{"-y", "left-pad"}, map[string]string{"HOME": long}, nil); !slices.Contains(codes, "custom_registry") {
		t.Errorf("HOME of %d bytes: %v", len(long), codes)
	}
}

// homeDirWhy: eco1-go's rule for a folder (round 4: absolute folders are not judged by name), for one folder.
func TestHomeDirWhy(t *testing.T) {
	for v, want := range map[string]string{
		".": whyDirRelative, "./h": whyDirRelative, "h": whyDirRelative, `.\cfg`: whyDirRelative, "~+": whyDirRelative,
		"~-/x": whyDirRelative, "/proc/self/cwd": whyDirRelative, "/proc/123/cwd/x": whyDirRelative, `\.`: whyDirRelative, `\cfg`: whyDirRelative, "~0": whyDirRelative, "~1/x": whyDirUser, "~+2": whyDirUser, "~+0": whyDirRelative,
		"/proc/self/task/1/cwd": whyDirRelative, "/proc/./self/cwd": whyDirRelative, "/run/lock/x": whyDirTemp, `C:\Temp\x`: whyDirTemp,
		"/a:./b": "", "~root": whyDirUser, "~xq7/x": whyDirUser, "~9z": whyDirUser, "~+x": whyDirUser, "~-lead/x": whyDirUser, "$home/x": "", `%USERPROFILE%\x`: "", "${env:HOME}": "", "//proc/./self/cwd": whyDirRelative,
		"..": whyDirClimb, "/a/../b": whyDirClimb, "$HOME/../x": whyDirClimb, `C:\a\..\b`: whyDirClimb,
		"/tmp/h": whyDirTemp, "/var/tmp": whyDirTemp, "/dev/shm/x": whyDirTemp, `C:\Users\me\AppData\Local\Temp\x`: whyDirTemp,
		"$PWD": whyDirVar, "${PWD}/x": whyDirVar, "$TMPDIR": whyDirVar, "$HOMEX": whyDirVar, "$HOME$X": whyDirVar,
		"$HOMEx/y": whyDirVar, "$HOME/$X": whyDirVar, "%CD%": whyDirVar, `%TEMP%\x`: whyDirVar, "$(pwd)": whyDirVar,
		"/home/u": "", "$HOME": "", "${HOME}/proj": "", "~": "", "~/x": "", "/workspace": "", "/etc/xdg": "", `C:\Users\me`: "",
		`%USERPROFILE%\AppData\Roaming`: "", "%USERPROFILE%": "", `$env:USERPROFILE\x`: "", "": "", `\\server\share`: "",
	} {
		if got := dirWhy(v); got != want {
			t.Errorf("dirWhy(%q) = %q, want %q", v, got, want)
		}
	}
}
