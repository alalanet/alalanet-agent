package installread

import (
	"slices"
	"testing"
)

// ECO-1-BREW round 2 (review-1117): the lines the review found read as nothing or as another repository. Sources:
// Homebrew 7.0.14 brew.sh (a leading -v moves to the end), cmd/exec.sh and utils/cmd.sh (brew exec and its alias x),
// tap.rb (Tap.fetch strips homebrew- or linuxbrew-; linuxbrew/core is the core tap), bin/brew (brew.env from
// XDG_CONFIG_HOME, HOMEBREW_XDG_CONFIG_HOME or HOME), env_config.rb (HOMEBREW_CURL_PATH, HOMEBREW_GIT_PATH,
// HOMEBREW_SSH_CONFIG_PATH, HOMEBREW_CURLRC). Placeholders only (u/r, zz-evil-pkg, evil.example).
func TestBrewRound2(t *testing.T) {
	// targets and no reason
	for line, want := range map[string][]string{
		// P1-1: brew.sh moves a leading -v to the end of the words
		"brew -v install u/r/x":           {"github:u/homebrew-r"},
		"brew -v tap u/r":                 {"github:u/homebrew-r"},
		"brew -v trust u/r":               {"github:u/homebrew-r"},
		"brew -v x --formulae=u/r/x -- x": {"github:u/homebrew-r"},
		// P1-2: brew exec / brew x install --formulae and run the command
		"brew x --formulae=u/r/x -- x":                                                 {"github:u/homebrew-r"},
		"brew exec --formulae u/r/x x":                                                 {"github:u/homebrew-r"},
		"brew exec --formulae=jq,u/r/x -- ./script.sh":                                 {"github:u/homebrew-r"},
		"brew exec --formulae=' jq , u/r/x ' -- ./script.sh":                           {"github:u/homebrew-r"},
		"brew exec --formulae=u/r/x,v/s/y -- y":                                        {"github:u/homebrew-r", "github:v/homebrew-s"},
		"brew x -- npx -y zz-evil-pkg":                                                 {"npm:zz-evil-pkg"},
		"brew exec npx -y zz-evil-pkg":                                                 {"npm:zz-evil-pkg"},
		"brew x -q --debug --formulae=node -- npx -y zz-evil-pkg":                      {"npm:zz-evil-pkg"},
		"brew x -dq --formulae=node npx -y zz-evil-pkg":                                {"npm:zz-evil-pkg"},
		"brew x --sandbox /tmp/s --deny-network --formulae=node -- npx -y zz-evil-pkg": {"npm:zz-evil-pkg"},
		"brew x --sandbox=/tmp/s -- uvx zz-evil-pkg":                                   {"pypi:zz-evil-pkg"},
		"brew x --formulae=u/r/x -- npx -y zz-evil-pkg":                                {"github:u/homebrew-r", "npm:zz-evil-pkg"},
		// P2-5: Tap.fetch strips homebrew- or linuxbrew- (one of them, once)
		"brew install u/linuxbrew-r/x":    {"github:u/homebrew-r"},
		"brew tap u/linuxbrew-r":          {"github:u/homebrew-r"},
		"brew tap U/LinuxBrew-R":          {"github:u/homebrew-linuxbrew-r"}, // the prefix is matched as written
		"brew tap u/homebrew-linuxbrew-r": {"github:u/homebrew-linuxbrew-r"},
		"brew install linuxbrew/xorg/x":   {"github:linuxbrew/homebrew-xorg"},
		"brew install Linuxbrew/xorg/x":   {"github:linuxbrew/homebrew-xorg"},
		// P2-4 honest: absolute folders the user owns
		"HOME=/Users/me brew install u/r/x":                    {"github:u/homebrew-r"},
		"XDG_CONFIG_HOME=$HOME/.config brew install u/r/x":     {"github:u/homebrew-r"},
		"HOMEBREW_XDG_CONFIG_HOME=/opt/cfg brew install u/r/x": {"github:u/homebrew-r"},
		// P3 honest: a program by name or an absolute program, a curlrc that is no path or the user's own
		"HOMEBREW_GIT_PATH=/usr/bin/git brew tap u/r":               {"github:u/homebrew-r"},
		"HOMEBREW_GIT_PATH=git brew tap u/r":                        {"github:u/homebrew-r"},
		"HOMEBREW_CURL_PATH=/usr/bin/curl brew install u/r/x":       {"github:u/homebrew-r"},
		"HOMEBREW_CURLRC=1 brew install u/r/x":                      {"github:u/homebrew-r"},
		"HOMEBREW_CURLRC=/Users/me/.curlrc brew install u/r/x":      {"github:u/homebrew-r"},
		"HOMEBREW_SSH_CONFIG_PATH=/Users/me/.ssh/brew brew tap u/r": {"github:u/homebrew-r"},
	} {
		if tg, codes := codesOn(line); !slices.Equal(tg, want) || len(codes) > 0 {
			t.Errorf("%q: targets %v codes %v, want %v and no reason", line, tg, codes, want)
		}
	}
	// no target and no reason: the version, help, a command brew exec refuses, official taps and their canonical remote
	for _, line := range []string{
		"brew -v", "brew -v -v install u/r/x", "brew --version install u/r/x", "brew -v --help install u/r/x",
		"brew x jq .", "brew exec --help npx -y zz-evil-pkg", "brew x",
		"brew x --formulae=jq -- jq .",
		"brew install linuxbrew/core/x", "brew install linuxbrew/homebrew-core/x", "brew install Linuxbrew/Homebrew/x",
		"brew tap homebrew/core https://github.com/Homebrew/homebrew-core",
		"brew tap homebrew/cask https://github.com/homebrew/homebrew-cask.git",
		"brew tap homebrew/cask-fonts git@github.com:Homebrew/homebrew-cask-fonts.git",
		"brew tap linuxbrew/core https://github.com/Homebrew/homebrew-core",
		"brew tap", "brew install wget", "brew x --formulae=wget -- wget -q https://example.com",
		// mutation round: the core tap by its other names, the case of an official name, exec's help, an empty entry, an
		// option where a value is due, an unknown option (each: nothing runs), brew.env with nothing run
		"brew tap homebrew/homebrew https://github.com/Homebrew/homebrew-core",
		"brew tap Homebrew/Core https://github.com/Homebrew/homebrew-core", "brew tap linuxbrew/homebrew git@github.com:Homebrew/homebrew-core.git",
		"brew x --formulae=u/r/x -? x", "brew x --formulae=u/r/x -vh x", "brew x --formulae=jq,,u/r/x -- x",
		"HOME=./h brew x --help npx -y zz-evil-pkg",
	} {
		if tg, codes := codesOn(line); len(tg) > 0 || len(codes) > 0 {
			t.Errorf("%q: targets %v codes %v, want none", line, tg, codes)
		}
	}
	// reasons
	for line, code := range map[string]string{
		// P1-1, P1-2
		"brew -v tap u/r https://evil.example/r.git":                "custom_registry",
		"brew x --formulae=$F x":                                    "variable_argument",
		"brew x --formulae $F x":                                    "variable_argument",
		"brew x --formulae=https://evil.example/x.rb x":             "git_or_url",
		"brew x --formulae=./Formula/x.rb -- x":                     "git_or_url",
		"brew x --formulae=u/r -- x":                                "unknown_install_form",
		"brew x --formulae=jq,u/r/x/y -- x":                         "unknown_install_form",
		"HOMEBREW_NO_REQUIRE_TAP_TRUST=1 brew x --formulae=u/r/x x": "custom_registry",
		"cat list | xargs brew x --formulae=jq --":                  "stdin_arguments",
		// P2-2: xargs supplies the tap
		"cat list | xargs brew tap":     "stdin_arguments",
		"echo u/r | xargs brew tap":     "stdin_arguments",
		"echo u/r | xargs -n1 brew tap": "stdin_arguments",
		// P2-3: the command word from a variable
		"brew $CMD u/r/x":              "variable_argument",
		"brew ${CMD} u/r/x":            "variable_argument",
		"brew ${CMD:-install} u/r/x":   "variable_argument",
		`brew "$CMD" u/r/x`:            "variable_argument",
		"CMD=install; brew $CMD u/r/x": "variable_argument",
		"brew -v $CMD u/r/x":           "variable_argument",
		"brew $CMD":                    "variable_argument",
		// P2-4: brew.env from a folder the line points at
		"XDG_CONFIG_HOME=./cfg brew install u/r/x":         "environment_override",
		"XDG_CONFIG_HOME=./cfg brew install wget":          "environment_override",
		"HOMEBREW_XDG_CONFIG_HOME=./cfg brew install wget": "environment_override",
		"HOME=./h brew install u/r/x":                      "environment_override",
		"HOME=/tmp/h brew tap u/r":                         "environment_override",
		"export HOME=$PWD/h; brew install u/r/x":           "environment_override",
		"env XDG_CONFIG_HOME=../cfg brew trust u/r":        "environment_override",
		"HOME=./h brew x --formulae=u/r/x -- x":            "environment_override",
		// P2-6: an official tap from another remote
		"brew tap homebrew/cask https://github.com/evil/homebrew-cask":     "custom_registry",
		"brew tap homebrew/core https://github.com/evil/homebrew-core":     "custom_registry",
		"brew tap HomeBrew/Cask git@github.com:evil/x.git":                 "custom_registry",
		"brew tap linuxbrew/core https://github.com/evil/homebrew-core":    "custom_registry",
		"brew tap homebrew/core https://github.com/Homebrew/homebrew-cask": "custom_registry",
		// P3: Homebrew's own programs and config files from the project or a temporary folder
		"HOMEBREW_GIT_PATH=./evil brew tap u/r":                                          "code_from_environment",
		"HOMEBREW_CURL_PATH=/tmp/c brew install wget":                                    "code_from_environment",
		"HOMEBREW_CURL_PATH=bin/curl brew install u/r/x":                                 "code_from_environment",
		"HOMEBREW_SSH_CONFIG_PATH=./sshcfg brew tap u/r git@github.com:u/homebrew-r.git": "custom_registry",
		"HOMEBREW_CURLRC=/tmp/x.curlrc brew install wget":                                "custom_registry",
		"HOMEBREW_CURLRC=$D/curlrc brew install wget":                                    "custom_registry",
		// P3: a tap-shaped item alalanet cannot name holds
		"brew install u+x/r/f":    "unknown_install_form",
		"brew install u/r:x/f":    "unknown_install_form",
		"brew install u/r%2F../f": "unknown_install_form",
		"brew install u/../x":     "unknown_install_form",
		"brew tap u+x/r":          "unknown_install_form",
		"brew trust u/r+x":        "unknown_install_form",
		// P3: any other remote of a tap holds, the registries' own hosts too; a GitHub URL with . or .. holds
		"brew tap u/r https://registry.npmjs.org/x.git": "custom_registry",
		"brew tap u/r https://pypi.org/x.git":           "custom_registry",
		"brew tap u/r https://files.pythonhosted.org/x": "custom_registry",
		"brew tap u/r https://github.com/x/..":          "custom_registry",
		"brew tap u/r https://github.com/../y":          "custom_registry",
		"brew tap u/r https://github.com/x/.":           "custom_registry",
		"brew tap u/r https://github.com/x/..git":       "custom_registry",
		"brew tap u/r https://github.com/./y":           "custom_registry",
	} {
		if _, codes := codesOn(line); !slices.Contains(codes, code) {
			t.Errorf("%q: codes %v, want %s", line, codes, code)
		}
	}
	// a GitHub URL with a dot segment names no target
	for _, line := range []string{"brew tap u/r https://github.com/x/..", "brew tap u/r https://github.com/../y",
		"brew tap homebrew/cask https://github.com/evil/homebrew-cask"} {
		if tg, _ := codesOn(line); len(tg) > 0 {
			t.Errorf("%q: targets %v, want none", line, tg)
		}
	}
	for in, want := range map[string]string{"u/linuxbrew-r": "github:u/homebrew-r", "u/homebrew-linuxbrew-r": "github:u/homebrew-linuxbrew-r",
		"linuxbrew/core": "", "linuxbrew/homebrew": "", "linuxbrew/homebrew-core": "", "linuxbrew/x": "github:linuxbrew/homebrew-x"} {
		if got := brewTapTarget(in); got != want {
			t.Errorf("brewTapTarget(%q) = %q, want %q", in, got, want)
		}
	}
}

// P2-1: a tap followed by installs of names (from that tap or core) is one install: the line's other commands are
// none, so install_check judges the tap; a command that is no install keeps the line mixed.
func TestBrewTapThenInstallIsOneInstall(t *testing.T) {
	for line, other := range map[string]bool{
		"brew tap kaplanelad/tap && brew install shellfirm":                   false,
		"brew tap qiz029/tap && brew trust qiz029/tap && brew install dscode": false,
		"brew tap mongodb/brew && brew install mongodb-community@7.0":         false,
		"brew tap u/r; brew install --cask x":                                 false,
		"brew tap u/r && brew reinstall x && brew upgrade x":                  false,
		"brew install u/r/x && brew install y":                                false,
		"brew tap u/r && brew install x && brew services start x":             true,
		"brew tap q00/tap && brew install ouroboros-ai && ouroboros setup":    true,
		"brew install x && brew tap u/r":                                      true, // before the tap: not from it
		"brew install wget && npx -y zz-evil-pkg":                             true,
		"brew trust u/r && brew install x":                                    false,
		"brew x --formulae=u/r/x -- true && brew install y":                   false,
		"brew tap u/r https://gitlab.com/u/r.git && brew install x":           false, // held by its remote
	} {
		_, _, got, _ := ParseLine(line)
		if got != other {
			t.Errorf("%q: other %v, want %v", line, got, other)
		}
	}
}
