package installread

import (
	"slices"
	"testing"
)

// ECO-1-BREW round 3 (re-review review-1117/eco1-brew-r2). Homebrew 7.0.14: cmd/exec.sh splits --formulae with
// `IFS=',' read -r -a` (a trailing comma ends the list; an empty entry inside it, or a blank last one, odies; read takes
// the first line); brew's other runners — cmd/sandbox-exec.rb, bundle/subcommand/exec.rb, dev-cmd/sh.rb (-c|--cmd),
// dev-cmd/ruby.rb, dev-cmd/benchmark.rb (--exec: hyperfine runs each string), cmd/alias.rb (a "!" or "%" alias is a shell
// command) — and the wrappers that run a brew command: cmd/as-brew-user.sh, cmd/as-console-user.sh (utils/as_user.sh:
// brew "$@"), dev-cmd/debugger.rb and dev-cmd/prof.rb (brew.rb with the named words). Placeholders only.

// The reviewer's proofs (probes/ir_zz_brewr2_proof_test.go, ir_zz_brewr2_runners_test.go), adopted.
func TestReviewR2ExecTrailingComma(t *testing.T) {
	for _, line := range []string{
		"brew exec --formulae=u/r/x, x", "brew x --formulae=u/r/x, -- x", "brew x --formulae u/r/x, x",
		"brew x '--formulae=u/r/x ,' x", "brew x --formulae=jq,u/r/x, -- ./run.sh",
	} {
		if tg, codes := codesOn(line); !slices.Contains(tg, "github:u/homebrew-r") && len(codes) == 0 {
			t.Errorf("%q: targets %v codes %v: the tap formula exec installs is not read", line, tg, codes)
		}
	}
	for _, line := range []string{"brew x --formulae=u/r/x,, x", "brew x --formulae=, x", "brew x --formulae=,u/r/x x"} {
		if tg, _ := codesOn(line); len(tg) != 0 {
			t.Errorf("%q: targets %v; exec odies on an empty entry", line, tg)
		}
	}
}

func TestReviewR2BrewRunners(t *testing.T) {
	for _, line := range []string{
		"brew sandbox-exec . -- npx -y zz-evil-pkg", "brew sandbox-exec --deny-network /tmp/s npx -y zz-evil-pkg",
		"brew bundle exec -- npx -y zz-evil-pkg", "brew bundle exec npx -y zz-evil-pkg", "brew sh --cmd='npx -y zz-evil-pkg'",
		"brew sh -c 'npx -y zz-evil-pkg'",
	} {
		if tg, codes := codesOn(line); len(tg) == 0 && len(codes) == 0 {
			t.Errorf("%q: no target and no reason", line)
		}
	}
}

func TestBrewRound3(t *testing.T) {
	// targets and no reason
	for line, want := range map[string][]string{
		// P1-1: the forms of --formulae's list, as bash's read splits it
		"brew exec --formulae=u/r/x, x":                  {"github:u/homebrew-r"},
		"brew x --formulae u/r/x, -- x":                  {"github:u/homebrew-r"},
		`brew x "--formulae=u/r/x ," x`:                  {"github:u/homebrew-r"},
		"brew x --formulae=jq,u/r/x, -- ./run.sh":        {"github:u/homebrew-r"},
		"brew x --formulae=u/r/x,v/s/y, -- y":            {"github:u/homebrew-r", "github:v/homebrew-s"},
		"brew x --formulae=u/r/x, -- npx -y zz-evil-pkg": {"github:u/homebrew-r", "npm:zz-evil-pkg"},
		"brew x --formulae='u/r/x\nv/s/y' -- x":          {"github:u/homebrew-r"}, // read takes the first line
		"brew x --formulae='u/r/x,\nv/s/y' -- x":         {"github:u/homebrew-r"},
		"brew x --formulae=' u/r/x' -- x":                {"github:u/homebrew-r"},
		// self-attack (round 3): a first line that is empty gives no formula, exec still runs the command
		"brew x --formulae='\nu/r/x' -- npx -y zz-evil-pkg":        {"npm:zz-evil-pkg"},
		"brew x --formulae='\n' -- npx -y zz-evil-pkg":             {"npm:zz-evil-pkg"},
		"brew x --formulae=u/r/x --formulae=v/s/y x":               {"github:u/homebrew-r", "github:v/homebrew-s"},
		"brew sandbox-exec --deny-network -- . npx -y zz-evil-pkg": {"npm:zz-evil-pkg"},
		"brew sandbox-exec . brew install u/r/x":                   {"github:u/homebrew-r"},
		"brew bundle exec brew install u/r/x":                      {"github:u/homebrew-r"},
		"brew sh --cmd='brew install u/r/x'":                       {"github:u/homebrew-r"},
		"brew alias zz='x --formulae=u/r/x, -- x'":                 {"github:u/homebrew-r"},
		"brew as-brew-user as-brew-user install u/r/x":             {"github:u/homebrew-r"},
		"brew as-brew-user sh -c 'npx -y zz-evil-pkg'":             {"npm:zz-evil-pkg"},
		"brew doctor && npx -y zz-evil-pkg":                        {"npm:zz-evil-pkg"},
		// mutation round 3: -c=SCRIPT read as SCRIPT (the safe side), -c after sh's FILE (OptionParser permutes)
		"brew sh x.sh -c 'npx -y zz-evil-pkg'": {"npm:zz-evil-pkg"},
		// P2-1: brew's command runners read their command
		"brew sandbox-exec . -- npx -y zz-evil-pkg":                            {"npm:zz-evil-pkg"},
		"brew sandbox-exec /tmp/s --deny-network -- npx -y zz-evil-pkg":        {"npm:zz-evil-pkg"},
		"brew sandbox-exec -- . npx -y zz-evil-pkg":                            {"npm:zz-evil-pkg"},
		"brew sandbox-exec -v . uvx zz-evil-pkg":                               {"pypi:zz-evil-pkg"},
		"brew -v sandbox-exec . -- npx -y zz-evil-pkg":                         {"npm:zz-evil-pkg"},
		"brew bundle exec -- npx -y zz-evil-pkg":                               {"npm:zz-evil-pkg"},
		"brew bundle --file=Brewfile exec -- npx -y zz-evil-pkg":               {"npm:zz-evil-pkg"},
		"brew bundle --global exec --check --no-secrets -- npx -y zz-evil-pkg": {"npm:zz-evil-pkg"},
		"brew bundle exec --sandbox=/tmp/s -- npx -y zz-evil-pkg":              {"npm:zz-evil-pkg"},
		"brew sh -c 'npx -y zz-evil-pkg'":                                      {"npm:zz-evil-pkg"},
		"brew sh --cmd='npx -y zz-evil-pkg'":                                   {"npm:zz-evil-pkg"},
		"brew sh --cmd 'npx -y zz-evil-pkg'":                                   {"npm:zz-evil-pkg"},
		"brew sh -c'npx -y zz-evil-pkg'":                                       {"npm:zz-evil-pkg"},
		"brew sh -r -c 'npx -y zz-evil-pkg'":                                   {"npm:zz-evil-pkg"},
		"brew sh --env=std -c 'npx -y zz-evil-pkg'":                            {"npm:zz-evil-pkg"},
		"brew sh --env std --cmd='uvx zz-evil-pkg'":                            {"pypi:zz-evil-pkg"},
		"brew benchmark --exec -- 'npx -y zz-evil-pkg'":                        {"npm:zz-evil-pkg"},
		"brew benchmark --exec 'npx -y zz-evil-pkg' 'uvx zz-evil-pkg'":         {"npm:zz-evil-pkg", "pypi:zz-evil-pkg"},
		"brew alias zz='!npx -y zz-evil-pkg'":                                  {"npm:zz-evil-pkg"},
		"brew alias zz='%npx -y zz-evil-pkg'":                                  {"npm:zz-evil-pkg"},
		"brew alias zz='install u/r/x'":                                        {"github:u/homebrew-r"},
		"brew alias --edit zz='install u/r/x'":                                 {"github:u/homebrew-r"},
		// the wrappers that run a brew command
		"brew as-brew-user install u/r/x":            {"github:u/homebrew-r"},
		"brew as-console-user -v install u/r/x":      {"github:u/homebrew-r"},
		"brew as-brew-user --quiet tap u/r":          {"github:u/homebrew-r"},
		"brew as-brew-user -v install u/r/x":         {"github:u/homebrew-r"},
		"brew as-brew-user x -- npx -y zz-evil-pkg":  {"npm:zz-evil-pkg"},
		"brew as-brew-user x --formulae=u/r/x, -- x": {"github:u/homebrew-r"},
		"brew debugger install u/r/x":                {"github:u/homebrew-r"},
		"brew debugger -O -- install --cask u/r/x":   {"github:u/homebrew-r"},
		"brew prof --stackprof install u/r/x":        {"github:u/homebrew-r"},
		"brew prof --timings -- reinstall u/r/x":     {"github:u/homebrew-r"},
		// P3: brew update and its read-only kin before a tap and its install: one install
		"brew update && brew tap u/r && brew install x": {"github:u/homebrew-r"},
		// P3: --no-quarantine is a switch (gone in Homebrew 7, which refuses the line; earlier ones read it)
		"brew install --cask --no-quarantine u/r/x":   {"github:u/homebrew-r"},
		"brew reinstall --no-quarantine --cask u/r/x": {"github:u/homebrew-r"},
		"brew upgrade --no-quarantine --cask u/r/x":   {"github:u/homebrew-r"},
		// P3: a Homebrew variable is no reason for a command that is not brew
		"HOMEBREW_API_DOMAIN=https://mirror.example/api npm i left-pad":           {"npm:left-pad"},
		"export HOMEBREW_BOTTLE_DOMAIN=https://m.example && pip install requests": {"pypi:requests"},
		"HOMEBREW_NO_REQUIRE_TAP_TRUST=1 npx -y left-pad":                         {"npm:left-pad"},
		"HOMEBREW_GIT_PATH=./git npm i left-pad":                                  {"npm:left-pad"},
		"SUDO_ASKPASS=./evil npm i left-pad":                                      {"npm:left-pad"},
		"brew install wget; HOMEBREW_API_DOMAIN=https://e.example npm i left-pad": {"npm:left-pad"},
		"SUDO_ASKPASS=/usr/libexec/ssh-askpass brew install --cask u/r/x":         {"github:u/homebrew-r"},
		"HOMEBREW_SVN=svn brew install u/r/x":                                     {"github:u/homebrew-r"},
	} {
		if tg, codes := codesOn(line); !slices.Equal(tg, want) || len(codes) > 0 {
			t.Errorf("%q: targets %v codes %v, want %v and no reason", line, tg, codes, want)
		}
	}
	// nothing: exec odies, a runner without its command or with its help, read-only brew commands
	for _, line := range []string{
		"brew x --formulae=u/r/x,, x", "brew x --formulae=, x", "brew x --formulae=,u/r/x x", "brew x '--formulae=u/r/x , ' x",
		"brew x --formulae=u/r/x,,v/s/y x",
		"brew x --formulae=u/r/x,,, x", "brew x --formulae='u/r/x,\t' x", "brew x --formulae= x", "brew x --formulae='' x",
		"brew x --formulae=u/r/x,v/s/y,, x", "brew sandbox-exec -- . -- npx -y zz-evil-pkg",
		"brew bundle exec -h npx", "brew sh --cmd=",
		"brew alias zz=", "brew alias zz='!'", "brew install --no-quarantine wget",
		// mutation round 3: exec's empty list, a second alias word, sandbox-exec's unknown option, bundle's other
		// subcommands and help, sh's help, benchmark without --exec, positional words after bash -s
		"brew x --formulae= -- npx -y zz-evil-pkg", "brew alias zz yy='!npx -y zz-evil-pkg'",
		"brew sh --help -c 'npx -y zz-evil-pkg'",
		"brew benchmark 'npx -y zz-evil-pkg'", "bash -s HOMEBREW_API_DOMAIN=https://e.example <<< 'brew install wget'",
		"brew sh ./x.sh", "brew ruby -e 'system(1)'",
		"brew sandbox-exec /tmp/s", "brew sandbox-exec",
		"brew bundle exec", "brew bundle sh", "brew bundle env",
		"brew sh", "brew sh -r", "brew benchmark wget", "brew alias", "brew alias zz", "brew as-brew-user",
		"brew as-brew-user --help install u/r/x", "brew as-console-user -vh install u/r/x", "brew debugger", "brew prof",
		"brew debugger --help install u/r/x", "brew alias zz='!echo hi'",
		"brew update", "brew update && brew upgrade", "brew doctor", "brew cleanup", "brew config",
	} {
		if tg, codes := codesOn(line); len(tg) > 0 || len(codes) > 0 {
			t.Errorf("%q: targets %v codes %v, want none", line, tg, codes)
		}
	}
	// reasons
	for line, code := range map[string]string{
		"brew x --formulae=$F, x":                          "variable_argument",
		"brew x --formulae=u/r,  -- x":                     "unknown_install_form",
		"brew sandbox-exec . -- npx -y $P":                 "variable_argument",
		"brew sh -c 'npx -y $P'":                           "variable_argument",
		"brew alias zz='install $T/x'":                     "variable_argument",
		"brew as-brew-user install https://e.example/x.rb": "git_or_url",
		"brew debugger tap u/r https://evil.example/r.git": "custom_registry",
		"cat cmds | xargs brew sandbox-exec .":             "stdin_arguments",
		"cat cmds | xargs brew bundle exec":                "stdin_arguments",
		"cat cmds | xargs brew as-brew-user":               "stdin_arguments",
		"cat cmds | xargs brew sh -c":                      "stdin_arguments",
		// self-attack: wrappers nested past five, and the Homebrew variables through every way a line reaches brew
		"brew as-brew-user as-brew-user as-brew-user as-brew-user as-brew-user as-brew-user install u/r/x": "nested_too_deep",
		"HOMEBREW_API_DOMAIN=https://e.example ${BREW:-brew} install wget":                                 "variable_argument",
		"HOMEBREW_API_DOMAIN=https://e.example fish -c 'brew install wget'":                                "custom_registry",
		"HOMEBREW_API_DOMAIN=https://e.example pwsh -Command 'brew install wget'":                          "custom_registry",
		"HOMEBREW_API_DOMAIN=https://e.example su -c 'brew install wget'":                                  "custom_registry",
		"HOMEBREW_API_DOMAIN=https://e.example watch brew install wget":                                    "custom_registry",
		"HOMEBREW_API_DOMAIN=https://e.example bash <<< 'brew install wget'":                               "script_not_read",
		"HOMEBREW_API_DOMAIN=https://e.example eval 'brew install wget'":                                   "custom_registry",
		"HOMEBREW_API_DOMAIN=https://e.example $(which brew) install wget":                                 "custom_registry",
		"HOMEBREW_API_DOMAIN=https://e.example br\\ew install wget":                                        "custom_registry",
		"env -S 'HOMEBREW_API_DOMAIN=https://e.example brew install wget'":                                 "custom_registry",
		"brew sandbox-exec . env HOMEBREW_API_DOMAIN=https://e.example brew install wget":                  "custom_registry",
		"brew sh -c 'HOMEBREW_API_DOMAIN=https://e.example brew install wget'":                             "custom_registry",
		"brew alias zz='tap u/r https://evil.example/r.git'":                                               "custom_registry",
		"brew as-brew-user $CMD u/r/x":                                                                     "variable_argument",
		"brew install --no-quarantine=1 u/r/x":                                                             "unknown_install_form",
		"HOME=./h fish -c 'brew install u/r/x'":                                                            "environment_override",
		"HOMEBREW_GIT_PATH=./g bash -c 'brew tap u/r'":                                                     "code_from_environment",
		"HOME=./h ${BREW:-brew} install wget":                                                              "variable_argument",
		"HOME=./h bash <<< 'brew install wget'":                                                            "script_not_read",
		// P3: Homebrew's variables hold a line that runs brew, in every form
		"HOMEBREW_API_DOMAIN=https://e.example brew install wget":                   "custom_registry",
		"export HOMEBREW_API_DOMAIN=https://e.example; brew install wget":           "custom_registry",
		"env HOMEBREW_API_DOMAIN=https://e.example brew x -- npx -y zz-evil-pkg":    "custom_registry",
		"HOMEBREW_API_DOMAIN=https://e.example bash -c 'brew install wget'":         "custom_registry",
		"HOMEBREW_API_DOMAIN=https://e.example sudo -u me brew install wget":        "custom_registry",
		"HOMEBREW_API_DOMAIN=https://e.example /opt/homebrew/bin/brew install wget": "custom_registry",
		"HOMEBREW_BREW_GIT_REMOTE=https://e.example/brew brew update":               "custom_registry",
		"HOMEBREW_NO_REQUIRE_TAP_TRUST=1 brew info u/r/x":                           "custom_registry",
		// a prefix's scope is not tracked: an earlier VAR=… holds a later brew (over-holds, the safe side)
		"HOMEBREW_API_DOMAIN=https://e.example npm i left-pad && brew install wget": "custom_registry",
		// P3: SUDO_ASKPASS and HOMEBREW_SVN name programs brew runs
		"SUDO_ASKPASS=./evil brew install --cask u/r/x": "code_from_environment",
		"SUDO_ASKPASS=/tmp/a brew install wget":         "code_from_environment",
		"HOMEBREW_SVN=./svn brew install u/r/x":         "code_from_environment",
		"export SUDO_ASKPASS=$D/a; brew install wget":   "code_from_environment",
	} {
		_, codes := codesOn(line)
		if code == "" {
			if len(codes) == 0 {
				t.Errorf("%q: no reason, want one", line)
			}
			continue
		}
		if !slices.Contains(codes, code) {
			t.Errorf("%q: codes %v, want %s", line, codes, code)
		}
	}
	// P3: the read-only brew commands are no other command; others still are
	for line, other := range map[string]bool{
		"brew update && brew tap u/r && brew install x":            false,
		"brew doctor && brew tap u/r && brew install x":            false,
		"brew update && brew cleanup && brew install u/r/x":        false,
		"brew -v update && brew tap u/r && brew install x":         false,
		"brew benchmark --exec -- 'npx -y zz-evil-pkg'":            false, // its options are no other command
		"brew benchmark --exec --warmup 3 -- 'npx -y zz-evil-pkg'": false, // round 4: hyperfine's --warmup and its value
		"brew update && brew services start x":                     true,
		"brew update && brew info u/r/x && brew install u/r/x":     true, // info loads the formula's Ruby (before Homebrew 7)
		"brew sh -c 'npx -y zz-evil-pkg'":                          false,
		"brew sh -c 'npx -y zz-evil-pkg; make'":                    true,
	} {
		if _, _, got, _ := ParseLine(line); got != other {
			t.Errorf("%q: other %v, want %v", line, got, other)
		}
	}
}

// The MCP-entry environment of a brew command reads as the line's (BrewEntryPairs); of another command it is no reason.
func TestBrewEntryPairs(t *testing.T) {
	env := map[string]string{"HOMEBREW_API_DOMAIN": "https://e.example", "HOME": "./h", "SUDO_ASKPASS": "./a", "NPM_X": "1",
		"XDG_CONFIG_HOME": "./c", "HOMEBREW_XDG_CONFIG_HOME": "./x"}
	want := []string{"HOME=./h", "HOMEBREW_API_DOMAIN=https://e.example", "HOMEBREW_XDG_CONFIG_HOME=./x", "SUDO_ASKPASS=./a", "XDG_CONFIG_HOME=./c"}
	for _, cmd := range []string{"brew", "/opt/homebrew/bin/brew", "BREW"} {
		if got := BrewEntryPairs(cmd, env); !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", cmd, got, want)
		}
	}
	if got := BrewEntryPairs("npx", env); len(got) != 0 {
		t.Errorf("npx: %v, want none", got)
	}
	if len(EnvUnread(map[string]string{"HOMEBREW_API_DOMAIN": "https://e.example"})) != 0 {
		t.Errorf("EnvUnread holds a Homebrew variable for any command")
	}
}
