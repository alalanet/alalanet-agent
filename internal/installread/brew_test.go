package installread

import (
	"slices"
	"testing"
)

// ECO-1, Homebrew taps (ADR, research work-1117/eco1-next §6.2): a third-party tap user/repo is the GitHub repository
// user/homebrew-repo, and its formula is Ruby run with the user's rights. brew install|reinstall|upgrade of an item
// user/repo/name, brew tap user/repo [URL] and brew trust user/repo[/name] name it as the target github:<user>/homebrew-
// <repo>, which the existing GitHub check judges. Official taps (homebrew/*) and bare names are not read (no target, no
// reason, as before). Options are Homebrew 7.0.14's (Library/Homebrew/cmd/{install,reinstall,upgrade,tap,trust}.rb and
// cli/parser.rb's global and cask options).
func TestBrewTaps(t *testing.T) {
	for line, want := range map[string][]string{
		"brew install u/tap/formula":                               {"github:u/homebrew-tap"},
		"brew install User/Homebrew-Tap/x":                         {"github:user/homebrew-homebrew-tap"}, // Tap.fetch: the prefix as written (round 2)
		"brew install User/homebrew-Tap/x":                         {"github:user/homebrew-tap"},
		"brew install --cask u/r/app":                              {"github:u/homebrew-r"},
		"brew install --HEAD u/r/x":                                {"github:u/homebrew-r"},
		"brew reinstall u/r/x":                                     {"github:u/homebrew-r"},
		"brew upgrade u/r/x":                                       {"github:u/homebrew-r"},
		"brew instal u/r/x":                                        {"github:u/homebrew-r"},
		"brew install wget u/r/x jq":                               {"github:u/homebrew-r"},
		"brew install u/r/x v/s/y":                                 {"github:u/homebrew-r", "github:v/homebrew-s"},
		"brew install --cc=clang u/r/x":                            {"github:u/homebrew-r"},
		"brew install --cc clang u/r/x":                            {"github:u/homebrew-r"},
		"brew install --env std u/r/x":                             {"github:u/homebrew-r"},
		"brew install --bottle-arch arm64 u/r/x":                   {"github:u/homebrew-r"},
		"brew install --cask --appdir /Applications u/r/x":         {"github:u/homebrew-r"},
		"brew install --cask --language en,de u/r/x":               {"github:u/homebrew-r"},
		"brew install -fv u/r/x":                                   {"github:u/homebrew-r"},
		"brew install --no-binaries --cask u/r/x":                  {"github:u/homebrew-r"},
		"brew install -- u/r/x":                                    {"github:u/homebrew-r"},
		"brew upgrade --min-version 2 u/r/x":                       {"github:u/homebrew-r"},
		"brew tap u/r":                                             {"github:u/homebrew-r"},
		"brew tap u/homebrew-r":                                    {"github:u/homebrew-r"},
		"brew tap --force u/r":                                     {"github:u/homebrew-r"},
		"brew tap u/r https://github.com/u/homebrew-r":             {"github:u/homebrew-r"},
		"brew tap u/r https://github.com/x/y.git":                  {"github:x/y"},
		"brew tap u/r git@github.com:x/y.git":                      {"github:x/y"},
		"brew tap --custom-remote u/r https://github.com/X/Y":      {"github:x/y"},
		"brew trust u/r":                                           {"github:u/homebrew-r"},
		"brew trust --formula u/r/x":                               {"github:u/homebrew-r"},
		"brew trust --json=v1 u/r":                                 {"github:u/homebrew-r"},
		"sudo -u me brew install u/r/x":                            {"github:u/homebrew-r"},
		"HOMEBREW_NO_AUTO_UPDATE=1 brew install u/r/x":             {"github:u/homebrew-r"},
		"/opt/homebrew/bin/brew install u/r/x":                     {"github:u/homebrew-r"},
		"brew tap u/r && brew install x":                           {"github:u/homebrew-r"},
		"brew install modelcontextprotocol/tap/mcp-publisher":      {"github:modelcontextprotocol/homebrew-tap"},
		"brew install homebrew/cask/firefox u/r/x":                 {"github:u/homebrew-r"},
		"HOMEBREW_NO_REQUIRE_TAP_TRUST= brew install u/r/x":        {"github:u/homebrew-r"}, // empty: not set (present?)
		"brew install -q u/r/x":                                    {"github:u/homebrew-r"},
		"brew trust -q u/r":                                        {"github:u/homebrew-r"},
		"brew tap u/r HTTPS://GitHub.com/X/Y.git":                  {"github:x/y"},
		"homebrew_api_domain=https://e.example brew install u/r/x": {"github:u/homebrew-r"}, // another variable: names have case
		"brew trust u/r/x u/s":                                     {"github:u/homebrew-r", "github:u/homebrew-s"},
	} {
		if tg, codes := codesOn(line); !slices.Equal(tg, want) || len(codes) > 0 {
			t.Errorf("%q: targets %v codes %v, want %v and no reason", line, tg, codes, want)
		}
	}
	// official taps, bare names and other commands: no target, no reason (counted as an unread brew line, as before)
	for _, line := range []string{
		"brew install wget", "brew install --cask docker", "brew install homebrew/cask/firefox", "brew tap homebrew/cask-fonts",
		"brew tap HomeBrew/core", "brew upgrade", "brew update", "brew tap", "brew list u/r/x", "brew install --help u/r/x",
		"brew help install u/r/x", "brew uninstall u/r/x", "brew info u/r/x", "brew trust", "brew untrust u/r",
	} {
		if tg, codes := codesOn(line); len(tg) > 0 || len(codes) > 0 {
			t.Errorf("%q: targets %v codes %v, want none", line, tg, codes)
		}
	}
	for line, code := range map[string]string{
		"brew tap u/r https://gitlab.com/u/homebrew-r.git":               "custom_registry",
		"brew tap u/r file:///tmp/x":                                     "custom_registry",
		"brew tap u/r /tmp/repo":                                         "custom_registry",
		"brew tap u/r git@gitlab.com:u/r.git":                            "custom_registry",
		"brew tap homebrew/core https://evil.example/core.git":           "custom_registry",
		"brew install https://example.com/x.rb":                          "git_or_url",
		"brew install ./x.rb":                                            "git_or_url",
		"brew install ~/f/x":                                             "git_or_url",
		"brew install foo.rb":                                            "git_or_url",
		"brew install FOO.RB":                                            "git_or_url",
		"brew tap $TAP":                                                  "variable_argument",
		"brew install /usr/local/f/x":                                    "git_or_url",
		"brew install .local/f/x":                                        "git_or_url",
		"brew install file:///tmp/x":                                     "git_or_url",
		"cat taps | xargs brew install":                                  "stdin_arguments",
		"brew trust u":                                                   "unknown_install_form",
		"brew trust u/r/x/y":                                             "unknown_install_form",
		"brew trust $T":                                                  "variable_argument",
		"brew install --force=1 u/r/x":                                   "unknown_install_form",
		"brew install --cask /tmp/x.rb":                                  "git_or_url",
		"brew install $TAP/x":                                            "variable_argument",
		"brew install u/$R/x":                                            "variable_argument",
		"brew tap u/r $URL":                                              "variable_argument",
		"HOMEBREW_NO_REQUIRE_TAP_TRUST=1 brew install u/r/x":             "custom_registry",
		"HOMEBREW_API_DOMAIN=https://evil.example/api brew install wget": "custom_registry",
		"export HOMEBREW_BOTTLE_DOMAIN=https://m.example; brew install u/r/x": "custom_registry",
		"HOMEBREW_BREW_GIT_REMOTE=https://e.example/brew brew update":         "custom_registry",
		"HOMEBREW_CORE_GIT_REMOTE=https://e.example/core brew install wget":   "custom_registry",
		"HOMEBREW_ARTIFACT_DOMAIN=https://e.example brew install u/r/x":       "custom_registry",
		"brew install --with-foo u/r/x":                                       "unknown_install_form",
		"brew install --build u/r/x":                                          "unknown_install_form", // an abbreviation: not read
		"brew install -fz u/r/x":                                              "unknown_install_form",
		"brew install u/r":                                                    "unknown_install_form",
		"brew install u/r/x/y":                                                "unknown_install_form",
		"brew tap u/r/x":                                                      "unknown_install_form",
		"brew tap u/r https://github.com/x/y/z":                               "custom_registry",
	} {
		if _, codes := codesOn(line); !slices.Contains(codes, code) {
			t.Errorf("%q: codes %v, want %s", line, codes, code)
		}
	}
	for line, want := range map[string]string{
		"brew install u/r/x": "github:u/homebrew-r",
		"HOMEBREW_NO_REQUIRE_TAP_TRUST=1 brew install u/r/x": "github:u/homebrew-r", // the target stays, with the reason
	} {
		if tg, _ := codesOn(line); !slices.Contains(tg, want) {
			t.Errorf("%q: targets %v, want %s", line, tg, want)
		}
	}
	for in, want := range map[string]string{"u/r": "github:u/homebrew-r", "u/homebrew-r": "github:u/homebrew-r",
		"homebrew/core": "", "Homebrew/cask": "", "u/r/x": "", "u": "", "u/": "", "/r": "", "u/r.x": "github:u/homebrew-r.x",
		"u/../x": "", "../r": "", "u/r$": "", "u/..": "", "u/.": "", "./r": ""} {
		if got := brewTapTarget(in); got != want {
			t.Errorf("brewTapTarget(%q) = %q, want %q", in, got, want)
		}
	}
}
