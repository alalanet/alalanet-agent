package installread

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

// READER-NPM-ABBREV-1 (ADR-0159 round 12): npm's option words as nopt reads them — a key's unambiguous prefix
// (--script-s, --node-o), a shorthand, a cluster, a one-dash long option — for the levers the second reader judges and
// the values the first one skips. Placeholders zz-abbrev-pkg and evil.example only.

func TestReaderAbbrevLevers(t *testing.T) {
	for _, line := range []string{
		"npm i zz-abbrev-pkg --script-s=./zz.sh", // confirmed on npm 10.8.2: npm config get script-shell
		"npm i zz-abbrev-pkg --script-sh ./zz.sh",
		"npm i zz-abbrev-pkg --scr=./zz.sh",
		"npm i zz-abbrev-pkg -script-s=./zz.sh", // one dash: nopt reads it as --script-s
		"npm i zz-abbrev-pkg --node-o=--require=./zz.js",
		"npm i zz-abbrev-pkg --no-strict-s",
		"npm i zz-abbrev-pkg --strict-ss=false",
		"npm i zz-abbrev-pkg --cafi=./zz.pem",
		"npm i zz-abbrev-pkg --init-m=./zz.js",
		"npm i zz-abbrev-pkg --node-g=./zz-gyp.js",
		"npx --script-s=./zz.sh -y zz-abbrev-pkg",
		"npm exec --node-o=--require=./zz.js -- zz-abbrev-pkg",
		"npm i zz-abbrev-pkg --nod=--require=./zz.js", // npm 9 and 10: node-options is the only key from "nod" on
	} {
		tg, un, _, s := ParseLine(line)
		if len(HookExtra(line, tg, un, s)) == 0 && len(un) == 0 {
			t.Errorf("%q: no reason", line)
		}
	}
	for _, line := range []string{
		"npm i zz-abbrev-pkg --script-s=/bin/bash", // a program on PATH or an absolute path is the user's own
		"npm i zz-abbrev-pkg --strict-ss=true",
		"npm i zz-abbrev-pkg --no-scr",           // script-shell set to false: no shell of the line's choosing
		"npm i zz-abbrev-pkg --sav",              // save, save-dev …: ambiguous, an unknown switch to npm
		"npm i zz-abbrev-pkg --Script-S=./zz.sh", // nopt's names are case-sensitive: an unknown switch
		"npm i -D zz-abbrev-pkg --loglev=warn",
		"pnpm add zz-abbrev-pkg --script-s=./zz.sh", // pnpm reads its own options (see the round's open question)
	} {
		tg, un, _, s := ParseLine(line)
		if ex := HookExtra(line, tg, un, s); len(ex) > 0 || len(un) > 0 {
			t.Errorf("%q: unread %q, extra %q; want neither", line, un, ex)
		}
	}
}

// The first reader skips the value of an option npm reads through a prefix or a shorthand, as for the full name.
func TestReaderAbbrevValues(t *testing.T) {
	for line, want := range map[string][]string{
		"npm i --loglev warn zz-abbrev-pkg":  {"npm:zz-abbrev-pkg"}, // --loglevel warn
		"npm i -workspace web zz-abbrev-pkg": {"npm:zz-abbrev-pkg"},
		"npm i -loglev warn zz-abbrev-pkg":   {"npm:zz-abbrev-pkg"}, // one dash and a prefix
		"npm i zz-abbrev-pkg --loglev warn":  {"npm:zz-abbrev-pkg"},
		"npm --loglev warn i zz-abbrev-pkg":  {"npm:zz-abbrev-pkg"}, // before the subcommand too
		// scope, and scopes from npm 10.9 on: ambiguous there, a switch, and the next word a package
		"npm i --scop @zz zz-abbrev-pkg": {"npm:@zz", "npm:zz-abbrev-pkg"},
		"npm i --no-scr zz-abbrev-pkg":   {"npm:zz-abbrev-pkg"}, // negated: no value
		"npm i --wor=web zz-abbrev-pkg":  {"npm:zz-abbrev-pkg"},
		"npm i --sav zz-abbrev-pkg":      {"npm:zz-abbrev-pkg"}, // ambiguous: a switch
	} {
		if tg, _, _, _ := ParseLine(line); !slices.Equal(tg, want) {
			t.Errorf("%q: targets %v, want %v", line, tg, want)
		}
	}
}

// npmOptionKeys gives, for every word tools/installread_npmopts.js checked against nopt (the prefixes of the reader's
// lever and value keys, every word of one or two letters, each also after "no-"), the union over npm 9.9.4 to 12.2.2
// of the keys nopt sets (testdata/npm_option_words.json, written by the generator).
func TestReaderAbbrevGolden(t *testing.T) {
	b, err := os.ReadFile("testdata/npm_option_words.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden map[string]string
	if err := json.Unmarshal(b, &golden); err != nil {
		t.Fatal(err)
	}
	if len(golden) < 1500 {
		t.Fatalf("golden: %d words", len(golden))
	}
	for w, want := range golden {
		for _, form := range []string{"--" + w, "--" + w + "=zz", "-" + w} {
			if got := strings.Join(npmOptionKeys(form), " "); got != want { // nopt takes every leading dash off
				t.Errorf("npmOptionKeys(%q) = %q, want %q", form, got, want)
			}
		}
	}
	// the generator's data: every npm key the reader names as a lever or a value option is a key npm has
	for k := range pmLongValueOptions["npm"] {
		if k != "--enjoy-by" && npmConfigKeys[strings.TrimPrefix(k, "--")] == 0 {
			t.Errorf("%s: a value option of npm's that no npm version in the tables has", k)
		}
	}
	if npmStrict != 1<<(len(npmVersions)-1) || npmVersions[len(npmVersions)-1] != "12.2.2" {
		t.Errorf("npm 12 alone refuses prefixes: npmStrict %b, versions %v", npmStrict, npmVersions)
	}
}

func TestReaderAbbrevResolve(t *testing.T) {
	for w, want := range map[string]string{
		"--script-s": "script-shell", "--NO-strict-s": "strict-ssl", "--no-no-strict-s": "strict-ssl", "-sc": "call loglevel",
		"--caf": "all call force", "--reg": "registry", "--a": "all", "--no-a": "a", "--zz-unknown": "zz-unknown",
		"--registry=https://evil.example/": "registry", "--": "", "-C": "prefix", "--porc": "parseable",
	} {
		if got := strings.Join(npmOptionKeys(w), " "); got != want {
			t.Errorf("npmOptionKeys(%q) = %q, want %q", w, got, want)
		}
	}
	for w, want := range map[string]bool{"script-s": false, "no-script-s": true, "No-NO-x": false, "no-no-no-x": true, "nox": false} {
		if npmNegated(w) != want {
			t.Errorf("npmNegated(%q) != %v", w, want)
		}
	}
	// npm 12 (the strict version) reads no prefix: a word only it would read gives nothing for it
	if got := npmResolve(npmStrict, "script-s"); got != nil {
		t.Errorf("npm 12 on script-s: %v", got)
	}
	if got := npmResolve(1, "script-s"); !slices.Equal(got, []string{"script-shell"}) {
		t.Errorf("npm 9 on script-s: %v", got)
	}
	if got := npmResolve(npmStrict, "porc"); got != nil {
		t.Errorf("npm 12 on a shorthand's prefix: %v", got)
	}
	if got := npmResolve(npmStrict, "reg"); !slices.Equal(got, []string{"registry"}) {
		t.Errorf("npm 12 on an exact shorthand: %v", got)
	}
}
