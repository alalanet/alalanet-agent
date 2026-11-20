package installread

import (
	"slices"
	"testing"
)

// READER-VAR-OPT-1 round 3 (ADR-0159 round 11). The value tables come from the tools' own parsers (pyOptions,
// tools/installread_pyopts.py): no option's value is read as the package, and no switch takes the next word.
// Placeholders zz-var-pkg only.

// Q6: the package that runs is the target, not an option's value (the re-review's lines, and the same class).
func TestReaderVarOpt3RunPackageIsTheTarget(t *testing.T) {
	for line, want := range map[string][]string{
		"uvx --torch-backend auto zz-var-pkg":                              {"pypi:zz-var-pkg"},
		"uv tool install --torch-backend cpu zz-var-pkg":                   {"pypi:zz-var-pkg"},
		"uv tool run --overrides o.in zz-var-pkg":                          {"pypi:zz-var-pkg"},
		"uv tool run --build-constraints c.txt zz-var-pkg":                 {"pypi:zz-var-pkg"},
		"uv tool install --excludes e.txt zz-var-pkg":                      {"pypi:zz-var-pkg"},
		"uv tool install --with-executables-from zz-a zz-var-pkg":          {"pypi:zz-a", "pypi:zz-var-pkg"}, // installs both
		"pipx run --backend uv zz-var-pkg":                                 {"pypi:zz-var-pkg"},
		"pipx install --backend uv zz-var-pkg":                             {"pypi:zz-var-pkg"},
		"pipx install --output json zz-var-pkg":                            {"pypi:zz-var-pkg"},
		"pipx install --upgrade-strategy eager zz-var-pkg":                 {"pypi:zz-var-pkg"},
		"pipx install --fetch-python always zz-var-pkg":                    {"pypi:zz-var-pkg"},
		"uv pip install --python-version 3.12 zz-var-pkg":                  {"pypi:zz-var-pkg"},
		"uv pip install --only-binary :all: zz-var-pkg":                    {"pypi:zz-var-pkg"},
		"uv pip install --output-format json zz-var-pkg":                   {"pypi:zz-var-pkg"},
		"uv add --script s.py zz-var-pkg":                                  {"pypi:zz-var-pkg"}, // a path in uv add
		"pip install zz-var-pkg --upgrade-st eager":                        {"pypi:zz-var-pkg"}, // optparse's abbreviation
		"pipx install --upgrade-str only-if-needed zz-var-pkg":             {"pypi:zz-var-pkg"}, // argparse's abbreviation
		"uv run --with zz-var-pkg --script app.py":                         {"pypi:zz-var-pkg"},
		"uv tool install --editable ./tool --with zz-var-pkg":              {"pypi:zz-var-pkg"},
		"pip install --prefix /opt/p --root-user-action ignore zz-var-pkg": {"pypi:zz-var-pkg"},
	} {
		tg, codes := codesOn(line)
		if len(codes) > 0 || !slices.Equal(tg, want) {
			t.Errorf("%q: targets %v, codes %v; want %v and no reason", line, tg, codes, want)
		}
	}
}

// Q1's class: a switch in one subcommand that valueFlags (or the round-2 union) read with a value — uv add's
// --editable and --workspace, pipx's --editable, uv run's --script — no longer hides the index option after it.
func TestReaderVarOpt3SwitchesPerSubcommand(t *testing.T) {
	for _, line := range []string{
		"uv add --editable --index-url /srv/simple zz-var-pkg",
		"uv add --workspace -f /srv/wheels zz-var-pkg",
		"uv tool install --editable -f /srv/wheels zz-var-pkg",
		"pipx install --editable -i /srv/simple zz-var-pkg",
		"uv run --with zz-var-pkg --script --find-links /srv/wheels app.py",
		"uv run --with zz-var-pkg --module --index-url /srv/simple zzmod",
	} {
		if _, codes := codesOn(line); !slices.Contains(codes, "custom_registry") {
			t.Errorf("%q: codes %v, want custom_registry", line, codes)
		}
	}
}

// The generated tables agree with the tools on the options this round turns on (uv 0.13.7 probed with OPT=zzv --help,
// pipx 1.17.2's argparse nargs, pip 26.2.2's takes_value). A regeneration from other tools fails here first.
func TestReaderVarOpt3TablesAgreeWithTheTools(t *testing.T) {
	for form, opts := range map[string]map[string]bool{
		"uv run":          {"--script": false, "-s": false, "--module": false, "-m": false, "--with": true, "--editable": false},
		"uv add":          {"--script": true, "--editable": false, "--workspace": false, "-m": true, "--marker": true},
		"uv tool install": {"-e": false, "--editable": false, "--torch-backend": true, "--with-executables-from": true},
		"uv tool run":     {"--overrides": true, "--from": true, "-w": true},
		"uv pip install":  {"-e": true, "-C": true, "-P": true, "-b": true, "--no-binary": true},
		"uv":              {"--directory": true, "--project": true, "--offline": false},
		"pipx install":    {"-e": false, "-f": false, "-i": true, "--backend": true, "--pip-args": true},
		"pipx run":        {"--spec": true, "--python-args": true, "--path": false},
		"pip install":     {"-C": true, "-e": true, "-U": false, "--upgrade-strategy": true, "--pre": false},
		"pip":             {"--cache-dir": true, "--isolated": false, "--python": true},
	} {
		for opt, want := range opts {
			if got, ok := pyOptions[form][opt]; !ok || got != want {
				t.Errorf("%s %s: in the table %v, takes a value %v; want %v", form, opt, ok, got, want)
			}
		}
	}
}

// pyForm reads the subcommand past the options the main parser reads with a value.
func TestReaderVarOpt3Forms(t *testing.T) {
	for _, c := range []struct {
		cmd  string
		rest []string
		want string
	}{
		{"pip", []string{"--cache-dir", "/c", "install", "x"}, "pip install"},
		{"pip3", []string{"install", "x"}, "pip install"},
		{"uv", []string{"--directory", "d", "tool", "install", "x"}, "uv tool install"},
		{"uv", []string{"pip", "install", "x"}, "uv pip install"},
		{"uv", []string{"run", "x.py"}, "uv run"},
		{"uv", []string{"python", "install", "3.12"}, ""},
		{"uvx", []string{"x"}, "uv tool run"},
		{"pipx", []string{"run", "x"}, "pipx run"},
		{"pipx", []string{"-w", "x", "run", "y"}, ""}, // not a pipx line: read as before
	} {
		if got := pyForm(c.cmd, c.rest); got != c.want {
			t.Errorf("%s %v: form %q, want %q", c.cmd, c.rest, got, c.want)
		}
	}
}

// shlexWordsWin against Python 3.15's shlex.split(v.strip("'"), posix=False) (outputs taken from Python on 2026-11-15;
// a differential run of 46,536 inputs agreed).
func TestReaderVarOpt3ShlexWordsWin(t *testing.T) {
	for in, want := range map[string][]string{
		`--cache-dir=C:\pc\ -i C:\idx`: {`--cache-dir=C:\pc\`, "-i", `C:\idx`},
		`"a\"b" c`:                     {`"a\"`, `b"`, "c"},
		`a ""b`:                        {"a", `""`, "b"},
		`ab' b`:                        {"ab'", "b"},
		`"-i" x`:                       {`"-i"`, "x"},
		`-i\ x`:                        {`-i\`, "x"},
	} {
		if got := shlexWordsWin(in); !slices.Equal(got, want) {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

// pyTakesValue: optparse and argparse take a long option's unambiguous prefix, clap does not; an ambiguous prefix and
// a --opt=value word take no next word.
func TestReaderVarOpt3TakesValue(t *testing.T) {
	for _, c := range []struct {
		form, cmd, x string
		want         bool
	}{
		{"pip install", "pip", "--upgrade-st", true},
		{"pip install", "pip", "--no-b", false}, // --no-binary or --no-build-isolation: pip refuses it
		{"pip install", "pip", "--upgrade-strategy=eager", false},
		{"pip install", "pip", "--ex", false}, // --exists-action or --extra-index-url, both with a value: still none
		{"pipx install", "pipx", "--upgrade-str", true},
		{"uv tool run", "uv", "--torch", false}, // clap: the full name only
		{"uv tool run", "uv", "--torch-backend", true},
		{"uv run", "uv", "-m", false},
	} {
		if got := pyTakesValue(pyOptions[c.form], c.cmd, c.x); got != c.want {
			t.Errorf("%s %s: %v, want %v", c.form, c.x, got, c.want)
		}
	}
}

// commandAfter and unseenCommandWord: what follows a hidden word before the command (Q2, Q3, Q7).
func TestReaderVarOpt3CommandAfter(t *testing.T) {
	for _, line := range []string{
		`uvx --from zz-var-pkg "$P" --with=zz-b zzbin`, // --with=zz-b takes no next word: zzbin is the command
		`uvx --from zz-var-pkg "$P" -- zzbin`,          // the command after "--"
		`npx -p zz-var-pkg "$P" --cal=zzbin`,           // nopt's abbreviation of --call, the command in its value
		`npx -p zz-var-pkg "$P" -call zzbin`,           // and its one-dash spelling
	} {
		if reasonless(line) {
			t.Errorf("%q: read as a plain install", line)
		}
	}
	for _, line := range []string{
		`uv run --with zz-var-pkg -m "$M" "$A"`, // the module is the command, "$A" its argument
		`uvx --from zz-var-pkg zzbin -- "$A" "$B"`,
		`uvx --from zz-var-pkg "$C" --python 3.12`, // an option's value after the hidden command is no command
	} {
		if !reasonless(line) {
			tg, codes := codesOn(line)
			t.Errorf("%q: targets %v, codes %v; want a plain install", line, tg, codes)
		}
	}
	if got := shlexWordsWin(`'q r'`); !slices.Equal(got, []string{"q", "r"}) { // pipx strips the outer single quotes
		t.Errorf("'q r': %q", got)
	}
}

// Outside the forms the tables have, the reader keeps valueFlags (uv pip "$P" install: the hidden word stands where
// the subcommand would be); an npm one-dash option with "=" carries its value (round 3: -userc=/x i pkg skipped i).
func TestReaderVarOpt3Fallbacks(t *testing.T) {
	for line, want := range map[string][]string{
		`uv pip "$P" install --python 3.12 zz-var-pkg`:      {"pypi:zz-var-pkg"},
		`uv pip "$P" install -rreq-i.txt zz-var-pkg`:        {"pypi:zz-var-pkg"},
		"npm -userc=/srv/rc i zz-var-pkg":                   {"npm:zz-var-pkg"},
		"npm -reg=https://evil.example/ install zz-var-pkg": {"npm:zz-var-pkg"},
	} {
		tg, codes := codesOn(line)
		if !slices.Equal(tg, want) || slices.Contains(codes, "custom_registry") != (line[:4] == "npm ") {
			t.Errorf("%q: targets %v, codes %v; want %v", line, tg, codes, want)
		}
	}
}
