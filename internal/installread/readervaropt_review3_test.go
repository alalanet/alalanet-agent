package installread

import (
	"slices"
	"testing"
)

// Independent re-review of READER-VAR-OPT-1 round 3 (dc635b6 on bd17ee4), 2026-11-15. Placeholders zz-var-pkg and
// evil.example only. pip 26.2.2 (its own optparse parser), uv 0.13.7 (clap, "OPT=zzv --help" probes over every
// name in the uv binary, offline), pipx 1.17.2.

// S1 (P1, a regression: hold on bd17ee4, silent on dc635b6). pip's --index-url has a hidden alias, --pypi-url
// (optparse: dest index_url, -i/--index-url/--pypi-url; pip install --pypi-url http://127.0.0.1:9/simple printed
// "Looking in indexes: http://127.0.0.1:9/simple", and so did its abbreviation --pyp). The generated table now knows
// it takes a value, so pkgs skips the URL that held the line as git_or_url before; neither registryFlags nor
// pyRegistryOption has it.
func TestReviewR3PipPypiURLAlias(t *testing.T) {
	for _, line := range []string{
		"pip install --pypi-url https://evil.example/simple zz-var-pkg",
		"pip install --pypi-url=https://evil.example/simple zz-var-pkg",
		"pip install --pyp /srv/simple zz-var-pkg",
		"pip3 install --pypi /srv/simple zz-var-pkg",
		"python -m pip install zz-var-pkg --pypi-url /srv/simple",
		"pipx install zz-var-pkg --pip-args='--pypi-url /srv/simple'",
	} {
		if _, codes := codesOn(line); !slices.Contains(codes, "custom_registry") {
			t.Errorf("%q: codes %v, want custom_registry", line, codes)
		}
	}
}

// S2 (P2, the generator). The uv tables take option names from --help only, and clap hides some options from a
// subcommand's help: global ones (--python-preference, --preview-features) and aliases (--override, --constraint,
// --trusted-host). Probed in uv tool run with "OPT=zzv --help", each takes a value. Missing from the table, its value
// is read as the tool, so uvx checks the value and runs the real package unchecked.
func TestReviewR3UvHiddenValueOptions(t *testing.T) {
	for line, want := range map[string][]string{
		"uvx --python-preference only-managed zz-var-pkg":            {"pypi:zz-var-pkg"},
		"uvx --preview-features pylock zz-var-pkg":                   {"pypi:zz-var-pkg"},
		"uvx --override pins.in zz-var-pkg":                          {"pypi:zz-var-pkg"},
		"uvx --constraint pins.in zz-var-pkg":                        {"pypi:zz-var-pkg"},
		"uv tool install --python-preference only-system zz-var-pkg": {"pypi:zz-var-pkg"},
	} {
		if tg, _ := codesOn(line); !slices.Equal(tg, want) {
			t.Errorf("%q: targets %v, want %v", line, tg, want)
		}
	}
}

// S3 (P3, the Windows split). pipx on Windows (shlex posix=False) treats a quote inside a word as an ordinary
// character, so a quote can hide "-i DIR" from the POSIX split without any backslash: Python 3.15 splits
// '--src=x"y -i C:/idx --src=z"' into ['--src=xy -i C:/idx --src=z'] (posix) and ['--src=x"y', '-i', 'C:/idx',
// '--src=z"'] (not). pipArgs reads the non-POSIX split only for a value with a backslash.
func TestReviewR3PipArgsWindowsQuote(t *testing.T) {
	if line := `pipx install zz-var-pkg --pip-args='--src=x"y -i C:/idx --src=z"'`; reasonless(line) {
		t.Errorf("%q: read as a plain install", line)
	}
}
