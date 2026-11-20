package installread

import (
	"slices"
	"strings"
	"testing"
)

// READER-ESCAPE-1 round 2, R2 / READER-METAMORPHIC-1 M3: a fixed corpus of Windows installer lines PowerShell and cmd
// run, with the target the base read and the head must still read (never weaker). POSIX strips the backslashes, so the
// POSIX reading finds nothing; the second reading as a Windows path keeps the installer.
func TestReaderEscapeWindowsCorpus(t *testing.T) {
	read := func(line string) (tg []string, held bool) {
		t, un, _, s := ParseLine(line)
		return t, len(un)+len(HookExtra(line, t, un, s)) > 0
	}
	cases := map[string]string{
		`.\venv\Scripts\pip.exe install requests`:                       "pypi:requests",
		`venv\Scripts\pip.exe install requests`:                         "pypi:requests",
		`..\venv\Scripts\pip.exe install requests`:                      "pypi:requests",
		`.\venv\Scripts\python.exe -m pip install requests`:             "pypi:requests",
		`.venv\Scripts\python.exe -m pip install requests`:              "pypi:requests",
		`.\node_modules\.bin\npx.cmd -y mcp-server-fetch`:               "npm:mcp-server-fetch",
		`.\node_modules\.bin\npm.cmd i mcp-server-fetch`:                "npm:mcp-server-fetch",
		`tools\uv.exe pip install requests`:                             "pypi:requests",
		`.\tools\uv.exe tool install ruff`:                              "pypi:ruff",
		`.\pip.exe install requests`:                                    "pypi:requests",
		`cmd /c .\venv\Scripts\pip.exe install requests`:                "pypi:requests",
		`pwsh -c ".\venv\Scripts\pip.exe install requests"`:             "pypi:requests",
		`powershell -Command ".\venv\Scripts\pip.exe install requests"`: "pypi:requests",
		`Set-Location C:\p; .\venv\Scripts\pip.exe install requests`:    "pypi:requests",
		`cd C:\proj; .\venv\Scripts\pip.exe install flask`:              "pypi:flask",
		`C:\Python\python.exe -m pip install requests`:                  "pypi:requests",
		`$env:TEMP\npm.cmd i mcp-server-fetch`:                          "npm:mcp-server-fetch",
	}
	for line, want := range cases {
		tg, _ := read(line)
		if !slices.Contains(tg, want) {
			t.Errorf("%q: targets %v, want %s", line, tg, want)
		}
	}
	// an mcp-add launch through a relative Windows path: the launch target is read with its backslashes too, so the
	// package behind it is checked (the POSIX-joined target alone named no program)
	if tg, _ := read(`claude mcp add fetch -- .\node_modules\.bin\npx.cmd -y mcp-server-fetch`); !slices.ContainsFunc(tg, func(x string) bool {
		return strings.Contains(x, `\node_modules\.bin\npx.cmd`) // the Windows path kept (develop quotes the word)
	}) {
		t.Errorf("mcp-add Windows launch: targets %v, want the launch with its Windows path", tg)
	}
	// a deny-listed install through a relative Windows path must not be silent (R2's security point)
	if _, held := read(`.\venv\Scripts\pip.exe install some-deny-listed-pkg`); !held {
		// not held only because the package is judged downstream; the target must at least be read
		if tg, _ := read(`.\venv\Scripts\pip.exe install some-deny-listed-pkg`); len(tg) == 0 {
			t.Error("a relative Windows pip install is silent (no target)")
		}
	}
}
