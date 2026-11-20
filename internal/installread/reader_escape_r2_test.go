package installread

import (
	"slices"
	"strings"
	"testing"
)

// Independent review of READER-ESCAPE-1 (2026-11-18). Each line installs in the shells named and was read by the base
// (71a26345 / 4f06c4aa); on reader-escape f59e3032 and reader-escape-dev b049de76 each reads clean: no target, no
// reason, so the hook stays silent.
func TestRvReaderEscapeWindowsRawKeepsSpecialEscape(t *testing.T) {
	// R1 (P1, new): a word whose raw spelling starts with $, ~, %NAME%\, a drive or \\ keeps ALL its backslashes,
	// also those before a special character (\' \; \ ) that the shell removes. The -c / eval script is then re-read
	// with those backslashes and loses its command. bash and zsh run npm i mcp-server-fetch for each (trace oracle,
	// work-1118/review-reader-escape/hand/table.txt).
	for _, line := range []string{
		`bash -c '$'\''npm'\'' i mcp-server-fetch'`,
		`sh -c '$'\''npm'\'' i mcp-server-fetch'`,
		`zsh -c '$'\''npm'\'' i mcp-server-fetch'`,
		`eval '$'\''npm'\'' i mcp-server-fetch'`,
		`eval $\'npm\' i mcp-server-fetch`,
		`sudo bash -c '$'\''npm'\'' i mcp-server-fetch'`,
		`bash -c '$@'\;' npm i mcp-server-fetch'`,
		`bash -c '~'\;'npm i mcp-server-fetch'`,
		`bash -c 'C:\x'\;'npm i mcp-server-fetch'`,
		`bash -c '\\srv\x'\;'npm i mcp-server-fetch'`,
		`bash -c '%A%\x'\;'npm i mcp-server-fetch'`,
		`bash -c '$HOME\x'\;'npm i mcp-server-fetch'`,
	} {
		tg, un, _, s := ParseLine(line)
		if len(tg)+len(un)+len(HookExtra(line, tg, un, s)) == 0 {
			t.Errorf("%q: read clean, the shell runs npm i mcp-server-fetch", line)
		}
	}
}

func TestRvReaderEscapeWindowsRelativePaths(t *testing.T) {
	// R2 (P1, new): an honest Windows relative path to the installer — the venv's pip, node_modules\.bin — which
	// PowerShell and cmd run (the hook takes the PowerShell tool too, web/api.go). The base read each; now POSIX
	// strips the backslashes (.venvScriptspip.exe) and the line is silent.
	for line, want := range map[string]string{
		`.\venv\Scripts\pip.exe install requests`:                    "pypi:requests",
		`venv\Scripts\pip.exe install requests`:                      "pypi:requests",
		`.\venv\Scripts\python.exe -m pip install requests`:          "pypi:requests",
		`..\venv\Scripts\pip.exe install requests`:                   "pypi:requests",
		`.\node_modules\.bin\npx.cmd -y mcp-server-fetch`:            "npm:mcp-server-fetch",
		`.\node_modules\.bin\npm.cmd i mcp-server-fetch`:             "npm:mcp-server-fetch",
		`cmd /c .\venv\Scripts\pip.exe install requests`:             "pypi:requests",
		`pwsh -c ".\venv\Scripts\pip.exe install requests"`:          "pypi:requests",
		`Set-Location C:\p; .\venv\Scripts\pip.exe install requests`: "pypi:requests",
		`tools\uv.exe pip install requests`:                          "pypi:requests",
		`.\pip.exe install requests`:                                 "pypi:requests",
	} {
		tg, _, _, _ := ParseLine(line)
		found := false
		for _, x := range tg {
			found = found || x == want
		}
		if !found {
			t.Errorf("%q: targets %v, want %s", line, tg, want)
		}
	}
}

// A Windows path to any program the readers read is read the Windows way, not only to an installer: a suffix
// (Git\bin\bash.exe) or a .\ path of two parts (.\node_modules\.bin\cross-env) marks it (READER-ESCAPE-1 round 2, R2).
func TestReaderEscapeR2WindowsPathAnyProgram(t *testing.T) {
	if tg, _, _, _ := ParseLine(`Git\bin\bash.exe -c 'npm i evil-pkg'`); len(tg) != 1 || tg[0] != "npm:evil-pkg" {
		t.Errorf("Git\\bin\\bash.exe -c: targets %q", tg)
	}
	const line = `.\node_modules\.bin\cross-env NODE_OPTIONS=--inspect=0.0.0.0:9229 npx -y ok-pkg`
	tg, un, _, subst := ParseLine(line)
	if x := HookExtra(line, tg, un, subst); !slices.ContainsFunc(x, func(s string) bool { return strings.Contains(s, "debugger port") }) {
		t.Errorf("%q: %q, want the debugger port among them", line, x)
	}
}
