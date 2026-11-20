package installread

import (
	"slices"
	"testing"
)

// PIP-VERSIONED-1 round 4 (re-review P2-C): a relative Windows path to a Python launcher or pip without its suffix
// (venv\Scripts\python3.12, pypy3, pip3.12) is read the second way as any launcher by the pattern, not by
// READER-ESCAPE-1's three fixed names (the reviewer's probe, h/zz_rvpv3_win_test.go, as assertions).
func TestPipVersionedWinPaths(t *testing.T) {
	for _, line := range []string{
		`C:\Python312\python.exe -m pip install zz-x`, `C:\Python312\python3.12.exe -m pip install zz-x`,
		`C:\Python312\pythonw.exe -m pip install zz-x`, `C:\pypy\pypy3.exe -m pip install zz-x`, `C:\Windows\py.exe -3.12 -m pip install zz-x`,
		`.\venv\Scripts\python.exe -m pip install zz-x`, `.\venv\Scripts\python3.12.exe -m pip install zz-x`,
		`venv\Scripts\pythonw -m pip install zz-x`, `.\venv\Scripts\pip.exe install zz-x`, `.\venv\Scripts\pip3.12.exe install zz-x`,
		`..\python_embeded\python.exe -s -m pip install zz-x`, `..\python_embeded\python3.11.exe -s -m pip install zz-x`,
		`venv\Scripts\python -m pip install zz-x`, `venv\Scripts\python3 -m pip install zz-x`, `venv\Scripts\python3.12 -m pip install zz-x`,
		`venv\Scripts\pypy3 -m pip install zz-x`, `venv\Scripts\pip3.12 install zz-x`, `venv\Scripts\pip install zz-x`,
		`venv\Scripts\python3.13t -m pip install zz-x`, `venv\Scripts\pyw -3.12 -m pip install zz-x`, `venv\Scripts\py -m pip install zz-x`,
		`venv\Scripts\pip3 install zz-x`, `sudo venv\Scripts\pip3.12 install zz-x`,
	} {
		if tg, un, _, _ := ParseLine(line); !slices.Contains(tg, "pypi:zz-x") {
			t.Errorf("%s: targets %q, unread %q; want pypi:zz-x", line, tg, un)
		}
	}
}
