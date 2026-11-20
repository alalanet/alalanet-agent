package installread

import (
	"slices"
	"testing"
)

// PIP-VERSIONED-1: versioned pip, pipx and Python launchers are read by pattern, one row per shape. The Windows py
// launcher takes a version selector before Python's own options (py -3.12, py -V:3.12, py -3.13t, py -3-64:
// docs.python.org/3/using/windows.html, "Python install manager" / "py launcher"); PyPy installs pypy, pypy3 and
// pypyX.Y; a free-threaded build adds "t" (python3.13t); Python's own options may stand before -m (-I, -u, -X opt).
func TestPipVersionedEveryLauncher(t *testing.T) {
	const want = "pypi:zz-x"
	for _, l := range []string{
		"pip3.12 install zz-x", "pip3.12.exe install zz-x", "/usr/local/bin/pip3.11 install zz-x", "PIP3.12 install zz-x",
		"pip3.13t install zz-x",
		"python3.12 -m pip install zz-x", "python3.12.exe -m pip install zz-x", "python3.13t -m pip install zz-x",
		"py -m pip install zz-x", "py -3 -m pip install zz-x", "py -3.12 -m pip install zz-x", "py.exe -3.12 -m pip install zz-x",
		"py -3.13t -m pip install zz-x", "py -3-64 -m pip install zz-x", "py -3.12-32 -m pip install zz-x", "py -V:3.12 -m pip install zz-x",
		"py -V:PythonCore/3.12 -m pip install zz-x",
		"pypy -m pip install zz-x", "pypy3 -m pip install zz-x", "pypy3.10 -m pip install zz-x", "pypy3.10.exe -m pip install zz-x",
		"python3 -I -m pip install zz-x", "python3 -u -B -m pip install zz-x", "python3 -X utf8 -m pip install zz-x", "py -3.12 -I -m pip install zz-x", "python3 -mpip install zz-x", "python3 -Im pip install zz-x",
		"python3.12 -m pipx run zz-x", "py -3 -m pipx install zz-x", "pypy3 -m uv pip install zz-x",
	} {
		if tg, _, _, _ := ParseLine(l); !slices.Contains(tg, want) {
			t.Errorf("%q: targets %v; want %s", l, tg, want)
		}
	}
	for _, l := range []string{"py -3 -c 'print(1)'", "py -3.12 -m venv .venv", "pypy3 -c 'import pip'", "pythonista install zz-x", "pypyx install zz-x"} {
		if tg, _, _, _ := ParseLine(l); len(tg) != 0 {
			t.Errorf("%q: targets %v; want none", l, tg)
		}
	}
}
