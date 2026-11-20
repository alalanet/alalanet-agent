package installread

import (
	"bufio"
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// PIP-VERSIONED-1 round 2 (review P2-1): CPython reads its options getopt-style. The stored cases are the reviewer's
// (work-1118/review-pip-versioned/gen: gen.py, from python -h's option grammar; 13,128 prefixes before -m pip, eight -m
// spellings), each with what the real Python 3.11 did (r10-oracle:1, --rm --network none, a stand-in module): runs is
// true when Python went on to import the module. Every case that runs pip must give pip's target, after every launcher
// name; a case that runs nothing gives none, except where a word Python stops at (-h, -?, -V, --help, --version) is
// read past, which reads more and only asks.
func TestPipVersionedOracle(t *testing.T) {
	f, err := os.Open("testdata/pyopts-oracle-3.11.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	type ocase struct {
		ID   int      `json:"id"`
		Argv []string `json:"argv"`
		Runs bool     `json:"runs"`
	}
	var cases []ocase
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var c ocase
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			t.Fatal(err)
		}
		cases = append(cases, c)
	}
	if len(cases) != 13128 {
		t.Fatalf("%d cases; want 13128", len(cases))
	}
	stops := func(argv []string) bool {
		for _, w := range argv {
			if w == "--help" || w == "--version" || strings.HasPrefix(w, "-") && !strings.HasPrefix(w, "--") && strings.ContainsAny(strings.SplitN(w, "W", 2)[0], "hV?") {
				return true
			}
		}
		return false
	}
	names := []string{"python3", "python3.12", "python3.13t", "python3.12-dbg", "pythonw", "python.exe", "pypy3", "pypy3.10", "py",
		"py -3.12", "py -V:3.12", "pyw", "pyw -3.12", "/usr/bin/python3", "env python3", "sudo python3"}
	silent, over := 0, 0
	for k, name := range names {
		for i, c := range cases {
			if k > 0 && i%11 != k%11 {
				continue // python3 takes every case; each other name a twelfth of them
			}
			q := make([]string, len(c.Argv))
			for j, w := range c.Argv {
				q[j] = ShellQuote(w)
			}
			line := name + " " + strings.Join(q, " ") + " install zz-x"
			tg, _, _, _ := ParseLine(line)
			got := slices.Contains(tg, "pypi:zz-x")
			switch {
			case c.Runs && !got:
				if silent++; silent <= 20 {
					t.Errorf("case %d: Python runs pip; %q gives %v", c.ID, line, tg)
				}
			case !c.Runs && got && !stops(c.Argv):
				if over++; over <= 20 {
					t.Errorf("case %d: Python runs no module; %q reads pip", c.ID, line)
				}
			}
		}
	}
	if silent+over > 0 {
		t.Errorf("%d cases silent, %d read past a word Python refuses", silent, over)
	}
}

// The review's lines, after every launcher name; and what ends the options with no module.
func TestPipVersionedGetopt(t *testing.T) {
	// a selector's tag may hold c, m, W or X (py -V:Company/3.12): it is the launcher's word, not Python's options
	for _, name := range []string{"python3", "python", "py -3.12", "pypy3", "python3.12", "pythonw", "pyw", "pyw -3.12",
		"py -V:Company/3.12", "pyw -V:Microsoft/3.12-arm64"} {
		for _, opts := range []string{"-Impip", "-IBmpip", "-IWerror -m pip", "-IW error -m pip", "-IXutf8 -m pip", "-BX utf8 -m pip",
			"-W error -m pip", "-Wd -m pip", "-qm pip", "--check-hash-based-pycs never -m pip", "-X importtime -Im pip", "-E -s -mpip"} {
			l := name + " " + opts + " install zz-x"
			if tg, _, _, _ := ParseLine(l); !slices.Contains(tg, "pypi:zz-x") {
				t.Errorf("%q: %v; want pypi:zz-x", l, tg)
			}
		}
		for _, opts := range []string{"-c 'import pip' -m pip", "-Ic pass -m pip", "-- x.py -m pip", "- -m pip", "x.py -m pip",
			"-W -m pip", "-Xutf8"} {
			l := name + " " + opts + " install zz-x"
			if tg, _, _, _ := ParseLine(l); slices.Contains(tg, "pypi:zz-x") {
				t.Errorf("%q: %v; want no pip target (Python runs no module)", l, tg)
			}
		}
	}
}

// PythonRun, one row per shape of the grammar.
func TestPythonRun(t *testing.T) {
	for _, r := range []struct {
		cmd, words string
		kind       int
		value      string
	}{
		{"python3", "-m pip install x", PyModule, "pip"},
		{"python3", "-Impip install x", PyModule, "pip"},
		{"python3", "-IWerror -mpip", PyModule, "pip"},
		{"python3", "-IW error -m pip", PyModule, "pip"},
		{"python3", "-Ic print(1)", PyCode, "print(1)"},
		{"python3", "-uc pass", PyCode, "pass"},
		{"python3", "-c pass -m pip", PyCode, "pass"},
		{"py", "-3 -c pass", PyCode, "pass"},
		{"pyw", "-3.12 -m pip", PyModule, "pip"},
		{"python3", "-B x.py -m pip", PyScript, "x.py"},
		{"python3", "-- -m pip", PyScript, "-m"},
		{"python3", "-E -", PyNone, ""},
		{"python3", "-W", PyNone, ""},
		{"python3", "--check-hash-based-pycs always x.py", PyScript, "x.py"},
		{"python2", "-Q new x.py", PyScript, "x.py"},
		{"python3", "-h -m pip", PyModule, "pip"}, // read past: Python prints its help, reading on reads more
		{"python3", "", PyNone, ""},
	} {
		kind, v, _ := PythonRun(r.cmd, strings.Fields(r.words))
		if kind != r.kind || v != r.value {
			t.Errorf("PythonRun(%s %s) = %d %q; want %d %q", r.cmd, r.words, kind, v, r.kind, r.value)
		}
	}
	for _, n := range []string{"python", "python3", "python3.12", "python3.13t", "pythonw", "python3.12-dbg", "py", "pyw", "pypy", "pypy3", "pypy3.10"} {
		if !PythonInterp(n) || !PythonLauncher(n) {
			t.Errorf("%s: no Python launcher", n)
		}
	}
	for _, n := range []string{"pip", "pip3", "pip3.12", "pip3.13t"} {
		if !PythonLauncher(n) || PythonInterp(n) {
			t.Errorf("%s: PythonLauncher %v, PythonInterp %v; want pip's own script", n, PythonLauncher(n), PythonInterp(n))
		}
	}
	for _, n := range []string{"pyx", "pypyx", "npx", "pipx", "python_presite=evil", "pythonwarnings=x"} {
		if PythonLauncher(n) {
			t.Errorf("%s: read as a Python launcher", n)
		}
	}
}

// PythonNamePattern takes the names PythonInterp takes, and no other (round 3: the text readers' fragment).
func TestPythonNamePattern(t *testing.T) {
	re := regexp.MustCompile(`^` + PythonNamePattern + `$`)
	for _, n := range []string{"python", "python3", "python3.12", "python3.13t", "python3.12-dbg", "pythonw", "py", "pyw", "pypy", "pypy3",
		"pypy3.10", "pip", "pip3.12", "pyright", "pyx", "pypyx", "node", "npx", "pipx", "pyenv"} {
		if re.MatchString(n) != PythonInterp(n) {
			t.Errorf("%s: PythonNamePattern %v, PythonInterp %v", n, re.MatchString(n), PythonInterp(n))
		}
	}
}
