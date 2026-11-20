package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/alalanet/alalanet-agent/internal/installread"
)

// review10Hold: a hold from the agent or the line reader (the re-review of round 22, reader-rows 80ac85e, adopted in
// round 23).
func review10Hold(t *testing.T, cwd, line string, getenv func(string) string) (bool, string) {
	t.Helper()
	why := reqFileHold(cwd, cwd, line, getenv)
	tg, un, _, subst := installread.ParseLine(line)
	ex := installread.HookExtra(line, tg, un, subst)
	return why != "" || len(un) > 0 || len(ex) > 0, why
}

// S: a write in a substitution the walk does not read as commands, before a source of the file it writes.
func TestReview10SubstForms(t *testing.T) {
	for _, line := range []string{
		`cat <<< "$(cp ./e.sh x.sh)"; . ./x.sh; pip install zz-pkg`,
		`cat <<< $(cp ./e.sh x.sh); . ./x.sh; pip install zz-pkg`,
		`echo ${X:-$(cp ./e.sh x.sh)}; . ./x.sh; pip install zz-pkg`,
		`echo "${X:-$(cp ./e.sh x.sh)}"; . ./x.sh; pip install zz-pkg`,
		`echo ${X/$(cp ./e.sh x.sh)/y}; . ./x.sh; pip install zz-pkg`,
		`echo $(( $(cp ./e.sh x.sh; echo 1) + 1 )); . ./x.sh; pip install zz-pkg`,
		`echo "$(( $(cp ./e.sh x.sh; echo 1) + 1 ))"; . ./x.sh; pip install zz-pkg`,
		`echo "$(echo "$(cp ./e.sh x.sh)")"; . ./x.sh; pip install zz-pkg`,
		`echo "a $(echo ')' ; cp ./e.sh x.sh) b"; . ./x.sh; pip install zz-pkg`,
		`echo "$(cat <<'E'` + "\n)\nE\n" + `cp ./e.sh x.sh)"; . ./x.sh; pip install zz-pkg`,
		`echo "$(cp ./e.sh x.sh`,
		`: "${X:=$(cp ./e.sh x.sh)}"; . ./x.sh; pip install zz-pkg`,
		`echo "$(case a in a) cp ./e.sh x.sh;; esac)"; . ./x.sh; pip install zz-pkg`,
		`echo "$(# )` + "\n" + `cp ./e.sh x.sh)"; . ./x.sh; pip install zz-pkg`,
	} {
		cwd := t.TempDir()
		zzWrite(t, cwd, "e.sh", []byte("pip() { :; }\n"))
		hold, why := review10Hold(t, cwd, line, nil)
		t.Logf("hold=%-5v %-95q %q", hold, line, why)
		if !hold {
			t.Errorf("%q: silent", line)
		}
	}
}

// P: PATH resolution: a FIFO and an unreadable file earlier in PATH, a folder named like the file.
func TestReview10PathForms(t *testing.T) {
	cwd, p1, p2 := t.TempDir(), t.TempDir(), t.TempDir()
	zzWrite(t, cwd, "x.sh", []byte("A=1\n"))
	zzWrite(t, p2, "x.sh", []byte("A=2\n"))
	env := func(k string) string { return map[string]string{"PATH": p1 + string(os.PathListSeparator) + p2}[k] }
	run := func(name string) {
		hold, why := review10Hold(t, cwd, "source x.sh && pip install zz-pkg", env)
		t.Logf("%-28s hold=%-5v %q", name, hold, why)
		if !hold && name != "a folder named x.sh" {
			t.Errorf("%s: silent", name)
		}
	}
	if err := os.MkdirAll(filepath.Join(p1, "x.sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	run("a folder named x.sh")
	if err := os.Remove(filepath.Join(p1, "x.sh")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(p1, "x.sh"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("a FIFO named x.sh") // bash sources a FIFO: what a writer feeds it
}
