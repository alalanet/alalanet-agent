package main

import (
	"testing"

	"github.com/alalanet/alalanet-agent/internal/installread"
)

// Re-review of round 24 (reader-rows 53441af): constructs that close a body in substTrack's count but not in the
// shell's parse. bash 5.2 and zsh 5.9 run the written pip() in each (r12/desync; bash 3.2 too except the first).
// Adopted in round 25; the honest-backslash probe, a log only, as TestReview12BackslashHonest.
func TestReview12TrackerDesync(t *testing.T) {
	for _, line := range []string{
		`echo "$(echo ${X:-)} ; cp ./e.sh x.sh)"; . ./x.sh; pip install zz-pkg`,
		`echo ${X:-$(echo ")" ; cp ./e.sh x.sh)}; . ./x.sh; pip install zz-pkg`,
		"echo \"$(echo `echo )` ; cp ./e.sh x.sh)\"; . ./x.sh; pip install zz-pkg",
		"echo ${X:-$(echo `echo )` ; cp ./e.sh x.sh)}; . ./x.sh; pip install zz-pkg",
		`echo "$(echo $")" ; cp ./e.sh x.sh)"; . ./x.sh; pip install zz-pkg`,
		`echo "$(echo "$(echo ")")" ; cp ./e.sh x.sh)"; . ./x.sh; pip install zz-pkg`,
	} {
		cwd := t.TempDir()
		zzWrite(t, cwd, "e.sh", []byte("pip() { :; }\n"))
		why := reqFileHold(cwd, cwd, line, nil)
		tg, un, _, subst := installread.ParseLine(line)
		ex := installread.HookExtra(line, tg, un, subst)
		hold := why != "" || len(un) > 0 || len(ex) > 0
		t.Logf("hold=%-5v %-75q %q %v %v", hold, line, why, un, ex)
		if !hold {
			t.Errorf("%q: silent", line)
		}
	}
}

// B: honest lines with a backslash in a substitution next to a source (round 24's class).
func TestReview12BackslashHonest(t *testing.T) {
	for _, line := range []string{
		`VERSION="$(printf '%s\n' "$v" | head -1)"; source .venv/bin/activate && pip install zz-pkg`,
		`source .venv/bin/activate && pip install "zz-pkg==$(printf '%s\n' 1.0)"`,
		`source ./env.sh && X="$(grep -E '^a\.b' f.txt)" && pip install zz-pkg`,
	} {
		cwd := t.TempDir()
		zzWrite(t, cwd, "env.sh", []byte("A=1\n"))
		why := reqFileHold(cwd, cwd, line, nil)
		t.Logf("%-95q agent %q", line, why)
	}
}
