package main

import (
	"testing"

	"github.com/alalanet/alalanet-agent/internal/installread"
)

// Re-review of round 23 (reader-rows a69360b): substTrack's count of parentheses against the shell's parse. bash 3.2,
// bash 5.2 and zsh 5.9 run the written pip() in each (r11/desync). Adopted in round 24 as it was.
func TestReview11TrackerDesync(t *testing.T) {
	for _, line := range []string{
		`echo "$(echo $'\')' ; cp ./e.sh x.sh)"; . ./x.sh; pip install zz-pkg`,
		`echo "$(echo \) ; cp ./e.sh x.sh)"; . ./x.sh; pip install zz-pkg`,
		`echo "$([[ a == \) ]] ; cp ./e.sh x.sh)"; . ./x.sh; pip install zz-pkg`,
		`echo ${X:-$(echo \) ; cp ./e.sh x.sh)}; . ./x.sh; pip install zz-pkg`,
		// controls the tracker gets right
		`echo "$(echo \"x\" > x.sh)"; . ./x.sh; pip install zz-pkg`,
		"echo \"$(echo `cp ./e.sh x.sh`)\"; . ./x.sh; pip install zz-pkg",
		`echo "$(echo $((1+2)) ; cp ./e.sh x.sh)"; . ./x.sh; pip install zz-pkg`,
	} {
		cwd := t.TempDir()
		zzWrite(t, cwd, "e.sh", []byte("pip() { :; }\n"))
		why := reqFileHold(cwd, cwd, line, nil)
		tg, un, _, subst := installread.ParseLine(line)
		ex := installread.HookExtra(line, tg, un, subst)
		hold := why != "" || len(un) > 0 || len(ex) > 0
		t.Logf("hold=%-5v %-80q %q", hold, line, why)
		if !hold {
			t.Errorf("%q: silent", line)
		}
	}
}
