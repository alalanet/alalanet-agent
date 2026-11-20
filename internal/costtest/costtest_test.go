package costtest

import (
	"runtime/debug"
	"slices"
	"strings"
	"testing"
	"time"
)

// Best runs the functions interleaved, round by round, and keeps each one's least cost; the collector is off while it
// measures and back as it was after.
func TestBestInterleavesAndKeepsTheLeast(t *testing.T) {
	var order []string
	spin := func(d time.Duration) {
		for start := time.Now(); time.Since(start) < d; {
		}
	}
	gcDuring := 0
	runs := 0
	d, _ := Best(3, func() {
		order = append(order, "a")
		if debug.SetGCPercent(-1) == -1 {
			gcDuring++
		}
		runs++
		spin(map[int]time.Duration{1: 30 * time.Millisecond, 2: 2 * time.Millisecond, 3: 10 * time.Millisecond}[runs])
	}, func() { order = append(order, "b"); spin(5 * time.Millisecond) })
	if got := strings.Join(order, ""); got != "ababab" {
		t.Fatalf("order %q, want ababab", got)
	}
	if gcDuring != 3 {
		t.Errorf("the collector was on in %d of 3 runs", 3-gcDuring)
	}
	// The spins are wall-clock long: the thread's CPU time of one is at most its length (less when the thread lost the
	// CPU in it), so the least is the short run's, not the 30 ms or the 10 ms one.
	if d[0] <= 0 || d[0] > 9*time.Millisecond {
		t.Errorf("a's least %v, want its 2 ms run (not the 30 ms or 10 ms one)", d[0])
	}
	if d[1] <= 0 || d[1] > 25*time.Millisecond {
		t.Errorf("b's least %v", d[1])
	}
	if p := debug.SetGCPercent(100); p == -1 {
		t.Error("the collector left off after Best")
	}
	if One(0, func() {}) < 0 {
		t.Error("One with no rounds")
	}
	w := Wall(2, func() { spin(3 * time.Millisecond) })
	if len(w) != 1 || w[0] < 3*time.Millisecond {
		t.Errorf("Wall %v", w)
	}
}

// The mechanism of COST-TEST-LOAD-1: a side whose runs the host stalls (here a sleep in four of five runs: wall time
// the thread does not run) fails a bound when each side is measured on its own as the median of its runs (the cost
// tests before), and passes when the sides are measured in the same rounds as their least: thread CPU leaves the
// stall out, and wall time (COSTTEST_WALL=1) keeps the one run it missed.
func TestBestOutlastsAStalledSide(t *testing.T) {
	spin := func(d time.Duration) {
		for start := time.Now(); time.Since(start) < d; {
		}
	}
	runs := 0
	develop := func() { spin(5 * time.Millisecond) }
	exact := func() {
		runs++
		if runs%5 != 0 { // the host's busy stretch: four of every five runs stalled
			time.Sleep(60 * time.Millisecond)
		}
		spin(6 * time.Millisecond)
	}
	bound := func(dev time.Duration) time.Duration { return 2*dev + 20*time.Millisecond }
	median := func(f func()) time.Duration {
		ds := make([]time.Duration, 5)
		for i := range ds {
			start := time.Now()
			f()
			ds[i] = time.Since(start)
		}
		slices.Sort(ds)
		return ds[len(ds)/2]
	}
	if dev, ex := median(develop), median(exact); ex <= bound(dev) {
		t.Fatalf("the median of each side alone passed a stalled side (%v against %v): the fixture does not stall", ex, dev)
	}
	runs = 0
	d, _ := Best(5, develop, exact)
	if d[1] > bound(d[0]) {
		t.Fatalf("interleaved, the least: %v against %v, bound %v", d[1], d[0], bound(d[0]))
	}
	t.Setenv("COSTTEST_WALL", "1")
	runs = 0
	d, cpu := Best(5, develop, exact)
	if cpu || d[1] > bound(d[0]) {
		t.Fatalf("interleaved, the least wall time: %v against %v, bound %v (cpu %v)", d[1], d[0], bound(d[0]), cpu)
	}
}
