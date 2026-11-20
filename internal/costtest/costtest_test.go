package costtest

import (
	"math"
	"runtime"
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

var linearSink int

// Linear tells a quadratic cost from a linear one by Bound (COST-WALLCLOCK-1): a loop over n gives a ratio near 1, a loop
// over n squared gives Scale. Against gives the ratio to a reference on the same input: Scan against itself, near 1.
func TestLinearTellsQuadraticFromLinear(t *testing.T) {
	work := func(n int) {
		s := 0
		for i := 0; i < n; i++ {
			s += i ^ (s >> 3)
		}
		linearSink += s
	}
	n := 1 << 22
	lin, db, ds := Linear(3, Scale, func() { work(n) }, func() { work(n / Scale) })
	if lin > Bound {
		t.Errorf("a linear loop: %v against %v (x%.1f), over the bound x%d", db, ds, lin, Bound)
	}
	q := 1 << 12
	quad, db, ds := Linear(3, Scale, func() { work(q * q) }, func() { work(q * q / Scale / Scale) })
	if quad <= Bound {
		t.Errorf("a quadratic loop: %v against %v (x%.1f), within the bound x%d", db, ds, quad, Bound)
	}
	s := string(make([]byte, 1<<20))
	if r, a, b := Against(3, func() { Scan(s) }, func() { Scan(s) }); r > 2 || r < 0.5 {
		t.Errorf("Scan against itself: %v and %v (x%.2f)", a, b, r)
	}
	t.Logf("linear x%.2f, quadratic x%.1f", lin, quad)
}

// Matched gives the ratio to one run of a much shorter reference, the sides measured at about the same length.
func TestMatchedRatioToAShortReference(t *testing.T) {
	work := func(n int) {
		s := 0
		for i := 0; i < n; i++ {
			s += i ^ (s >> 3)
		}
		linearSink += s
	}
	r, df, dref := Matched(3, func() { work(1 << 24) }, func() { work(1 << 14) })
	if r < 500 || r > 2000 { // 1024 by the work
		t.Errorf("ratio x%.0f (%v against %v a run), want about 1024", r, df, dref)
	}
}

var allocSink []byte

// A reading that allocates quadratically fails Linear's bound instead of taking the machine's memory (re-review P2-1):
// with MemoryLimit lowered to 256 MiB, a big run that allocates about 2 GiB of garbage keeps the heap near the limit,
// and the ratio still says quadratic.
func TestBestBoundsAQuadraticAllocation(t *testing.T) {
	defer func(l int64) { MemoryLimit = l }(MemoryLimit)
	MemoryLimit = 256 << 20
	alloc := func(n int) { // n(n-1)/2 * 64 bytes
		for i := 0; i < n; i++ {
			allocSink = make([]byte, i*64)
		}
	}
	n := 8192 // about 2 GiB at the big size
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	ratio, db, ds := Linear(1, Scale, func() { alloc(n) }, func() { alloc(n / Scale) })
	runtime.ReadMemStats(&after)
	grew := int64(after.HeapSys) - int64(before.HeapSys)
	t.Logf("quadratic allocation: %v against %v (x%.1f); the heap grew %d MiB", db, ds, ratio, grew>>20)
	if ratio <= Bound {
		t.Errorf("a quadratic allocation: x%.1f, within the bound x%d", ratio, Bound)
	}
	if grew > 1<<30 {
		t.Errorf("the heap grew %d MiB for a limit of %d MiB: the collector did not run at the limit", grew>>20, MemoryLimit>>20)
	}
	if p := debug.SetMemoryLimit(-1); p != math.MaxInt64 {
		t.Errorf("the memory limit left at %d after Best", p)
	}
}
