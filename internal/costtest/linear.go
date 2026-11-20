package costtest

import (
	"time"
)

// Linear and Against are COST-WALLCLOCK-1's measures: bounds a loaded host does not fail and a quadratic reading still
// does. Best's least of interleaved rounds was not enough under load (make ci at load ~30: "1 MiB 150 ms against
// 256 KiB 14 ms: not linear"; the reader's "second reader against the first plus 1 s"): a short run finds a quiet
// stretch of the host far more often than a run ten times longer. So both sides of a bound here do the same amount of
// work and last about as long — the small input is run Scale times in each of its measurements — and the host's load,
// whatever it is, slows both: a test thread given an eighth of a core (containers at half a CPU with three CPU or
// memory burners, throttled in 100 ms periods) kept the linear ratios at 0.47-1.26, as on an idle host, and the race
// detector's at most 1.78 (2026-11-19, work-1119/cost-wallclock/stress), while a reading quadratic in its input gives
// Scale.

// Scale is how many times smaller Linear's small input is than its big one (and how many times it runs per
// measurement); Bound is the ratio of the big input's cost to the small one's Scale runs that a linear reading stays
// under: more than twice the largest ratio measured idle or loaded. A reading whose cost at the big size is about four
// times its linear cost or more fails it; the quadratic regressions these tests were written for cost 50-150 times
// (P2-2's long folder, PIPE-SCRIPT's "| sh", P2-4's substitutions).
const (
	Scale = 64
	Bound = 4
)

// Linear measures big (the shape at its full size) against small (the same shape at 1/k of it) run k times, both
// measured as Best measures them (interleaved, the least of rounds, the thread's own CPU time where the kernel counts
// it), and returns the ratio of the costs and the costs themselves (small's for its k runs together).
func Linear(rounds, k int, big, small func()) (ratio float64, dBig, dSmall time.Duration) {
	if k < 1 {
		k = 1
	}
	d, _ := Best(rounds, big, func() {
		for range k {
			small()
		}
	})
	return ratioOf(d[0], d[1]), d[0], d[1]
}

// Against measures f and ref interleaved as Best does and returns the ratio of f's cost to ref's, and both costs: an
// absolute bound in the host's own units, so that a host ten times slower is no failure and a reading that became
// slow on any host is (ref is work of a known cost on the same input: Scan).
func Against(rounds int, f, ref func()) (ratio float64, df, dref time.Duration) {
	d, _ := Best(rounds, f, ref)
	return ratioOf(d[0], d[1]), d[0], d[1]
}

func ratioOf(a, b time.Duration) float64 {
	if b <= 0 {
		b = 1
	}
	return float64(a) / float64(b)
}

// Sink keeps Scan's result from being optimised away.
var Sink uint64

// Scan is the reference work of Against: one pass over s that reads every byte (FNV-1a), linear and with no allocation,
// as a reader's own pass over its input is at the least.
func Scan(s string) {
	h := uint64(14695981039346656037)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	Sink += h
}

// Matched is Against with the sides of equal length: ref runs as many times in each of its measurements as it takes
// to last about as long as f (from one unmeasured run of each), so a loaded host does not favour the shorter side, and
// the ratio is f's cost to one run of ref. For a bound whose reference is much shorter than the work it bounds (a
// query against a scan of its table).
func Matched(rounds int, f, ref func()) (ratio float64, df, dref time.Duration) {
	reps := 1
	if tf, tr := wallOnce(f), wallOnce(ref); tr > 0 && tf > tr {
		reps = int(min(int64(tf/tr), 1<<20))
	}
	d, _ := Best(rounds, f, func() {
		for range reps {
			ref()
		}
	})
	dref = d[1] / time.Duration(reps)
	return ratioOf(d[0], dref), d[0], dref
}

func wallOnce(f func()) time.Duration {
	start := time.Now()
	f()
	return time.Since(start)
}
