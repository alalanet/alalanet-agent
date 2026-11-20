// Package costtest measures what the cost tests bound (make ci's -run 'Bounded|Cost' lines) so that a busy host does
// not fail them (COST-TEST-LOAD-1: make ci on e21063ec, the Mac at load ~30, failed two of them while the race suite
// passed). Only test files import it.
//
// Each case is the least of several runs, and the sides of a bound (the exact reading against develop's, 1 MiB
// against 256 KiB) are measured interleaved in the same rounds, so a busy stretch slows a side's one run, not all of
// them, and both sides see the same host. Where the kernel counts it (Linux, getrusage RUSAGE_THREAD), the cost is the
// measuring thread's own CPU time: time the scheduler gave other processes is not in it. The collector runs before the
// rounds and is off during them: one side does not pay for the other's garbage.
package costtest

import (
	"os"
	"runtime"
	"runtime/debug"
	"time"
)

// Rounds is how many times Best runs each function unless told otherwise.
const Rounds = 3

// Best runs fs rounds times, interleaved (fs[0], fs[1], …, then again), and returns the least cost of each, and
// whether the costs are thread CPU time (true) or wall time (false: the kernel does not count a thread's own CPU here).
// Each f must do its work on the calling goroutine.
func Best(rounds int, fs ...func()) ([]time.Duration, bool) {
	if rounds < 1 {
		rounds = 1
	}
	runtime.GC()
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	best := make([]time.Duration, len(fs))
	measure := threadCPU
	if os.Getenv("COSTTEST_WALL") == "1" { // the proof of the rounds alone (COST-TEST-LOAD-1): wall time everywhere
		measure = wallTime
	}
	cpu := true
	for r := 0; r < rounds; r++ {
		for i, f := range fs {
			d, ok := measure(f)
			cpu = cpu && ok
			if r == 0 || d < best[i] {
				best[i] = d
			}
		}
	}
	return best, cpu
}

// One is Best of a single function.
func One(rounds int, f func()) time.Duration {
	d, _ := Best(rounds, f)
	return d[0]
}

// Wall runs fs rounds times, interleaved, and returns the least wall time of each: for work that is not on the calling
// goroutine alone (a database, a server, goroutines) or whose bound is a deadline of the code under test.
func Wall(rounds int, fs ...func()) []time.Duration {
	if rounds < 1 {
		rounds = 1
	}
	best := make([]time.Duration, len(fs))
	for r := 0; r < rounds; r++ {
		for i, f := range fs {
			start := time.Now()
			f()
			if d := time.Since(start); r == 0 || d < best[i] {
				best[i] = d
			}
		}
	}
	return best
}

// wallTime runs f and returns its wall time (not thread CPU time).
func wallTime(f func()) (time.Duration, bool) {
	start := time.Now()
	f()
	return time.Since(start), false
}
