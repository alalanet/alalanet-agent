//go:build linux

package repopolicy

import (
	"runtime"
	"runtime/debug"
	"syscall"
	"time"
)

// rusageThread is RUSAGE_THREAD: getrusage of the calling thread alone (Linux 2.6.26 and later).
const rusageThread = 1

// threadCPU runs f on one OS thread, locked to it, and returns the CPU time, user and system, that thread spent:
// time the thread did not run — the machine's load — is not in it, unlike the wall clock, and work that allocates
// nothing is, unlike the allocation counters (flakes-5, review 1116 P3-2). ok is false when the kernel refuses
// RUSAGE_THREAD.
func threadCPU(f func()) (cpu time.Duration, ok bool) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var before, after syscall.Rusage
	if syscall.Getrusage(rusageThread, &before) != nil {
		f()
		return 0, false
	}
	f()
	if syscall.Getrusage(rusageThread, &after) != nil {
		return 0, false
	}
	used := func(r syscall.Rusage) int64 { return r.Utime.Nano() + r.Stime.Nano() }
	return time.Duration(used(after) - used(before)), true
}

// threadCPUWhy is why threadCPU cannot measure here ("" where it can).
const threadCPUWhy = ""

// quietCPU is the least threadCPU of f over rounds runs with the collector off (runtime.GC first, then GOGC off until
// the runs end): a collection's assists grow with the live heap, faster than the work of an allocation-heavy read,
// and the least of several runs leaves out the time a busy host took the virtual CPU away, which the guest counts as
// the thread's (flakes-5).
func quietCPU(rounds int, f func()) (time.Duration, bool) {
	runtime.GC()
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	best, ok := time.Duration(-1), true
	for i := 0; i < rounds; i++ {
		d, measured := threadCPU(f)
		ok = ok && measured
		if best < 0 || d < best {
			best = d
		}
	}
	return best, ok
}
