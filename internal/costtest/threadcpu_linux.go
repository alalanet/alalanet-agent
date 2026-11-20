//go:build linux

package costtest

import (
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

// threadCPU runs f on one OS thread, locked to it, and returns the CPU time that thread spent, and whether the kernel
// counted it; when it did not, the wall time. The clock is CLOCK_THREAD_CPUTIME_ID, which the kernel brings up to date
// when it is read (COST-WALLCLOCK-1): getrusage(RUSAGE_THREAD), used before, reads the thread's runtime as of its last
// scheduler tick, so a run shorter than a tick measured 0 or one tick — under load, Against's 62 us pass over 64 KiB
// read as 0 s and TestUnseenCost's bound as two million passes.
func threadCPU(f func()) (time.Duration, bool) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var before, after unix.Timespec
	start := time.Now()
	if unix.ClockGettime(unix.CLOCK_THREAD_CPUTIME_ID, &before) != nil {
		f()
		return time.Since(start), false
	}
	f()
	if unix.ClockGettime(unix.CLOCK_THREAD_CPUTIME_ID, &after) != nil {
		return time.Since(start), false
	}
	return time.Duration(after.Nano() - before.Nano()), true
}
