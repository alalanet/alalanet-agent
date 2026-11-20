//go:build linux

package costtest

import (
	"runtime"
	"syscall"
	"time"
)

// rusageThread is RUSAGE_THREAD: getrusage of the calling thread alone (Linux 2.6.26 and later).
const rusageThread = 1

// threadCPU runs f on one OS thread, locked to it, and returns the CPU time (user and system) that thread spent, and
// whether the kernel counted it; when it did not, the wall time.
func threadCPU(f func()) (time.Duration, bool) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var before, after syscall.Rusage
	start := time.Now()
	if syscall.Getrusage(rusageThread, &before) != nil {
		f()
		return time.Since(start), false
	}
	f()
	if syscall.Getrusage(rusageThread, &after) != nil {
		return time.Since(start), false
	}
	used := func(r syscall.Rusage) int64 { return r.Utime.Nano() + r.Stime.Nano() }
	return time.Duration(used(after) - used(before)), true
}
