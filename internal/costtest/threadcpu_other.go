//go:build !linux

package costtest

import "time"

// threadCPU runs f and returns its wall time: a thread's own CPU time (CLOCK_THREAD_CPUTIME_ID) is read on Linux alone; make
// ci runs the cost lines in the pinned Linux image.
func threadCPU(f func()) (time.Duration, bool) {
	start := time.Now()
	f()
	return time.Since(start), false
}
