//go:build !linux

package costtest

import "time"

// threadCPU runs f and returns its wall time: a thread's own CPU time (getrusage RUSAGE_THREAD) is Linux's alone; make
// ci runs the cost lines in the pinned Linux image.
func threadCPU(f func()) (time.Duration, bool) {
	start := time.Now()
	f()
	return time.Since(start), false
}
