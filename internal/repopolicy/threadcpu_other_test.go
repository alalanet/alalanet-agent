//go:build !linux

package repopolicy

import "time"

// threadCPU runs f; a thread's own CPU time (getrusage RUSAGE_THREAD) is Linux's alone, so it measures nothing here.
func threadCPU(f func()) (time.Duration, bool) {
	f()
	return 0, false
}

// threadCPUWhy is why threadCPU cannot measure here.
const threadCPUWhy = "a thread's own CPU time (getrusage RUSAGE_THREAD) is Linux's alone; CI and make run the tests in the pinned Linux image"

// quietCPU runs f rounds times through threadCPU; it measures nothing here.
func quietCPU(rounds int, f func()) (time.Duration, bool) {
	for i := 0; i < rounds; i++ {
		_, _ = threadCPU(f)
	}
	return 0, false
}
