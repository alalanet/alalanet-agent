// Package safetest fails the tests on a panic the service recovered from (TEST-NIL-1, ADR-0165). The
// service goes on past a panic — safe.Recover, Go and Loop, the HTTP middleware, the MCP tools, the
// install hook's targets — and only a log line shows it; go test shows a passing package's output to
// nobody, so a test whose code hit a nil pointer under parallelEach passed. It is for tests only:
// nothing in the service imports it.
package safetest

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alalanet/alalanet-agent/internal/safe"
)

// expected counts the panics the tests made on purpose (Expect).
var expected atomic.Int64

// checked holds the tests Check already watches: a test that calls a checking helper twice is told once.
var checked sync.Map

// Main runs a package's tests and fails the run when a panic was recovered that no test made on
// purpose: func TestMain(m *testing.M) { safetest.Main(m) }. A package whose code recovers from panics
// has it, or Run (TestEveryPackageThatRecoversFailsOnAPanic).
func Main(m *testing.M) { os.Exit(Run(m)) }

// Run is Main for a TestMain that does more than run the tests (a child process it plays, as tlog's and
// alalanet-agent's do): it runs them and returns the exit code, 1 when a panic was recovered that no
// test made on purpose. Use as os.Exit(safetest.Run(m)).
func Run(m *testing.M) int {
	code := m.Run()
	if n, last := safe.Recovered(); n > expected.Load() {
		fmt.Fprintf(os.Stderr, "FAIL: %d panics were recovered while the tests ran, %d of them made on purpose (safetest.Expect); the last: %s\n",
			n, expected.Load(), last)
		if code == 0 {
			code = 1
		}
	}
	return code
}

// Check fails t when a panic that no Expect made is recovered between this call and t's end. A helper
// that builds what tests run calls it, so the failure names the test (repoTestApp); Main still catches
// what no helper does.
func Check(t testing.TB) {
	t.Helper()
	if _, dup := checked.LoadOrStore(t, true); dup {
		return
	}
	n0, _ := safe.Recovered()
	e0 := expected.Load()
	t.Cleanup(func() {
		t.Helper() // the failure names the test's line that called the helper
		checked.Delete(t)
		n, last := safe.Recovered()
		if extra := n - n0 - (expected.Load() - e0); extra > 0 {
			t.Errorf("%d panics were recovered while the test ran (the last: %s): the service goes on past them, a test must not", extra, last)
		}
	})
}

// Expect runs f, which makes exactly n panics that are recovered on purpose (a test of the recovery
// itself), and waits up to 10 s until n are counted: a recovery can be counted after f returns (a
// proof's, which closes its callers' wait first). Up to n of the panics counted by then are taken as
// made on purpose and fail neither Check nor Main; fewer than n fail t, and so do more (the review of
// TEST-NIL-1, P3-4: an extra one in a test of the recovery passed as one of its own) — Main and Check
// then count the extra ones as no one's, as they do one that comes after the wait.
func Expect(t testing.TB, n int64, f func()) {
	t.Helper()
	n0, _ := safe.Recovered()
	f()
	var got int64
	for end := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
		cur, _ := safe.Recovered()
		if got = cur - n0; got >= n || time.Now().After(end) {
			break
		}
	}
	expected.Add(min(got, n))
	if got != n {
		t.Errorf("%d panics were recovered, want %d", got, n)
	}
}
