// Package safe runs goroutines that must not take the process down. Most of alalanetd's goroutines
// read third-party data (MCP servers, registries, chain nodes, webhooks); a panic on one bad answer
// used to end the whole process, and with it every check, payment and hook answer (ADR-0082, WP1).
package safe

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"
)

// loops counts the running Loop and Go goroutines, so a shutdown can let them finish before the store
// closes (deep review OPS-10: "database is closed" and an unsigned transition at every deploy). It is
// not a sync.WaitGroup: a Wait that timed out leaves its waiter behind, and a later Add from zero
// would then break the WaitGroup's reuse rule (the race detector reports it).
var loops tracker

type tracker struct {
	mu   sync.Mutex
	n    int
	zero chan struct{} // closed when n falls to 0; a new one on every rise from 0
}

func (t *tracker) add() {
	t.mu.Lock()
	if t.n == 0 {
		t.zero = make(chan struct{})
	}
	t.n++
	t.mu.Unlock()
}

func (t *tracker) done() {
	t.mu.Lock()
	t.n--
	if t.n == 0 {
		close(t.zero)
	}
	t.mu.Unlock()
}

// Track counts work its caller runs itself (a live check inside a request that can outlast the HTTP
// drain) in Wait, as Go counts its goroutine. Call the returned func, once or more, when it ends.
func Track() func() {
	loops.add()
	var once sync.Once
	return func() { once.Do(loops.done) }
}

// Wait waits up to d for every Loop and Go goroutine to return (loops return when their context
// ends, detached work when Stop is called) and reports whether they all did.
func Wait(d time.Duration) bool {
	loops.mu.Lock()
	if loops.n == 0 {
		loops.mu.Unlock()
		return true
	}
	zero := loops.zero
	loops.mu.Unlock()
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-zero:
		return true
	case <-timer.C:
		return false
	}
}

// ErrStopping is the cause of a Detach context that Stop ended.
var ErrStopping = errors.New("service stopping")

// The live Detach contexts, so Stop ends each of them before it returns (an AfterFunc would end them
// a moment later, on goroutines of its own).
var (
	stopMu  sync.Mutex
	stopped bool
	live    = map[*context.CancelCauseFunc]bool{}
)

// Detach returns a context with ctx's values that outlives ctx's cancel (work shared by several
// callers, such as one install check, must not end when its first caller leaves) but ends at Stop,
// so a shutdown does not wait out its whole budget (round 3, R3-CODE-15).
func Detach(ctx context.Context) (context.Context, context.CancelFunc) {
	c, cancel := context.WithCancelCause(context.WithoutCancel(ctx))
	key := &cancel
	stopMu.Lock()
	if stopped {
		stopMu.Unlock()
		cancel(ErrStopping)
		return c, func() { cancel(context.Canceled) }
	}
	live[key] = true
	stopMu.Unlock()
	return c, func() {
		stopMu.Lock()
		delete(live, key)
		stopMu.Unlock()
		cancel(context.Canceled)
	}
}

// Stop ends every Detach context, now and later; when it returns, each has ended. Shutdown calls it
// after the HTTP drain and before Wait.
func Stop() {
	stopMu.Lock()
	stopped = true
	ended := live
	live = map[*context.CancelCauseFunc]bool{}
	stopMu.Unlock()
	for c := range ended {
		(*c)(ErrStopping)
	}
}

// Stopped reports whether ctx ended because the service is stopping: work cut short then is not a
// result to sign or keep.
func Stopped(ctx context.Context) bool { return errors.Is(context.Cause(ctx), ErrStopping) }

// RestartDelay is how long a supervised loop waits after a panic before it starts again.
var RestartDelay = 30 * time.Second

// Recover logs a panic with its stack; use as `defer safe.Recover(log, "where")`.
func Recover(log *slog.Logger, where string) {
	if r := recover(); r != nil {
		logPanic(log, where, r)
	}
}

func logPanic(log *slog.Logger, where string, r any) {
	Caught(where, r)
	if log == nil {
		log = slog.Default()
	}
	log.Error("panic recovered", "where", where, "panic", printed(r), "stack", string(debug.Stack()))
}

// cannotPrint stands for a recovered value that panics again while it is printed.
const cannotPrint = "a value that cannot be printed"

// printed is fmt.Sprint(r) for a recovered value r, or cannotPrint when printing it panics: fmt prints
// a String or Error method that panics as "%!v(PANIC=…)", but panics itself when that panic's value
// panics too, and a panic out of a recovery takes the answer, or the process, with it (the review of
// TEST-NIL-1, P3-1).
func printed(r any) (s string) {
	defer func() {
		if recover() != nil {
			s = cannotPrint
		}
	}()
	return fmt.Sprint(r)
}

// recovered counts the panics recovered since the process started, by Recover, Go and Loop and by the
// handlers that recover on their own (Caught), and keeps where the last one was and what it said. The
// service goes on past them; a test must not (TEST-NIL-1): a nil Checker's panic under parallelEach
// was only a log line, and go test shows a passing package's log to nobody. internal/safe/safetest
// fails the tests on them.
var recovered struct {
	mu   sync.Mutex
	n    int64
	last string
}

// Caught counts a panic recovered at where, with the value recover returned: Recover, Go and Loop count
// theirs; a handler that recovers on its own (the HTTP middleware, an MCP tool, the install hook's
// targets) calls it. It counts first, then prints the value without letting a panic out (printed): its
// caller still has its answer to write.
func Caught(where string, r any) {
	recovered.mu.Lock()
	recovered.n++
	recovered.mu.Unlock()
	last := where + ": " + printed(r)
	recovered.mu.Lock()
	recovered.last = last
	recovered.mu.Unlock()
}

// Recovered reports how many panics were recovered since the process started, and the last one's
// place and value.
func Recovered() (n int64, last string) {
	recovered.mu.Lock()
	defer recovered.mu.Unlock()
	return recovered.n, recovered.last
}

// Go runs f on a new goroutine; a panic is logged and ends only that goroutine. Wait waits for it as
// for the loops: an install check shared by callers runs past any one caller's context and must not
// sign or write after the log and the store close (round 3, R3-CODE-15).
func Go(log *slog.Logger, where string, f func()) {
	loops.add()
	go func() {
		defer loops.done()
		defer Recover(log, where)
		f()
	}()
}

// Loop runs a background loop on a new goroutine. If it panics, the panic is logged and the loop
// starts again after RestartDelay; if it returns, it is done.
func Loop(ctx context.Context, log *slog.Logger, where string, run func(context.Context)) {
	loops.add()
	go func() {
		defer loops.done()
		for {
			panicked := func() (p bool) {
				defer func() {
					if r := recover(); r != nil {
						logPanic(log, where, r)
						p = true
					}
				}()
				run(ctx)
				return false
			}()
			if !panicked || ctx.Err() != nil {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(RestartDelay):
			}
		}
	}()
}
