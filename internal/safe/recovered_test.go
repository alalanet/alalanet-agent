package safe

import (
	"log/slog"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// unprintable's String panics with its inner value; with an inner value of the same kind fmt panics
// again while it prints the first panic.
type unprintable struct{ inner any }

func (u unprintable) String() string { panic(u.inner) }

// endsTheGoroutine's String ends its goroutine (runtime.Goexit), which no recover stops.
type endsTheGoroutine struct{}

func (endsTheGoroutine) String() string {
	runtime.Goexit()
	return "never"
}

// Caught counts before it prints the value (the review of TEST-NIL-1, P3-1): a value whose printing
// does not come back is counted all the same.
func TestCaughtCountsBeforeItPrints(t *testing.T) {
	n0, _ := Recovered()
	done := make(chan struct{})
	go func() {
		defer close(done)
		Caught("t", endsTheGoroutine{})
	}()
	<-done
	if n, _ := Recovered(); n != n0+1 {
		t.Fatalf("counted %d; want the panic counted before its value is printed", n-n0)
	}
}

type lockedLog struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedLog) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// A recovered value that cannot be printed is counted, logged with a fixed text and goes no further
// (the review of TEST-NIL-1, P3-1). Caught printed it with fmt before it counted, and logPanic printed
// it with fmt too: fmt panicked again inside the recovery, the second panic left Recover, and on a
// goroutine of Go or Loop it ended the process.
func TestARecoveredValueThatCannotBePrintedIsCountedAndLogged(t *testing.T) {
	for _, c := range []struct {
		name    string
		recover func(log *slog.Logger, v any)
	}{
		{"Recover", func(log *slog.Logger, v any) {
			defer Recover(log, "t")
			panic(v)
		}},
		{"Caught", func(log *slog.Logger, v any) {
			defer func() {
				if r := recover(); r != nil {
					Caught("t", r)
					log.Error("panic", "panic", r) // as the HTTP middleware logs it
				}
			}()
			panic(v)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			var buf lockedLog
			log := slog.New(slog.NewTextHandler(&buf, nil))
			n0, _ := Recovered()
			var escaped any
			func() {
				defer func() { escaped = recover() }()
				c.recover(log, unprintable{inner: unprintable{inner: "inner"}})
			}()
			n, last := Recovered()
			if escaped != nil || n != n0+1 || last != "t: a value that cannot be printed" || !strings.Contains(buf.String(), "level=ERROR") {
				t.Fatalf("escaped %v, counted %d, last %q, log %q; want one counted with the fixed text and the log line", escaped, n-n0, last, buf.String())
			}
		})
	}
}
