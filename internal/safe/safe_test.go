package safe

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

func TestGoRecovers(t *testing.T) {
	done := make(chan struct{})
	Go(slog.New(slog.NewTextHandler(io.Discard, nil)), "t", func() {
		defer close(done)
		var m map[string]int
		//lint:ignore SA5000 the panic is what this test recovers from
		m["x"] = 1 // panics
	})
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("goroutine did not finish")
	}
}

func TestLoopRestartsAfterPanicOnly(t *testing.T) {
	RestartDelay = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var runs atomic.Int32
	finished := make(chan struct{})
	Loop(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), "t", func(context.Context) {
		if runs.Add(1) < 3 {
			panic("boom")
		}
		close(finished) // the third run returns normally: no more restarts
	})
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatalf("loop not restarted: %d runs", runs.Load())
	}
	time.Sleep(50 * time.Millisecond)
	if n := runs.Load(); n != 3 {
		t.Fatalf("runs after a normal return: %d", n)
	}
}

// OPS-10: Wait returns once every loop has returned after its context ended.
func TestWaitForLoops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	Loop(ctx, nil, "w", func(ctx context.Context) {
		<-ctx.Done()
		time.Sleep(50 * time.Millisecond) // finishing work, e.g. a last flush
		close(stopped)
	})
	if Wait(20 * time.Millisecond) {
		t.Fatal("Wait returned while a loop ran")
	}
	cancel()
	if !Wait(2 * time.Second) {
		t.Fatal("Wait timed out after the loop ended")
	}
	select {
	case <-stopped:
	default:
		t.Fatal("Wait returned before the loop finished")
	}
}

// R3-CODE-15: a goroutine started with Go (an install check shared by callers, run past any one
// caller's context) is waited for too, so it does not sign or write after the log and store close.
func TestWaitForGo(t *testing.T) {
	done := make(chan struct{})
	Go(nil, "flight", func() {
		time.Sleep(80 * time.Millisecond)
		close(done)
	})
	if Wait(20 * time.Millisecond) {
		t.Fatal("Wait returned while a Go goroutine ran")
	}
	if !Wait(2 * time.Second) {
		t.Fatal("Wait timed out after the goroutine ended")
	}
	select {
	case <-done:
	default:
		t.Fatal("Wait returned before the goroutine finished")
	}
}

// R3-CODE-15: work detached from its caller ends at Stop, with ErrStopping as its cause; a budget
// that ends is not a stop. Wait counts Track and Go work, and a Wait that timed out leaves nothing
// that breaks a later Wait (the WaitGroup it replaced did, under the race detector).
func TestDetachTrackStop(t *testing.T) {
	type key struct{}
	defer func() { stopMu.Lock(); stopped = false; stopMu.Unlock() }()
	parent, cancelParent := context.WithCancel(context.WithValue(context.Background(), key{}, "v"))
	d, cancel := Detach(parent)
	defer cancel()
	cancelParent()
	if d.Err() != nil || d.Value(key{}) != "v" || Stopped(d) {
		t.Fatalf("detached work ended with its caller or lost its values: %v", d.Err())
	}
	b, cancelB := context.WithTimeout(d, time.Millisecond)
	<-b.Done()
	cancelB()
	if Stopped(b) {
		t.Fatal("a budget that ended counted as a stop")
	}

	end := Track()
	if Wait(10 * time.Millisecond) {
		t.Fatal("Wait returned while tracked work ran")
	}
	end()
	end() // a second call is harmless
	if !Wait(time.Second) {
		t.Fatal("Wait timed out after the tracked work ended")
	}

	flight := make(chan struct{})
	Go(nil, "flight", func() {
		w, cw := context.WithTimeout(d, time.Minute) // a budget under the detached context
		defer cw()
		<-w.Done()
		if !Stopped(w) {
			t.Error("the budget under a stopped context does not report the stop")
		}
		close(flight)
	})
	if Wait(10 * time.Millisecond) {
		t.Fatal("Wait returned while detached work ran")
	}
	Stop()
	if !Stopped(d) {
		t.Fatal("Stop returned before the detached context ended")
	}
	if !Wait(2 * time.Second) {
		t.Fatal("detached work did not end at Stop")
	}
	<-flight
	if !Stopped(d) {
		t.Fatalf("cause after Stop: %v", context.Cause(d))
	}
	later, cl := Detach(context.Background()) // started after Stop: ends at once, not a moment later
	defer cl()
	if !Stopped(later) {
		t.Fatal("work detached after Stop is live")
	}
}
