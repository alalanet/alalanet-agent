//go:build !windows

package filelock

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO is refused before it is opened: a writer waiting on it is never let through (an open for reading would
// release it).
func TestOpenRegularRefusesAFIFOBeforeOpening(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	opened := make(chan struct{})
	go func() {
		f, err := os.OpenFile(path, os.O_WRONLY, 0) // blocks until a reader opens the FIFO
		if err == nil {
			f.Close()
		}
		close(opened)
	}()
	time.Sleep(200 * time.Millisecond) // the writer is waiting in its open by now
	if f, _, err := OpenRegular(path); !errors.Is(err, ErrNotRegular) {
		if f != nil {
			f.Close()
		}
		t.Fatalf("a FIFO: %v", err)
	}
	select {
	case <-opened:
		t.Fatal("OpenRegular opened the FIFO")
	case <-time.After(200 * time.Millisecond):
	}
	if f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0); err == nil { // release the writer
		<-opened
		f.Close()
	}
}

// A device is refused; so is a FIFO swapped in between the check and the open (the second check, on the file opened).
func TestOpenRegularRefusesDevicesAndSwaps(t *testing.T) {
	if _, _, err := OpenRegular("/dev/null"); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("/dev/null: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	afterStat = func() {
		_ = os.Remove(path)
		_ = syscall.Mkfifo(path, 0o600)
	}
	defer func() { afterStat = nil }()
	if f, _, err := OpenRegular(path); !errors.Is(err, ErrNotRegular) {
		if f != nil {
			f.Close()
		}
		t.Fatalf("a FIFO swapped in after the check: %v", err)
	}
	afterStat = nil
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, fi, err := OpenRegular(path)
	if err != nil || fi.Size() != 2 {
		t.Fatalf("a regular file: %v", err)
	}
	f.Close()
}

// A lock is held against a second taker, broken when stale (old or far in the future), and kept when it is a live
// holder's whose clock reads it a few seconds ahead.
func TestLockStaleAndFuture(t *testing.T) {
	dir := t.TempDir()
	unlock, err := LockFor(dir, "l", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LockFor(dir, "l", 50*time.Millisecond); !errors.Is(err, ErrLocked) {
		t.Fatalf("a second taker: %v", err)
	}
	path := filepath.Join(dir, "l")
	ahead := time.Now().Add(5 * time.Second) // a clock a few seconds ahead: a live holder
	_ = os.Chtimes(path, ahead, ahead)
	if _, err := LockFor(dir, "l", 50*time.Millisecond); !errors.Is(err, ErrLocked) {
		t.Fatalf("a lock a few seconds ahead was broken: %v", err)
	}
	for _, at := range []time.Time{time.Now().Add(-time.Minute), time.Now().Add(time.Hour)} {
		_ = os.Chtimes(path, at, at)
		u, err := Lock(context.Background(), dir, "l", time.Second)
		if err != nil {
			t.Fatalf("a stale lock (%v) was not broken: %v", at, err)
		}
		u()
		if err := os.WriteFile(path, []byte("someone"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	unlock() // not its lock any more: left alone
	if _, err := os.Stat(path); err != nil {
		t.Fatal("unlock removed another holder's lock")
	}
}
