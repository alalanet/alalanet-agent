// Package filelock is alalanet-agent's lock file and its reading of local files (VERIFY-AUTO-1's MCP state,
// REPO-POL-NPMRC's startup-file pin): a lock with an owner token, broken when stale by one breaker at a time, and files
// read only when they are regular files, opened without blocking.
package filelock

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// ErrLocked: the lock is held by another alalanet-agent and was not let go within the wait.
var ErrLocked = errors.New("locked by another alalanet-agent")

// Lock takes the lock file name in dir, made 0700 (hooks of parallel tool calls run at once). The file holds a random
// token: unlock removes it only while the token is still its own. A lock older than ten seconds (an agent killed while
// holding it) or dated in the future (no live holder writes one) is broken, by one breaker at a time (breakStale). The
// wait ends with ctx or after maxWait.
func Lock(ctx context.Context, dir, name string, maxWait time.Duration) (func(), error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	_ = os.Chmod(dir, 0o700)
	path := filepath.Join(dir, name)
	token := randomToken()
	deadline := time.Now().Add(maxWait)
	for {
		if err := createWith(path, token); err == nil {
			return func() { RemoveIfOwn(path, token) }, nil
		} else if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		breakStale(path)
		if time.Now().After(deadline) || ctx.Err() != nil {
			return nil, ErrLocked
		}
		select {
		case <-ctx.Done():
			return nil, ErrLocked
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// LockFor is Lock for at most wait.
func LockFor(dir, name string, wait time.Duration) (func(), error) {
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	return Lock(ctx, dir, name, wait)
}

func randomToken() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// createWith creates path with content, failing when it exists.
func createWith(path, content string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = f.WriteString(content)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// RemoveIfOwn removes the lock file at path while it holds token: never another holder's lock, nor a file that is
// not a regular file (a FIFO there blocks no one).
func RemoveIfOwn(path, token string) {
	if !Regular(path) {
		return // not a lock this code wrote
	}
	f, _, err := OpenRegular(path)
	if err != nil {
		return
	}
	b, err := io.ReadAll(io.LimitReader(f, 64))
	f.Close()
	if err == nil && string(b) == token {
		_ = os.Remove(path)
	}
}

// afterStat: tests only, run between OpenRegular's check and its open.
var afterStat func()

// stale: a lock file no live holder keeps: older than ten seconds, or dated more than ten seconds in the future (a
// live holder's time read by a clock adjusted meanwhile stays within that; review r4, R4-4).
func stale(fi os.FileInfo) bool {
	age := time.Since(fi.ModTime())
	return age > 10*time.Second || age < -10*time.Second
}

// breakStale removes a stale lock at path. Breakers take a lock of their own first (path + ".break", itself broken
// when stale), and remove the lock only if it is still the stale one they saw (its time): a waiter that saw
// the stale lock never removes the lock another waiter took after breaking it (review F6).
func breakStale(path string) {
	fi, err := os.Stat(path)
	if err != nil || !stale(fi) {
		return
	}
	brk := path + ".break"
	token := randomToken()
	if createWith(brk, token) != nil {
		if bi, err := os.Stat(brk); err == nil && stale(bi) {
			_ = os.Remove(brk) // a breaker killed while breaking; the next round breaks the lock
		}
		return
	}
	defer RemoveIfOwn(brk, token)
	// Still the stale file seen: a lock taken since is new, so not stale and of another time.
	if now, err := os.Stat(path); err == nil && stale(now) && now.ModTime().Equal(fi.ModTime()) {
		_ = os.Remove(path)
	}
}

// ErrNotRegular: a path alalanet-agent reads is not a regular file (a FIFO, a device, a folder): it is not read, so it can
// neither block the check nor feed it without end (review r3, P3-1 and P3-3).
var ErrNotRegular = errors.New("not a regular file")

// OpenRegular opens path for reading when it is a regular file (a link is followed to one), without blocking: the
// open is non-blocking, and the file opened is checked again, so a FIFO swapped in between is not read either.
func OpenRegular(path string) (*os.File, os.FileInfo, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, nil, ErrNotRegular
	}
	if afterStat != nil {
		afterStat()
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	if fi, err = f.Stat(); err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, nil, ErrNotRegular
	}
	return f, fi, nil
}

// Regular: path itself (not a link) is a regular file.
func Regular(path string) bool {
	fi, err := os.Lstat(path)
	return err == nil && fi.Mode().IsRegular()
}
