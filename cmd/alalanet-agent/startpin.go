package main

// REPO-POL-NPMRC round 8 (ADR-0174 round 13): the shell startup files are pinned, not only read. A startup file is
// code the shell runs before the line: a function named like a command an activate template runs (hash, echo), a PATH
// that puts another pip first, a BASH_SOURCE the relocatable template trusts — no reading of its lines can tell all
// of what it does. So, on the exception path, the hook keeps a pin of the startup files it reads (startupList): each
// path's sha256, or "absent". The first time there is no pin, the files are pinned as they are (trust on first use)
// and the exception applies as before; while every file equals its pin, the exception applies; a file that differs,
// one that appears or one that goes is unread:local, the reason naming that file by its path only, until the user
// accepts the files as they are in their own terminal (alalanet-agent policy-approve: a terminal of its own, the
// changed paths and a random code shown there, the files pinned again when the code is typed back). The reading of the
// files' values (assignments, pmShadow) stays as a second layer.
//
// What this does not do: a file that is already hostile when it is first pinned is trusted (the reader's own checks
// still apply to it); the pin is in the user's folder, which a process that is trying can write; the terminal and the
// code stop a model that is not trying to get past them, not a determined local process (ADR-0174 round 13).
//
// Round 9 (ADR-0174 round 14): the pin is kept in a state folder from the home folder only; marks that a pin was made
// (beside it and beside the agent's key) make a gone pin no first use; a pinned path the current list does not give is
// no change (another environment's), and policy-approve merges, with the paths the hook recorded; the startup list
// takes in what the files name (startfiles.go).

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/alalanet/alalanet-agent/internal/filelock"
)

// startPin is the pin as it is kept (startup-pin.json, 0600 in a 0700 folder): the startup files by path, each a
// sha256 in hex or pinAbsent. Never a file's bytes.
type startPin struct {
	V     int               `json:"v"`
	At    int64             `json:"at"` // unix nanoseconds
	Files map[string]string `json:"files"`
}

// startPending is what the hook saw differ from the pin (startup-pending.json): paths only, which policy-approve reads
// and pins too — the hook's list may hold files the user's terminal does not list (another environment; round 14).
type startPending struct {
	V     int      `json:"v"`
	Paths []string `json:"paths"`
}

const (
	pinAbsent = "absent"
	// pinGone: a tombstone of a Codex shell snapshot that was pinned and is gone: the same name written again is no
	// new snapshot (round 15, R9-1)
	pinGone     = "gone"
	pinName     = "startup-pin.json"
	pinLockName = "startup-pin.lock"
	pendingName = "startup-pending.json"
	// pinMarkName: a pin was made; beside the pin and in a second folder (pf.pinMark): a pin that is gone while a mark
	// is there is no first use (round 14, R8-5)
	pinMarkName = "startup-pinned"
	maxPinFile  = 1 << 20
)

// maxPinned bounds the paths of a pin (a variable for tests).
var maxPinned = 4096

// snapshotHorizon: how long a snapshot's tombstone is kept, from the time in its name — Codex removes snapshots after
// three days (SNAPSHOT_RETENTION, core/src/shell_snapshot.rs), plus a day. A snapshot that appears with a name older
// than this, from the future, or with no time Codex writes is no new snapshot either.
const snapshotHorizon = 4 * 24 * time.Hour

// pinNow is the clock of the snapshots' times (a variable for tests).
var pinNow = time.Now

// snapshotTime: the time in a Codex snapshot's name (<session>.<unix nanoseconds>.sh).
func snapshotTime(p string) (time.Time, bool) {
	parts := strings.Split(strings.TrimSuffix(filepath.Base(p), ".sh"), ".")
	if len(parts) != 2 {
		return time.Time{}, false
	}
	ns, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(0, ns), true
}

// freshSnapshot: a snapshot name Codex could have written within the horizon (an hour of clock skew allowed).
func freshSnapshot(p string) bool {
	t, ok := snapshotTime(p)
	now := pinNow()
	return ok && now.Sub(t) < snapshotHorizon && t.Before(now.Add(time.Hour))
}

// pinLockWait: the longest the hook waits for the pin's lock (hooks of parallel tool calls run at once); within
// policyDeadline. A variable for tests.
var pinLockWait = 400 * time.Millisecond

// defaultPinDir is where the pin is kept: a state folder, not a cache one (a cache cleanup must not make a first use):
// ~/.local/state/alalanet/policy, %LOCALAPPDATA%\alalanet\policy on Windows. Taken from the home folder only, never
// from XDG_STATE_HOME or XDG_CACHE_HOME: the user's terminal and the runtime may have different environments, and
// policy-approve must write the pin the hook reads (round 14, R8-6).
func defaultPinDir(getenv func(string) string, home func() (string, error)) (string, error) {
	if runtime.GOOS == "windows" {
		if d := getenv("LOCALAPPDATA"); d != "" && filepath.IsAbs(d) {
			return filepath.Join(d, "alalanet", "policy"), nil
		}
	}
	h, err := home()
	if err != nil || !filepath.IsAbs(h) {
		return "", errors.New("no home folder")
	}
	return filepath.Join(h, ".local", "state", "alalanet", "policy"), nil
}

// defaultPinMark is the second mark that a pin was made: beside the agent's key (~/.config/alalanet).
func defaultPinMark(home func() (string, error)) (string, error) {
	h, err := home()
	if err != nil || !filepath.IsAbs(h) {
		return "", errors.New("no home folder")
	}
	return filepath.Join(h, ".config", "alalanet", pinMarkName), nil
}

// fileSum is how the pin keeps a file it read.
func fileSum(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// pinCheck compares the startup files as read (state) with the pin, pinning them when there is none yet and none was
// ever made; Codex's shell snapshots (c.autoDirs) are pinned on first sight and dropped when they go.
func (c *regCheck) pinCheck(state map[string]string) {
	if c.pf.pinDir == nil {
		return
	}
	dir, err := c.pf.pinDir()
	if err != nil || !filepath.IsAbs(dir) {
		c.moved("the shell startup files", "cannot be pinned: alalanet-agent has no folder for its state")
		return
	}
	unlock, err := pinLock(dir, pinLockWait)
	if err != nil {
		c.moved("the shell startup files", "could not be compared with their pin (its lock: "+lockWhy(err)+")")
		return
	}
	defer unlock()
	pin, err := loadPin(dir)
	switch {
	case err != nil:
		c.moved(filepath.Join(dir, pinName), "does not load, so the shell startup files cannot be compared with their pin; it is kept as it is (the user pins them again in their own terminal with alalanet-agent policy-approve)")
	case pin == nil && c.pinMarked(dir):
		c.moved(filepath.Join(dir, pinName), "is gone although alalanet-agent made one, so the shell startup files are not trusted as on a first use (the user pins them again in their own terminal with alalanet-agent policy-approve)")
	case pin == nil:
		if err := c.savePin(dir, state); err != nil {
			c.moved("the shell startup files", "could not be pinned (the pin could not be written)")
		}
	default:
		if ch := pinChanges(pin.Files, state, c.enumerated, c.autoDirs); len(ch) > 0 {
			_ = savePending(dir, ch) // best effort: policy-approve also reads its own list
			c.moved(ch[0], "is a shell startup file that "+pinWhat(pin.Files, state, ch[0])+" since alalanet-agent pinned it (the user accepts it in their own terminal with alalanet-agent policy-approve)")
			return
		}
		if merged := mergePin(pin.Files, state, c.enumerated, c.autoDirs); !maps.Equal(merged, pin.Files) {
			if err := c.savePin(dir, merged); err != nil {
				c.moved("the shell startup files", "could not be pinned (the pin could not be written)")
			}
		}
	}
}

// pinChanges: the paths whose state differs from the pin, in order — changed, appeared (not pinned, or pinned absent),
// or gone from a folder the list takes whole (enumerated). A pinned path the list does not give now is no change (it
// came from another environment: ZDOTDIR's, BASH_ENV's in the user's terminal; round 14, R8-6). In auto folders a file
// that appears or goes is no change; one that changed is.
func pinChanges(pinned, state map[string]string, enumerated, auto map[string]bool) []string {
	var out []string
	for p, s := range state {
		was, ok := pinned[p]
		if !ok {
			if auto[filepath.Dir(p)] && freshSnapshot(p) {
				continue // a new shell snapshot: pinned on first sight
			}
			was = pinAbsent // a path the pin does not name was not there
		}
		if was != s {
			out = append(out, p)
		}
	}
	for p, s := range pinned {
		if _, ok := state[p]; !ok && s != pinAbsent && enumerated[filepath.Dir(p)] && !auto[filepath.Dir(p)] {
			out = append(out, p) // a file of a listed folder (conf.d) that is gone
		}
	}
	slices.Sort(out)
	return out
}

// mergePin is the pin with state taken in: the old entries are kept (another environment's), except files of a folder
// the list takes whole that are no longer there.
func mergePin(pinned, state map[string]string, enumerated, auto map[string]bool) map[string]string {
	out := maps.Clone(pinned)
	for p, s := range out {
		if _, ok := state[p]; ok {
			continue
		}
		switch d := filepath.Dir(p); {
		case auto[d] && s != pinGone:
			out[p] = pinGone // a tombstone: the name is not new again
		case auto[d] && !freshSnapshot(p):
			delete(out, p) // past the horizon: a name that old is no new snapshot anyway
		case enumerated[d] && !auto[d]:
			delete(out, p)
		}
	}
	maps.Copy(out, state)
	return out
}

func pinWhat(pinned, state map[string]string, p string) string {
	was, had := pinned[p]
	now, has := state[p]
	switch {
	case !has || now == pinAbsent:
		return "is gone"
	case was == pinGone:
		return "appeared again"
	case !had || was == pinAbsent:
		return "appeared"
	}
	return "changed"
}

// pinMarked: a mark says a pin was made (beside the pin, or in the second folder).
func (c *regCheck) pinMarked(dir string) bool {
	if _, err := os.Lstat(filepath.Join(dir, pinMarkName)); err == nil {
		return true
	}
	if c.pf.pinMark != nil {
		if m, err := c.pf.pinMark(); err == nil && filepath.IsAbs(m) {
			if _, err := os.Lstat(m); err == nil {
				return true
			}
		}
	}
	return false
}

// loadPin reads the pin: nil when there is none; an error when it is there but does not load (it is kept as it is).
func loadPin(dir string) (*startPin, error) {
	b, err := readRegular(filepath.Join(dir, pinName), maxPinFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p startPin
	if json.Unmarshal(b, &p) != nil || p.V != 1 || p.Files == nil || len(p.Files) > maxPinned {
		return nil, errors.New("the pin does not load")
	}
	for path, s := range p.Files {
		if !filepath.IsAbs(path) || (s != pinAbsent && s != pinGone && !hex64(s)) {
			return nil, errors.New("the pin does not load")
		}
	}
	return &p, nil
}

func hex64(s string) bool { return len(s) == 64 && strings.Trim(s, "0123456789abcdef") == "" }

// savePin writes the pin whole (writeAtomic) and the marks that a pin was made.
func (c *regCheck) savePin(dir string, state map[string]string) error {
	if len(state) > maxPinned {
		return errors.New("too many startup files to pin")
	}
	b, err := json.Marshal(startPin{V: 1, At: time.Now().UnixNano(), Files: state})
	if err != nil {
		return err
	}
	if err := writeAtomic(dir, pinName, b); err != nil {
		return err
	}
	if err := markFile(filepath.Join(dir, pinMarkName)); err != nil {
		return err
	}
	if c.pf.pinMark != nil {
		m, err := c.pf.pinMark()
		if err != nil || !filepath.IsAbs(m) {
			return errors.New("no folder for the pin's second mark")
		}
		if err := os.MkdirAll(filepath.Dir(m), 0o700); err != nil {
			return err
		}
		return markFile(m)
	}
	return nil
}

// markFile makes an empty file (0600) at path, when there is none.
func markFile(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return f.Close()
}

// writeAtomic writes name in dir whole: a temporary file in the same folder (0600), synced, then a rename, so a reader
// never sees half of it.
func writeAtomic(dir, name string, b []byte) error {
	var rnd [8]byte
	_, _ = rand.Read(rnd[:])
	tmp := filepath.Join(dir, ".pin-"+hex.EncodeToString(rnd[:])+".tmp")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, filepath.Join(dir, name))
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}

// savePending records the paths the hook saw differ (under the pin's lock), with those already recorded.
func savePending(dir string, paths []string) error {
	old, _ := loadPending(dir)
	all := slices.Compact(slices.Sorted(slices.Values(append(old, paths...))))
	if len(all) > maxPinned {
		all = all[:maxPinned]
	}
	b, err := json.Marshal(startPending{V: 1, Paths: all})
	if err != nil {
		return err
	}
	return writeAtomic(dir, pendingName, b)
}

// loadPending: the paths the hook recorded (absolute ones only); none when there is no file or it does not load.
func loadPending(dir string) ([]string, error) {
	b, err := readRegular(filepath.Join(dir, pendingName), maxPinFile)
	if err != nil {
		return nil, err
	}
	var p startPending
	if json.Unmarshal(b, &p) != nil || p.V != 1 || len(p.Paths) > maxPinned {
		return nil, errors.New("the pending list does not load")
	}
	var out []string
	for _, x := range p.Paths {
		if filepath.IsAbs(x) {
			out = append(out, filepath.Clean(x))
		}
	}
	return out, nil
}

var errPinLocked = filelock.ErrLocked

func lockWhy(err error) string {
	if errors.Is(err, errPinLocked) {
		return "held by another alalanet-agent"
	}
	return why(err)
}

// pinLock takes the pin's lock file: the shared lock of alalanet-agent's local state (internal/filelock, as
// VERIFY-AUTO-1's MCP state takes it): an owner token, a stale or future-dated lock broken by one breaker at a time, the
// folder made 0700.
func pinLock(dir string, wait time.Duration) (func(), error) {
	return filelock.LockFor(dir, pinLockName, wait)
}

// startupNow reads the startup files as the hook does, without judging their values, with the paths the hook recorded
// (pending) read too: their state and the reading (its enumerated and auto folders), or why they cannot be pinned (a
// file that cannot be read).
func startupNow(pf *policyFiles, pending []string) (map[string]string, *regCheck, string) {
	c := newRegCheck(pf, "")
	state := c.startupFiles(false)
	for _, p := range pending {
		if _, ok := state[p]; ok || c.why != "" {
			continue
		}
		delete(c.seen, p)
		if b := c.readFollow(p); b != nil {
			state[p] = fileSum(b)
		} else {
			state[p] = pinAbsent
		}
	}
	if c.why != "" {
		return nil, nil, c.why
	}
	return state, c, ""
}

// policyApprove pins the shell startup files as they are now, on the user's own terminal: it refuses without one,
// shows the paths that differ from the pin and a random code on the terminal only, and pins when the code is typed
// back — and the files are still what was shown. What it pins is merged into the pin (mergePin), with the files the
// hook recorded as differing (pending): the user's terminal and the runtime may list different files. A process with
// no terminal of its own cannot answer; one that has a terminal the model reads (an IDE's, Codex's PTY) can, and there
// the hook's hold on a line naming policy-approve is the protection (README).
func policyApprove(w io.Writer, pf *policyFiles, tty func() (io.Reader, io.Writer, func(), error)) error {
	in, screen, closeTTY, err := tty()
	if err != nil {
		return errors.New("policy-approve asks on a terminal and there is none: the user runs it in their own terminal")
	}
	defer closeTTY()
	if pf.pinDir == nil {
		return errors.New("no folder for alalanet-agent's state")
	}
	dir, err := pf.pinDir()
	if err != nil || !filepath.IsAbs(dir) {
		return errors.New("no folder for alalanet-agent's state")
	}
	unlock, err := pinLock(dir, 5*time.Second)
	if err != nil {
		return errors.New("the pin's lock: " + lockWhy(err))
	}
	pin, perr := loadPin(dir)
	pending, _ := loadPending(dir)
	unlock()
	state, c, bad := startupNow(pf, pending)
	if bad != "" {
		return errors.New("the shell startup files cannot be pinned: " + bad)
	}
	old := map[string]string{}
	if pin != nil && perr == nil {
		old = pin.Files
	}
	if perr != nil {
		fmt.Fprintf(screen, "The pin %s does not load; it is replaced.\n", shownPath(filepath.Join(dir, pinName)))
	}
	changed := pinChanges(old, state, c.enumerated, c.autoDirs)
	merged := mergePin(old, state, c.enumerated, c.autoDirs)
	if perr == nil && pin != nil && len(changed) == 0 {
		if !maps.Equal(merged, old) || len(pending) > 0 {
			if err := savePinLocked(c, dir, merged); err != nil {
				return err
			}
		}
		fmt.Fprintln(w, "the shell startup files match their pin: nothing to accept")
		return nil
	}
	fmt.Fprintln(screen, "These shell startup files differ from what alalanet-agent pinned (read them yourself before you accept):")
	for _, p := range changed {
		fmt.Fprintf(screen, "  %s: %s\n", pinWhat(old, state, p), shownPath(p))
	}
	code := terminalCode()
	fmt.Fprintf(screen, "Type %s and Enter to pin them as they are now (anything else cancels): ", code)
	lines := bufio.NewScanner(in)
	if !lines.Scan() || strings.TrimSpace(lines.Text()) != code {
		fmt.Fprintln(screen, "Not accepted.")
		return errors.New("not accepted")
	}
	again, _, bad := startupNow(pf, pending)
	if bad != "" || !maps.Equal(again, state) {
		return errors.New("the shell startup files changed while they were shown: nothing was pinned; run policy-approve again")
	}
	if err := savePinLocked(c, dir, merged); err != nil {
		return err
	}
	fmt.Fprintln(w, "the shell startup files are pinned as they are now")
	return nil
}

// savePinLocked saves the pin under its lock and clears what the hook recorded.
func savePinLocked(c *regCheck, dir string, files map[string]string) error {
	unlock, err := pinLock(dir, 5*time.Second)
	if err != nil {
		return errors.New("the pin's lock: " + lockWhy(err))
	}
	defer unlock()
	if err := c.savePin(dir, files); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(dir, pendingName)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// shownPath is a path as a terminal shows it: quoted when it has a byte that is not a printable character (a file
// name the agent wrote may carry a terminal's control sequence).
func shownPath(p string) string {
	for _, r := range p {
		if r == unicode.ReplacementChar || !unicode.IsPrint(r) {
			return strconv.QuoteToASCII(p)
		}
	}
	return p
}

// policyApproveHold: pinning changed startup files is the user's step in their own terminal; a line that may run
// policy-approve through the agent's shell is held whatever else it holds.
const policyApproveHold = "alalanet-agent: HOLD — accepting changed shell startup files (policy-approve) is the user's own step in their own terminal, not the agent's. Run it only if the user asks for it."

// approvesPolicy: the line may run policy-approve, as far as a reading of the line can tell: with its quotes and
// backslashes removed it names policy-approve; or it names alalanet together with "approve", or with a word
// "policy-..." the shell completes from a variable or a substitution; or it runs alalanet under a program that gives it
// a terminal of its own (script, expect, unbuffer, a Python pty). A line that merely mentions policy-approve is held
// too. Defence in depth against a model that is not trying; a model that is (a decoded string, a script written first)
// is not stopped by any reading of one line, nor by the terminal and the code.
func approvesPolicy(line string) bool {
	low := strings.ToLower(line)
	norm := strings.NewReplacer(`"`, "", `'`, "", `\`, "").Replace(low)
	if strings.Contains(norm, "policy-approve") {
		return true
	}
	if !strings.Contains(norm, "alalanet") {
		return false
	}
	return strings.Contains(norm, "approve") || policyComputed.MatchString(norm) || policyPtyRunner.MatchString(norm)
}

// pinPathHold: the pin, its marks and its folder are the user's (policy-approve), not the agent's to change or remove.
const pinPathHold = "alalanet-agent: HOLD — this command names alalanet-agent's pin of the shell startup files or its folder; changing or removing it is the user's own step (policy-approve in their own terminal), not the agent's. Run it only if the user asks for it."

// touchesPin: the line names the pin, its marks or a folder that holds them, as far as a reading of the line can tell
// (quotes and backslashes removed, any case). A line that names a parent folder by a variable or builds the path is
// not seen: the stated limit of a reading of one line (ADR-0174 round 14).
func touchesPin(line string) bool {
	low := strings.ToLower(line)
	norm := strings.NewReplacer(`"`, "", `'`, "", `\`, "/").Replace(low)
	for _, n := range []string{"startup-pin", "alalanet/policy", ".local/state", "xdg_state_home", ".config/alalanet",
		"shell_snapshots", "codex_home"} {
		if strings.Contains(norm, n) {
			return true
		}
	}
	return false
}

var (
	policyComputed  = regexp.MustCompile("(^|[^a-z0-9_-])policy-[a-z0-9_-]*(\\$|`)")
	policyPtyRunner = regexp.MustCompile(`(^|[^a-z0-9_.-])(script|expect|unbuffer|pexpect|ptyprocess|pty)([^a-z0-9_-]|$)`)
)
