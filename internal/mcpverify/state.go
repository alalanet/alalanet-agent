package mcpverify

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/alalanet/alalanet-agent/internal/filelock"
	"github.com/alalanet/alalanet-agent/internal/tooldigest"
)

// The local state (~/.cache/alalanet/mcp/state.json, 0600 in a 0700 folder): per configured server, keyed by a hash of
// its configured URL, the last read, the last answer of alalanet's record, the pin and what this session was already
// told. Never a description, a schema, a URL or a header: the tools are kept by name and digest only.

// sig is a tool as the state keeps it: no description.
type sig struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
	Hints  string `json:"hints,omitempty"`
	V      int    `json:"v,omitempty"`
}

// keep is a set as the state keeps it, bounded whoever wrote it (the server read, or ALALANET_API's answer): at most
// maxKept tools, names of 128 bytes at most and valid UTF-8 on both sides of every comparison (a name tooldigest cut
// inside a character reads the same fresh and stored), digests of 32 hex only, hints of 64 bytes at most.
func keep(sigs []tooldigest.ToolSig) []sig {
	out := make([]sig, 0, min(len(sigs), maxKept))
	for _, s := range sigs {
		if len(out) == maxKept {
			break
		}
		if !hex32(s.Digest) {
			continue
		}
		out = append(out, sig{Name: validName(s.Name), Digest: s.Digest, Hints: bound(s.Hints, 64), V: s.V})
	}
	return out
}

const maxKept = tooldigest.MaxTools

// keepSigs bounds sigs already in the state's form, as keep does.
func keepSigs(in []sig) []sig {
	out := make([]sig, 0, min(len(in), maxKept))
	for _, s := range in {
		if len(out) == maxKept {
			break
		}
		if hex32(s.Digest) {
			out = append(out, sig{Name: validName(s.Name), Digest: s.Digest, Hints: bound(s.Hints, 64), V: s.V})
		}
	}
	return out
}

// validName is a tool name as every comparison here reads it: at most 128 bytes, invalid UTF-8 written U+FFFD.
func validName(n string) string { return strings.ToValidUTF8(bound(n, 128), "\uFFFD") }

func bound(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func hex32(s string) bool { return len(s) == 32 && strings.Trim(s, "0123456789abcdef") == "" }

func (s sig) tool() tooldigest.ToolSig {
	return tooldigest.ToolSig{Name: s.Name, Digest: s.Digest, Hints: s.Hints, V: s.V}
}

func tools(sigs []sig) []tooldigest.ToolSig {
	out := make([]tooldigest.ToolSig, 0, len(sigs))
	for _, s := range sigs {
		out = append(out, s.tool())
	}
	return out
}

type readState struct {
	At     int64    `json:"at"`
	Design string   `json:"design,omitempty"`
	Failed string   `json:"failed,omitempty"`
	Hash   string   `json:"hash,omitempty"`
	Sigs   []sig    `json:"sigs,omitempty"`
	Flags  []string `json:"flags,omitempty"`
	Scope  string   `json:"scope,omitempty"`
	TTLMs  int64    `json:"ttl_ms,omitempty"`
	Descs  []sig    `json:"descs,omitempty"` // the read's tools by name and description only, compared with the agent's copy
}

type witnessState struct {
	At       int64  `json:"at"`
	Listed   int    `json:"listed"`
	Current  string `json:"current,omitempty"`
	Sigs     []sig  `json:"sigs,omitempty"`
	Previous string `json:"previous,omitempty"`
}

type pinState struct {
	At       int64  `json:"at"` // unix nanoseconds: two pins of one second differ
	Hash     string `json:"hash"`
	Sigs     []sig  `json:"sigs"`
	Approved bool   `json:"approved,omitempty"` // by the user, in a terminal (mcp-approve): its flags too
	// Gone: tools of an accepted set the server no longer lists, by their last digest (at most maxKept): a name that
	// comes back with another definition is a changed tool, not an added one (review F1).
	Gone []sig `json:"gone,omitempty"`
}

// same: p and q are the same pin (both nil, or written at once with one set).
func (p *pinState) same(q *pinState) bool {
	if p == nil || q == nil {
		return p == q
	}
	return p.At == q.At && p.Hash == q.Hash && p.Approved == q.Approved
}

// accepted is every tool the pin knows: the set's, then the gone ones not in it.
func (p *pinState) accepted() []sig {
	out := append([]sig(nil), p.Sigs...)
	in := map[string]bool{}
	for _, s := range p.Sigs {
		in[s.Name] = true
	}
	for _, s := range p.Gone {
		if !in[s.Name] {
			out = append(out, s)
		}
	}
	return out
}

// newPin pins set, keeping as gone what the old pin knew and set does not list.
func newPin(old *pinState, at int64, hash string, set []sig, approved bool) *pinState {
	p := &pinState{At: at, Hash: hash, Sigs: set, Approved: approved}
	if old == nil {
		return p
	}
	in := map[string]bool{}
	for _, s := range set {
		in[s.Name] = true
	}
	for _, s := range old.accepted() {
		if !in[s.Name] && len(p.Gone) < maxKept {
			p.Gone = append(p.Gone, s)
		}
	}
	return p
}

type entry0 struct {
	Read    *readState    `json:"read,omitempty"`
	Witness *witnessState `json:"witness,omitempty"`
	Pin     *pinState     `json:"pin,omitempty"`
	AVPin   *pinState     `json:"av_pin,omitempty"` // the agent's own copy this machine accepted (Cursor, Antigravity)
	Told    []string      `json:"told,omitempty"`   // hashes of (session, answer, set) already given
	// LookupFailedAt: when a lookup at alalanet last failed (unix seconds): the next waits a minute.
	LookupFailedAt int64 `json:"lookup_failed_at,omitempty"`
}

type stateFile struct {
	V       int                `json:"v"`
	Servers map[string]*entry0 `json:"servers"`
}

// serverKey is the state's key of a configured URL: a hash, kept on this machine only.
func serverKey(configured string) string {
	sum := sha256.Sum256([]byte("alalanet-mcp-state\x00" + configured))
	return hex.EncodeToString(sum[:16])
}

// DefaultStateDir is where the state is kept: $XDG_CACHE_HOME/alalanet/mcp, %LOCALAPPDATA%\alalanet\mcp on Windows,
// otherwise ~/.cache/alalanet/mcp.
func DefaultStateDir(getenv func(string) string, home string) string {
	if d := getenv("XDG_CACHE_HOME"); d != "" && filepath.IsAbs(d) {
		return filepath.Join(d, "alalanet", "mcp")
	}
	if runtime.GOOS == "windows" {
		if d := getenv("LOCALAPPDATA"); d != "" {
			return filepath.Join(d, "alalanet", "mcp")
		}
	}
	return filepath.Join(home, ".cache", "alalanet", "mcp")
}

const (
	stateName = "state.json"
	lockName  = "state.lock"
	maxState  = 16 << 20
	maxTold   = 64
)

var errLocked = filelock.ErrLocked

// maxLockWait: the longest a check waits for the state's lock, within its own context.
const maxLockWait = 2 * time.Second

// lockCtx takes the state's lock (filelock.Lock).
func lockCtx(ctx context.Context, dir string) (func(), error) {
	return filelock.Lock(ctx, dir, lockName, maxLockWait)
}

// lock is lockCtx for at most wait.
func lock(dir string, wait time.Duration) (func(), error) {
	return filelock.LockFor(dir, lockName, wait)
}

func removeIfOwn(path, token string) { filelock.RemoveIfOwn(path, token) }

// errState: the state file is there but does not load (cut, not JSON, past maxState): it is kept as it is, never
// overwritten, and every check is not checked until the user looks at it (review F3).
var errState = errors.New("the MCP state file of alalanet-agent does not load; it is kept as it is")

// loadState reads the state: an empty one when there is no file, errState when the file does not load. The file is
// read only when it is itself a regular file (not a link, a FIFO or a device), opened without blocking, and the read
// stops with ctx (review r3, P3-1).
func loadState(ctx context.Context, dir string) (stateFile, error) {
	st := stateFile{V: 1, Servers: map[string]*entry0{}}
	path := filepath.Join(dir, stateName)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if !lregular(path) {
		return st, errState
	}
	f, _, err := openRegular(path)
	if err != nil {
		return st, errState
	}
	defer f.Close()
	var got stateFile
	if json.NewDecoder(&limited{ctx: ctx, f: f, n: maxState}).Decode(&got) != nil || got.V != 1 {
		return st, errState
	}
	if got.Servers == nil {
		got.Servers = map[string]*entry0{}
	}
	return got, nil
}

type limited struct {
	ctx context.Context
	f   *os.File
	n   int64
}

func (l *limited) Read(p []byte) (int, error) {
	if err := l.ctx.Err(); err != nil {
		return 0, err
	}
	if l.n <= 0 {
		return 0, errors.New("the MCP state is larger than it is written")
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.f.Read(p)
	l.n -= int64(n)
	return n, err
}

// save writes the state whole: a temporary file in the same folder, then a rename, so a reader never sees half of it.
func save(dir string, st stateFile) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	var rnd [8]byte
	_, _ = rand.Read(rnd[:])
	tmp := filepath.Join(dir, ".state-"+hex.EncodeToString(rnd[:])+".tmp")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, filepath.Join(dir, stateName))
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}

// update changes one server's entry under the lock: the state is read again, so a parallel hook's entries are kept;
// a state that does not load is not written.
func update(ctx context.Context, dir, key string, fn func(e *entry0)) error {
	unlock, err := lockCtx(ctx, dir)
	if err != nil {
		return err
	}
	defer unlock()
	st, err := loadState(ctx, dir)
	if err != nil {
		return err
	}
	e := st.Servers[key]
	if e == nil {
		e = &entry0{}
		st.Servers[key] = e
	}
	fn(e)
	return save(dir, st)
}

// snapshot is one server's entry as it is now (a copy; nil fields when there is none); an error when the state cannot
// be locked or read, which is never "no state".
func snapshot(ctx context.Context, dir, key string) (entry0, error) {
	unlock, err := lockCtx(ctx, dir)
	if err != nil {
		return entry0{}, err
	}
	defer unlock()
	st, err := loadState(ctx, dir)
	if err != nil {
		return entry0{}, err
	}
	if e := st.Servers[key]; e != nil {
		return *e, nil
	}
	return entry0{}, nil
}

func toldKey(session, what, hash string) string {
	sum := sha256.Sum256([]byte(session + "\x00" + what + "\x00" + hash))
	return hex.EncodeToString(sum[:8])
}

func (e *entry0) told(k string) bool {
	for _, t := range e.Told {
		if t == k {
			return true
		}
	}
	return false
}

func (e *entry0) tell(k string) {
	if e.told(k) {
		return
	}
	e.Told = append(e.Told, k)
	if len(e.Told) > maxTold {
		e.Told = e.Told[len(e.Told)-maxTold:]
	}
}
