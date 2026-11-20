package main

// The policy the hook applies to alalanet's answer (REPO-POL-1 step 2, ADR-0174): the organisation's file, which an
// administrator's device management places where users cannot write, and .alalanet.yml at the root of the git
// repository the agent works in. Both are read here, on this machine, and only after alalanet answered; neither the
// files nor anything in them is sent. A file that is absent is no policy. A repository's file that cannot be read or
// parsed is not applied (it could only tighten), and the hook says so on stderr; an organisation's file that cannot be
// read or parsed fails closed — an install alalanet allows is held until it is fixed. The repository's exceptions apply
// only when the organisation's policy trusts the repository by its origin's address (trusted_repositories) and does not
// say repository_exceptions: never; its tightening applies at once.

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/alalanet/alalanet-agent/internal/installread"
	"github.com/alalanet/alalanet-agent/internal/repopolicy"
)

// policyFiles is where one hook call reads policies; nil in hookCall reads none.
type policyFiles struct {
	managed string                 // the organisation's policy file
	getwd   func() (string, error) // the hook's own working directory, when the input names none
	// adminOnly: the organisation's file must be the administrator's (adminOwned): on in the agent, off in tests that
	// place one in a temporary folder.
	adminOnly bool
	// Where the package managers' registry settings are read beyond the workspace (registries.go, REPO-POL-NPMRC): the
	// user's home folder, the hook's environment, programs on PATH (node's and Python's prefixes) and the system's
	// fixed files. All set in the agent; nil or off in tests, which read the workspace only.
	home     func() (string, error)
	environ  func() []string
	lookPath func(string) (string, error)
	system   bool
	// pinDir: the folder of the shell startup files' pin (startpin.go, round 13); nil in tests that do not pin.
	// pinMark: the second mark that a pin was made (round 14); nil: the mark beside the pin only.
	pinDir, pinMark func() (string, error)
}

func defaultPolicyFiles() *policyFiles {
	return &policyFiles{managed: managedPolicyPath(runtime.GOOS), getwd: os.Getwd, adminOnly: true,
		home: os.UserHomeDir, environ: os.Environ, lookPath: exec.LookPath, system: true,
		pinDir:  func() (string, error) { return defaultPinDir(os.Getenv, os.UserHomeDir) },
		pinMark: func() (string, error) { return defaultPinMark(os.UserHomeDir) }}
}

// managedPolicyPath: the organisation's policy beside Claude Code's managed settings, in the system folder only an
// administrator writes (code.claude.com/docs/en/managed-settings, read 2026-11-15: /Library/Application Support/
// ClaudeCode/ on macOS, /etc/claude-code/ on Linux and WSL, C:\Program Files\ClaudeCode\ on Windows — Claude Code no
// longer reads the legacy C:\ProgramData path). WSL's /etc is user-writable, as those docs say of /etc/claude-code.
func managedPolicyPath(goos string) string {
	switch goos {
	case "darwin":
		return "/Library/Application Support/alalanet/policy.yml"
	case "windows":
		return `C:\Program Files\alalanet\policy.yml`
	}
	return "/etc/alalanet/policy.yml"
}

// maxGitConfig bounds the git config read for origin's address; a larger file is not read (no identity).
const maxGitConfig = 256 << 10

// hookPolicy is what one hook call read.
type hookPolicy struct {
	layers   []repopolicy.Layer
	repoFile string // the workspace's policy file, when one was read
	// managedBroken: the organisation's policy file is there but cannot be read or parsed (fail closed).
	managedBroken bool
	notes         []string
	// registries says why an install's registry may not be the public one alalanet judged ("" when nothing moves it);
	// nil reads nothing.
	registries func(command string, targets []string) string
}

// policyDeadline bounds each of the two readings (the organisation's file, the workspace's): a file the agent can make
// — a FIFO, a file on a stalled network mount — never stands between alalanet's answer and the runtime (round 4, S1).
// Past it the organisation's file holds an allow, as an unreadable one does; the workspace's is not applied.
var policyDeadline = time.Second

// within runs f and gives up after d; a goroutine left behind ends with the process (the hook answers and exits).
func within[T any](d time.Duration, f func() T) (T, bool) {
	ch := make(chan T, 1)
	go func() { ch <- f() }()
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case v := <-ch:
		return v, true
	case <-t.C:
		var zero T
		return zero, false
	}
}

// managedRead is what reading the organisation's file gave: a policy, nothing (absent), or a note (broken).
type managedRead struct {
	policy *repopolicy.Policy
	broken string
}

// repoRead is what reading the workspace gave: the repository's file and its origin's id, nothing, or a note.
type repoRead struct {
	file, origin string
	policy       *repopolicy.Policy
	note         string
}

// loadPolicy reads the organisation's policy and the workspace's file, each under policyDeadline. cwd is the directory
// the runtime names; "" or a relative path falls back to the hook's own working directory.
func loadPolicy(pf *policyFiles, cwd string) hookPolicy {
	var hp hookPolicy
	hp.registries = func(command string, targets []string) string {
		why, ok := within(policyDeadline, func() string { return registryMoved(pf, workDir(pf, cwd), command, targets) })
		if !ok {
			return "the package managers' registry settings could not be read in time"
		}
		return why
	}
	m, ok := within(policyDeadline, func() managedRead { return readManaged(pf) })
	switch {
	case !ok:
		m.broken = "could not be read in time"
	case m.policy != nil:
		hp.layers = append(hp.layers, repopolicy.Layer{Source: repopolicy.Managed, Policy: *m.policy})
	}
	if m.broken != "" {
		hp.managedBroken = true
		hp.notes = append(hp.notes, "the organisation's policy file "+pf.managed+" "+m.broken+": installs alalanet allows are held until it is fixed")
	}
	r, ok := within(policyDeadline, func() repoRead { return readRepo(pf, cwd) })
	switch {
	case !ok:
		hp.notes = append(hp.notes, "the workspace's alalanet policy could not be read in time, so it is not applied")
		return hp
	case r.note != "":
		hp.notes = append(hp.notes, r.note)
		return hp
	case r.policy == nil:
		return hp
	}
	managed := m.policy
	trusted := managed != nil && !managed.RepositoryExceptionsNever && managed.TrustsRepository(r.origin)
	hp.repoFile = r.file
	hp.layers = append(hp.layers, repopolicy.Layer{Source: repopolicy.Repo, Policy: *r.policy, TrustExceptions: trusted})
	return hp
}

// readManaged reads the organisation's file: absent is no policy; there but not a regular file, not the
// administrator's (adminOwned, unix), unreadable or not parsed is broken (fail closed). The parser is strict: a key this
// agent does not know is a parse error, not ignored — a key the organisation added may be a rule it relies on (round 4,
// S4); update alalanet-agent before adding one.
func readManaged(pf *policyFiles) managedRead {
	if _, err := os.Lstat(pf.managed); errors.Is(err, fs.ErrNotExist) {
		return managedRead{}
	}
	if pf.adminOnly {
		if err := adminOwned(pf.managed); err != nil {
			return managedRead{broken: "is not the administrator's (" + err.Error() + ")"}
		}
	}
	b, err := readRegular(pf.managed, repopolicy.MaxBytes)
	if err != nil {
		return managedRead{broken: "could not be read (" + why(err) + ")"}
	}
	p, err := repopolicy.ParseManaged(b)
	if err != nil {
		return managedRead{broken: "is not a policy this version reads (" + err.Error() + "; a file newer than this alalanet-agent needs the agent updated first)"}
	}
	return managedRead{policy: &p}
}

// readRepo finds the repository the agent works in and reads its .alalanet.yml (the one check_repo_config judges: at
// git's toplevel, found by .git above cwd, that exact name; outside a repository there is none) and its origin's id.
func readRepo(pf *policyFiles, cwd string) repoRead {
	if cwd = workDir(pf, cwd); cwd == "" {
		return repoRead{}
	}
	root, gitPath := repoRoot(filepath.Clean(cwd))
	if gitPath == "" {
		return repoRead{}
	}
	file := filepath.Join(root, repopolicy.FileName)
	b, err := readRegular(file, repopolicy.MaxBytes)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return repoRead{}
	case err != nil:
		return repoRead{note: file + " could not be read (" + why(err) + "), so it is not applied"}
	}
	p, err := repopolicy.Parse(b)
	if err != nil {
		return repoRead{note: file + " is not a policy this version reads (" + err.Error() + "), so it is not applied"}
	}
	return repoRead{file: file, origin: repopolicy.RepositoryID(originURL(gitPath)), policy: &p}
}

// workDir is the workspace: cwd when the runtime names an absolute one, else the hook's own working directory, else "".
func workDir(pf *policyFiles, cwd string) string {
	if cwd != "" && filepath.IsAbs(cwd) {
		return cwd
	}
	if pf.getwd != nil {
		if d, err := pf.getwd(); err == nil && filepath.IsAbs(d) {
			return d
		}
	}
	return ""
}

func why(err error) string {
	switch {
	case errors.Is(err, fs.ErrPermission):
		return "permission denied"
	case errors.Is(err, errNotRegular):
		return "not a regular file"
	case errors.Is(err, errTooBig):
		return "larger than a policy"
	}
	return "an error"
}

// beforeOpen runs between readRegular's Lstat and its open; nil but in tests, which swap the file there.
var beforeOpen atomic.Pointer[func(path string)]

var (
	errNotRegular = errors.New("not a regular file")
	errTooBig     = errors.New("too large")
)

// readRegular reads a file of at most max bytes that is a regular file and no link, without ever waiting on it (round
// 4, S1): Lstat first — a FIFO, a device, a socket or a link is refused before any open — then an open that neither
// follows a link nor waits for a FIFO's writer (openNoWait: O_NOFOLLOW|O_NONBLOCK on unix), then fstat, which must be a
// regular file and the same file the Lstat saw (nothing swapped in between): the same inode, and — since a file
// system may reuse a freed inode at once (it does in the pinned image) — the same size and mtime. A file of the same
// size swapped in within the clock's tick is not told apart; it is a regular file the writer could have written in
// the first place, so the reading still never waits.
func readRegular(path string, max int64) ([]byte, error) {
	seen, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !seen.Mode().IsRegular() {
		return nil, errNotRegular
	}
	if f := beforeOpen.Load(); f != nil {
		(*f)(path)
	}
	f, err := openNoWait(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !os.SameFile(fi, seen) || !fi.Mode().IsRegular() || fi.Size() != seen.Size() || !fi.ModTime().Equal(seen.ModTime()) {
		return nil, errNotRegular
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errTooBig
	}
	return b, nil
}

// installPart: the line up to the end of its last install command, when what follows is joined by && ; or || at the
// top level (outside quotes, parentheses, braces, $( ) and backticks); else the whole line — a & or a | after it, a
// here-document, or a quote left open keep it all. The last install command, not the last new target: a second
// install of the same target after it (… ; cd /srv && npm i x) is read (round 10, S1).
func installPart(line string) string {
	if all, _, _, _ := installread.ParseLine(line); len(all) == 0 || strings.Contains(line, "<<") {
		return line
	}
	type sep struct{ at, next int } // a top-level && || ; or newline: its offset, and the offset after it
	var seps []sep
	var others []int // the offsets of a top-level & or |: a background job or a pipe
	depth, q := 0, byte(0)
	for i := 0; i < len(line); i++ {
		ch := line[i]
		switch {
		case q == '\'':
			if ch == '\'' {
				q = 0
			}
		case ch == '\\':
			i++
		case q == '"':
			if ch == '"' {
				q = 0
			} else if ch == '`' || ch == '$' && i+1 < len(line) && line[i+1] == '(' {
				return line // a substitution inside double quotes: keep it all
			}
		case ch == '\'' || ch == '"':
			q = ch
		case ch == '(' || ch == '{' || ch == '`':
			depth++
		case ch == ')' || ch == '}':
			depth--
		case depth != 0:
		case ch == ';' || ch == '\n':
			seps = append(seps, sep{i, i + 1})
		case (ch == '&' || ch == '|') && i+1 < len(line) && line[i+1] == ch:
			seps = append(seps, sep{i, i + 2})
			i++
		case ch == '&' || ch == '|':
			others = append(others, i)
		}
	}
	if q != 0 || depth != 0 {
		return line
	}
	installs := func(s string) bool { t, _, _, _ := installread.ParseLine(s); return len(t) > 0 }
	last, start := -1, 0 // the separator after the last command that installs anything
	for k, sp := range seps {
		if installs(line[start:sp.at]) {
			last = k
		}
		start = sp.next
	}
	if last < 0 || installs(line[start:]) {
		return line
	}
	for _, o := range others {
		if o > seps[last].at {
			return line
		}
	}
	return line[:seps[last].at]
}

// readFollow is readRegular for a file a link may name — the user's startup and config files, which dotfile managers
// (stow, chezmoi, home-manager) link (REPO-POL-NPMRC round 8, F3): Stat follows the link, the open follows it without
// waiting for a FIFO's writer, and fstat must see a regular file, the one Stat saw, with its size and mtime.
func readFollow(path string, max int64) ([]byte, error) {
	seen, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !seen.Mode().IsRegular() { // the open-file check below decides; this narrows the window before the open
		return nil, errNotRegular
	}
	if f := beforeOpen.Load(); f != nil {
		(*f)(path)
	}
	f, err := openFollowNoWait(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !os.SameFile(fi, seen) || !fi.Mode().IsRegular() || fi.Size() != seen.Size() || !fi.ModTime().Equal(seen.ModTime()) {
		return nil, errNotRegular
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errTooBig
	}
	return b, nil
}

// repoRoot walks up from dir to the first directory with a .git entry (a folder, or a file naming the git directory in
// a worktree or a submodule): the repository's root and that entry. Without one, dir itself and "".
func repoRoot(dir string) (root, gitPath string) {
	for d, i := dir, 0; i < 64; i++ {
		g := filepath.Join(d, ".git")
		if _, err := os.Lstat(g); err == nil {
			return d, g
		}
		up := filepath.Dir(d)
		if up == d {
			break
		}
		d = up
	}
	return dir, ""
}

// originURL is the url of [remote "origin"] in the repository's git config, read as data (git is not run): from
// .git/config, or for a .git file from the git directory it names — the common directory's config when commondir says
// one (a worktree). Several urls must agree, or there is none. Every file is read by readRegular.
func originURL(gitPath string) string {
	dir := gitPath
	if fi, err := os.Lstat(gitPath); err != nil {
		return ""
	} else if !fi.IsDir() {
		b, err := readRegular(gitPath, maxGitConfig)
		if err != nil {
			return ""
		}
		rest, ok := strings.CutPrefix(strings.TrimSpace(string(b)), "gitdir:")
		if !ok {
			return ""
		}
		dir = strings.TrimSpace(rest)
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(filepath.Dir(gitPath), dir)
		}
		if c, err := readRegular(filepath.Join(dir, "commondir"), maxGitConfig); err == nil {
			common := strings.TrimSpace(string(c))
			if !filepath.IsAbs(common) {
				common = filepath.Join(dir, common)
			}
			dir = common
		}
	}
	b, err := readRegular(filepath.Join(dir, "config"), maxGitConfig)
	if err != nil {
		return ""
	}
	return gitConfigOrigin(b)
}

// gitConfigOrigin reads remote.origin.url from a git config file: section names without case, the subsection exactly,
// the key without case, a value with its quotes removed; comments after ; or #. Every url of origin must be the same.
func gitConfigOrigin(b []byte) string {
	in, url, seen := false, "", false
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 4096), maxGitConfig)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			head, _, _ := strings.Cut(strings.TrimPrefix(line, "["), "]")
			name, sub, _ := strings.Cut(head, " ")
			in = strings.EqualFold(strings.TrimSpace(name), "remote") && strings.TrimSpace(sub) == `"origin"`
			continue
		}
		if !in {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "url") {
			continue
		}
		val = strings.TrimSpace(val)
		if strings.HasPrefix(val, `"`) {
			val, _, _ = strings.Cut(val[1:], `"`)
		} else if i := strings.IndexAny(val, ";#"); i >= 0 {
			val = strings.TrimSpace(val[:i])
		}
		if seen && val != url {
			return ""
		}
		url, seen = val, true
	}
	return url
}

// heldItem is one target of alalanet's HOLD and its reason codes, as the hook's answer names them (internal/app
// InstallHook: "<ecosystem>:<name>@<version> — code, code"; a remote server as remote-mcp:<URL>).
type heldItem struct {
	target string
	codes  []string
}

var heldCode = regexp.MustCompile(`^[a-z0-9_]+(:[^\s,;]+)?$`)

const (
	holdPrefix = "alalanet install_check: HOLD. "
	holdSuffix = ". Install only if the user confirms."
)

// heldTargets reads the HOLD part of alalanet's ask. ok is false when the answer is anything else: a NOT CHECKED part
// (alalanet could not check something), a second reader's hold in words, an item that is not a target and its codes,
// a reason cut short — no exception covers such a hold.
func heldTargets(reason string) (items []heldItem, ok bool) {
	body, ok := strings.CutPrefix(reason, holdPrefix)
	if !ok {
		return nil, false
	}
	if body, ok = strings.CutSuffix(body, holdSuffix); !ok {
		return nil, false
	}
	// A NOT CHECKED part after the HOLD one, or words in place of codes, fail the code's pattern; a target with a
	// space in it matches no exception.
	for _, it := range strings.Split(body, "; ") {
		target, codes, ok := strings.Cut(it, " — ")
		if !ok || target == "" {
			return nil, false
		}
		item := heldItem{target: target}
		for _, c := range strings.Split(codes, ", ") {
			if !heldCode.MatchString(c) {
				return nil, false
			}
			item.codes = append(item.codes, c)
		}
		items = append(items, item)
	}
	return items, len(items) > 0
}

// apply is the policy's answer to alalanet's verdict v for command: v itself, or an allow (live exceptions cover every
// held target and every code alalanet gave), or a deny (on_hold: deny), or a hold where the organisation's policy could
// not be read (fail closed). The targets and codes are the server's own (its HOLD part); what the line holds beyond them
// is read by alalanet's reader here — a command substitution, a reason of either reader — and is a code no exception
// covers, as is anything of the answer heldTargets cannot read.
func (hp hookPolicy) apply(v verdict, command string, now time.Time) (verdict, []string) {
	if len(hp.layers) == 0 {
		return v, nil
	}
	var server string
	switch v.Decision {
	case "deny":
		server = "block"
	case "":
		server = "allow"
	default:
		server = "hold"
	}
	// other: the line runs something besides installs and harmless commands — it may write the very config the install
	// reads before the install runs (echo … > .npmrc && npm i x), after the hook read it (REPO-POL-NPMRC round 8, B5)
	targets, unread, _, subst := installread.ParseLine(command)
	// Commands after the last install, joined by && ; or ||, run after it and cannot move it (npm i x && npm test):
	// other and the line's own check read the line up to the last install (round 9). A & or a | after it keeps the
	// whole line: a background job or a pipe runs beside the install.
	part := installPart(command)
	_, _, other, _ := installread.ParseLine(part)
	local := len(unread) > 0 || subst || other || len(installread.HookExtra(command, targets, unread, subst)) > 0
	items, readable := heldTargets(v.Reason)
	pkg := repopolicy.Hold{Kind: repopolicy.Package}
	srv := repopolicy.Hold{Kind: repopolicy.MCPServer}
	for _, it := range items {
		switch {
		case strings.HasPrefix(it.target, "npm:"), strings.HasPrefix(it.target, "pypi:"):
			pkg.Targets, pkg.Reasons = append(pkg.Targets, it.target), append(pkg.Reasons, it.codes...)
		case strings.HasPrefix(it.target, "remote-mcp:"):
			srv.Targets, srv.Reasons = append(srv.Targets, it.target), append(srv.Reasons, it.codes...)
		default:
			readable = false
		}
	}
	if !readable || local {
		pkg.Reasons = append(pkg.Reasons, "unread:local") // a code no exception covers
		srv.Reasons = append(srv.Reasons, "unread:local")
	}
	decide := func(layers []repopolicy.Layer, pkg repopolicy.Hold) repopolicy.Action {
		holds := []repopolicy.Hold{}
		if len(pkg.Targets) > 0 || len(srv.Targets) == 0 {
			holds = append(holds, pkg)
		}
		if len(srv.Targets) > 0 {
			holds = append(holds, srv)
		}
		out := repopolicy.Allow
		for _, h := range holds {
			a := repopolicy.Decide(layers, server, h, now)
			if a == repopolicy.Deny || a == repopolicy.Ask && out == repopolicy.Allow {
				out = a
			}
		}
		return out
	}
	var notes []string
	got := decide(hp.layers, pkg)
	// An exception that would let a package hold go is bound to the registry alalanet judged (REPO-POL-NPMRC): when a
	// config file or variable moves the target's registry, or cannot be read, the hold gets a code no exception covers.
	// Targets come from alalanet's HOLD part only: an allow, or a hold of servers alone, has no package target, and
	// registryMoved reads no file for it.
	if got == repopolicy.Allow && hp.registries != nil {
		if moved := hp.registries(part, pkg.Targets); moved != "" {
			pkg.Reasons = append(slices.Clip(pkg.Reasons), "unread:local")
			got = decide(hp.layers, pkg)
			notes = append(notes, moved+": no exception covers an install whose registry may not be the public one alalanet judged")
		}
	}
	switch {
	case server == "hold" && got == repopolicy.Allow:
		return verdict{}, append(notes, "alalanet held this install and an exception in the alalanet policy lets it go ahead ("+hp.sources()+")")
	case server == "hold" && got == repopolicy.Deny:
		return verdict{Decision: "deny", Reason: v.reason() + " The alalanet policy (" + hp.sources() + ") denies installs alalanet holds."},
			append(notes, "alalanet held this install and the alalanet policy denies it ("+hp.sources()+")")
	case server == "hold" && hp.repoFile != "":
		// Would the repository's exceptions have let it go, were they the developer's own? Then say why they did not.
		unbound := append([]repopolicy.Layer(nil), hp.layers...)
		for i := range unbound {
			if unbound[i].Source == repopolicy.Repo {
				unbound[i].Source = repopolicy.User
			}
		}
		if decide(unbound, pkg) == repopolicy.Allow {
			notes = append(notes, "the exceptions in "+hp.repoFile+" are not applied: a repository's exceptions apply only where the organisation's policy trusts the repository (trusted_repositories) and only inside its repository_exception_scopes")
		}
	}
	return v, notes
}

// applyNotes is apply, with the notes of what was read and not applied first. When the organisation's policy file is
// there but cannot be read or parsed, the hook fails closed (review of 2950215, F7): an install alalanet allows is held
// until the file is fixed — the organisation's deny or its other rules would otherwise be lost without a sign.
func (hp hookPolicy) applyNotes(v verdict, command string, now time.Time) (verdict, []string) {
	out, notes := hp.apply(v, command, now)
	if hp.managedBroken && out.Decision == "" {
		out = notChecked("the organisation's alalanet policy could not be read, so this install is held until it is fixed")
	}
	return out, append(append([]string(nil), hp.notes...), notes...)
}

// sources names the files the layers came from.
func (hp hookPolicy) sources() string {
	var s []string
	for _, l := range hp.layers {
		if l.Source == repopolicy.Managed {
			s = append(s, "the organisation's policy")
		} else {
			s = append(s, hp.repoFile)
		}
	}
	return strings.Join(s, ", ")
}
