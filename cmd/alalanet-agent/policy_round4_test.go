//go:build unix

package main

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// ADR-0174 round 4 (the re-review of f7ca627): no file the agent can make stands between alalanet's answer and the
// runtime; trust needs scopes the organisation owns; the organisation's file must be the administrator's.

// runTimed is runWithPolicy that fails instead of hanging.
func runTimed(t *testing.T, answer, managed, input string, pf *policyFiles) (form, stderr string) {
	t.Helper()
	f := &fakeHook{answer: func(w http.ResponseWriter) {
		if answer != "" {
			_, _ = w.Write([]byte(answer))
		}
	}}
	srv := f.server(t)
	var o, e bytes.Buffer
	if pf == nil {
		pf = &policyFiles{managed: managed, getwd: func() (string, error) { return "", os.ErrNotExist }}
	}
	call := hookCall{client: &http.Client{Timeout: 2 * time.Second}, api: srv.URL, stderr: &e, policy: pf}
	if pf.home != nil { // one home for the hook and its policy files, as main gives both os.UserHomeDir (round 20)
		call.home, _ = pf.home()
	}
	done := make(chan error, 1)
	go func() { done <- runHookContext(context.Background(), "codex", strings.NewReader(input), &o, call) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("no answer within 3 s (stderr %q)", e.String())
	}
	return answerForm(t, "codex", o.String()), e.String()
}

// S1: a FIFO (or any file that is not a regular one) wherever the hook reads is not opened for reading in a way that
// waits: every answer comes back at once, and the verdict stands — a hold stays a hold, an allow an allow.
func TestRound4FIFOsNeverHang(t *testing.T) {
	for _, c := range []struct {
		name   string
		make   func(t *testing.T) (dir, fifo string)
		answer string
		want   string
	}{
		{"the policy file, a hold", func(t *testing.T) (string, string) {
			dir := workspace(t, "git@github.com:acme/app.git", "")
			return dir, filepath.Join(filepath.Dir(filepath.Dir(dir)), ".alalanet.yml")
		}, holdAnswer, "hold"},
		{"the policy file, an allow", func(t *testing.T) (string, string) {
			dir := workspace(t, "git@github.com:acme/app.git", "")
			return dir, filepath.Join(filepath.Dir(filepath.Dir(dir)), ".alalanet.yml")
		}, "", "silent"},
		{"the git config", func(t *testing.T) (string, string) {
			dir := workspace(t, "git@github.com:acme/app.git", exceptOurs)
			root := filepath.Dir(filepath.Dir(dir))
			_ = os.Remove(filepath.Join(root, ".git", "config"))
			return dir, filepath.Join(root, ".git", "config")
		}, holdAnswer, "hold"},
		{"a .git file", func(t *testing.T) (string, string) {
			dir := t.TempDir()
			write(t, filepath.Join(dir, ".alalanet.yml"), exceptOurs)
			return dir, filepath.Join(dir, ".git")
		}, holdAnswer, "hold"},
		{"commondir", func(t *testing.T) (string, string) {
			gd := t.TempDir()
			dir := t.TempDir()
			write(t, filepath.Join(dir, ".git"), "gitdir: "+gd+"\n")
			write(t, filepath.Join(dir, ".alalanet.yml"), exceptOurs)
			return dir, filepath.Join(gd, "commondir")
		}, holdAnswer, "hold"},
	} {
		dir, fifo := c.make(t)
		if err := syscall.Mkfifo(fifo, 0o644); err != nil {
			t.Skip("no mkfifo:", err)
		}
		start := time.Now()
		form, stderr := runTimed(t, c.answer, managedFile(t, trustAcme), codexInputIn(dir, "npm i @acme/cli"), nil)
		// at once: refused before any open, never by the deadline
		if form != c.want || strings.Contains(stderr, "in time") || time.Since(start) >= policyDeadline {
			t.Errorf("%s: %s, want %s, after %s (stderr %q)", c.name, form, c.want, time.Since(start), stderr)
		}
	}
}

// S1: the organisation's file as a FIFO cannot be read: it holds an allow (fail closed), at once.
func TestRound4OrganisationFIFOHolds(t *testing.T) {
	managed := filepath.Join(t.TempDir(), "policy.yml")
	if err := syscall.Mkfifo(managed, 0o644); err != nil {
		t.Skip("no mkfifo:", err)
	}
	dir := workspace(t, "git@github.com:acme/app.git", "")
	if form, stderr := runTimed(t, "", managed, codexInputIn(dir, "npm i @acme/cli"), nil); form != "hold" || !strings.Contains(stderr, "could not be read (not a regular file)") {
		t.Errorf("a FIFO for the organisation's file: %s (stderr %q)", form, stderr)
	}
}

// S1: a block is answered before any policy is read.
func TestRound4BlockReadsNoPolicy(t *testing.T) {
	read := false
	pf := &policyFiles{managed: managedFile(t, trustAcme), getwd: func() (string, error) { read = true; return "", os.ErrNotExist }}
	in := `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"npm i @acme/cli"}}`
	if form, _ := runTimed(t, blockAnswer, "", in, pf); form != "deny" || read {
		t.Errorf("a block: %s, policy read %v", form, read)
	}
}

// S1: past the deadline the reading is given up: the organisation's file holds, the repository's file is not applied.
func TestRound4PolicyDeadline(t *testing.T) {
	old := policyDeadline
	policyDeadline = 50 * time.Millisecond
	t.Cleanup(func() { policyDeadline = old })
	stall := make(chan struct{})
	t.Cleanup(func() { close(stall) })
	dir := workspace(t, "git@github.com:acme/app.git", denyHolds)
	pf := &policyFiles{managed: managedFile(t, ""), getwd: func() (string, error) { <-stall; return dir, nil }}
	in := `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"npm i @acme/cli"}}`
	start := time.Now()
	form, stderr := runTimed(t, holdAnswer, "", in, pf)
	if form != "hold" || time.Since(start) > 2*time.Second || !strings.Contains(stderr, "in time") {
		t.Errorf("a stalled workspace: %s after %s (stderr %q)", form, time.Since(start), stderr)
	}
}

// S4: the origin is [remote "origin"] exactly (git's subsections are case-sensitive), and urls that disagree give none
// whichever comes first.
func TestRound4OriginSpelling(t *testing.T) {
	for name, cfg := range map[string]string{
		"ORIGIN in capitals":     "[remote \"ORIGIN\"]\n\turl = git@github.com:acme/app.git\n",
		"the evil url first":     "[remote \"origin\"]\n\turl = https://evil.example/x/app\n\turl = git@github.com:acme/app.git\n",
		"the evil url last":      "[remote \"origin\"]\n\turl = git@github.com:acme/app.git\n\turl = https://evil.example/x/app\n",
		"a second origin header": "[remote \"origin\"]\n\turl = git@github.com:acme/app.git\n[remote \"origin\"]\n\turl = https://evil.example/x/app\n",
	} {
		dir := workspace(t, "", exceptOurs)
		write(t, filepath.Join(filepath.Dir(filepath.Dir(dir)), ".git", "config"), cfg)
		if form, _ := runTimed(t, holdAnswer, managedFile(t, trustAcme), codexInputIn(dir, "npm i @acme/cli"), nil); form != "hold" {
			t.Errorf("%s: %s, want hold", name, form)
		}
	}
	if got := gitConfigOrigin([]byte("[Remote \"origin\"]\n\tURL = git@github.com:acme/app.git\n")); got != "git@github.com:acme/app.git" {
		t.Errorf("the section and key names are not case-sensitive in git: %q", got)
	}
}

// S2: a trusted repository's exceptions apply only inside the organisation's scopes — npm scopes and domains it owns;
// PyPI exceptions only in the organisation's own file.
func TestRound4ScopesBoundRepositoryExceptions(t *testing.T) {
	acme := "git@github.com:acme/app.git"
	repo := "version: 1\nexceptions:\n  - {package: npm:@acme/cli, reason: ours, expires: " + soon + "}\n  - {package: npm:acme-helpers, reason: ours, expires: " + soon + "}\n" +
		"  - {package: pypi:acme-tools, reason: ours, expires: " + soon + "}\n  - {mcp_server: \"https://api.mcp.acme.dev/mcp\", reason: ours, expires: " + soon + "}\n"
	hold := func(target, code string) string {
		return `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"alalanet install_check: HOLD. ` + target + ` — ` + code + `. Install only if the user confirms."}}`
	}
	scoped := "version: 1\ntrusted_repositories:\n  - github.com/acme/*\nrepository_exception_scopes:\n  - npm:@acme/*\n  - mcp:*.acme.dev\n"
	noScopes := "version: 1\ntrusted_repositories:\n  - github.com/acme/*\n"
	for _, c := range []struct {
		name, managed, answer, command, want string
	}{
		{"an npm scope the organisation owns", scoped, hold("npm:@acme/cli@1.0.0", "new_package"), "npm i @acme/cli", "silent"},
		{"an unscoped npm name", scoped, hold("npm:acme-helpers@0.0.1", "new_package"), "npm i acme-helpers", "hold"},
		{"PyPI from a repository", scoped, hold("pypi:acme-tools@1.0", "new_package"), "pip install acme-tools", "hold"},
		{"a server under the organisation's domain", scoped, hold("remote-mcp:https://api.mcp.acme.dev/mcp", "unverified_yet"), "claude mcp add --transport http a https://api.mcp.acme.dev/mcp", "silent"},
		{"trusted but no scopes", noScopes, hold("npm:@acme/cli@1.0.0", "new_package"), "npm i @acme/cli", "hold"},
	} {
		dir := workspace(t, acme, repo)
		if form, stderr := runTimed(t, c.answer, managedFile(t, c.managed), codexInputIn(dir, c.command), nil); form != c.want {
			t.Errorf("%s: %s, want %s (stderr %q)", c.name, form, c.want, stderr)
		}
	}
}

// S4: on unix the organisation's file is the administrator's: owned by root, and neither it nor its folder writable by
// anyone else; otherwise it is not trusted, and holds (fail closed).
func TestRound4OrganisationFileOwnership(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("as root every file is root's")
	}
	managed := managedFile(t, trustAcme)
	dir := workspace(t, "git@github.com:acme/app.git", "")
	pf := &policyFiles{managed: managed, getwd: func() (string, error) { return "", os.ErrNotExist }, adminOnly: true}
	form, stderr := runTimed(t, "", "", codexInputIn(dir, "npm i @acme/cli"), pf)
	if form != "hold" || !strings.Contains(stderr, "not owned by root") {
		t.Errorf("a user's own file as the organisation's: %s (stderr %q)", form, stderr)
	}
	if err := adminOwned(managed); err == nil {
		t.Error("a file of this user passes as the administrator's")
	}
	// A root-owned folder anyone can write (/tmp, sticky) is not the administrator's; nor is a root-owned entry inside it.
	if fi, err := os.Stat("/tmp"); err == nil && fi.Mode().Perm()&0o002 != 0 {
		if err := adminOwned("/tmp"); err == nil {
			t.Error("/tmp, which anyone writes, passes")
		}
		entries, _ := os.ReadDir("/tmp")
		for _, e := range entries {
			p := filepath.Join("/tmp", e.Name())
			fi, err := os.Stat(p)
			if st, ok := fi.Sys().(*syscall.Stat_t); err == nil && ok && st.Uid == 0 && fi.Mode().Perm()&0o022 == 0 {
				if err := adminOwned(p); err == nil {
					t.Errorf("%s, root's in a folder anyone writes, passes", p)
				}
				break
			}
		}
	}
	// The real system folders pass where they exist (macOS /Library, /etc).
	for _, p := range []string{"/etc/hosts", "/etc/passwd"} {
		if _, err := os.Stat(p); err == nil {
			if err := adminOwned(p); err != nil {
				t.Errorf("%s: %v", p, err)
			}
		}
	}
}

// S1: what is swapped in between readRegular's Lstat and its open is not read: a FIFO (the open does not wait), a link
// to the very file Lstat saw (the open does not follow it), another regular file (not the inode Lstat saw).
func TestRound4SwapBetweenLookAndOpen(t *testing.T) {
	for _, c := range []struct {
		name string
		swap func(t *testing.T, path string)
	}{
		{"a FIFO", func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(path, 0o644); err != nil {
				t.Skip("no mkfifo:", err)
			}
		}},
		{"a link to the same file", func(t *testing.T, path string) {
			if err := os.Rename(path, path+".moved"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(path+".moved", path); err != nil {
				t.Fatal(err)
			}
		}},
		{"another regular file", func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			// of another size: on a file system that reuses the freed inode at once (the pinned image's), a file of the
			// same size written within the clock's tick is the same inode, size and mtime — nothing tells it apart
			write(t, path, denyHolds+"# swapped in\n")
		}},
	} {
		dir := workspace(t, "git@github.com:acme/app.git", denyHolds)
		file := filepath.Join(filepath.Dir(filepath.Dir(dir)), ".alalanet.yml")
		swap := func(p string) {
			if p == file {
				beforeOpen.Store(nil)
				c.swap(t, p)
			}
		}
		beforeOpen.Store(&swap)
		form, stderr := runTimed(t, holdAnswer, managedFile(t, ""), codexInputIn(dir, "npm i @acme/cli"), nil)
		beforeOpen.Store(nil)
		// refused by the open or the fstat, never by the deadline (an open that waited for the FIFO's writer)
		if form != "hold" || strings.Contains(stderr, "in time") || !strings.Contains(stderr, "could not be read") {
			t.Errorf("%s swapped in: %s (stderr %q)", c.name, form, stderr)
		}
	}
}

// S1: the organisation's file stalled past the deadline holds an allow, as an unreadable one does.
func TestRound4OrganisationFileDeadline(t *testing.T) {
	old := policyDeadline
	policyDeadline = 50 * time.Millisecond
	stall := make(chan struct{})
	managed := managedFile(t, trustAcme)
	wait := func(p string) {
		if p == managed {
			<-stall
		}
	}
	beforeOpen.Store(&wait)
	t.Cleanup(func() { policyDeadline = old; beforeOpen.Store(nil); close(stall) })
	dir := workspace(t, "git@github.com:acme/app.git", "")
	if form, stderr := runTimed(t, "", managed, codexInputIn(dir, "npm i @acme/cli"), nil); form != "hold" || !strings.Contains(stderr, "in time") {
		t.Errorf("a stalled organisation's file: %s (stderr %q)", form, stderr)
	}
}

// fakeInfo is a FileInfo with the owner and mode adminOwnedWith reads.
type fakeInfo struct {
	mode os.FileMode
	uid  uint32
}

func (f fakeInfo) Name() string       { return "x" }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() os.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return &syscall.Stat_t{Uid: f.uid} }

// Round 5: adminOwned with a stat the test gives — root's, writable by nobody else, for the file and its folder; a
// group-writable entry (the 0o022 mask, not 0o002 alone) is not the administrator's.
func TestRound5AdminOwnedModes(t *testing.T) {
	for _, c := range []struct {
		name      string
		file, dir fakeInfo
		ok        bool
	}{
		{"root's, 0644 in 0755", fakeInfo{0o644, 0}, fakeInfo{os.ModeDir | 0o755, 0}, true},
		{"group-writable file", fakeInfo{0o664, 0}, fakeInfo{os.ModeDir | 0o755, 0}, false},
		{"world-writable file", fakeInfo{0o646, 0}, fakeInfo{os.ModeDir | 0o755, 0}, false},
		{"group-writable folder", fakeInfo{0o644, 0}, fakeInfo{os.ModeDir | 0o775, 0}, false},
		{"world-writable folder", fakeInfo{0o644, 0}, fakeInfo{os.ModeDir | 0o757, 0}, false},
		{"a user's file", fakeInfo{0o644, 501}, fakeInfo{os.ModeDir | 0o755, 0}, false},
		{"a user's folder", fakeInfo{0o644, 0}, fakeInfo{os.ModeDir | 0o755, 501}, false},
	} {
		stat := func(p string) (os.FileInfo, error) {
			if p == "/etc/alalanet/policy.yml" {
				return c.file, nil
			}
			return c.dir, nil
		}
		if err := adminOwnedWith(stat, "/etc/alalanet/policy.yml"); (err == nil) != c.ok {
			t.Errorf("%s: %v, want ok=%v", c.name, err, c.ok)
		}
	}
}
