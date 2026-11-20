//go:build unix

package main

// REPO-POL-NPMRC round 8 (ADR-0174 round 13): the shell startup files' pin (startpin.go), policy-approve, and the hold
// of a line that may run it.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

// pinned is npmrcFiles with home and a pin in dir.
func pinned(t *testing.T, home, dir string) *policyFiles {
	t.Helper()
	pf := npmrcFiles(t, "", home, nil, nil)
	pf.pinDir = func() (string, error) { return dir, nil }
	return pf
}

// r13pinned runs command once with home as it is (which pins it: it must be silent), then change, then again with the
// same pin: the second run's answer.
func r13pinned(t *testing.T, cwd, command, home string, change func()) (form, stderr string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "pin")
	if form, stderr := round7(t, cwd, command, pinned(t, home, dir)); form != "silent" {
		t.Fatalf("%s, before the change: %s (stderr %q)", command, form, stderr)
	}
	change()
	return round7(t, cwd, command, pinned(t, home, dir))
}

// why13 is registryMoved for an npm target with home and the pin in dir.
func why13(t *testing.T, cwd, home, dir string) string {
	t.Helper()
	return registryMoved(pinned(t, home, dir), cwd, "npm i @acme/cli", []string{"npm:@acme/cli"})
}

func TestRound13PinFirstUse(t *testing.T) {
	_, _, cwd := npmWorkspace(t)
	home := t.TempDir()
	write(t, filepath.Join(home, ".zshrc"), "export SECRET_MARK=s3cr3t-value\n")
	dir := filepath.Join(t.TempDir(), "state", "pin")
	if why := why13(t, cwd, home, dir); why != "" {
		t.Fatalf("first use: %s", why)
	}
	fi, err := os.Stat(filepath.Join(dir, pinName))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("the pin's mode is %v", fi.Mode().Perm())
	}
	if di, _ := os.Stat(dir); di.Mode().Perm() != 0o700 {
		t.Errorf("the pin folder's mode is %v", di.Mode().Perm())
	}
	b, _ := os.ReadFile(filepath.Join(dir, pinName))
	if bytes.Contains(b, []byte("s3cr3t")) || bytes.Contains(b, []byte("SECRET_MARK")) {
		t.Errorf("the pin keeps a file's bytes: %s", b)
	}
	var p startPin
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	if p.Files[filepath.Join(home, ".zshenv")] != pinAbsent || !hex64(p.Files[filepath.Join(home, ".zshrc")]) {
		t.Errorf("the pin: %v", p.Files)
	}
	if _, err := os.Stat(filepath.Join(dir, pinLockName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the lock is left behind: %v", err)
	}
	if why := why13(t, cwd, home, dir); why != "" {
		t.Errorf("nothing changed: %s", why)
	}
}

func TestRound13PinChanges(t *testing.T) {
	for _, c := range []struct {
		name   string
		before func(t *testing.T, home string)
		change func(t *testing.T, home string) string // the path the reason must name
		what   string
	}{
		{"a file changed", func(t *testing.T, h string) { write(t, filepath.Join(h, ".zshrc"), "alias ll='ls -l'\n") },
			func(t *testing.T, h string) string {
				write(t, filepath.Join(h, ".zshrc"), "alias ll='ls -la'\n")
				return filepath.Join(h, ".zshrc")
			}, "changed"},
		{"a file appeared", func(t *testing.T, h string) {}, func(t *testing.T, h string) string {
			write(t, filepath.Join(h, ".zshenv"), "\n")
			return filepath.Join(h, ".zshenv")
		}, "appeared"},
		{"a file is gone", func(t *testing.T, h string) { write(t, filepath.Join(h, ".bashrc"), "set -o vi\n") },
			func(t *testing.T, h string) string {
				if err := os.Remove(filepath.Join(h, ".bashrc")); err != nil {
					t.Fatal(err)
				}
				return filepath.Join(h, ".bashrc")
			}, "is gone"},
		{"a new conf.d file", func(t *testing.T, h string) { mkdir(t, filepath.Join(h, ".config", "fish", "conf.d")) },
			func(t *testing.T, h string) string {
				write(t, filepath.Join(h, ".config", "fish", "conf.d", "x.fish"), "set -x A b\n")
				return filepath.Join(h, ".config", "fish", "conf.d", "x.fish")
			}, "appeared"},
		{"a conf.d file is gone", func(t *testing.T, h string) {
			mkdir(t, filepath.Join(h, ".config", "environment.d"))
			write(t, filepath.Join(h, ".config", "environment.d", "a.conf"), "A=b\n")
		}, func(t *testing.T, h string) string {
			if err := os.Remove(filepath.Join(h, ".config", "environment.d", "a.conf")); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(h, ".config", "environment.d", "a.conf")
		}, "is gone"},
		{"a link's target changed", func(t *testing.T, h string) {
			tgt := filepath.Join(t.TempDir(), "zshrc")
			write(t, tgt, "PS1=x\n")
			if err := os.Symlink(tgt, filepath.Join(h, ".zshrc")); err != nil {
				t.Fatal(err)
			}
		}, func(t *testing.T, h string) string {
			tgt, _ := os.Readlink(filepath.Join(h, ".zshrc"))
			write(t, tgt, "PS1=y\n")
			return filepath.Join(h, ".zshrc")
		}, "changed"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, _, cwd := npmWorkspace(t)
			home := t.TempDir()
			c.before(t, home)
			dir := filepath.Join(t.TempDir(), "pin")
			if why := why13(t, cwd, home, dir); why != "" {
				t.Fatalf("before: %s", why)
			}
			pinBefore, _ := os.ReadFile(filepath.Join(dir, pinName))
			path := c.change(t, home)
			why := why13(t, cwd, home, dir)
			if !strings.HasPrefix(why, path+" is a shell startup file that "+c.what+" since") || !strings.Contains(why, "policy-approve") {
				t.Errorf("after: %q", why)
			}
			if strings.Contains(why, "ls -la") || strings.Contains(why, "set -x") {
				t.Errorf("the reason carries a file's bytes: %q", why)
			}
			if again := why13(t, cwd, home, dir); again != why {
				t.Errorf("the hold does not stay until policy-approve: %q", again)
			}
			if pinAfter, _ := os.ReadFile(filepath.Join(dir, pinName)); !bytes.Equal(pinBefore, pinAfter) {
				t.Errorf("the hook changed the pin")
			}
			// the exception does not apply, end to end
			if form, stderr := round7(t, cwd, "npm i @acme/cli", pinned(t, home, dir)); form != "hold" {
				t.Errorf("end to end: %s (stderr %q)", form, stderr)
			}
		})
	}
}

// First use trusts what is there (ADR-0174 round 13): a startup file already hostile when the pin is first taken is
// pinned as it is; the reader's own checks still judge its values. This test keeps that stated limit visible.
func TestRound13PinTrustsFirstUse(t *testing.T) {
	_, _, cwd := npmWorkspace(t)
	other := t.TempDir()
	home := t.TempDir()
	write(t, filepath.Join(home, ".zshenv"), "echo() { builtin cd "+other+"; }\n")
	if why := why13(t, cwd, home, filepath.Join(t.TempDir(), "pin")); why != "" {
		t.Errorf("first use is trusted by design; got %q", why)
	}
	// the value layer still applies at first use
	write(t, filepath.Join(home, ".zshenv"), "export npm_config_registry=https://evil.example/\n")
	if why := why13(t, cwd, home, filepath.Join(t.TempDir(), "pin")); why == "" {
		t.Errorf("a registry in .zshenv at first use is not judged")
	}
}

func TestRound13PinBroken(t *testing.T) {
	for _, c := range []struct {
		name string
		make func(t *testing.T, dir string)
	}{
		{"not JSON", func(t *testing.T, dir string) { write(t, filepath.Join(dir, pinName), "{cut") }},
		{"another version", func(t *testing.T, dir string) { write(t, filepath.Join(dir, pinName), `{"v":2,"files":{}}`) }},
		{"no files", func(t *testing.T, dir string) { write(t, filepath.Join(dir, pinName), `{"v":1}`) }},
		{"a relative path", func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, pinName), `{"v":1,"files":{"x/.zshrc":"absent"}}`)
		}},
		{"a bad sum", func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, pinName), `{"v":1,"files":{"/x/.zshrc":"abc"}}`)
		}},
		{"a link", func(t *testing.T, dir string) {
			tgt := filepath.Join(t.TempDir(), "p.json")
			write(t, tgt, `{"v":1,"files":{}}`)
			if err := os.Symlink(tgt, filepath.Join(dir, pinName)); err != nil {
				t.Fatal(err)
			}
		}},
		{"a FIFO", func(t *testing.T, dir string) {
			if err := syscall.Mkfifo(filepath.Join(dir, pinName), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, _, cwd := npmWorkspace(t)
			home := t.TempDir()
			dir := filepath.Join(t.TempDir(), "pin")
			mkdir(t, dir)
			c.make(t, dir)
			before, _ := os.Lstat(filepath.Join(dir, pinName))
			done := make(chan string, 1)
			go func() { done <- why13(t, cwd, home, dir) }()
			select {
			case why := <-done:
				if !strings.HasPrefix(why, filepath.Join(dir, pinName)+" does not load") {
					t.Errorf("%q", why)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("the pin's reading waits")
			}
			if after, _ := os.Lstat(filepath.Join(dir, pinName)); !os.SameFile(before, after) || after.ModTime() != before.ModTime() {
				t.Errorf("a broken pin was overwritten")
			}
		})
	}
}

func TestRound13PinLock(t *testing.T) {
	old := pinLockWait
	pinLockWait = 30 * time.Millisecond
	t.Cleanup(func() { pinLockWait = old })
	_, _, cwd := npmWorkspace(t)
	home := t.TempDir()
	dir := filepath.Join(t.TempDir(), "pin")
	mkdir(t, dir)
	lock := filepath.Join(dir, pinLockName)
	write(t, lock, "someone-else")
	if why := why13(t, cwd, home, dir); !strings.Contains(why, "could not be compared with their pin (its lock: held by another alalanet-agent)") {
		t.Errorf("a held lock: %q", why)
	}
	if b, _ := os.ReadFile(lock); string(b) != "someone-else" {
		t.Errorf("another's live lock was taken")
	}
	if _, err := os.Stat(filepath.Join(dir, pinName)); err == nil {
		t.Errorf("pinned without the lock")
	}
	stale := time.Now().Add(-time.Minute)
	if err := os.Chtimes(lock, stale, stale); err != nil {
		t.Fatal(err)
	}
	if why := why13(t, cwd, home, dir); why != "" {
		t.Errorf("a stale lock is not broken: %q", why)
	}
	if _, err := os.Stat(filepath.Join(dir, pinName)); err != nil {
		t.Errorf("not pinned after a stale lock: %v", err)
	}
}

func TestRound13PinUnwritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes a read-only folder")
	}
	_, _, cwd := npmWorkspace(t)
	home := t.TempDir()
	// pinLock makes its own folder 0700: the folder above it is what cannot be written here
	parent := t.TempDir()
	pf := pinned(t, home, filepath.Join(parent, "pin"))
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })
	if why := registryMoved(pf, cwd, "npm i @acme/cli", []string{"npm:@acme/cli"}); !strings.HasPrefix(why, "the shell startup files ") {
		t.Errorf("an unwritable pin: %q", why)
	}
	pf.pinDir = func() (string, error) { return "", errors.New("no home") }
	if why := registryMoved(pf, cwd, "npm i @acme/cli", []string{"npm:@acme/cli"}); why != "the shell startup files cannot be pinned: alalanet-agent has no folder for its state" {
		t.Errorf("no pin folder: %q", why)
	}
}

// A startup file another reader read first (here as pip's config file, by PIP_CONFIG_FILE): the pin takes the file
// all the same, not as absent.
func TestRound13PinFileReadBefore(t *testing.T) {
	_, _, cwd := npmWorkspace(t)
	home := t.TempDir()
	zshrc := filepath.Join(home, ".zshrc")
	write(t, zshrc, "# nothing\n")
	dir := filepath.Join(t.TempDir(), "pin")
	pf := npmrcFiles(t, "", home, []string{"PIP_CONFIG_FILE=" + zshrc}, nil)
	pf.pinDir = func() (string, error) { return dir, nil }
	if why := registryMoved(pf, cwd, "pip install acme-tools==2.0.1", []string{"pypi:acme-tools"}); why != "" {
		t.Fatal(why)
	}
	if p, err := loadPin(dir); err != nil || p == nil || !hex64(p.Files[zshrc]) {
		t.Errorf("a startup file read before was not pinned by its sum: %v %v", p, err)
	}
}

// codeTTY is a terminal: what is typed is the code it shows (or wrong), after before runs.
type codeTTY struct {
	screen bytes.Buffer
	wrong  bool
	before func()
	done   bool
}

var shownCode = regexp.MustCompile(`Type ([A-Z0-9]{6}) and Enter`)

func (c *codeTTY) Read(p []byte) (int, error) {
	if c.done {
		return 0, io.EOF
	}
	c.done = true
	if c.before != nil {
		c.before()
	}
	m := shownCode.FindStringSubmatch(c.screen.String())
	code := "NOCODE"
	if m != nil && !c.wrong {
		code = m[1]
	}
	return copy(p, code+"\n"), nil
}

func (c *codeTTY) open() (io.Reader, io.Writer, func(), error) { return c, &c.screen, func() {}, nil }

func TestRound13PolicyApprove(t *testing.T) {
	_, _, cwd := npmWorkspace(t)
	home := t.TempDir()
	write(t, filepath.Join(home, ".zshrc"), "PS1=x\n")
	dir := filepath.Join(t.TempDir(), "pin")
	pf := pinned(t, home, dir)
	if why := why13(t, cwd, home, dir); why != "" {
		t.Fatal(why)
	}
	write(t, filepath.Join(home, ".zshrc"), "PS1=y # secret-bytes\n")
	mkdir(t, filepath.Join(home, ".config", "fish", "conf.d"))
	odd := filepath.Join(home, ".config", "fish", "conf.d", "x\x1b[2J.fish")
	write(t, odd, "\n")
	var out bytes.Buffer
	// no terminal
	if err := policyApprove(&out, pf, func() (io.Reader, io.Writer, func(), error) { return nil, nil, nil, os.ErrNotExist }); err == nil ||
		!strings.Contains(err.Error(), "no terminal") && !strings.Contains(err.Error(), "there is none") {
		t.Errorf("without a terminal: %v", err)
	}
	// the wrong code
	tty := &codeTTY{wrong: true}
	if err := policyApprove(&out, pf, tty.open); err == nil {
		t.Errorf("a wrong code was accepted")
	}
	if why := why13(t, cwd, home, dir); !strings.Contains(why, "policy-approve") {
		t.Errorf("after a wrong code: %q", why)
	}
	screen := tty.screen.String()
	if !strings.Contains(screen, "changed: "+filepath.Join(home, ".zshrc")) || strings.Contains(screen, "secret-bytes") {
		t.Errorf("the screen: %q", screen)
	}
	if strings.Contains(screen, "\x1b") || !strings.Contains(screen, `\x1b[2J.fish`) {
		t.Errorf("a control byte in a path reaches the terminal: %q", screen)
	}
	// a file that changes while the paths are shown is not pinned unseen
	tty = &codeTTY{before: func() { write(t, filepath.Join(home, ".zshrc"), "PS1=z\n") }}
	if err := policyApprove(&out, pf, tty.open); err == nil || !strings.Contains(err.Error(), "changed while") {
		t.Errorf("changed while shown: %v", err)
	}
	// the right code
	out.Reset()
	tty = &codeTTY{}
	if err := policyApprove(&out, pf, tty.open); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), home) || !strings.Contains(out.String(), "pinned") {
		t.Errorf("stdout: %q", out.String())
	}
	if why := why13(t, cwd, home, dir); why != "" {
		t.Errorf("after policy-approve: %q", why)
	}
	if fi, _ := os.Stat(filepath.Join(dir, pinName)); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	// nothing to accept
	out.Reset()
	tty = &codeTTY{}
	if err := policyApprove(&out, pf, tty.open); err != nil || !strings.Contains(out.String(), "nothing to accept") || tty.done {
		t.Errorf("nothing changed: %v %q", err, out.String())
	}
	// a broken pin is replaced through the terminal only
	write(t, filepath.Join(dir, pinName), "{cut")
	tty = &codeTTY{}
	if err := policyApprove(&out, pf, tty.open); err != nil || !strings.Contains(tty.screen.String(), "does not load") {
		t.Errorf("a broken pin: %v %q", err, tty.screen.String())
	}
	if why := why13(t, cwd, home, dir); why != "" {
		t.Errorf("after replacing a broken pin: %q", why)
	}
	// a startup file that cannot be read is not pinned
	if err := os.Remove(filepath.Join(home, ".zshrc")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(home, ".zshrc"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := policyApprove(&out, pf, (&codeTTY{}).open); err == nil || !strings.Contains(err.Error(), "cannot be pinned") {
		t.Errorf("a FIFO: %v", err)
	}
}

func TestRound13ApproveLineHeld(t *testing.T) {
	for _, line := range []string{
		"alalanet-agent policy-approve",
		"~/.local/bin/alalanet-agent policy-approve < /dev/null",
		`alalanet-agent "policy-ap"'prove'`,
		`alalanet-agent policy\-approve`,
		"grep -n policy-approve README.md",
		"alalanet-agent policy-$X",
		"alalanet-agent policy-`echo approve`",
		"x=approve; alalanet-agent policy-$x",
		"script -q /dev/null alalanet-agent anything",
		"ALALANET=1 unbuffer alalanet-agent x",
		"alalanet-agent policy-approve && npm i @acme/cli",
		`alalanet-agent "$(printf policy)-approve"`,
	} {
		if !approvesPolicy(line) {
			t.Errorf("%s: not held", line)
		}
	}
	for _, line := range []string{"npm i @acme/cli", "echo approve", "alalanet-agent version", "git commit -m policy"} {
		if approvesPolicy(line) {
			t.Errorf("%s: held", line)
		}
	}
	// end to end: the hook holds it whatever else the line is, and says why
	_, _, cwd := npmWorkspace(t)
	f := &fakeHook{}
	srv := f.server(t)
	var o bytes.Buffer
	if err := runHook("codex", strings.NewReader(codexInputIn(cwd, "alalanet-agent policy-approve")), &o, srv.Client(), srv.URL); err != nil {
		t.Fatal(err)
	}
	if answerForm(t, "codex", o.String()) != "hold" || !strings.Contains(o.String(), "policy-approve") {
		t.Errorf("the hook: %s", o.String())
	}
}

// P3: each template's bytes are parsed once (CPython 3.13, 3.14 and 3.15 are one file's bytes).
func TestRound13TemplatesOnce(t *testing.T) {
	seen := map[string]bool{}
	for _, tm := range templates {
		if seen[tm.name] {
			t.Errorf("%s parsed twice", tm.name)
		}
		seen[tm.name] = true
	}
	if len(templates) != len(activateTemplates) {
		t.Errorf("%d templates for %d sums", len(templates), len(activateTemplates))
	}
}

// R7-2 with a known home: ~+, ~- and ~user are never read as the home's; ~/ without a known home is not placed.
func TestRound13TildeForms(t *testing.T) {
	const evil = "export npm_config_registry=https://evil.example/\n"
	for _, cmd := range []string{"source ~+/e/bin/activate && npm i @acme/cli", "source ~-/e/bin/activate && npm i @acme/cli",
		"source ~root/e/bin/activate && npm i @acme/cli", "source ~/e/bin/activate && npm i @acme/cli"} {
		_, _, cwd := npmWorkspace(t)
		home := t.TempDir()
		mkdir(t, filepath.Join(cwd, "e", "bin"))
		write(t, filepath.Join(cwd, "e", "bin", "activate"), evil)
		pf := npmrcFiles(t, "", home, nil, nil)
		if strings.HasPrefix(cmd, "source ~/") {
			pf.home = nil // the home folder is not known
		}
		if form, stderr := round7(t, cwd, cmd, pf); form != "hold" {
			t.Errorf("%s: %s (stderr %q)", cmd, form, stderr)
		}
	}
}

// A startup file the pin did not name and that is not there (ZDOTDIR set since the pin) is no change; one that is
// there appeared.
func TestRound13PinNewPathAbsent(t *testing.T) {
	_, _, cwd := npmWorkspace(t)
	home := t.TempDir()
	dir := filepath.Join(t.TempDir(), "pin")
	if why := why13(t, cwd, home, dir); why != "" {
		t.Fatal(why)
	}
	z := t.TempDir()
	pf := npmrcFiles(t, "", home, []string{"ZDOTDIR=" + z}, nil)
	pf.pinDir = func() (string, error) { return dir, nil }
	if why := registryMoved(pf, cwd, "npm i @acme/cli", []string{"npm:@acme/cli"}); why != "" {
		t.Errorf("an empty ZDOTDIR: %q", why)
	}
	write(t, filepath.Join(z, ".zshrc"), "\n")
	if why := registryMoved(pf, cwd, "npm i @acme/cli", []string{"npm:@acme/cli"}); !strings.HasPrefix(why, filepath.Join(z, ".zshrc")+" is a shell startup file that appeared") {
		t.Errorf("a file in ZDOTDIR: %q", why)
	}
}

// A pin that cannot be written (more paths than a pin keeps) is no first use.
func TestRound13PinNotWritten(t *testing.T) {
	old := maxPinned
	maxPinned = 2
	t.Cleanup(func() { maxPinned = old })
	_, _, cwd := npmWorkspace(t)
	dir := filepath.Join(t.TempDir(), "pin")
	if why := why13(t, cwd, t.TempDir(), dir); why != "the shell startup files could not be pinned (the pin could not be written)" {
		t.Errorf("%q", why)
	}
}
