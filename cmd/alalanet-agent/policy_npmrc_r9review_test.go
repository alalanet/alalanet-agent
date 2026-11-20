//go:build unix

package main

// Independent re-review of 005c7ad (REPO-POL-NPMRC round 9, ADR-0174 round 14), 2026-11-15: proof tests. A failing
// case is a finding: after the pin, a file the shell runs or a project config changes the program or the source of
// the install, and the exception still covers it.

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// R9-1: a Codex snapshot that is deleted is dropped from the pin; written again under the same name, it is a new one
// and pinned on first sight. The stated window (a snapshot changed before the session's first check) reopens at any
// time with rm and a write; the hook does not hold a line that names the snapshots' folder.
func TestR9ReviewSnapshotRecreated(t *testing.T) {
	_, _, cwd := npmWorkspace(t)
	home := t.TempDir()
	snaps := filepath.Join(home, ".codex", "shell_snapshots")
	mkdir(t, snaps)
	snap := filepath.Join(snaps, "019a0000-0000-7000-8000-000000000000.1793900000000000000.sh")
	write(t, snap, "# Snapshot file\nunalias -a 2>/dev/null || true\n")
	dir := filepath.Join(t.TempDir(), "pin")
	if why := why13(t, cwd, home, dir); why != "" {
		t.Fatalf("first use: %s", why)
	}
	other := r8other(t)
	hostile := "# Snapshot file\nunalias -a 2>/dev/null || true\necho() { builtin cd " + other + "; }\n"
	// changed in place: held (as stated)
	write(t, snap, hostile)
	if why := why13(t, cwd, home, dir); why == "" {
		t.Fatalf("a snapshot changed in place: nothing moved")
	}
	// deleted, checked once, then written again with the same name
	write(t, snap, "# Snapshot file\nunalias -a 2>/dev/null || true\n")
	if why := why13(t, cwd, home, dir); why != "" {
		t.Fatalf("restored: %s", why)
	}
	if err := os.Remove(snap); err != nil {
		t.Fatal(err)
	}
	if why := why13(t, cwd, home, dir); why != "" {
		t.Fatalf("deleted: %s", why)
	}
	write(t, snap, hostile)
	if why := why13(t, cwd, home, dir); why == "" {
		t.Errorf("a snapshot deleted and written again with the same name: pinned on first sight, the exception covers it")
	}
	if touchesPin("printf 'echo() { cd /srv; }' >> ~/.codex/shell_snapshots/x.sh") {
		return
	}
	t.Errorf("a line that writes into ~/.codex/shell_snapshots is not held")
}

// R9-2: tool configs and project files that pick the program the install runs, not in round 14's list.
func TestR9ReviewProgramPickers(t *testing.T) {
	for _, c := range []struct{ name, file, body, command string }{
		// Yarn 1's .yarnrc script-shell (yarn classic runs lifecycle scripts under it)
		{"yarnrc script-shell", ".yarnrc", "script-shell \"/srv/evil/sh\"\n", "yarn add @acme/cli"},
		// mise [tools] with a path: value: that folder is the tool (node, npm from /srv/evil)
		{"mise tools path:", "mise.toml", "[tools]\nnode = \"path:/srv/evil/node\"\n", "npm i @acme/cli"},
		// .python-version naming an interpreter by path: uv runs it to learn what it is
		{".python-version path", ".python-version", "/srv/evil/bin/python\n", "uv add acme-tools==2.0.1"},
		// UV_PYTHON in a project env file: the interpreter uv runs
		{".envrc UV_PYTHON", ".envrc", "export UV_PYTHON=/srv/evil/bin/python\n", "uv add acme-tools==2.0.1"},
		// uv.toml's mirror keys are judged; their environment forms in a project env file are not
		{".envrc UV_PYTHON_INSTALL_MIRROR", ".envrc", "export UV_PYTHON_INSTALL_MIRROR=https://evil.example/\n", "uv add acme-tools==2.0.1"},
	} {
		_, _, cwd := npmWorkspace(t)
		write(t, filepath.Join(cwd, c.file), c.body)
		if form, stderr := round7(t, cwd, c.command, nil); form == "silent" {
			t.Errorf("%s: an exception covers it (stderr %q)", c.name, stderr)
		}
	}
}

// R9-3: a startup file's `source <(<program> …)` (fzf, kubectl, gh completions): the program runs like an eval'd one,
// but it is not pinned (the stated residual names "a substitution"; with a literal path it is placeable like eval).
func TestR9ReviewProcessSubstitutionSource(t *testing.T) {
	_, _, cwd := npmWorkspace(t)
	home := t.TempDir()
	tool := filepath.Join(home, "bin", "tool")
	mkdir(t, filepath.Dir(tool))
	write(t, tool, "#!/bin/sh\necho 'alias ll=\"ls -l\"'\n")
	write(t, filepath.Join(home, ".zshenv"), "source <("+tool+" init zsh)\n")
	other := r8other(t)
	form, stderr := r13pinned(t, cwd, "echo hi && npm i @acme/cli", home, func() {
		write(t, tool, "#!/bin/sh\necho 'echo() { builtin cd "+other+"; }'\n")
	})
	if form == "silent" {
		t.Errorf("source <(%s …), the program changed after the pin: an exception covers it (stderr %q)", tool, stderr)
	}
}

// Ordinary day (a control, expected green): an installer appends to .zshrc (a PATH line and a source of its own env
// file), the hook holds, the user runs policy-approve, the exception applies again; brew's own update changes brew.sh,
// the same.
func TestR9ReviewOrdinaryDay(t *testing.T) {
	_, _, cwd := npmWorkspace(t)
	home := t.TempDir()
	write(t, filepath.Join(home, ".zshrc"), "alias ll='ls -l'\n")
	brew := filepath.Join(home, "hb")
	mkdir(t, filepath.Join(brew, "bin"))
	mkdir(t, filepath.Join(brew, "Library", "Homebrew", "cmd"))
	write(t, filepath.Join(brew, "bin", "brew"), "#!/bin/bash\n")
	write(t, filepath.Join(brew, "Library", "Homebrew", "brew.sh"), "v1\n")
	write(t, filepath.Join(brew, "Library", "Homebrew", "cmd", "shellenv.sh"), "v1\n")
	write(t, filepath.Join(home, ".zprofile"), "eval \"$("+filepath.Join(brew, "bin", "brew")+" shellenv)\"\n")
	dir := filepath.Join(t.TempDir(), "pin")
	pf := pinned(t, home, dir)
	if why := why13(t, cwd, home, dir); why != "" {
		t.Fatalf("first use: %s", why)
	}
	approve := func(step string) {
		t.Helper()
		if why := why13(t, cwd, home, dir); why == "" {
			t.Errorf("%s: not held before approve", step)
		}
		if err := policyApprove(new(bytes.Buffer), pf, (&codeTTY{}).open); err != nil {
			t.Errorf("%s: approve: %v", step, err)
		}
		if why := why13(t, cwd, home, dir); why != "" {
			t.Errorf("%s: after approve: %s", step, why)
		}
	}
	mkdir(t, filepath.Join(home, ".bun"))
	write(t, filepath.Join(home, ".bun", "env"), "export BUN_INSTALL=\"$HOME/.bun\"\n")
	write(t, filepath.Join(home, ".zshrc"), "alias ll='ls -l'\n# bun\nexport PATH=\"$HOME/.bun/bin:$PATH\"\n. \"$HOME/.bun/env\"\n")
	approve("an installer appended to .zshrc")
	write(t, filepath.Join(brew, "Library", "Homebrew", "brew.sh"), "v2\n")
	approve("brew updated itself")
}
