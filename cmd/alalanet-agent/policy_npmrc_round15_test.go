//go:build unix

package main

// REPO-POL-NPMRC round 10 (ADR-0174 round 15): snapshot tombstones, what picks uv's and mise's programs, a source of
// a process substitution, fish_variables by content, the reason for a startup file the runtime cannot read.

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func snapName(t time.Time) string {
	return fmt.Sprintf("019a0000-0000-7000-8000-000000000000.%d.sh", t.UnixNano())
}

func TestRound15SnapshotTombstones(t *testing.T) {
	_, _, cwd := npmWorkspace(t)
	home := t.TempDir()
	snaps := filepath.Join(home, ".codex", "shell_snapshots")
	mkdir(t, snaps)
	dir := filepath.Join(t.TempDir(), "pin")
	if why := r14(t, cwd, home, dir, nil, false); why != "" {
		t.Fatal(why)
	}
	now := time.Now()
	snap := filepath.Join(snaps, snapName(now))
	write(t, snap, "PS1=x\n")
	if why := r14(t, cwd, home, dir, nil, false); why != "" {
		t.Fatalf("a new snapshot: %q", why)
	}
	if err := os.Remove(snap); err != nil {
		t.Fatal(err)
	}
	if why := r14(t, cwd, home, dir, nil, false); why != "" {
		t.Fatalf("gone: %q", why)
	}
	write(t, snap, "echo() { builtin cd /x; }\n")
	if why := r14(t, cwd, home, dir, nil, false); !strings.HasPrefix(why, snap+" is a shell startup file that appeared again") {
		t.Errorf("written again under its name: %q", why)
	}
	// policy-approve pins it as it is now
	pf := npmrcFiles(t, "", home, nil, nil)
	pf.pinDir = func() (string, error) { return dir, nil }
	if err := policyApprove(&bytes.Buffer{}, pf, (&codeTTY{}).open); err != nil {
		t.Fatal(err)
	}
	if why := r14(t, cwd, home, dir, nil, false); why != "" {
		t.Errorf("after policy-approve: %q", why)
	}
	// past the horizon the tombstone is dropped: the name is too old to be new anyway
	if err := os.Remove(snap); err != nil {
		t.Fatal(err)
	}
	_ = r14(t, cwd, home, dir, nil, false) // the tombstone
	old := pinNow
	pinNow = func() time.Time { return now.Add(snapshotHorizon + time.Hour) }
	t.Cleanup(func() { pinNow = old })
	_ = r14(t, cwd, home, dir, nil, false) // pruned
	if p, _ := loadPin(dir); p == nil || p.Files[snap] != "" {
		t.Errorf("the tombstone is kept past the horizon: %v", p)
	}
	write(t, snap, "PS1=x\n")
	if why := r14(t, cwd, home, dir, nil, false); !strings.HasPrefix(why, snap+" is a shell startup file that appeared") {
		t.Errorf("an old name, new: %q", why)
	}
	pinNow = old
	// names Codex does not write now: from the future, without a time
	for _, n := range []string{snapName(now.Add(3 * time.Hour)), "019a.sh", "x.notatime.sh"} {
		home := t.TempDir()
		mkdir(t, filepath.Join(home, ".codex", "shell_snapshots"))
		dir := filepath.Join(t.TempDir(), "pin")
		if why := r14(t, cwd, home, dir, nil, false); why != "" {
			t.Fatal(why)
		}
		p := filepath.Join(home, ".codex", "shell_snapshots", n)
		write(t, p, "PS1=x\n")
		if why := r14(t, cwd, home, dir, nil, false); !strings.HasPrefix(why, p+" is a shell startup file that appeared") {
			t.Errorf("%s: %q", n, why)
		}
	}
	for _, line := range []string{"rm ~/.codex/shell_snapshots/*", "CODEX_HOME=/tmp/x codex"} {
		if !touchesPin(line) {
			t.Errorf("%s: not held", line)
		}
	}
}

func TestRound15ProgramPickers(t *testing.T) {
	for _, c := range []struct{ name, file, body, command, want string }{
		{".python-versions path", ".python-versions", "3.12\n/x/bin/python\n", "uv add acme-tools==2.0.1", "hold"},
		{".python-version home path", ".python-version", "~/py/bin/python\n", "uv add acme-tools==2.0.1", "hold"},
		{".python-version version", ".python-version", "3.12\n", "uv add acme-tools==2.0.1", "silent"},
		{".python-version request", ".python-version", "# pinned from /usr/bin\ncpython@3.12.4\n", "uv add acme-tools==2.0.1", "silent"},
		{".python-version venv", ".python-version", ".venv\n", "uv add acme-tools==2.0.1", "hold"},
		{".envrc UV_PYTHON version", ".envrc", "export UV_PYTHON=3.12\n", "uv add acme-tools==2.0.1", "silent"},
		{".envrc UV_TOOL_DIR", ".envrc", "export UV_TOOL_DIR=/x\n", "uvx acme-tools --help", "hold"},
		{".envrc UV_ENV_FILE", ".envrc", "export UV_ENV_FILE=.env.x\n", "uv add acme-tools==2.0.1", "hold"},
		{".envrc UV_TORCH_BACKEND", ".envrc", "export UV_TORCH_BACKEND=auto\n", "uv add acme-tools==2.0.1", "hold"},
		{".envrc UV_PYTHON_DOWNLOADS_JSON_URL", ".envrc", "export UV_PYTHON_DOWNLOADS_JSON_URL=https://evil.example/x.json\n", "uv add acme-tools==2.0.1", "hold"},
		{".envrc PIP_KEYRING_PROVIDER", ".envrc", "export PIP_KEYRING_PROVIDER=subprocess\n", "pip install acme-tools==2.0.1", "hold"},
		{"mise tools table path", "mise.toml", "[tools]\nnode = { version = \"path:/x/node\" }\n", "npm i @acme/cli", "hold"},
		{"mise tools list path", "mise.toml", "[tools]\nnode = [\"22\", \"path:/x/node\"]\n", "npm i @acme/cli", "hold"},
		{"mise tools url", "mise.toml", "[tools]\n\"http:x\" = \"https://evil.example/x.tgz\"\n", "npm i @acme/cli", "hold"},
		{"mise tools versions", "mise.toml", "[tools]\nnode = [\"22\", \"20\"]\npython = { version = \"3.12\" }\n", "npm i @acme/cli", "silent"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, _, cwd := npmWorkspace(t)
			write(t, filepath.Join(cwd, c.file), c.body)
			if form, stderr := round7(t, cwd, c.command, nil); form != c.want {
				t.Errorf("%s, want %s (stderr %q)", form, c.want, stderr)
			}
		})
	}
	// uv's own folders and (round 16, R10-3) a path UV_PYTHON from the user's environment are the user's choice
	_, _, cwd := npmWorkspace(t)
	for env, want := range map[string]bool{"UV_TOOL_DIR=/opt/tools": false, "UV_PYTHON=/x/bin/python": false, "UV_PYTHON_INSTALL_MIRROR=https://m.example/": true} {
		why := registryMoved(npmrcFiles(t, "", "", []string{env}, nil), cwd, "uv add acme-tools==2.0.1", []string{"pypi:acme-tools"})
		if (why != "") != want {
			t.Errorf("the hook's environment %s: %q", env, why)
		}
	}
	// uv python pin --global
	home := t.TempDir()
	mkdir(t, filepath.Join(home, ".config", "uv"))
	write(t, filepath.Join(home, ".config", "uv", ".python-version"), "/x/bin/python\n")
	if why := registryMoved(npmrcFiles(t, "", home, nil, nil), cwd, "uv add acme-tools==2.0.1", []string{"pypi:acme-tools"}); !strings.Contains(why, ".python-version names the interpreter uv runs by its path") {
		t.Errorf("the global .python-version: %q", why)
	}
}

func TestRound15ProcessSubstitution(t *testing.T) {
	for _, form := range []string{". <(@P@)", "[ -x @P@ ] && source <( @P@ completion zsh )"} {
		home := t.TempDir()
		tool := filepath.Join(t.TempDir(), "tool")
		write(t, tool, "#!/bin/sh\n")
		write(t, filepath.Join(home, ".zshrc"), strings.ReplaceAll(form, "@P@", tool)+"\n")
		why := pinThenChange(t, home, nil, func() { write(t, tool, "#!/bin/sh\necho x\n") })
		if !strings.HasPrefix(why, tool+" is a shell startup file that changed") {
			t.Errorf("%s: %q", form, why)
		}
	}
}

func TestRound15FishVariables(t *testing.T) {
	const base = "# This file contains fish universal variable definitions.\n# VERSION: 3.0\nSETUVAR __fish_initialized:3800\nSETUVAR fish_color_command:blue\nSETUVAR fish_user_paths:/opt/homebrew/bin\n"
	fv := func(home string) string { return filepath.Join(home, ".config", "fish", "fish_variables") }
	setup := func() string {
		home := t.TempDir()
		mkdir(t, filepath.Join(home, ".config", "fish"))
		write(t, fv(home), base)
		return home
	}
	// a prompt's state changes: no hold
	home := setup()
	if why := pinThenChange(t, home, nil, func() {
		write(t, fv(home), strings.ReplaceAll(base, "blue", "red")+"SETUVAR _tide_left_items:time\n")
	}); why != "" {
		t.Errorf("a prompt's universal variable: %q", why)
	}
	// fish_user_paths, fish_function_path, an exported variable: held
	for _, change := range []string{
		strings.ReplaceAll(base, "/opt/homebrew/bin", "/x/bin\\x1e/opt/homebrew/bin"),
		base + "SETUVAR fish_function_path:/x/functions\n",
		base + "SETUVAR --export EDITOR:vim\n",
	} {
		home := setup()
		if why := pinThenChange(t, home, nil, func() { write(t, fv(home), change) }); !strings.HasPrefix(why, fv(home)+" is a shell startup file that changed") {
			t.Errorf("%q: %q", change, why)
		}
	}
	// an exported registry, escaped as fish writes it: judged at first use too
	home = setup()
	write(t, fv(home), base+"SETUVAR --export npm_config_registry:https\\x3a//evil\\x2eexample/\n")
	_, _, cwd := npmWorkspace(t)
	if why := r14(t, cwd, home, filepath.Join(t.TempDir(), "pin"), nil, false); !strings.Contains(why, "sets the default registry") {
		t.Errorf("an exported registry: %q", why)
	}
	write(t, fv(home), base+"SETUVAR --export npm_config_registry:https\\x3a//registry\\x2enpmjs\\x2eorg/\n")
	if why := r14(t, cwd, home, filepath.Join(t.TempDir(), "pin"), nil, false); why != "" {
		t.Errorf("the public registry, escaped: %q", why)
	}
	if got := fishUnescape(`a\x3ab\\c\x1`); got != `a:b\c\x1` {
		t.Errorf("fishUnescape: %q", got)
	}
}

func TestRound15UnreadableStartupFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a file of mode 000")
	}
	home := t.TempDir()
	f := filepath.Join(home, ".zshrc")
	write(t, f, "PS1=x\n")
	if err := os.Chmod(f, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(f, 0o600) })
	_, _, cwd := npmWorkspace(t)
	if why := r14(t, cwd, home, filepath.Join(t.TempDir(), "pin"), nil, false); !strings.HasPrefix(why, f+" is a shell startup file this agent runtime cannot read (permission denied): give the runtime read access") {
		t.Errorf("%q", why)
	}
}
