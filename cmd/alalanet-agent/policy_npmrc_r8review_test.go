//go:build unix

package main

// Independent re-review of 17afb8d (REPO-POL-NPMRC round 8, ADR-0174 round 13), 2026-11-15: proof tests. A failing
// case is a finding: after the pin, a file the shell runs or a tool config changes where the install comes from (or
// runs code in it), and the exception still covers the hold; or, for the false-hold case, a normal user's
// policy-approve leaves a hold that never clears.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// r8other is a folder with its own package.json and an .npmrc naming another registry: a cd there moves npm.
func r8other(t *testing.T) string {
	t.Helper()
	other := t.TempDir()
	write(t, filepath.Join(other, "package.json"), "{}\n")
	write(t, filepath.Join(other, ".npmrc"), "registry=https://evil.example/\n")
	return other
}

// R8-1: files the pinned startup files source (uv's installer adds `. "$HOME/.local/bin/env"`; oh-my-zsh, nvm,
// cargo, a completion script on this Mac) are not pinned: changing one after the pin is silent.
func TestR8ReviewSourcedByStartupFile(t *testing.T) {
	_, _, cwd := npmWorkspace(t)
	home := t.TempDir()
	mkdir(t, filepath.Join(home, ".local", "bin"))
	write(t, filepath.Join(home, ".zshenv"), ". \"$HOME/.local/bin/env\"\n")
	write(t, filepath.Join(home, ".local", "bin", "env"), "case \":${PATH}:\" in *:\"$HOME/.local/bin\":*) ;; *) export PATH=\"$HOME/.local/bin:$PATH\" ;; esac\n")
	other := r8other(t)
	form, stderr := r13pinned(t, cwd, "echo hi && npm i @acme/cli", home, func() {
		write(t, filepath.Join(home, ".local", "bin", "env"), "echo() { builtin cd "+other+"; }\n")
	})
	if form == "silent" {
		t.Errorf("a file .zshenv sources, changed after the pin: an exception covers it (stderr %q)", stderr)
	}
}

// R8-2: ZDOTDIR set in ~/.zshenv (the usual XDG setup), not in the hook's environment (a runtime started from the
// Dock): zsh reads $ZDOTDIR/.zprofile, .zshrc, .zlogin, none of which startupList names.
func TestR8ReviewZdotdirFromZshenv(t *testing.T) {
	_, _, cwd := npmWorkspace(t)
	home := t.TempDir()
	mkdir(t, filepath.Join(home, ".config", "zsh"))
	write(t, filepath.Join(home, ".zshenv"), "export ZDOTDIR=\"$HOME/.config/zsh\"\n")
	other := r8other(t)
	form, stderr := r13pinned(t, cwd, "echo hi && npm i @acme/cli", home, func() {
		write(t, filepath.Join(home, ".config", "zsh", ".zprofile"), "echo() { builtin cd "+other+"; }\n")
	})
	if form == "silent" {
		t.Errorf("$ZDOTDIR/.zprofile (ZDOTDIR from .zshenv), written after the pin: an exception covers it (stderr %q)", stderr)
	}
}

// R8-3: BASH_ENV in the hook's environment: a non-interactive bash (bash -c in the line, npm's scripts) runs that file;
// it is not in startupList.
func TestR8ReviewBashEnvTarget(t *testing.T) {
	_, _, cwd := npmWorkspace(t)
	home := t.TempDir()
	benv := filepath.Join(home, ".bash_env")
	write(t, benv, "shopt -s expand_aliases\n")
	dir := filepath.Join(t.TempDir(), "pin")
	pf := func() *policyFiles {
		p := npmrcFiles(t, "", home, []string{"BASH_ENV=" + benv}, nil)
		p.pinDir = func() (string, error) { return dir, nil }
		return p
	}
	if why := registryMoved(pf(), cwd, "npm i @acme/cli", []string{"npm:@acme/cli"}); why != "" {
		t.Fatalf("before: %s", why)
	}
	write(t, benv, "export PATH=\"/srv/evil/bin:$PATH\"\n")
	if why := registryMoved(pf(), cwd, "npm i @acme/cli", []string{"npm:@acme/cli"}); why == "" {
		t.Errorf("the BASH_ENV file, changed after the pin: nothing moved")
	}
}

// R8-4: fish's autoloaded functions (~/.config/fish/functions/<name>.fish, read when <name> runs) and universal
// variables (fish_variables, set -Ux) are not pinned.
func TestR8ReviewFishFunctionsAndVariables(t *testing.T) {
	for _, c := range []struct{ name, file, body string }{
		{"an autoloaded echo function", filepath.Join(".config", "fish", "functions", "echo.fish"), "function echo\n  builtin cd @OTHER@\nend\n"},
		{"a universal PATH", filepath.Join(".config", "fish", "fish_variables"), "SETUVAR --export fish_user_paths:/srv/evil/bin\n"},
	} {
		_, _, cwd := npmWorkspace(t)
		home := t.TempDir()
		mkdir(t, filepath.Join(home, ".config", "fish", "functions"))
		write(t, filepath.Join(home, ".config", "fish", "config.fish"), "set -g fish_greeting\n")
		other := r8other(t)
		form, stderr := r13pinned(t, cwd, "echo hi && npm i @acme/cli", home, func() {
			write(t, filepath.Join(home, c.file), strings.ReplaceAll(c.body, "@OTHER@", other))
		})
		if form == "silent" {
			t.Errorf("%s, after the pin: an exception covers it (stderr %q)", c.name, stderr)
		}
	}
}

// R8-5: the pin is deleted (one rm, a cache cleanup): the next check is a first use and pins the hostile state; the hook
// does not hold a line that removes the pin.
func TestR8ReviewPinDeleted(t *testing.T) {
	_, _, cwd := npmWorkspace(t)
	home := t.TempDir()
	write(t, filepath.Join(home, ".zshrc"), "alias ll='ls -l'\n")
	dir := filepath.Join(t.TempDir(), "alalanet", "policy")
	if why := why13(t, cwd, home, dir); why != "" {
		t.Fatalf("first use: %s", why)
	}
	other := r8other(t)
	write(t, filepath.Join(home, ".zshrc"), "echo() { builtin cd "+other+"; }\n")
	if why := why13(t, cwd, home, dir); why == "" {
		t.Fatalf("changed after the pin: nothing moved")
	}
	for _, line := range []string{"rm -f ~/.cache/alalanet/policy/startup-pin.json", "rm -rf ~/.cache"} {
		if approvesPolicy(line) {
			continue
		}
		t.Logf("%q is not held by the hook's policy-approve rule", line)
	}
	if err := os.Remove(filepath.Join(dir, pinName)); err != nil {
		t.Fatal(err)
	}
	if why := why13(t, cwd, home, dir); why == "" {
		t.Errorf("the pin deleted, then the same changed .zshrc: a first use, the exception covers it")
	}
}

// R8-6 (false hold): policy-approve runs in the user's terminal, whose environment has ZDOTDIR (exported by .zshenv);
// the runtime, started from the Dock, has not. The pin names $ZDOTDIR/.zshrc; the hook does not list it, so it reads
// as gone — a hold that policy-approve, run again, cannot clear.
func TestR8ReviewApproveEnvMismatch(t *testing.T) {
	_, _, cwd := npmWorkspace(t)
	home := t.TempDir()
	z := filepath.Join(home, ".config", "zsh")
	mkdir(t, z)
	write(t, filepath.Join(z, ".zshrc"), "PS1=x\n")
	dir := filepath.Join(t.TempDir(), "pin")
	terminal := npmrcFiles(t, "", home, []string{"ZDOTDIR=" + z}, nil)
	terminal.pinDir = func() (string, error) { return dir, nil }
	var out bytes.Buffer
	if err := policyApprove(&out, terminal, (&codeTTY{}).open); err != nil {
		t.Fatal(err)
	}
	if why := why13(t, cwd, home, dir); why != "" {
		t.Errorf("after the user's policy-approve, the hook without ZDOTDIR: %q", why)
	}
}

// R8-7: tool configs that run a program during the install — they are "parsed in full", but these keys are not judged.
func TestR8ReviewToolConfigsRunCode(t *testing.T) {
	// pip.conf's [global] python: pip runs that program in place of itself (checked: pip 26.3, PIP_CONFIG_FILE with
	// python = <script> — `pip list` ran the script with pip's runner as its argument)
	_, _, cwd := npmWorkspace(t)
	home := t.TempDir()
	mkdir(t, filepath.Join(home, ".config", "pip"))
	write(t, filepath.Join(home, ".config", "pip", "pip.conf"), "[global]\npython = /srv/evil/bin/python\n")
	if form, stderr := round7(t, cwd, "pip install acme-tools==2.0.1", npmrcFiles(t, "", home, nil, nil)); form == "silent" {
		t.Errorf("pip.conf python = …: an exception covers it (stderr %q)", stderr)
	}
	// .npmrc script-shell and node-options: the dependencies' install scripts run under them (checked: npm 10.8.2 ran a
	// file: dependency's postinstall through the .npmrc's script-shell); git: the program for git dependencies
	for _, body := range []string{"script-shell=/srv/evil/sh\n", "node-options=--require /srv/evil/hook.js\n", "git=/srv/evil/git\n"} {
		_, root, cwd := npmWorkspace(t)
		write(t, filepath.Join(root, ".npmrc"), body)
		if form, stderr := round7(t, cwd, "npm i @acme/cli", nil); form == "silent" {
			t.Errorf(".npmrc %q: an exception covers it (stderr %q)", strings.TrimSpace(body), stderr)
		}
	}
	// mise: [env] _.path and PATH put another npm or pip first; [hooks] run shell code when mise is activated
	for _, body := range []string{
		"[env]\n_.path = [\"/srv/evil/bin\"]\n",
		"[env]\nPATH = \"/srv/evil/bin:{{env.PATH}}\"\n",
		"[hooks]\nenter = \"cd /srv/evil\"\n",
	} {
		_, _, cwd := npmWorkspace(t)
		write(t, filepath.Join(cwd, "mise.toml"), body)
		if form, stderr := round7(t, cwd, "npm i @acme/cli", nil); form == "silent" {
			t.Errorf("mise.toml %q: an exception covers it (stderr %q)", strings.TrimSpace(body), stderr)
		}
	}
}
