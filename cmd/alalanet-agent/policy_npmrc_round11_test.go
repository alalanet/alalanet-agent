//go:build unix

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// REPO-POL-NPMRC round 6 (ADR-0174 round 11, re-review of b35419f): a sourced script is accepted only as a known
// activate template, byte for byte once its venv's path and prompt are put back; helper-named functions and aliases
// in startup files count as moved.

// activateFrom: a template of activate/ (embedded) with its venv and prompt put back.
func activateFrom(t *testing.T, name, venv, prompt string) string {
	t.Helper()
	b, err := activateFS.ReadFile("activate/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(strings.ReplaceAll(string(b), "@VENV@", venv), "@PROMPT@", prompt)
}

// templateVenv makes cwd/.venv with the template's activate script and a pyvenv.cfg (a prompt for the -prompt ones).
func templateVenv(t *testing.T, cwd, name string) (venv string) {
	t.Helper()
	venv = filepath.Join(cwd, ".venv")
	mkdir(t, filepath.Join(venv, "bin"))
	cfg, prompt := "home = /usr/bin\n", ".venv"
	if strings.HasSuffix(name, "-prompt") {
		cfg, prompt = cfg+"prompt = proj\n", "proj"
	}
	write(t, filepath.Join(venv, "pyvenv.cfg"), cfg)
	write(t, filepath.Join(venv, "bin", "activate"), activateFrom(t, name, venv, prompt))
	return venv
}

// Every template in testdata is listed by its sha256, every listed sha256 has a template, and each template, put
// back, is silent for pip and npm and still reads its venv's pip.conf.
func TestRound11ActivateTemplates(t *testing.T) {
	ents, err := os.ReadDir(filepath.Join("activate"))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join("activate", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		h := hex.EncodeToString(sum[:])
		if _, ok := activateTemplates[h]; !ok {
			t.Errorf("activate/%s (%s) is no listed template", e.Name(), h)
		}
		seen[h] = true
		for _, c := range []struct{ conf, command, want string }{
			{"", "source .venv/bin/activate && pip install acme-tools==2.0.1", "silent"},
			{"", ". .venv/bin/activate && npm i @acme/cli", "silent"},
			{"[global]\nindex-url = https://evil.example/simple\n", "source .venv/bin/activate && pip install acme-tools==2.0.1", "hold"},
		} {
			_, _, cwd := npmWorkspace(t)
			venv := templateVenv(t, cwd, e.Name())
			if c.conf != "" {
				write(t, filepath.Join(venv, "pip.conf"), c.conf)
			}
			if form, stderr := round7(t, cwd, c.command, nil); form != c.want {
				t.Errorf("%s, %q: %s, want %s (stderr %q)", e.Name(), c.command, form, c.want, stderr)
			}
		}
	}
	for h, name := range activateTemplates {
		if !seen[h] {
			t.Errorf("%s (%s) has no template in activate/", name, h)
		}
	}
}

// A template that is not byte for byte its own: a line added or changed (T1 PATH, T2 SCRIPT_PATH, T3 a helper
// function), another venv's path, a script not in its venv's bin, a prompt this reader does not put back.
func TestRound11TamperedTemplates(t *testing.T) {
	for _, c := range []struct {
		name, template string
		tamper         func(t *testing.T, cwd, venv, body string) (file, body2 string)
	}{
		{"PATH to another folder (T1)", "uv-0.13.7-prompt", func(t *testing.T, cwd, venv, body string) (string, string) {
			return "", strings.Replace(body, `PATH="$VIRTUAL_ENV/bin:$PATH"`, `PATH="/srv/evil/bin:$PATH"`, 1)
		}},
		{"a line added at the end", "cpython-3.12.14", func(t *testing.T, cwd, venv, body string) (string, string) {
			return "", body + "export npm_config_registry=https://registry.npmjs.org/\n"
		}},
		{"SCRIPT_PATH set before the relocatable form (T2)", "uv-0.13.7-relocatable", func(t *testing.T, cwd, venv, body string) (string, string) {
			return "", strings.Replace(body, "\nVIRTUAL_ENV=", "\nSCRIPT_PATH=\"/srv/evil/bin/activate\"\nVIRTUAL_ENV=", 1)
		}},
		{"a cygpath function (T3)", "uv-0.13.7", func(t *testing.T, cwd, venv, body string) (string, string) {
			return "", "cygpath() { echo /srv/evil; }\n" + body
		}},
		{"another venv's path", "uv-0.13.7", func(t *testing.T, cwd, venv, body string) (string, string) {
			return "", strings.ReplaceAll(body, venv, "/srv/evil")
		}},
		{"a script outside its venv's bin", "uv-0.13.7", func(t *testing.T, cwd, venv, body string) (string, string) {
			return filepath.Join(venv, "activate"), body
		}},
		{"one comment changed", "cpython-3.15.2", func(t *testing.T, cwd, venv, body string) (string, string) {
			return "", strings.Replace(body, "#", "# x", 1)
		}},
	} {
		_, _, cwd := npmWorkspace(t)
		venv := templateVenv(t, cwd, c.template)
		body, err := os.ReadFile(filepath.Join(venv, "bin", "activate"))
		if err != nil {
			t.Fatal(err)
		}
		file, body2 := c.tamper(t, cwd, venv, string(body))
		command := "source .venv/bin/activate && pip install acme-tools==2.0.1"
		if file != "" {
			write(t, file, body2)
			command = "source .venv/activate && pip install acme-tools==2.0.1"
		} else {
			write(t, filepath.Join(venv, "bin", "activate"), body2)
		}
		if form, stderr := round7(t, cwd, command, nil); form != "hold" {
			t.Errorf("%s: %s, want hold (stderr %q)", c.name, form, stderr)
		}
	}
	// a prompt this reader does not put back: the template matches nothing
	_, _, cwd := npmWorkspace(t)
	venv := filepath.Join(cwd, ".venv")
	mkdir(t, filepath.Join(venv, "bin"))
	write(t, filepath.Join(venv, "pyvenv.cfg"), "home = /usr/bin\nprompt = my proj\n")
	write(t, filepath.Join(venv, "bin", "activate"), activateFrom(t, "uv-0.13.7-prompt", venv, "my proj"))
	if form, stderr := round7(t, cwd, "source .venv/bin/activate && pip install acme-tools==2.0.1", nil); form != "hold" {
		t.Errorf("a prompt with a space: %s (stderr %q)", form, stderr)
	}
}

// A venv reached through a link: the template names the real folder, which is the script's own through the link.
func TestRound11LinkedVenv(t *testing.T) {
	_, _, cwd := npmWorkspace(t)
	real := t.TempDir()
	mkdir(t, filepath.Join(real, "bin"))
	write(t, filepath.Join(real, "pyvenv.cfg"), "home = /usr/bin\n")
	write(t, filepath.Join(real, "bin", "activate"), activateFrom(t, "uv-0.13.7", real, ""))
	if err := os.Symlink(real, filepath.Join(cwd, ".venv")); err != nil {
		t.Fatal(err)
	}
	if form, stderr := round7(t, cwd, "source .venv/bin/activate && pip install acme-tools==2.0.1", nil); form != "silent" {
		t.Errorf("a linked venv: %s (stderr %q)", form, stderr)
	}
}

// T3 in startup files: a function or alias named after a helper this reader trusts counts as moved; cygpath is unwrapped
// only for VIRTUAL_ENV.
func TestRound11HelperNames(t *testing.T) {
	for _, c := range []struct{ name, body, cmd, want string }{
		{"a dirname function", "dirname() { echo /srv/evil; }\n", "", "hold"},
		{"a realpath alias", "alias realpath=grealpath\n", "", "hold"},
		{"a command function", "function command { builtin command \"$@\"; }\n", "", "hold"},
		{"zsh's functions array, uname", "functions[uname]='echo Linux'\n", "", "hold"},
		{"cygpath for another name", "export npm_config_registry=$(cygpath https://registry.npmjs.org/)\n", "", "hold"},
		{"cygpath for VIRTUAL_ENV", "export VIRTUAL_ENV=$(cygpath /srv/v)\n", "pip install acme-tools==2.0.1", "silent"},
		{"another program's alias", "alias ll='ls -l'\nalias pip=pip3\n", "", "silent"},
	} {
		_, _, cwd := npmWorkspace(t)
		home := t.TempDir()
		write(t, filepath.Join(home, ".zshenv"), c.body)
		cmd := c.cmd
		if cmd == "" {
			cmd = "npm i @acme/cli"
		}
		if form, stderr := round7(t, cwd, cmd, npmrcFiles(t, "", home, nil, nil)); form != c.want {
			t.Errorf("%s: %s, want %s (stderr %q)", c.name, form, c.want, stderr)
		}
	}
}

// A sourced name with no slash is looked up on PATH by bash and zsh: it holds (ParseLine's other).
func TestRound11SourcedByName(t *testing.T) {
	for _, command := range []string{". env.sh && npm i @acme/cli", "source activate && pip install acme-tools==2.0.1"} {
		_, _, cwd := npmWorkspace(t)
		if form, stderr := round7(t, cwd, command, nil); form != "hold" {
			t.Errorf("%s: %s (stderr %q)", command, form, stderr)
		}
	}
}

// The forms a venv's path and prompt take on disk: a relative link, a folder above it that is a link (/var on macOS),
// a prompt that is also part of a word on its line; and a template outside bin, whose venv the path rule would not read.
func TestRound11VenvForms(t *testing.T) {
	// a relative link to the venv
	_, _, cwd := npmWorkspace(t)
	mkdir(t, filepath.Join(cwd, "real", "bin"))
	real := filepath.Join(cwd, "real")
	write(t, filepath.Join(real, "pyvenv.cfg"), "home = /usr/bin\n")
	write(t, filepath.Join(real, "bin", "activate"), activateFrom(t, "uv-0.13.7", real, ""))
	if err := os.Symlink("real", filepath.Join(cwd, ".venv")); err != nil {
		t.Fatal(err)
	}
	if form, stderr := round7(t, cwd, "source .venv/bin/activate && pip install acme-tools==2.0.1", nil); form != "silent" {
		t.Errorf("a relative link: %s (stderr %q)", form, stderr)
	}
	// the template names the venv through its resolved folders
	_, _, cwd = npmWorkspace(t)
	venv := filepath.Join(cwd, ".venv")
	mkdir(t, filepath.Join(venv, "bin"))
	resolved, err := filepath.EvalSymlinks(venv)
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(venv, "pyvenv.cfg"), "home = /usr/bin\n")
	write(t, filepath.Join(venv, "bin", "activate"), activateFrom(t, "uv-0.13.7", resolved, ""))
	if form, stderr := round7(t, cwd, "source .venv/bin/activate && pip install acme-tools==2.0.1", nil); form != "silent" {
		t.Errorf("the resolved path (%s): %s (stderr %q)", resolved, form, stderr)
	}
	// a venv named ENV: its prompt is also part of VIRTUAL_ENV_PROMPT
	_, _, cwd = npmWorkspace(t)
	venv = filepath.Join(cwd, "ENV")
	mkdir(t, filepath.Join(venv, "bin"))
	write(t, filepath.Join(venv, "pyvenv.cfg"), "home = /usr/bin\n")
	write(t, filepath.Join(venv, "bin", "activate"), activateFrom(t, "cpython-3.15.2", venv, "ENV"))
	if form, stderr := round7(t, cwd, "source ENV/bin/activate && pip install acme-tools==2.0.1", nil); form != "silent" {
		t.Errorf("a venv named ENV: %s (stderr %q)", form, stderr)
	}
	// a template outside bin naming the folder above it, which has another index: the line's path names no bin, so
	// the path rule would not read that venv
	_, _, cwd = npmWorkspace(t)
	venv = filepath.Join(cwd, "v")
	mkdir(t, filepath.Join(venv, "scripts"))
	write(t, filepath.Join(venv, "pyvenv.cfg"), "home = /usr/bin\n")
	write(t, filepath.Join(venv, "pip.conf"), "[global]\nindex-url = https://evil.example/simple\n")
	write(t, filepath.Join(venv, "scripts", "activate"), activateFrom(t, "uv-0.13.7", venv, ""))
	if form, stderr := round7(t, cwd, "source v/scripts/activate && pip install acme-tools==2.0.1", nil); form != "hold" {
		t.Errorf("a template outside bin: %s (stderr %q)", form, stderr)
	}
}
