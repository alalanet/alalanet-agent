//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// REPO-POL-NPMRC round 7 (ADR-0174 round 12): the invariants of the template match, each with made-up folder names in
// a temporary folder.

// sourcedMoved: whether sourcing path counts as moved, and why.
func sourcedMoved(t *testing.T, path string) (bool, string) {
	t.Helper()
	c := &regCheck{pf: &policyFiles{}, seen: map[string]bool{}, budget: maxReadBudget, progs: map[string]bool{}}
	c.sourced(path)
	return c.why != "", c.why
}

// venvAt makes base/name/bin/activate from a template, with venv and prompt in its fields, and a pyvenv.cfg naming the
// prompt; it returns the script's path.
func venvAt(t *testing.T, base, name, tmpl, prompt string) string {
	t.Helper()
	venv := filepath.Join(base, name)
	mkdir(t, filepath.Join(venv, "bin"))
	cfg := "home = /usr/bin\n"
	if prompt != "" {
		cfg += "prompt = " + prompt + "\n"
	}
	write(t, filepath.Join(venv, "pyvenv.cfg"), cfg)
	p := filepath.Join(venv, "bin", "activate")
	write(t, p, activateFrom(t, tmpl, venv, prompt))
	return p
}

// Invariant 1: the venv's path carries no shell syntax (a space only where the template quotes it), the prompt only
// [A-Za-z0-9._-], each bounded.
func TestRound12SafeFields(t *testing.T) {
	for _, c := range []struct {
		name, tmpl string
		moved      bool
	}{
		{`v"x`, "uv-0.13.7", true}, {`v'x`, "uv-0.13.7", true}, {"v$x", "uv-0.13.7", true}, {"v`x", "uv-0.13.7", true},
		{`v\x`, "uv-0.13.7", true}, {"v;x", "cpython-3.15.2", true}, {"v&x", "cpython-3.15.2", true},
		{"v|x", "cpython-3.15.2", true}, {"v<x", "cpython-3.15.2", true}, {"v>x", "cpython-3.15.2", true},
		{"v(x", "cpython-3.15.2", true}, {"v)x", "cpython-3.15.2", true}, {"v{x", "cpython-3.15.2", true},
		{"v}x", "cpython-3.15.2", true}, {"v*x", "cpython-3.15.2", true}, {"v?x", "cpython-3.15.2", true},
		{"v[x", "cpython-3.15.2", true}, {"v]x", "cpython-3.15.2", true}, {"v!x", "cpython-3.15.2", true},
		{"v#x", "cpython-3.15.2", true}, {"v\nx", "uv-0.13.7", true}, {"v\tx", "uv-0.13.7", true},
		{"v\x01x", "uv-0.13.7", true},
		// a space: only where the template quotes every place of the path (uv's '…', CPython 3.9's "…")
		{"v x", "cpython-3.15.2", true}, {"v x", "cpython-3.12.14", true},
		{"v x", "uv-0.13.7", false}, {"v x", "cpython-3.9.6", false},
		// the safe set
		{"v+x@y~z.w_q-r", "cpython-3.15.2", false}, {"v+x@y~z.w_q-r", "uv-0.13.7", false},
	} {
		prompt := "" // uv's plain template has no prompt; CPython's writes one, here a plain word
		if strings.HasPrefix(c.tmpl, "cpython") {
			prompt = "p"
		}
		p := venvAt(t, t.TempDir(), c.name, c.tmpl, prompt)
		if moved, why := sourcedMoved(t, p); moved != c.moved {
			t.Errorf("%q in %s: moved %v, want %v (%s)", c.name, c.tmpl, moved, c.moved, why)
		}
	}
	for _, c := range []struct {
		prompt string
		moved  bool
	}{
		{"proj", false}, {"fc-api", false}, {"my_proj.v2", false}, {strings.Repeat("a", maxPrompt), false},
		{strings.Repeat("a", maxPrompt+1), true},
	} {
		p := venvAt(t, t.TempDir(), ".venv", "uv-0.13.7-prompt", c.prompt)
		if moved, why := sourcedMoved(t, p); moved != c.moved {
			t.Errorf("a prompt of %d bytes: moved %v, want %v (%s)", len(c.prompt), moved, c.moved, why)
		}
	}
}

// Invariant 1, the bound of the path: a field value longer than maxVenvPath never matches.
func TestRound12PathBound(t *testing.T) {
	var tm template
	for _, x := range templates {
		if x.name == "uv 0.13.7" {
			tm = x
		}
	}
	b, err := activateFS.ReadFile("activate/uv-0.13.7")
	if err != nil {
		t.Fatal(err)
	}
	for n, want := range map[int]bool{maxVenvPath: true, maxVenvPath + 1: false} {
		v := "/" + strings.Repeat("a", n-1)
		if _, _, ok := tm.match([]byte(strings.ReplaceAll(string(b), "@VENV@", v))); ok != want {
			t.Errorf("a path of %d bytes: match %v, want %v", n, ok, want)
		}
	}
}

// Invariant 2: the values stand only at the template's places, and every place of a field has the same one.
func TestRound12Positional(t *testing.T) {
	base := t.TempDir()
	p := venvAt(t, base, ".venv", "uv-0.13.7-prompt", "proj")
	venv := filepath.Dir(filepath.Dir(p))
	body, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, body string }{
		{"the path in a comment", strings.Replace(string(body), "# This file must", "# "+venv+"\n# This file must", 1)},
		{"the path in a command", string(body) + "export npm_config_userconfig=" + venv + "/npmrc\n"},
		{"the prompt where the template has none", strings.Replace(string(body), "export PATH\n", "export PATH proj\n", 1)},
		{"two prompts", strings.Replace(string(body), `VIRTUAL_ENV_PROMPT="proj"`, `VIRTUAL_ENV_PROMPT="other"`, 1)},
	} {
		write(t, p, c.body)
		if moved, _ := sourcedMoved(t, p); !moved {
			t.Errorf("%s: matched a template", c.name)
		}
	}
}

// Invariant 3: the path the script names must resolve to the folder it is in.
func TestRound12OneVenv(t *testing.T) {
	base := t.TempDir()
	other := filepath.Join(base, "other")
	mkdir(t, filepath.Join(other, "bin"))
	// a script naming another folder
	a := filepath.Join(base, "a")
	mkdir(t, filepath.Join(a, "bin"))
	write(t, filepath.Join(a, "bin", "activate"), activateFrom(t, "uv-0.13.7", other, ""))
	if moved, _ := sourcedMoved(t, filepath.Join(a, "bin", "activate")); !moved {
		t.Error("a script naming another folder matched")
	}
	// a script naming a link to another folder
	if err := os.Symlink(other, filepath.Join(base, "link-to-other")); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(a, "bin", "activate"), activateFrom(t, "uv-0.13.7", filepath.Join(base, "link-to-other"), ""))
	if moved, _ := sourcedMoved(t, filepath.Join(a, "bin", "activate")); !moved {
		t.Error("a script naming a link to another folder matched")
	}
	// the same folder by a link, or by its resolved path: one venv
	if err := os.Symlink(a, filepath.Join(base, "link-to-a")); err != nil {
		t.Fatal(err)
	}
	for _, named := range []string{filepath.Join(base, "link-to-a"), a} {
		write(t, filepath.Join(a, "bin", "activate"), activateFrom(t, "uv-0.13.7", named, ""))
		if moved, why := sourcedMoved(t, filepath.Join(base, "link-to-a", "bin", "activate")); moved {
			t.Errorf("the venv named %s, sourced through the link: %s", named, why)
		}
	}
	// a relative path in the field, even one that names the folder from where the hook runs
	t.Chdir(base)
	write(t, filepath.Join(a, "bin", "activate"), activateFrom(t, "uv-0.13.7", "a", ""))
	if moved, _ := sourcedMoved(t, filepath.Join(a, "bin", "activate")); !moved {
		t.Error("a relative path matched")
	}
	// a path that is not clean, and an empty one
	for _, named := range []string{base + "/./a", base + "//a", base + "/a/", ""} {
		write(t, filepath.Join(a, "bin", "activate"), activateFrom(t, "uv-0.13.7", named, ""))
		if moved, _ := sourcedMoved(t, filepath.Join(a, "bin", "activate")); !moved {
			t.Errorf("the path %q matched", named)
		}
	}
	// a template outside its venv's bin (sourced directly, past ParseLine)
	mkdir(t, filepath.Join(a, "scripts"))
	write(t, filepath.Join(a, "scripts", "activate"), activateFrom(t, "uv-0.13.7", a, ""))
	if moved, _ := sourcedMoved(t, filepath.Join(a, "scripts", "activate")); !moved {
		t.Error("a template outside bin matched")
	}
}

// Invariant 4: byte for byte — a byte-order mark, CRLF, a byte more or less at the end.
func TestRound12ByteExact(t *testing.T) {
	p := venvAt(t, t.TempDir(), ".venv", "cpython-3.13.18", ".venv")
	body, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if moved, why := sourcedMoved(t, p); moved {
		t.Fatalf("the template itself: %s", why)
	}
	for _, c := range []struct{ name, body string }{
		{"a byte-order mark", "\xef\xbb\xbf" + string(body)},
		{"CRLF", strings.ReplaceAll(string(body), "\n", "\r\n")},
		{"a newline more", string(body) + "\n"},
		{"a space at the end", string(body) + " "},
		{"the last byte cut", string(body[:len(body)-1])},
		{"a tab for spaces", strings.Replace(string(body), "    ", "\t", 1)},
	} {
		write(t, p, c.body)
		if moved, _ := sourcedMoved(t, p); !moved {
			t.Errorf("%s: matched a template", c.name)
		}
	}
}

// The templates themselves: a field's next byte is never one the field takes (so a value's end is known), and the
// path is quoted at every place exactly in uv's and CPython 3.9's.
func TestRound12TemplateShape(t *testing.T) {
	quoted := map[string]bool{"uv 0.13.7": true, "uv 0.13.7, a prompt": true, "CPython 3.9.6 venv": true}
	names := map[string]bool{}
	for _, tm := range templates {
		names[tm.name] = true
	}
	if len(names) != len(activateTemplates) {
		t.Fatalf("%d templates parsed, %d listed", len(names), len(activateTemplates))
	}
	for _, tm := range templates {
		hasVenv := false
		for i, p := range tm.parts {
			if p.field == "" {
				continue
			}
			hasVenv = hasVenv || p.field == "VENV"
			if i+1 == len(tm.parts) || tm.parts[i+1].field != "" || len(tm.parts[i+1].lit) == 0 {
				t.Errorf("%s: field %s is not followed by literal bytes", tm.name, p.field)
				continue
			}
			next := tm.parts[i+1].lit[0]
			if p.field == "VENV" && venvByte(next, true) || p.field == "PROMPT" && promptByte(next) {
				t.Errorf("%s: field %s is followed by %q, a byte it takes", tm.name, p.field, next)
			}
		}
		if hasVenv && tm.venvQuoted != quoted[tm.name] {
			t.Errorf("%s: quoted %v, want %v", tm.name, tm.venvQuoted, quoted[tm.name])
		}
	}
}
