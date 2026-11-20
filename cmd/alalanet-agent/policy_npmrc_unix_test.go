//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// REPO-POL-NPMRC beyond the workspace: the user's files, the hook's environment, the prefixes of node and Python on
// PATH; and no file the agent can make holds the hook up.

// npmrcFiles is the policyFiles of a call with the user's home folder, the environment and PATH given.
func npmrcFiles(t *testing.T, managed, home string, env []string, path map[string]string) *policyFiles {
	t.Helper()
	pf := &policyFiles{managed: managed, getwd: func() (string, error) { return "", os.ErrNotExist },
		environ: func() []string { return env }}
	if home != "" {
		pf.home = func() (string, error) { return home, nil }
	}
	if path != nil {
		pf.lookPath = func(n string) (string, error) {
			if p, ok := path[n]; ok {
				return p, nil
			}
			return "", os.ErrNotExist
		}
	}
	return pf
}

func TestNpmrcBeyondTheWorkspace(t *testing.T) {
	const evil = "@acme:registry=https://evil.example/\n"
	for _, c := range []struct {
		name  string
		setup func(t *testing.T, home string) ([]string, map[string]string)
		want  string
	}{
		{"nothing set", func(t *testing.T, home string) ([]string, map[string]string) { return nil, nil }, "silent"},
		{"the user's ~/.npmrc", func(t *testing.T, home string) ([]string, map[string]string) {
			write(t, filepath.Join(home, ".npmrc"), evil)
			return nil, nil
		}, "hold"},
		{"the user's ~/.yarnrc.yml", func(t *testing.T, home string) ([]string, map[string]string) {
			write(t, filepath.Join(home, ".yarnrc.yml"), "npmRegistryServer: https://evil.example\n")
			return nil, nil
		}, "hold"},
		{"the user's ~/.bunfig.toml", func(t *testing.T, home string) ([]string, map[string]string) {
			write(t, filepath.Join(home, ".bunfig.toml"), "[install]\nregistry = \"https://evil.example/\"\n")
			return nil, nil
		}, "hold"},
		{"pnpm's global config.yaml", func(t *testing.T, home string) ([]string, map[string]string) {
			mkdir(t, filepath.Join(home, ".config", "pnpm"))
			write(t, filepath.Join(home, ".config", "pnpm", "config.yaml"), "registries:\n  \"@acme\": https://evil.example/\n")
			return nil, nil
		}, "hold"},
		{"pnpm's rc under XDG_CONFIG_HOME", func(t *testing.T, home string) ([]string, map[string]string) {
			x := t.TempDir()
			mkdir(t, filepath.Join(x, "pnpm"))
			write(t, filepath.Join(x, "pnpm", "rc"), evil)
			return []string{"XDG_CONFIG_HOME=" + x}, nil
		}, "hold"},
		{"NPM_CONFIG_USERCONFIG names the user's file", func(t *testing.T, home string) ([]string, map[string]string) {
			p := filepath.Join(t.TempDir(), "npmrc")
			write(t, p, evil)
			return []string{"NPM_CONFIG_USERCONFIG=" + p}, nil
		}, "hold"},
		{"a userconfig under ~/", func(t *testing.T, home string) ([]string, map[string]string) {
			write(t, filepath.Join(home, "other-npmrc"), evil)
			return []string{"npm_config_userconfig=~/other-npmrc"}, nil
		}, "hold"},
		{"a userconfig under ~/, the public registry", func(t *testing.T, home string) ([]string, map[string]string) {
			write(t, filepath.Join(home, "clean-npmrc"), "registry=https://registry.npmjs.org/\n")
			return []string{"npm_config_userconfig=~/clean-npmrc"}, nil
		}, "silent"},
		{"npm_config_ the scope", func(t *testing.T, home string) ([]string, map[string]string) {
			return []string{"npm_config_@acme:registry=https://evil.example/"}, nil
		}, "hold"},
		{"NPM_CONFIG_REGISTRY", func(t *testing.T, home string) ([]string, map[string]string) {
			return []string{"NPM_CONFIG_REGISTRY=https://evil.example/"}, nil
		}, "hold"},
		{"YARN_NPM_REGISTRY_SERVER", func(t *testing.T, home string) ([]string, map[string]string) {
			return []string{"YARN_NPM_REGISTRY_SERVER=https://evil.example/"}, nil
		}, "hold"},
		{"BUN_CONFIG_REGISTRY", func(t *testing.T, home string) ([]string, map[string]string) {
			return []string{"BUN_CONFIG_REGISTRY=https://evil.example/"}, nil
		}, "hold"},
		{"the public registry in the environment", func(t *testing.T, home string) ([]string, map[string]string) {
			return []string{"NPM_CONFIG_REGISTRY=https://registry.npmjs.org/", "npm_config_@corp:registry=https://npm.corp.example/",
				"npm_config_//npm.corp.example/:_authToken=x", "YARN_ENABLE_TELEMETRY=0"}, nil
		}, "silent"},
		{"YARN_RC_FILENAME names another rc file", func(t *testing.T, home string) ([]string, map[string]string) {
			return []string{"YARN_RC_FILENAME=.corp.yml"}, nil
		}, "hold"},
		{"node's global npmrc", func(t *testing.T, home string) ([]string, map[string]string) {
			prefix := t.TempDir()
			mkdir(t, filepath.Join(prefix, "bin"))
			mkdir(t, filepath.Join(prefix, "etc"))
			write(t, filepath.Join(prefix, "etc", "npmrc"), evil)
			return nil, map[string]string{"node": filepath.Join(prefix, "bin", "node")}
		}, "hold"},
		{"node's built-in npmrc sets a prefix", func(t *testing.T, home string) ([]string, map[string]string) {
			prefix, other := t.TempDir(), t.TempDir()
			mkdir(t, filepath.Join(prefix, "lib", "node_modules", "npm"))
			write(t, filepath.Join(prefix, "lib", "node_modules", "npm", "npmrc"), "prefix="+other+"\n")
			mkdir(t, filepath.Join(other, "etc"))
			write(t, filepath.Join(other, "etc", "npmrc"), evil)
			return nil, map[string]string{"node": filepath.Join(prefix, "bin", "node")}
		}, "hold"},
		{"PNPM_CONFIG_REGISTRY", func(t *testing.T, home string) ([]string, map[string]string) {
			return []string{"PNPM_CONFIG_REGISTRY=https://evil.example/"}, nil
		}, "hold"},
		{"YARN_RC_FILENAME out of the folder", func(t *testing.T, home string) ([]string, map[string]string) {
			return []string{"YARN_RC_FILENAME=../x.yml"}, nil
		}, "hold"},
		{"a userconfig by a variable", func(t *testing.T, home string) ([]string, map[string]string) {
			return []string{"NPM_CONFIG_USERCONFIG=/tmp/${USER}/npmrc"}, nil
		}, "hold"},
		{"node by a link", func(t *testing.T, home string) ([]string, map[string]string) {
			cellar, bin := t.TempDir(), t.TempDir()
			mkdir(t, filepath.Join(cellar, "bin"))
			mkdir(t, filepath.Join(cellar, "etc"))
			write(t, filepath.Join(cellar, "bin", "node"), "")
			write(t, filepath.Join(cellar, "etc", "npmrc"), evil)
			if err := os.Symlink(filepath.Join(cellar, "bin", "node"), filepath.Join(bin, "node")); err != nil {
				t.Fatal(err)
			}
			return nil, map[string]string{"node": filepath.Join(bin, "node")}
		}, "hold"},
		{"node in its prefix (Windows' layout)", func(t *testing.T, home string) ([]string, map[string]string) {
			prefix := t.TempDir()
			mkdir(t, filepath.Join(prefix, "node_modules", "npm"))
			write(t, filepath.Join(prefix, "node_modules", "npm", "npmrc"), evil)
			return nil, map[string]string{"node": filepath.Join(prefix, "node.exe")}
		}, "hold"},
		{"Yarn 1's global yarnrc", func(t *testing.T, home string) ([]string, map[string]string) {
			prefix := t.TempDir()
			mkdir(t, filepath.Join(prefix, "etc"))
			write(t, filepath.Join(prefix, "etc", "yarnrc"), "registry \"https://evil.example/\"\n")
			return nil, map[string]string{"node": filepath.Join(prefix, "bin", "node")}
		}, "hold"},
		{"node not on PATH", func(t *testing.T, home string) ([]string, map[string]string) {
			return nil, map[string]string{}
		}, "silent"},
		{"$PREFIX", func(t *testing.T, home string) ([]string, map[string]string) {
			prefix := t.TempDir()
			mkdir(t, filepath.Join(prefix, "etc"))
			write(t, filepath.Join(prefix, "etc", "npmrc"), evil)
			return []string{"PREFIX=" + prefix}, nil
		}, "hold"},
	} {
		_, _, cwd := npmWorkspace(t)
		home := t.TempDir()
		env, path := c.setup(t, home)
		if c.name == "YARN_RC_FILENAME names another rc file" {
			write(t, filepath.Join(filepath.Dir(filepath.Dir(cwd)), ".corp.yml"), "npmRegistryServer: https://evil.example\n")
		}
		pf := npmrcFiles(t, managedFile(t, trustAcme), home, env, path)
		form, stderr := runTimed(t, holdAnswer, "", codexInputIn(cwd, "npm i @acme/cli"), pf)
		if form != c.want {
			t.Errorf("%s: %s, want %s (stderr %q)", c.name, form, c.want, stderr)
		}
		if c.want == "hold" && !strings.Contains(stderr, movedNote) {
			t.Errorf("%s: stderr %q does not say the registry moved", c.name, stderr)
		}
		if strings.Contains(stderr, "evil.example") {
			t.Errorf("%s: stderr %q shows a value", c.name, stderr)
		}
	}
}

func TestPipIndexBeyondTheWorkspace(t *testing.T) {
	const evil = "[global]\nindex-url = https://evil.example/simple\n"
	for _, c := range []struct {
		name    string
		setup   func(t *testing.T, home string) ([]string, map[string]string)
		command string
		want    string
	}{
		{"nothing set", func(t *testing.T, home string) ([]string, map[string]string) { return nil, nil }, "pip install acme-tools==2.0.1", "silent"},
		{"PIP_INDEX_URL", func(t *testing.T, home string) ([]string, map[string]string) {
			return []string{"PIP_INDEX_URL=https://evil.example/simple"}, nil
		}, "pip install acme-tools==2.0.1", "hold"},
		{"PIP_EXTRA_INDEX_URL", func(t *testing.T, home string) ([]string, map[string]string) {
			return []string{"PIP_EXTRA_INDEX_URL=https://pypi.org/simple https://evil.example/simple"}, nil
		}, "pip install acme-tools==2.0.1", "hold"},
		{"PIP_NO_INDEX", func(t *testing.T, home string) ([]string, map[string]string) {
			return []string{"PIP_NO_INDEX=1", "PIP_FIND_LINKS="}, nil
		}, "pip install acme-tools==2.0.1", "hold"},
		{"UV_INDEX", func(t *testing.T, home string) ([]string, map[string]string) {
			return []string{"UV_INDEX=corp=https://evil.example/simple"}, nil
		}, "uv pip install acme-tools==2.0.1", "hold"},
		{"the public index in the environment", func(t *testing.T, home string) ([]string, map[string]string) {
			return []string{"PIP_INDEX_URL=https://pypi.org/simple", "UV_DEFAULT_INDEX=https://pypi.org/simple/", "UV_INDEX=pypi=https://pypi.org/simple", "PIP_NO_INDEX=off", "PIP_TIMEOUT=60"}, nil
		}, "pip install acme-tools==2.0.1", "silent"},
		{"PIP_CONFIG_FILE", func(t *testing.T, home string) ([]string, map[string]string) {
			p := filepath.Join(t.TempDir(), "pip.conf")
			write(t, p, evil)
			return []string{"PIP_CONFIG_FILE=" + p}, nil
		}, "pip install acme-tools==2.0.1", "hold"},
		{"PIP_CONFIG_FILE, relative", func(t *testing.T, home string) ([]string, map[string]string) {
			return []string{"PIP_CONFIG_FILE=pip.conf"}, nil
		}, "pip install acme-tools==2.0.1", "hold"},
		{"PIP_CONFIG_FILE is the null device", func(t *testing.T, home string) ([]string, map[string]string) {
			return []string{"PIP_CONFIG_FILE=" + os.DevNull}, nil
		}, "pip install acme-tools==2.0.1", "silent"},
		{"VIRTUAL_ENV's pip.conf", func(t *testing.T, home string) ([]string, map[string]string) {
			v := t.TempDir()
			write(t, filepath.Join(v, "pip.conf"), evil)
			return []string{"VIRTUAL_ENV=" + v}, nil
		}, "pip install acme-tools==2.0.1", "hold"},
		{"VIRTUAL_ENV in another spelling", func(t *testing.T, home string) ([]string, map[string]string) {
			v := t.TempDir()
			write(t, filepath.Join(v, "pip.conf"), evil)
			return []string{"Virtual_Env=" + v}, nil
		}, "pip install acme-tools==2.0.1", "hold"},
		{"the user's pip.conf", func(t *testing.T, home string) ([]string, map[string]string) {
			mkdir(t, filepath.Join(home, ".config", "pip"))
			write(t, filepath.Join(home, ".config", "pip", "pip.conf"), evil)
			return nil, nil
		}, "pip install acme-tools==2.0.1", "hold"},
		{"the user's legacy pip.conf", func(t *testing.T, home string) ([]string, map[string]string) {
			mkdir(t, filepath.Join(home, ".pip"))
			write(t, filepath.Join(home, ".pip", "pip.conf"), evil)
			return nil, nil
		}, "pip install acme-tools==2.0.1", "hold"},
		{"the user's uv.toml", func(t *testing.T, home string) ([]string, map[string]string) {
			mkdir(t, filepath.Join(home, ".config", "uv"))
			write(t, filepath.Join(home, ".config", "uv", "uv.toml"), "index-url = \"https://evil.example/simple\"\n")
			return nil, nil
		}, "uv pip install acme-tools==2.0.1", "hold"},
		{"UV_FIND_LINKS", func(t *testing.T, home string) ([]string, map[string]string) {
			return []string{"UV_FIND_LINKS=/srv/wheels"}, nil
		}, "uv pip install acme-tools==2.0.1", "hold"},
		{"UV_CONFIG_FILE", func(t *testing.T, home string) ([]string, map[string]string) {
			p := filepath.Join(t.TempDir(), "uv.toml")
			write(t, p, "index-url = \"https://evil.example/simple\"\n")
			return []string{"UV_CONFIG_FILE=" + p}, nil
		}, "uv pip install acme-tools==2.0.1", "hold"},
		{"XDG_CONFIG_HOME's pip.conf", func(t *testing.T, home string) ([]string, map[string]string) {
			x := t.TempDir()
			mkdir(t, filepath.Join(x, "pip"))
			write(t, filepath.Join(x, "pip", "pip.conf"), evil)
			return []string{"XDG_CONFIG_HOME=" + x}, nil
		}, "pip install acme-tools==2.0.1", "hold"},
		{"a file where a folder of the path would be", func(t *testing.T, home string) ([]string, map[string]string) {
			write(t, filepath.Join(home, ".config"), "")
			return nil, nil
		}, "pip install acme-tools==2.0.1", "silent"},
		{"a venv by a link in the workspace", func(t *testing.T, home string) ([]string, map[string]string) {
			return nil, nil
		}, "pip install acme-tools==2.0.1", "hold"},
		{"the prefix of python on PATH", func(t *testing.T, home string) ([]string, map[string]string) {
			prefix := t.TempDir()
			write(t, filepath.Join(prefix, "pip.conf"), evil)
			return nil, map[string]string{"python3": filepath.Join(prefix, "bin", "python3")}
		}, "python3 -m pip install acme-tools==2.0.1", "hold"},
		{"a venv by its path, its index public", func(t *testing.T, home string) ([]string, map[string]string) {
			return nil, nil
		}, "/nonexistent/venv/bin/pip install acme-tools==2.0.1", "silent"},
	} {
		_, root, cwd := npmWorkspace(t)
		home := t.TempDir()
		env, path := c.setup(t, home)
		if c.name == "a venv by a link in the workspace" {
			v := t.TempDir()
			write(t, filepath.Join(v, "pyvenv.cfg"), "home = /usr/bin\n")
			write(t, filepath.Join(v, "pip.conf"), evil)
			if err := os.Symlink(v, filepath.Join(root, ".venv")); err != nil {
				t.Fatal(err)
			}
		}
		managed := "version: 1\nexceptions:\n  - {package: pypi:acme-tools, reason: ours, expires: " + soon + "}\n"
		pf := npmrcFiles(t, managedFile(t, managed), home, env, path)
		form, stderr := runTimed(t, holdPyPIAt, "", codexInputIn(cwd, c.command), pf)
		if form != c.want {
			t.Errorf("%s: %s, want %s (stderr %q)", c.name, form, c.want, stderr)
		}
		if c.want == "hold" && !strings.Contains(stderr, movedNote) {
			t.Errorf("%s: stderr %q does not say the registry moved", c.name, stderr)
		}
	}
}

// movedNote is the hook's stderr line when a moved registry keeps an exception from covering.
const movedNote = "no exception covers an install whose registry may not be the public one alalanet judged"

func mkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

// A FIFO in place of any config file the check reads does not hang the hook: refused before any open, at once, and it
// counts as moved (the hold stays a hold).
func TestNpmrcFIFOsNeverHang(t *testing.T) {
	for _, c := range []struct {
		name, file, answer, command, managed string
	}{
		{".npmrc", ".npmrc", holdAnswer, "npm i @acme/cli", trustAcme},
		{".yarnrc.yml", ".yarnrc.yml", holdAnswer, "npm i @acme/cli", trustAcme},
		{"bunfig.toml", "bunfig.toml", holdAnswer, "npm i @acme/cli", trustAcme},
		{"a venv's pip.conf", ".venv/pip.conf", holdPyPIAt, "pip install acme-tools==2.0.1",
			"version: 1\nexceptions:\n  - {package: pypi:acme-tools, reason: ours, expires: " + soon + "}\n"},
		{"uv.toml", "uv.toml", holdPyPIAt, "uv pip install acme-tools==2.0.1",
			"version: 1\nexceptions:\n  - {package: pypi:acme-tools, reason: ours, expires: " + soon + "}\n"},
	} {
		_, root, cwd := npmWorkspace(t)
		p := filepath.Join(root, c.file)
		mkdir(t, filepath.Dir(p))
		if strings.HasSuffix(c.file, "pip.conf") {
			write(t, filepath.Join(filepath.Dir(p), "pyvenv.cfg"), "home = /usr/bin\n")
		}
		if err := syscall.Mkfifo(p, 0o644); err != nil {
			t.Skip("no mkfifo:", err)
		}
		start := time.Now()
		form, stderr := runTimed(t, c.answer, managedFile(t, c.managed), codexInputIn(cwd, c.command), nil)
		if form != "hold" || strings.Contains(stderr, "in time") || !strings.Contains(stderr, "could not be read (not a regular file)") || time.Since(start) >= policyDeadline {
			t.Errorf("%s as a FIFO: %s after %s (stderr %q)", c.name, form, time.Since(start), stderr)
		}
	}
}

// A file that stalls (swapped for a FIFO between the look and the open is refused by the open; one that stalls in
// another way is given up at the deadline): the hold stays a hold.
func TestNpmrcDeadline(t *testing.T) {
	old := policyDeadline
	policyDeadline = 100 * time.Millisecond
	t.Cleanup(func() { policyDeadline = old })
	stall := make(chan struct{})
	t.Cleanup(func() { close(stall) })
	_, root, cwd := npmWorkspace(t)
	file := filepath.Join(root, ".npmrc")
	write(t, file, "registry=https://registry.npmjs.org/\n")
	var stalledAt atomic.Int64 // when the stalled read began (Unix ns): the deadline is measured from it
	wait := func(p string) {
		if p == file {
			stalledAt.CompareAndSwap(0, time.Now().UnixNano())
			<-stall
		}
	}
	beforeOpen.Store(&wait)
	t.Cleanup(func() { beforeOpen.Store(nil) })
	managed := managedFile(t, trustAcme)
	// Each reading has its own 100 ms. Under a loaded race run the workspace's policy once passed its deadline first
	// (the hold then names that reading, and the stalled .npmrc is never read): such a run proves nothing about the
	// stall and is run again, at most five times; any other answer fails (ADR-0188, FLAKE-NPMRC-1).
	for attempt := 1; ; attempt++ {
		stalledAt.Store(0)
		start := time.Now()
		form, stderr := runTimed(t, holdAnswer, managed, codexInputIn(cwd, "npm i @acme/cli"), nil)
		if whole := time.Since(start); whole > 2500*time.Millisecond { // the whole hook, each attempt: a slow step before the .npmrc read too (round 9, P3-6)
			t.Errorf("attempt %d: the hook answered after %s (stderr %q)", attempt, whole, stderr)
			return
		}
		if at := stalledAt.Load(); form == "hold" && at != 0 && strings.Contains(stderr, "registry settings could not be read in time") {
			if d := time.Since(time.Unix(0, at)); d > 2*time.Second {
				t.Errorf("a stalled .npmrc was given up %s after its read began (stderr %q)", d, stderr)
			}
			return
		}
		otherFirst := form == "hold" && !strings.Contains(stderr, "registry settings") &&
			(strings.Contains(stderr, "the workspace's alalanet policy could not be read in time") || strings.Contains(stderr, " could not be read in time: installs alalanet allows are held"))
		if !otherFirst || attempt == 5 {
			t.Errorf("a stalled .npmrc, attempt %d: %s (stalled read began: %v; stderr %q)", attempt, form, stalledAt.Load() != 0, stderr)
			return
		}
		t.Logf("attempt %d: another reading passed its deadline first (%q); again", attempt, strings.TrimSpace(stderr))
	}
}

// A config file without the right to read it counts as moved.
func TestNpmrcNoPermission(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a file of mode 000")
	}
	_, root, cwd := npmWorkspace(t)
	p := filepath.Join(root, ".npmrc")
	write(t, p, "registry=https://registry.npmjs.org/\n")
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	if form, stderr := runTimed(t, holdAnswer, managedFile(t, trustAcme), codexInputIn(cwd, "npm i @acme/cli"), nil); form != "hold" || !strings.Contains(stderr, "permission denied") {
		t.Errorf("an unreadable .npmrc: %s (stderr %q)", form, stderr)
	}
}

// The system's files are read where the agent reads them (pf.system), and not in tests that leave it off.
func TestPipIndexSystemFiles(t *testing.T) {
	for _, system := range []bool{false, true} {
		_, _, cwd := npmWorkspace(t)
		dirs := t.TempDir()
		mkdir(t, filepath.Join(dirs, "pip"))
		write(t, filepath.Join(dirs, "pip", "pip.conf"), "[global]\nindex-url = https://evil.example/simple\n")
		managed := "version: 1\nexceptions:\n  - {package: pypi:acme-tools, reason: ours, expires: " + soon + "}\n"
		pf := npmrcFiles(t, managedFile(t, managed), "", []string{"XDG_CONFIG_DIRS=/nonexistent" + string(filepath.ListSeparator) + dirs}, nil)
		pf.system = system
		form, stderr := runTimed(t, holdPyPIAt, "", codexInputIn(cwd, "pip install acme-tools==2.0.1"), pf)
		if want := map[bool]string{false: "silent", true: "hold"}[system]; form != want {
			t.Errorf("system %v: %s, want %s (stderr %q)", system, form, want, stderr)
		}
	}
}

// The registry is read only for a hold an exception would let go: an allow is not touched and says nothing of it.
func TestNpmrcAllowSaysNothing(t *testing.T) {
	_, root, cwd := npmWorkspace(t)
	write(t, filepath.Join(root, ".npmrc"), "@acme:registry=https://evil.example/\n")
	if form, stderr := runTimed(t, "", managedFile(t, trustAcme), codexInputIn(cwd, "npm i @acme/cli"), nil); form != "silent" || strings.Contains(stderr, "registry") {
		t.Errorf("an allow: %s (stderr %q)", form, stderr)
	}
}

// pnpm installs the scope @jsr from npm.jsr.io unless told otherwise: an exception does not cover it.
func TestNpmrcJSRScope(t *testing.T) {
	hold := `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"alalanet install_check: HOLD. npm:@jsr/std__path@1.0.0 — new_package. Install only if the user confirms."}}`
	managed := "version: 1\nexceptions:\n  - {package: npm:@jsr/std__path, reason: ours, expires: " + soon + "}\n  - {package: npm:@acme/cli, reason: ours, expires: " + soon + "}\n"
	_, _, cwd := npmWorkspace(t)
	if form, stderr := runTimed(t, hold, managedFile(t, managed), codexInputIn(cwd, "pnpm add @jsr/std__path"), nil); form != "hold" || !strings.Contains(stderr, movedNote) {
		t.Errorf("@jsr: %s (stderr %q)", form, stderr)
	}
	if form, stderr := runTimed(t, holdAnswer, managedFile(t, managed), codexInputIn(cwd, "pnpm add @acme/cli"), nil); form != "silent" {
		t.Errorf("@acme beside it: %s (stderr %q)", form, stderr)
	}
}

// Outside a repository, a .venv in the directory the agent works in or in a parent is read (uv looks there).
func TestPipIndexInsideAVenv(t *testing.T) {
	v := filepath.Join(t.TempDir(), ".venv")
	cwd := filepath.Join(v, "lib")
	mkdir(t, cwd)
	write(t, filepath.Join(v, "pyvenv.cfg"), "home = /usr/bin\n")
	managed := "version: 1\nexceptions:\n  - {package: pypi:acme-tools, reason: ours, expires: " + soon + "}\n"
	for _, body := range []string{"[global]\nindex-url = https://pypi.org/simple\n", "[global]\nindex-url = https://evil.example/simple\n"} {
		write(t, filepath.Join(v, "pip.conf"), body)
		form, stderr := runTimed(t, holdPyPIAt, managedFile(t, managed), codexInputIn(cwd, "pip install acme-tools==2.0.1"), nil)
		if want := map[bool]string{false: "silent", true: "hold"}[strings.Contains(body, "evil")]; form != want {
			t.Errorf("%q: %s, want %s (stderr %q)", body, form, want, stderr)
		}
	}
}

// A regular file swapped in between readRegular's look and its open (a file system that reuses the freed inode at once
// gives it the same inode): its size or its mtime tells it apart.
func TestReadRegularSwapKeepsTheInode(t *testing.T) {
	const ask = "version: 1\non_hold:\n  packages: ask \n" // the same size as denyHolds
	for _, c := range []struct {
		name, before string
		mtime        time.Duration // the swapped-in file's mtime, from the old one's
	}{
		{"another size, the old mtime", "version: 1\n", 0},
		{"the same size, another mtime", ask, -time.Hour},
	} {
		dir := workspace(t, "git@github.com:acme/app.git", c.before)
		file := filepath.Join(filepath.Dir(filepath.Dir(dir)), ".alalanet.yml")
		swap := func(p string) {
			if p != file {
				return
			}
			beforeOpen.Store(nil)
			fi, err := os.Lstat(p)
			if err == nil {
				err = os.Remove(p)
			}
			if err == nil {
				err = os.WriteFile(p, []byte(denyHolds), 0o644)
			}
			if err == nil {
				err = os.Chtimes(p, fi.ModTime().Add(c.mtime), fi.ModTime().Add(c.mtime))
			}
			if err != nil {
				t.Error(err)
			}
		}
		beforeOpen.Store(&swap)
		form, stderr := runTimed(t, holdAnswer, managedFile(t, ""), codexInputIn(dir, "npm i @acme/cli"), nil)
		beforeOpen.Store(nil)
		if form != "hold" || !strings.Contains(stderr, "could not be read") {
			t.Errorf("%s: %s (stderr %q)", c.name, form, stderr)
		}
	}
}
