//go:build unix

package main

// REPO-POL-NPMRC round 9 (ADR-0174 round 14): what the startup files name, the pin's place and marks, the hold on a
// line naming the pin, policy-approve across environments, Codex's shell snapshots, tool configs that run code.

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// r14 is registryMoved for an npm target (or a PyPI one when pypi) with home, env and the pin in dir.
func r14(t *testing.T, cwd, home, dir string, env []string, pypi bool) string {
	t.Helper()
	pf := npmrcFiles(t, "", home, env, nil)
	pf.pinDir = func() (string, error) { return dir, nil }
	if pypi {
		return registryMoved(pf, cwd, "pip install acme-tools==2.0.1", []string{"pypi:acme-tools"})
	}
	return registryMoved(pf, cwd, "npm i @acme/cli", []string{"npm:@acme/cli"})
}

// pinThenChange: silent before (which pins), then change, then the reason.
func pinThenChange(t *testing.T, home string, env []string, change func()) string {
	t.Helper()
	_, _, cwd := npmWorkspace(t)
	dir := filepath.Join(t.TempDir(), "pin")
	if why := r14(t, cwd, home, dir, env, false); why != "" {
		t.Fatalf("before: %s", why)
	}
	change()
	return r14(t, cwd, home, dir, env, false)
}

func TestRound14SourcedForms(t *testing.T) {
	for _, c := range []struct{ name, startup, rel, startFile string }{
		{"a variable set above", `export ZSH="$HOME/.oh-my-zsh"` + "\nsource $ZSH/oh-my-zsh.sh\n", ".oh-my-zsh/oh-my-zsh.sh", ".zshrc"},
		{"nvm's form", "export NVM_DIR=\"$HOME/.nvm\"\n[ -s \"$NVM_DIR/nvm.sh\" ] && \\. \"$NVM_DIR/nvm.sh\"\n", ".nvm/nvm.sh", ".zshrc"},
		{"if then", "if [ -f ~/.bash_aliases ]; then . ~/.bash_aliases; fi\n", ".bash_aliases", ".bashrc"},
		{"HOME in braces", "source ${HOME}/.p10k.zsh\n", ".p10k.zsh", ".zshrc"},
		{"cargo", ". \"$HOME/.cargo/env\"\n", ".cargo/env", ".profile"},
		{"fish and", "test -f ~/.config/fish/x.fish; and source ~/.config/fish/x.fish\n", ".config/fish/x.fish", ".config/fish/config.fish"},
		{"in ZDOTDIR's file", "", "", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			home := t.TempDir()
			if c.startup == "" { // a ZDOTDIR file (level 0) sources one
				mkdir(t, filepath.Join(home, ".config", "zsh"))
				write(t, filepath.Join(home, ".zshenv"), "ZDOTDIR=${XDG_CONFIG_HOME:-$HOME/.config}/zsh\n")
				write(t, filepath.Join(home, ".config", "zsh", ".zshrc"), "source ~/.aliases.zsh\n")
				c.rel = ".aliases.zsh"
			} else {
				mkdir(t, filepath.Dir(filepath.Join(home, c.startFile)))
				write(t, filepath.Join(home, c.startFile), c.startup)
			}
			mkdir(t, filepath.Dir(filepath.Join(home, c.rel)))
			write(t, filepath.Join(home, c.rel), "PS1=x\n")
			why := pinThenChange(t, home, nil, func() { write(t, filepath.Join(home, c.rel), "echo() { builtin cd /x; }\n") })
			if !strings.HasPrefix(why, filepath.Join(home, c.rel)+" is a shell startup file that changed") {
				t.Errorf("%q", why)
			}
		})
	}
}

// What is not placed is the stated residual: a source by a command's output, a variable not set to a literal above,
// and a file a sourced file sources (one level only). Not holds.
func TestRound14SourcedResidual(t *testing.T) {
	home := t.TempDir()
	write(t, filepath.Join(home, ".zshrc"), "source $(brew --prefix)/x.sh\nsource $UNSET/y.sh\nsource ~/.a.zsh\n")
	write(t, filepath.Join(home, ".a.zsh"), "source ~/.b.zsh\n")
	write(t, filepath.Join(home, ".b.zsh"), "PS1=x\n")
	if why := pinThenChange(t, home, nil, func() { write(t, filepath.Join(home, ".b.zsh"), "PS1=y\n") }); why != "" {
		t.Errorf("two levels down is not pinned (stated): %q", why)
	}
}

func TestRound14EvalPrograms(t *testing.T) {
	for _, form := range []string{`eval "$(@P@ shellenv)"`, "eval $(@P@ shellenv)", "eval (@P@ shellenv)", "@P@ shellenv | source"} {
		home := t.TempDir()
		prefix := filepath.Join(t.TempDir(), "homebrew")
		brew := filepath.Join(prefix, "bin", "brew")
		lib := filepath.Join(prefix, "Library", "Homebrew")
		mkdir(t, filepath.Dir(brew))
		mkdir(t, filepath.Join(lib, "cmd"))
		write(t, brew, "#!/bin/bash\nsource \"$HOMEBREW_LIBRARY/Homebrew/brew.sh\"\n")
		write(t, filepath.Join(lib, "brew.sh"), "x=1\n")
		write(t, filepath.Join(lib, "cmd", "shellenv.sh"), "echo export PATH\n")
		write(t, filepath.Join(home, ".zprofile"), strings.ReplaceAll(form, "@P@", brew)+"\n")
		for _, f := range []string{brew, filepath.Join(lib, "brew.sh"), filepath.Join(lib, "cmd", "shellenv.sh")} {
			why := pinThenChange(t, home, nil, func() { write(t, f, "echo() { builtin cd /x; }\n") })
			if !strings.HasPrefix(why, f+" is a shell startup file that changed") {
				t.Errorf("%s, %s: %q", form, f, why)
			}
		}
	}
	// a program larger than a config file is pinned by its sum, not counted against the reading's bytes
	home := t.TempDir()
	prog := filepath.Join(t.TempDir(), "bin", "mise")
	mkdir(t, filepath.Dir(prog))
	write(t, prog, strings.Repeat("\x7fELF", 1<<19)) // 2 MiB
	write(t, filepath.Join(home, ".zshrc"), `eval "$(`+prog+` activate zsh)"`+"\n")
	if why := pinThenChange(t, home, nil, func() { write(t, prog, "x") }); !strings.HasPrefix(why, prog+" is a shell startup file that changed") {
		t.Errorf("a large program: %q", why)
	}
	// a program that is a FIFO is not read (and not waited on)
	home = t.TempDir()
	fifo := filepath.Join(t.TempDir(), "brew")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(home, ".zshrc"), `eval "$(`+fifo+` shellenv)"`+"\n")
	_, _, cwd := npmWorkspace(t)
	if why := r14(t, cwd, home, filepath.Join(t.TempDir(), "pin"), nil, false); !strings.HasPrefix(why, fifo+" is a program a shell startup file runs and could not be read") {
		t.Errorf("a FIFO program: %q", why)
	}
}

func TestRound14ZdotdirAndEnvFiles(t *testing.T) {
	for _, c := range []struct{ name, file, body, target string }{
		{"ZDOTDIR literal", ".zshenv", "export ZDOTDIR=~/zdot\n", "zdot/.zlogin"},
		{"ZDOTDIR by XDG's default", ".zshenv", "ZDOTDIR=\"${XDG_CONFIG_HOME:-$HOME/.config}/zsh\"\n", ".config/zsh/.zshrc"},
		{"BASH_ENV in .profile", ".profile", "export BASH_ENV=$HOME/.bash_env\n", ".bash_env"},
		{"ENV in .profile", ".profile", "ENV=~/.shrc; export ENV\n", ".shrc"},
	} {
		t.Run(c.name, func(t *testing.T) {
			home := t.TempDir()
			write(t, filepath.Join(home, c.file), c.body)
			mkdir(t, filepath.Dir(filepath.Join(home, c.target)))
			why := pinThenChange(t, home, nil, func() { write(t, filepath.Join(home, c.target), "alias ls=x\n") })
			if !strings.HasPrefix(why, filepath.Join(home, c.target)+" is a shell startup file that appeared") {
				t.Errorf("%q", why)
			}
		})
	}
	// ZDOTDIR in .zshrc (not .zshenv) is too late for zsh's own files: not followed
	home := t.TempDir()
	write(t, filepath.Join(home, ".zshrc"), "ZDOTDIR=~/zdot\n")
	mkdir(t, filepath.Join(home, "zdot"))
	if why := pinThenChange(t, home, nil, func() { write(t, filepath.Join(home, "zdot", ".zlogin"), "x\n") }); why != "" {
		t.Errorf("ZDOTDIR in .zshrc: %q", why)
	}
}

func TestRound14FishPlaces(t *testing.T) {
	xdg := t.TempDir()
	for _, c := range []struct {
		name string
		env  []string
		rel  string // under home, or under xdg when it starts with "@"
	}{
		{"vendor conf.d", nil, ".local/share/fish/vendor_conf.d/x.fish"},
		{"vendor functions", nil, ".local/share/fish/vendor_functions.d/echo.fish"},
		{"XDG_CONFIG_HOME's fish", []string{"XDG_CONFIG_HOME=" + xdg}, "@fish/conf.d/x.fish"},
		{"XDG_CONFIG_HOME's fish_variables", []string{"XDG_CONFIG_HOME=" + xdg}, "@fish/fish_variables"},
	} {
		t.Run(c.name, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, c.rel)
			if strings.HasPrefix(c.rel, "@") {
				path = filepath.Join(xdg, c.rel[1:])
			}
			mkdir(t, filepath.Dir(path))
			why := pinThenChange(t, home, c.env, func() { write(t, path, "set -x PATH /x $PATH\n") })
			if !strings.HasPrefix(why, path+" is a shell startup file that appeared") {
				t.Errorf("%q", why)
			}
		})
	}
}

func TestRound14PinPlaceAndMarks(t *testing.T) {
	home := t.TempDir()
	getenv := func(k string) string {
		return map[string]string{"XDG_CACHE_HOME": "/tmp/c", "XDG_STATE_HOME": "/tmp/s"}[k]
	}
	if d, err := defaultPinDir(getenv, func() (string, error) { return home, nil }); err != nil || d != filepath.Join(home, ".local", "state", "alalanet", "policy") {
		t.Errorf("the pin's folder: %s %v", d, err)
	}
	if m, err := defaultPinMark(func() (string, error) { return home, nil }); err != nil || m != filepath.Join(home, ".config", "alalanet", pinMarkName) {
		t.Errorf("the second mark: %s %v", m, err)
	}
	// the folder removed whole: the second mark says a pin was made
	_, _, cwd := npmWorkspace(t)
	dir := filepath.Join(t.TempDir(), "state", "pin")
	mark := filepath.Join(t.TempDir(), "cfg", pinMarkName)
	pf := npmrcFiles(t, "", home, nil, nil)
	pf.pinDir = func() (string, error) { return dir, nil }
	pf.pinMark = func() (string, error) { return mark, nil }
	moved := func() string { return registryMoved(pf, cwd, "npm i @acme/cli", []string{"npm:@acme/cli"}) }
	if why := moved(); why != "" {
		t.Fatal(why)
	}
	for _, m := range []string{filepath.Join(dir, pinMarkName), mark} {
		if fi, err := os.Stat(m); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("mark %s: %v", m, err)
		}
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if why := moved(); !strings.HasPrefix(why, filepath.Join(dir, pinName)+" is gone although alalanet-agent made one") {
		t.Errorf("the folder removed: %q", why)
	}
	// policy-approve pins again, and the hook is silent after
	var out bytes.Buffer
	if err := policyApprove(&out, pf, (&codeTTY{}).open); err != nil {
		t.Fatal(err)
	}
	if why := moved(); why != "" {
		t.Errorf("after policy-approve: %q", why)
	}
	// both marks and the pin gone: a first use (the stated limit)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(mark); err != nil {
		t.Fatal(err)
	}
	if why := moved(); why != "" {
		t.Errorf("everything removed is a first use (stated): %q", why)
	}
}

func TestRound14PinLineHeld(t *testing.T) {
	for _, line := range []string{
		"rm -f ~/.local/state/alalanet/policy/startup-pin.json",
		"rm -rf ~/.local/state",
		`rm -rf "$HOME/.config/alalanet"`,
		`del %LOCALAPPDATA%\alalanet\policy\startup-pin.json`,
		"echo {} > startup-pin.json",
		"XDG_STATE_HOME=/tmp/x alalanet-agent version",
		"rm ~/.config/alalanet/startup-pinned",
		"cp x ~/.local/state/alalanet/policy/startup-pending.json",
		`rmdir /s /q %LOCALAPPDATA%\alalanet\policy`,
	} {
		if !touchesPin(line) {
			t.Errorf("%s: not held", line)
		}
	}
	for _, line := range []string{"npm i @acme/cli", "ls ~/.config", "rm -rf ~/.cache/npm", "alalanet-agent version"} {
		if touchesPin(line) {
			t.Errorf("%s: held", line)
		}
	}
	_, _, cwd := npmWorkspace(t)
	srv := (&fakeHook{}).server(t)
	var o bytes.Buffer
	if err := runHook("codex", strings.NewReader(codexInputIn(cwd, "rm -rf ~/.local/state/alalanet")), &o, srv.Client(), srv.URL); err != nil {
		t.Fatal(err)
	}
	if answerForm(t, "codex", o.String()) != "hold" || !strings.Contains(o.String(), "pin of the shell startup files") {
		t.Errorf("the hook: %s", o.String())
	}
}

// R8-6 the other way: the hook lists a file the user's terminal does not (BASH_ENV in the runtime's environment
// only). The hook records it; policy-approve reads it too, and the hold clears.
func TestRound14ApproveTakesWhatTheHookSaw(t *testing.T) {
	_, _, cwd := npmWorkspace(t)
	home := t.TempDir()
	benv := filepath.Join(home, ".bash_env")
	dir := filepath.Join(t.TempDir(), "pin")
	hook := []string{"BASH_ENV=" + benv}
	if why := r14(t, cwd, home, dir, hook, false); why != "" {
		t.Fatal(why)
	}
	write(t, benv, "shopt -s expand_aliases\n")
	if why := r14(t, cwd, home, dir, hook, false); !strings.HasPrefix(why, benv+" is a shell startup file that appeared") {
		t.Fatalf("%q", why)
	}
	terminal := npmrcFiles(t, "", home, nil, nil)
	terminal.pinDir = func() (string, error) { return dir, nil }
	tty := &codeTTY{}
	if err := policyApprove(&bytes.Buffer{}, terminal, tty.open); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(tty.screen.String(), "appeared: "+benv) {
		t.Errorf("the screen: %q", tty.screen.String())
	}
	if why := r14(t, cwd, home, dir, hook, false); why != "" {
		t.Errorf("after policy-approve: %q", why)
	}
	if _, err := os.Stat(filepath.Join(dir, pendingName)); !os.IsNotExist(err) {
		t.Errorf("the pending list is left: %v", err)
	}
	// the merge keeps what the terminal does not list
	p, _ := loadPin(dir)
	if p == nil || !hex64(p.Files[benv]) {
		t.Errorf("the pin after the merge: %v", p)
	}
}

func TestRound14CodexSnapshots(t *testing.T) {
	_, _, cwd := npmWorkspace(t)
	home := t.TempDir()
	codex := t.TempDir()
	env := []string{"CODEX_HOME=" + codex}
	snaps := filepath.Join(codex, "shell_snapshots")
	mkdir(t, snaps)
	dir := filepath.Join(t.TempDir(), "pin")
	if why := r14(t, cwd, home, dir, env, false); why != "" {
		t.Fatal(why)
	}
	// a new session's snapshot: pinned on first sight
	s1 := filepath.Join(snaps, fmt.Sprintf("019a.%d.sh", time.Now().UnixNano())) // round 15: a name Codex writes now
	write(t, s1, "export PATH=/usr/bin\n")
	if why := r14(t, cwd, home, dir, env, false); why != "" {
		t.Errorf("a new snapshot: %q", why)
	}
	if p, _ := loadPin(dir); p == nil || !hex64(p.Files[s1]) {
		t.Errorf("the new snapshot is not pinned: %v", p)
	}
	// changed after: held
	write(t, s1, "echo() { builtin cd /x; }\n")
	if why := r14(t, cwd, home, dir, env, false); !strings.HasPrefix(why, s1+" is a shell startup file that changed") {
		t.Errorf("a changed snapshot: %q", why)
	}
	// policy-approve pins it as it is now
	pf := npmrcFiles(t, "", home, env, nil)
	pf.pinDir = func() (string, error) { return dir, nil }
	if err := policyApprove(&bytes.Buffer{}, pf, (&codeTTY{}).open); err != nil {
		t.Fatal(err)
	}
	if why := r14(t, cwd, home, dir, env, false); why != "" {
		t.Errorf("after policy-approve: %q", why)
	}
	// Codex removes old snapshots: gone is no change, and the pin keeps a tombstone (round 15)
	if err := os.Remove(s1); err != nil {
		t.Fatal(err)
	}
	if why := r14(t, cwd, home, dir, env, false); why != "" {
		t.Errorf("a snapshot gone: %q", why)
	}
	if p, _ := loadPin(dir); p == nil || p.Files[s1] != pinGone {
		t.Errorf("a gone snapshot has no tombstone: %v", p)
	}
	// ~/.codex without CODEX_HOME
	home = t.TempDir()
	mkdir(t, filepath.Join(home, ".codex", "shell_snapshots"))
	dir = filepath.Join(t.TempDir(), "pin")
	s2 := filepath.Join(home, ".codex", "shell_snapshots", "x.sh")
	write(t, s2, "PS1=x\n")
	if why := r14(t, cwd, home, dir, nil, false); why != "" {
		t.Fatal(why)
	}
	write(t, s2, "PS1=y\n")
	if why := r14(t, cwd, home, dir, nil, false); !strings.HasPrefix(why, s2+" is a shell startup file that changed") {
		t.Errorf("~/.codex: %q", why)
	}
}

func TestRound14ToolConfigs(t *testing.T) {
	type tc struct {
		name, file, body string
		pypi             bool
		want             string
	}
	for _, c := range []tc{
		{"script_shell", ".npmrc", "script_shell=/x/sh\n", false, "hold"},
		{"scriptShell", ".npmrc", "scriptShell=/x/sh\n", false, "hold"},
		{"node-gyp", ".npmrc", "node-gyp=/x/gyp\n", false, "hold"},
		{"pnpm npm-path", ".npmrc", "npm-path=/x/npm\n", false, "hold"},
		{"pnpm node-mirror", ".npmrc", "node-mirror:release=https://evil.example/\n", false, "hold"},
		{"pnpm-workspace scriptShell", "pnpm-workspace.yaml", "scriptShell: /x/sh\n", false, "hold"},
		{"script-shell empty", ".npmrc", "script-shell=\n", false, "silent"},
		{".envrc npm_config_script_shell", ".envrc", "export npm_config_script_shell=/x/sh\n", false, "hold"},
		{".envrc NODE_OPTIONS", ".envrc", "export NODE_OPTIONS=--require=/x/h.js\n", false, "hold"},
		{".envrc PATH", ".envrc", "export PATH=$PWD/bin:$PATH\n", false, "hold"},
		{".envrc use node", ".envrc", "use node\n", false, "hold"},
		{".envrc layout node", ".envrc", "layout node\n", false, "hold"},
		{".envrc plain", ".envrc", "export FOO=bar\n", false, "silent"},
		{"pip [install] python", "pip.conf", "[install]\npython = /x/python\n", true, "hold"},
		{"pip keyring subprocess", "pip.conf", "[global]\nkeyring-provider = subprocess\n", true, "hold"},
		{"pip keyring import", "pip.conf", "[global]\nkeyring-provider = import\n", true, "silent"},
		{"uv python-install-mirror", "uv.toml", "python-install-mirror = \"https://evil.example/\"\n", true, "hold"},
		{"uv keyring subprocess", "uv.toml", "keyring-provider = \"subprocess\"\n", true, "hold"},
		{"mise plugins", "mise.toml", "[plugins]\nnode = \"https://evil.example/asdf-node.git\"\n", false, "hold"},
		{"mise asdf url", "mise.toml", "[tools]\n\"asdf:https://evil.example/p\" = \"1\"\n", false, "hold"},
		{"mise asdf repo", "mise.toml", "[tools]\n\"asdf:owner/asdf-x\" = \"1\"\n", false, "hold"},
		{"mise tools plain", "mise.toml", "[tools]\nnode = \"22\"\n", false, "silent"},
		// round 16 (R10-1): a backend prefix is no registry name
		{"mise tools npm backend", "mise.toml", "[tools]\n\"npm:prettier\" = \"latest\"\n", false, "hold"},
		{"mise python venv", "mise.toml", "[env]\n_.python.venv = \".venv\"\n", false, "hold"},
		{"mise NODE_OPTIONS", "mise.toml", "[env]\nNODE_OPTIONS = \"-r /x/h.js\"\n", false, "hold"},
		{"mise env plain", "mise.toml", "[env]\nFOO = \"bar\"\n", false, "silent"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, root, cwd := npmWorkspace(t)
			where := root
			if c.file == "pip.conf" {
				where = filepath.Join(cwd, ".venv")
				mkdir(t, where)
				write(t, filepath.Join(where, "pyvenv.cfg"), "home = /usr/bin\n")
			}
			write(t, filepath.Join(where, c.file), c.body)
			cmd := "npm i @acme/cli"
			if c.pypi {
				cmd = "pip install acme-tools==2.0.1"
			}
			if form, stderr := round7(t, cwd, cmd, nil); form != c.want {
				t.Errorf("%s: %s, want %s (stderr %q)", c.name, form, c.want, stderr)
			}
		})
	}
	// npm sets npm_config_node_gyp for the scripts it runs: from the hook's own environment that one is not counted;
	// npm_config_script_shell there is
	_, _, cwd := npmWorkspace(t)
	if why := registryMoved(npmrcFiles(t, "", "", []string{"npm_config_node_gyp=/usr/lib/node_modules/npm/node_modules/node-gyp/bin/node-gyp.js"}, nil),
		cwd, "npm i @acme/cli", []string{"npm:@acme/cli"}); why != "" {
		t.Errorf("npm_config_node_gyp in the hook's environment: %q", why)
	}
	if why := registryMoved(npmrcFiles(t, "", "", []string{"npm_config_script_shell=/x/sh"}, nil),
		cwd, "npm i @acme/cli", []string{"npm:@acme/cli"}); why == "" {
		t.Errorf("npm_config_script_shell in the hook's environment: silent")
	}
}

func TestRound14StartRefsBound(t *testing.T) {
	old := maxStartRefs
	maxStartRefs = 3
	t.Cleanup(func() { maxStartRefs = old })
	home := t.TempDir()
	write(t, filepath.Join(home, ".zshrc"), "source ~/a\nsource ~/b\nsource ~/c\nsource ~/d\n")
	_, _, cwd := npmWorkspace(t)
	if why := r14(t, cwd, home, filepath.Join(t.TempDir(), "pin"), nil, false); why != filepath.Join(home, ".zshrc")+" names more files than this reader pins" {
		t.Errorf("%q", why)
	}
}

// policy-approve keeps what the user's terminal does not list and the hook recorded nothing of: the merge.
func TestRound14ApproveKeepsOtherEnvironment(t *testing.T) {
	_, _, cwd := npmWorkspace(t)
	home := t.TempDir()
	benv := filepath.Join(home, ".bash_env")
	write(t, benv, "shopt -s expand_aliases\n")
	write(t, filepath.Join(home, ".zshrc"), "PS1=x\n")
	dir := filepath.Join(t.TempDir(), "pin")
	hook := []string{"BASH_ENV=" + benv}
	if why := r14(t, cwd, home, dir, hook, false); why != "" {
		t.Fatal(why)
	}
	write(t, filepath.Join(home, ".zshrc"), "PS1=y\n")
	if why := r14(t, cwd, home, dir, hook, false); why == "" {
		t.Fatal("a changed .zshrc: silent")
	}
	terminal := npmrcFiles(t, "", home, nil, nil)
	terminal.pinDir = func() (string, error) { return dir, nil }
	if err := policyApprove(&bytes.Buffer{}, terminal, (&codeTTY{}).open); err != nil {
		t.Fatal(err)
	}
	if why := r14(t, cwd, home, dir, hook, false); why != "" {
		t.Errorf("after policy-approve in another environment: %q", why)
	}
}

func TestRound14ProgramBound(t *testing.T) {
	old := maxProgram
	maxProgram = 8
	t.Cleanup(func() { maxProgram = old })
	home := t.TempDir()
	prog := filepath.Join(t.TempDir(), "brew")
	write(t, prog, "0123456789")
	write(t, filepath.Join(home, ".zshrc"), `eval "$(`+prog+` shellenv)"`+"\n")
	_, _, cwd := npmWorkspace(t)
	if why := r14(t, cwd, home, filepath.Join(t.TempDir(), "pin"), nil, false); !strings.HasPrefix(why, prog+" is a program a shell startup file runs and could not be read") {
		t.Errorf("%q", why)
	}
}
