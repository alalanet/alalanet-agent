//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// REPO-POL-NPMRC round 4 (ADR-0174 round 9, re-review of 7b8cd53): a valued option and the next option, run tools'
// own arguments, commands after the install, sourced scripts, TLS, aliases, the byte budget.

func TestRound9Line(t *testing.T) {
	for _, c := range []struct{ command, want string }{
		{"pnpm add @acme/cli --reporter --dir /srv", "hold"},
		{"npm exec @acme/cli --prefix /srv", "hold"},
		{"npm exec -- @acme/cli --prefix /srv", "silent"},
		{"uvx --from acme-tools acme serve --dir /srv", "silent"},
		{"uv run --isolated --with acme-tools python x.py", "silent"},
		{"uv run --offline --with acme-tools python x.py", "hold"},
		{"pip install -- acme-tools==2.0.1", "silent"},
		{"pnpm dlx --offline @acme/cli", "hold"},
		{"pnpm --reporter silent dlx @acme/cli --help", "silent"},
		{"bun x @acme/cli --help", "silent"},
		{"uv run --with acme-tools pytest --cov", "silent"},
		{"npm exec -- @acme/cli $HOME", "silent"},
		{"source $VENV/bin/activate && npm i @acme/cli", "hold"},
		{"npm i @acme/cli && npm test --coverage", "silent"},
		{"pnpm add --save-catalog @acme/cli", "silent"},
		{"npm i -g @acme/cli --location=global", "silent"},
		// commands after the last install
		{"npm i @acme/cli && npm test", "silent"},
		{"npm i @acme/cli && npm run build -- --watch", "silent"},
		{"npm i @acme/cli; git add package.json", "silent"},
		{"npm i @acme/cli || echo failed > log.txt", "silent"},
		{"npm i @acme/cli & echo x > .npmrc", "hold"},
		{"npm i @acme/cli && git add . | cat", "hold"},
		{"echo x > .npmrc && npm i @acme/cli && npm test", "hold"},
		{"npm i @acme/cli && npm i --offline left-pad", "hold"},
	} {
		_, _, cwd := npmWorkspace(t)
		if form, stderr := round7(t, cwd, c.command, nil); form != c.want {
			t.Errorf("%s: %s, want %s (stderr %q)", c.command, form, c.want, stderr)
		}
	}
}

func TestRound9InstallPart(t *testing.T) {
	for _, c := range []struct{ line, want string }{
		{"npm i x && npm test", "npm i x "},
		{"cd a && npm i x; npm test", "cd a && npm i x"},
		{"npm i x && echo '&&' && npm test", "npm i x "},
		{"npm i x && (npm test && npm run b)", "npm i x "},
		{"npm i x && echo \"$(date)\"", "npm i x && echo \"$(date)\""},
		{"npm i x & npm test", "npm i x & npm test"},
		{"npm i x && npm test | cat", "npm i x && npm test | cat"},
		{"npm i x && cat <<EOF\nhi\nEOF", "npm i x && cat <<EOF\nhi\nEOF"},
		{"npm i x 'unclosed && y", "npm i x 'unclosed && y"},
		{"npm test && npm i x", "npm test && npm i x"},
		{"(npm i x; npm test)", "(npm i x; npm test)"},
		{"npm i x && (npm test", "npm i x && (npm test"},
	} {
		if got := installPart(c.line); got != c.want {
			t.Errorf("%q: %q, want %q", c.line, got, c.want)
		}
	}
}

func TestRound9Activate(t *testing.T) {
	cpython313 := func(venv string) string {
		return "deactivate () {\n    unset VIRTUAL_ENV\n}\ndeactivate nondestructive\n" +
			"if ([ \"${OSTYPE:-}\" = \"cygwin\" ] || [ \"${OSTYPE:-}\" = \"msys\" ]) && $(command -v cygpath &> /dev/null) ; then\n" +
			"    VIRTUAL_ENV=$(cygpath \"" + venv + "\")\nelse\n    VIRTUAL_ENV=\"" + venv + "\"\nfi\nexport VIRTUAL_ENV\n" +
			"_OLD_VIRTUAL_PATH=\"$PATH\"\nPATH=\"$VIRTUAL_ENV/bin:$PATH\"\nexport PATH\nVIRTUAL_ENV_PROMPT=\".venv\"\nexport VIRTUAL_ENV_PROMPT\nhash -r 2> /dev/null\n"
	}
	for _, c := range []struct{ name, file, body, command, want string }{
		{"an excerpt of CPython 3.13's activate", "bin/activate", "", "source .venv/bin/activate && pip install acme-tools==2.0.1", "hold"},                                                                                                                      // round 11: no known template
		{"fish's activate", "bin/activate.fish", "function deactivate -d \"Exit\"\n    set -e VIRTUAL_ENV\nend\nset -gx VIRTUAL_ENV VENV\nset -gx PATH \"$VIRTUAL_ENV/bin\" $PATH\n", "source .venv/bin/activate.fish && pip install acme-tools==2.0.1", "hold"}, // ParseLine: activate.fish is other
		{"an activate script with an npm alias", "bin/activate", "alias npm='npm --userconfig /srv/npmrc'\n", ". .venv/bin/activate && npm i @acme/cli", "hold"},
		{"an activate script reading ${VIRTUAL_ENV}", "bin/activate", "VIRTUAL_ENV='VENV'\nexport VIRTUAL_ENV\nPATH=\"${VIRTUAL_ENV}/bin:$PATH\"\nexport PATH\n", "source .venv/bin/activate && pip install acme-tools==2.0.1", "hold"}, // round 11
		{"an activate script with a proxy and a CA", "bin/activate", "export HTTPS_PROXY=http://127.0.0.1:8080\nexport NODE_EXTRA_CA_CERTS=/srv/ca.pem\n", ". .venv/bin/activate && npm i @acme/cli", "hold"},
	} {
		_, _, cwd := npmWorkspace(t)
		venv := filepath.Join(cwd, ".venv")
		mkdir(t, filepath.Join(venv, "bin"))
		write(t, filepath.Join(venv, "pyvenv.cfg"), "home = /usr/bin\n")
		body := c.body
		if body == "" {
			body = cpython313(venv)
		}
		write(t, filepath.Join(venv, c.file), strings.ReplaceAll(body, "VENV", venv))
		if form, stderr := round7(t, cwd, c.command, nil); form != c.want {
			t.Errorf("%s: %s, want %s (stderr %q)", c.name, form, c.want, stderr)
		}
	}
}

func TestRound9TLS(t *testing.T) {
	const npm, py = "npm i @acme/cli", "pip install acme-tools==2.0.1"
	for _, c := range []struct {
		name, file, body string
		env              []string
		command, want    string
	}{
		{"strict-ssl on", ".npmrc", "strict-ssl=true\n", nil, npm, "silent"},
		{"ca=null", ".npmrc", "ca=null\n", nil, npm, "silent"},
		{"ca=null and a proxy", ".npmrc", "ca=null\nhttps-proxy=http://127.0.0.1:8080/\n", nil, npm, "silent"},
		{"a CA alone", ".npmrc", "cafile=/srv/ca.pem\n", nil, npm, "silent"},
		{"a proxy alone", ".npmrc", "https-proxy=http://proxy.example:8080/\n", nil, npm, "silent"},
		{"a CA and a proxy", ".npmrc", "cafile=/srv/ca.pem\nhttps-proxy=http://127.0.0.1:8080/\n", nil, npm, "hold"},
		{"a registry's CA and the environment's proxy", ".npmrc", "//registry.npmjs.org/:cafile=/srv/ca.pem\n", []string{"HTTPS_PROXY=http://127.0.0.1:8080"}, npm, "hold"},
		{"Yarn strict SSL on", ".yarnrc.yml", "enableStrictSsl: true\n", nil, npm, "silent"},
		{"Yarn's CA and proxy", ".yarnrc.yml", "httpsCaFilePath: /srv/ca.pem\nhttpsProxy: http://127.0.0.1:8080\n", nil, npm, "hold"},
		{"pnpm strict-ssl on", "pnpm-workspace.yaml", "strictSsl: true\n", nil, npm, "silent"},
		{"bun's CA and the environment's proxy", "bunfig.toml", "[install]\ncafile = \"/srv/ca.pem\"\n", []string{"https_proxy=http://127.0.0.1:8080"}, npm, "hold"},
		{"uv's empty insecure hosts", "uv.toml", "allow-insecure-host = []\n", nil, py, "silent"},
		{"TLS on for node", "", "", []string{"NODE_TLS_REJECT_UNAUTHORIZED=1"}, npm, "silent"},
		{"TLS off for node", "", "", []string{"NODE_TLS_REJECT_UNAUTHORIZED=0"}, npm, "hold"},
		{"TLS off for node, a pip install", "", "", []string{"NODE_TLS_REJECT_UNAUTHORIZED=0"}, py, "silent"},
		{"node's CA and a proxy", "", "", []string{"NODE_EXTRA_CA_CERTS=/srv/ca.pem", "HTTPS_PROXY=http://127.0.0.1:8080"}, npm, "hold"},
		{"a proxy in the environment alone", "", "", []string{"HTTPS_PROXY=http://proxy.example:8080"}, npm, "silent"},
		{"pip's trusted host", "", "", []string{"PIP_TRUSTED_HOST=pypi.org"}, py, "hold"},
		{"pip's trusted host for an npm install", "", "", []string{"PIP_TRUSTED_HOST=pypi.org"}, npm, "silent"},
		{"pip's CA and proxy", "", "", []string{"PIP_CERT=/srv/ca.pem", "PIP_PROXY=http://127.0.0.1:8080"}, py, "hold"},
	} {
		_, root, cwd := npmWorkspace(t)
		if c.file != "" {
			write(t, filepath.Join(root, c.file), c.body)
		}
		if form, stderr := round7(t, cwd, c.command, npmrcFiles(t, "", "", c.env, nil)); form != c.want {
			t.Errorf("%s: %s, want %s (stderr %q)", c.name, form, c.want, stderr)
		}
	}
	// pip.conf in a venv in the workspace: its cert and proxy; an empty trusted-host
	for body, want := range map[string]string{"[global]\ncert = /srv/ca.pem\nproxy = http://127.0.0.1:8080\n": "hold",
		"[global]\ntrusted-host =\ntimeout = 60\n": "silent"} {
		_, _, cwd := npmWorkspace(t)
		mkdir(t, filepath.Join(cwd, ".venv"))
		write(t, filepath.Join(cwd, ".venv", "pyvenv.cfg"), "home = /usr/bin\n")
		write(t, filepath.Join(cwd, ".venv", "pip.conf"), body)
		if form, stderr := round7(t, cwd, py, nil); form != want {
			t.Errorf("pip.conf %q: %s, want %s (stderr %q)", body, form, want, stderr)
		}
	}
}

func TestRound9StartupTLSAndAliases(t *testing.T) {
	for _, c := range []struct{ name, file, body, want string }{
		{"a proxy by a command and a CA", ".zshrc", "export HTTPS_PROXY=$(proxyfinder)\nexport NODE_EXTRA_CA_CERTS=/etc/ca.pem\n", "hold"},
		{"a proxy by a command alone", ".zshrc", "export HTTPS_PROXY=$(proxyfinder)\n", "silent"},
		{"zsh's global alias", ".zshenv", "alias -g npm='npm --x'\n", "hold"},
		{"a function keyword", ".bashrc", "function pnpm {\n  command pnpm --dir /srv \"$@\"\n}\n", "hold"},
		{"fish's alias", ".config/fish/config.fish", "alias npm \"npm --registry https://evil.example/\"\n", "hold"},
		{"the second alias of a line", ".zshrc", "alias gs='git status' npm='npm --registry=https://evil.example/'\n", "hold"},
		{"another program's alias", ".zshrc", "alias ll='ls -l'\nalias gs='git status'\n", "silent"},
		{"npm as pnpm", ".zshrc", "alias npm=pnpm\nalias python=/opt/py/bin/python3\n", "silent"},
		{"another function", ".zshrc", "mkcd () { mkdir -p \"$1\" && cd \"$1\"; }\n", "silent"},
	} {
		_, _, cwd := npmWorkspace(t)
		home := t.TempDir()
		mkdir(t, filepath.Dir(filepath.Join(home, c.file)))
		write(t, filepath.Join(home, c.file), c.body)
		if form, stderr := round7(t, cwd, "npm i @acme/cli", npmrcFiles(t, "", home, nil, nil)); form != c.want {
			t.Errorf("%s: %s, want %s (stderr %q)", c.name, form, c.want, stderr)
		}
	}
}

func TestRound9Budgets(t *testing.T) {
	oldB, oldL := maxReadBudget, maxListed
	t.Cleanup(func() { maxReadBudget, maxListed = oldB, oldL })
	// the bytes of one call in all
	maxReadBudget = 64
	_, root, cwd := npmWorkspace(t)
	write(t, filepath.Join(root, ".npmrc"), "registry=https://registry.npmjs.org/\n; "+strings.Repeat("x", 80)+"\n")
	if form, stderr := round7(t, cwd, "npm i @acme/cli", nil); form != "hold" || !strings.Contains(stderr, "past the bytes") {
		t.Errorf("past the budget: %s (stderr %q)", form, stderr)
	}
	maxReadBudget = oldB
	// the files of one folder
	maxListed = 2
	for n, want := range map[int]string{2: "silent", 3: "hold"} {
		_, _, cwd := npmWorkspace(t)
		home := t.TempDir()
		mkdir(t, filepath.Join(home, ".config", "fish", "conf.d"))
		for i := 0; i < n; i++ {
			write(t, filepath.Join(home, ".config", "fish", "conf.d", string(rune('a'+i))+".fish"), "set -gx EDITOR vim\n")
		}
		if form, stderr := round7(t, cwd, "npm i @acme/cli", npmrcFiles(t, "", home, nil, nil)); form != want {
			t.Errorf("%d files in conf.d: %s, want %s (stderr %q)", n, form, want, stderr)
		}
	}
}

func TestRound9Lockfiles(t *testing.T) {
	tar := func(p string) string { return "https://registry.npmjs.org/" + p }
	for _, c := range []struct{ name, file, body, want string }{
		{"a dot segment with a version", "package-lock.json", `{"packages":{"node_modules/@acme/cli":{"version":"1.2.0","resolved":"` + tar("@acme/cli/-/../cli/-/cli-1.2.0.tgz") + `"}}}`, "hold"},
		{"no version, the registry's path", "package-lock.json", `{"packages":{"node_modules/@acme/cli":{"resolved":"` + tar("@acme/cli/-/cli-1.2.0.tgz") + `"}}}`, "hold"},
		{"an escaped dot segment", "package-lock.json", `{"packages":{"node_modules/@acme/cli":{"version":"1.2.0","resolved":"` + tar("@acme/cli/-/%2e%2e/cli/-/cli-1.2.0.tgz") + `"}}}`, "hold"},
		{"Yarn 1, its own tarball before the version", "yarn.lock", "\"@acme/cli@^1.2.0\":\n  resolved \"" + tar("@acme/cli/-/cli-1.2.0.tgz#abc") + "\"\n  version \"1.2.0\"\n", "silent"},
	} {
		_, root, cwd := npmWorkspace(t)
		write(t, filepath.Join(root, c.file), c.body)
		if form, stderr := round7(t, cwd, "npm i @acme/cli", nil); form != c.want {
			t.Errorf("%s: %s, want %s (stderr %q)", c.name, form, c.want, stderr)
		}
	}
}

// A sourced script under the home folder (~/), and an alias in direnv's .envrc, which direnv does not carry to the
// shell (so it moves nothing).
func TestRound9SourcedAndEnvrc(t *testing.T) {
	_, _, cwd := npmWorkspace(t)
	home := t.TempDir()
	mkdir(t, filepath.Join(home, "v", "bin"))
	write(t, filepath.Join(home, "v", "bin", "activate"), "alias npm='npm --userconfig /srv/npmrc'\n")
	if form, stderr := round7(t, cwd, "source ~/v/bin/activate && npm i @acme/cli", npmrcFiles(t, "", home, nil, nil)); form != "hold" {
		t.Errorf("an activate script under ~/: %s (stderr %q)", form, stderr)
	}
	_, root, cwd := npmWorkspace(t)
	write(t, filepath.Join(root, ".envrc"), "alias npm='npm --userconfig /srv/npmrc'\nexport EDITOR=vim\n")
	if form, stderr := round7(t, cwd, "npm i @acme/cli", nil); form != "silent" {
		t.Errorf("an alias in .envrc: %s (stderr %q)", form, stderr)
	}
}

// A file a link names, swapped between readFollow's Stat and its open for another file of the same size and mtime:
// only the inode tells it apart.
func TestRound9FollowSwap(t *testing.T) {
	_, _, cwd := npmWorkspace(t)
	home := t.TempDir()
	target := filepath.Join(home, "dotfiles", "npmrc")
	mkdir(t, filepath.Dir(target))
	write(t, target, "registry=https://registry.npmjs.org/\n")
	if err := os.Symlink(target, filepath.Join(home, ".npmrc")); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, ".npmrc")
	reused := false
	swap := func(p string) {
		if p != link {
			return
		}
		beforeOpen.Store(nil)
		fi, err := os.Stat(target)
		if err == nil {
			err = os.Remove(target)
		}
		if err == nil {
			err = os.WriteFile(target, []byte("registry=https://evil.example.orgxx/\n"), 0o644)
		}
		if err == nil {
			err = os.Chtimes(target, fi.ModTime(), fi.ModTime())
		}
		if err != nil {
			t.Error(err)
		}
		if now, err := os.Stat(target); err == nil {
			reused = os.SameFile(fi, now)
		}
	}
	beforeOpen.Store(&swap)
	t.Cleanup(func() { beforeOpen.Store(nil) })
	form, stderr := round7(t, cwd, "npm i @acme/cli", npmrcFiles(t, "", home, nil, nil))
	// A file system that hands the freed inode to the new file (the pinned image's) makes the swap invisible, the
	// limit ADR-0174 round 8 records: the swapped-in file is then read and judged — it names another registry, so the
	// answer is a hold either way (round 10: asserted in both branches, never skipped).
	if form != "hold" {
		t.Errorf("a swapped link target: %s (stderr %q)", form, stderr)
	}
	if !reused && !strings.Contains(stderr, "could not be read") {
		t.Errorf("a swapped link target, the inode not reused: stderr %q", stderr)
	}
}
