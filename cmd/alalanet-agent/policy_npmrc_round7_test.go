//go:build unix

package main

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/alalanet/alalanet-agent/internal/installread"
)

// REPO-POL-NPMRC round 2 (ADR-0174 round 7, review of 6d69681): what moves a package's source beyond the registry
// settings the hook reads — the line changes directory, sources a file, names a requirements file, goes offline or
// moves the cache (N1–N4); the shell's startup files; manifest overrides, lockfiles, code the package manager runs,
// bun's .env. On the exception path only: each is a hold an exception does not cover.

// round7 runs one call with the organisation's npm scopes trusted and its PyPI exception, and the pf given (nil: the
// workspace only).
func round7(t *testing.T, cwd, command string, pf *policyFiles) (form, stderr string) {
	t.Helper()
	answer := holdAnswer
	if strings.Contains(command, "acme-tools") {
		answer = holdPyPIAt
	}
	managed := managedFile(t, trustAcme+exceptPyPIManaged)
	if pf != nil {
		pf.managed = managed
	}
	return runTimed(t, answer, managed, codexInputIn(cwd, command), pf)
}

func TestRound7LineMoves(t *testing.T) {
	for _, c := range []struct{ command, want string }{
		{"npm i @acme/cli", "silent"},
		{"pip install acme-tools==2.0.1", "silent"},
		{"npm i @acme/cli && echo cd", "silent"},
		{"git commit -m cd && npm i @acme/cli", "hold"}, // round 8: a command besides the install (B5)
		{"npm i -D @acme/cli", "silent"},
		{"echo -c x && npm i @acme/cli", "silent"},
		{"npm i @acme/cli --save-exact", "silent"},
		{"npm i @acme/cli --prefer-offline=false", "hold"}, // round 8: an option plainFlags does not name
		// N1: another directory
		{"(cd sub && npm i @acme/cli)", "hold"},
		{"builtin cd sub; npm i @acme/cli", "hold"},
		{"popd && npm i @acme/cli", "hold"},
		{"sudo -D /srv npm i @acme/cli", "hold"},
		{"LANG=C cd sub && npm i @acme/cli", "hold"},
		{"command -p cd sub && npm i @acme/cli", "hold"},
		{"eval 'cd sub' && npm i @acme/cli", "hold"},
		{"bash --norc -c 'cd /srv && npm i @acme/cli'", "hold"},
		{"uvx -c c.txt acme-tools", "hold"},
		{"uvx.exe -c c.txt acme-tools", "hold"},
		{"npm --prefix=/srv i @acme/cli", "hold"},
		{"npm -C /srv i @acme/cli", "hold"},
		{"env -C /srv npm i @acme/cli", "hold"},
		{"env --chdir=/srv npm i @acme/cli", "hold"},
		{"uv --project /srv add acme-tools", "hold"},
		{"bash -c 'cd /srv && npm i @acme/cli'", "hold"},
		{"npm i @acme/cli --userconfig /srv/npmrc", "hold"},
		// N2: a sourced file
		{"source ~/.nvm/nvm.sh && npm i @acme/cli", "hold"},
		{"sh -c '. ./env.sh; npm i @acme/cli'", "hold"},
		// N3: requirements and constraints
		{"pip install acme-tools -rreq.txt", "hold"},
		{"pip install acme-tools --requirement=req.txt", "hold"},
		{"python3 -m pip install -r req.txt acme-tools", "hold"},
		{"uv pip install acme-tools --constraint c.txt", "hold"},
		{"uv pip install acme-tools --overrides o.txt", "hold"},
		{"uvx --with-requirements r.txt acme-tools", "hold"},
		// N4: offline, the cache, the store
		{"npm i @acme/cli --offline", "hold"},
		{"npm i @acme/cli --prefer-offline=true", "hold"},
		{"npm i @acme/cli --cache /srv/c", "hold"},
		{"pnpm add @acme/cli --store-dir /srv/s", "hold"},
		{"yarn add @acme/cli --cache-folder /srv/c", "hold"},
		{"uv pip install acme-tools --offline", "hold"},
		{"pip install acme-tools --cache-dir /srv/c", "hold"},
		{"pip install --no-index acme-tools", "hold"},
	} {
		_, _, cwd := npmWorkspace(t)
		form, stderr := round7(t, cwd, c.command, nil)
		if form != c.want {
			t.Errorf("%s: %s, want %s (stderr %q)", c.command, form, c.want, stderr)
		}
		// what the line reader holds already (--userconfig) never reaches the exception path
		targets, unread, other, subst := installread.ParseLine(c.command)
		local := len(unread) > 0 || subst || other || len(installread.HookExtra(c.command, targets, unread, subst)) > 0
		if c.want == "hold" && !local && !strings.Contains(stderr, movedNote) {
			t.Errorf("%s: stderr %q does not say why", c.command, stderr)
		}
	}
}

func TestRound7ConfigMoves(t *testing.T) {
	const npm, py = "npm i @acme/cli", "pip install acme-tools==2.0.1"
	lockNPM := func(resolved string) string {
		return `{"lockfileVersion": 3, "packages": {"": {"dependencies": {"@acme/cli": "^1.2.0"}}, "node_modules/@acme/cli": {"version": "1.2.0", "resolved": "` + resolved + `"}}}`
	}
	for _, c := range []struct{ name, file, body, command, want string }{
		{"npm offline", ".npmrc", "offline=true\n", npm, "hold"},
		{"npm prefer-offline", ".npmrc", "prefer-offline = true\n", npm, "hold"},
		{"npm offline off", ".npmrc", "offline=false\nprefer-offline=false\n", npm, "silent"},
		{"npm's cache", ".npmrc", "cache=/srv/c\n", npm, "hold"},
		{"Yarn 1's cache folder", ".yarnrc", "cache-folder \"/srv/c\"\n", npm, "hold"},
		{"Yarn 1's yarn-path", ".yarnrc", "yarn-path \"./y.js\"\n", npm, "hold"},
		{"Yarn offline", ".yarnrc.yml", "enableOfflineMode: true\n", npm, "hold"},
		{"Yarn offline off", ".yarnrc.yml", "enableOfflineMode: false\n", npm, "silent"},
		{"Yarn's cache folder", ".yarnrc.yml", "cacheFolder: ./c\n", npm, "hold"},
		{"Yarn's yarnPath", ".yarnrc.yml", "yarnPath: .yarn/releases/yarn-4.cjs\n", npm, "hold"},
		{"Yarn's plugins", ".yarnrc.yml", "plugins:\n  - path: .yarn/plugins/x.cjs\n", npm, "hold"},
		{"a committed .yarn/cache", ".yarn/cache/x.zip", "", npm, "hold"},
		{"pnpm offline", "pnpm-workspace.yaml", "offline: true\n", npm, "hold"},
		{"pnpm offline off", "pnpm-workspace.yaml", "offline: false\npreferOffline: false\n", npm, "silent"},
		{"pnpm's store", "pnpm-workspace.yaml", "storeDir: /srv/s\n", npm, "hold"},
		{"pnpm's pnpmfile setting", "pnpm-workspace.yaml", "pnpmfile: hooks.cjs\n", npm, "hold"},
		{"pnpm's override to another package", "pnpm-workspace.yaml", "overrides:\n  \"@acme/cli\": npm:evil@1\n", npm, "hold"},
		{"pnpm's override to a version", "pnpm-workspace.yaml", "overrides:\n  \"@acme/cli\": ^1.2.0\n", npm, "silent"},
		{"pnpm's override of another package", "pnpm-workspace.yaml", "overrides:\n  left-pad: npm:evil@1\n", npm, "silent"},
		{"a .pnpmfile.cjs", ".pnpmfile.cjs", "module.exports = {}\n", npm, "hold"},
		{"a .pnpmfile.mjs", ".pnpmfile.mjs", "export default {}\n", npm, "hold"},
		{"bun's cache", "bunfig.toml", "[install.cache]\ndir = \"/srv/c\"\n", npm, "hold"},
		{"bun's cache as a string", "bunfig.toml", "[install]\ncache = \"/srv/c\"\n", npm, "hold"},
		{"bun's .env names the registry", ".env", "BUN_CONFIG_REGISTRY=https://evil.example/\n", "bun add @acme/cli", "hold"},
		{"bun's .env.local names the registry", ".env.local", "npm_config_registry=https://evil.example/\n", "bun add @acme/cli", "hold"},
		{"bun's .env, the public registry", ".env", "NPM_CONFIG_REGISTRY=https://registry.npmjs.org/\nFOO=bar\n", "bun add @acme/cli", "silent"},
		{"a .env npm does not read", ".env", "npm_config_registry=https://evil.example/\nPREFIX=api\n", npm, "silent"},
		{"Yarn's .env.yarn", ".env.yarn", "YARN_NPM_REGISTRY_SERVER=https://evil.example\n", "yarn add @acme/cli", "hold"},
		{"a .env.yarn npm does not read", ".env.yarn", "YARN_NPM_REGISTRY_SERVER=https://evil.example\n", npm, "silent"},
		{"Yarn's resolution to another package", "package.json", `{"resolutions": {"@acme/cli": "npm:evil@1"}}`, npm, "hold"},
		{"Yarn's resolution by a pattern", "package.json", `{"resolutions": {"**/@acme/cli": "https://evil.example/x.tgz"}}`, npm, "hold"},
		{"npm's override to a version", "package.json", `{"overrides": {"@acme/cli": "1.2.0"}}`, npm, "silent"},
		{"pnpm's override in package.json", "package.json", `{"pnpm": {"overrides": {"@acme/cli": "link:../x"}}}`, npm, "hold"},
		{"a nested override", "package.json", `{"overrides": {"foo": {"@acme/cli": "file:../x"}}}`, npm, "hold"},
		{"a resolution of a longer name", "package.json", `{"resolutions": {"@acme/cli-tools": "npm:x@1"}}`, npm, "silent"},
		{"a package.json that does not parse", "package.json", `{"resolutions": `, npm, "hold"},
		{"package-lock.json, another host", "package-lock.json", lockNPM("https://evil.example/cli-1.2.0.tgz"), npm, "hold"},
		{"package-lock.json, the registry", "package-lock.json", lockNPM("https://registry.npmjs.org/@acme/cli/-/cli-1.2.0.tgz"), npm, "silent"},
		{"package-lock.json, a link", "package-lock.json", `{"packages": {"node_modules/@acme/cli": {"link": true}}}`, npm, "hold"},
		{"package-lock.json, no resolved", "package-lock.json", `{"packages": {"node_modules/@acme/cli": {"version": "1.2.0"}}}`, npm, "silent"},
		{"package-lock.json that does not parse", "package-lock.json", `{"packages": `, npm, "hold"},
		{"package-lock.json v1", "package-lock.json", `{"lockfileVersion": 1, "dependencies": {"@acme/cli": {"version": "1.2.0", "resolved": "https://evil.example/x.tgz"}}}`, npm, "hold"},
		{"yarn.lock v1, another host", "yarn.lock", "\"@acme/cli@^1.2.0\":\n  version \"1.2.0\"\n  resolved \"https://evil.example/x.tgz#abc\"\n", npm, "hold"},
		{"yarn.lock v1, the registry", "yarn.lock", "\"@acme/cli@^1.2.0\", \"@acme/cli@^1.0.0\":\n  version \"1.2.0\"\n  resolved \"https://registry.yarnpkg.com/@acme/cli/-/cli-1.2.0.tgz#abc\"\n", npm, "silent"},
		{"yarn.lock 2+, the registry", "yarn.lock", "__metadata:\n  version: 8\n\n\"@acme/cli@npm:^1.2.0\":\n  version: 1.2.0\n  resolution: \"@acme/cli@npm:1.2.0\"\n", npm, "silent"},
		{"yarn.lock 2+, a URL", "yarn.lock", "\"@acme/cli@https://evil.example/x.tgz\":\n  version: 1.2.0\n  resolution: \"@acme/cli@https://evil.example/x.tgz\"\n", npm, "hold"},
		{"pnpm-lock.yaml, a tarball", "pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n  '@acme/cli@1.2.0':\n    resolution: {tarball: https://evil.example/x.tgz}\n", npm, "hold"},
		{"pnpm-lock.yaml, the registry", "pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n  '@acme/cli@1.2.0':\n    resolution: {integrity: sha512-abc}\n", npm, "silent"},
		{"pnpm-lock.yaml, a link", "pnpm-lock.yaml", "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      '@acme/cli':\n        specifier: ^1.2.0\n        version: link:../x\n", npm, "hold"},
		{"bun.lock, another registry", "bun.lock", "{\n  \"lockfileVersion\": 1,\n  \"packages\": {\n    \"@acme/cli\": [\"@acme/cli@1.2.0\", \"https://evil.example/\", {}, \"sha512-abc\"],\n  },\n}\n", npm, "hold"},
		{"bun.lock, the registry", "bun.lock", "{\n  \"lockfileVersion\": 1,\n  \"packages\": {\n    \"@acme/cli\": [\"@acme/cli@1.2.0\", \"\", {}, \"sha512-abc\"],\n  },\n}\n", npm, "silent"},
		{"bun.lockb, which this reader cannot read", "bun.lockb", "\x00\x01", npm, "hold"},
		{"uv.lock, a URL", "uv.lock", "version = 1\n[[package]]\nname = \"acme-tools\"\nversion = \"2.0.1\"\nsource = { url = \"https://evil.example/x.whl\" }\n", py, "hold"},
		{"uv.lock, another package's URL", "uv.lock", "version = 1\n[[package]]\nname = \"other\"\nversion = \"1\"\nsource = { url = \"https://x.example/o.whl\" }\n", py, "silent"},
		{"uv.lock, another index", "uv.lock", "version = 1\n[[package]]\nname = \"acme-tools\"\nversion = \"2.0.1\"\nsource = { registry = \"https://evil.example/simple\" }\n", py, "hold"},
		{"uv.lock, the registry", "uv.lock", "version = 1\n[[package]]\nname = \"Acme_Tools\"\nversion = \"2.0.1\"\nsource = { registry = \"https://pypi.org/simple\" }\n", py, "silent"},
		{"pip's requirement in a venv's pip.conf", ".venv/pip.conf", "[install]\nrequirement = r.txt\n", py, "hold"},
		{"pip's cache in a venv's pip.conf", ".venv/pip.conf", "[global]\ncache-dir = /srv/c\n", py, "hold"},
		{"uv offline", "uv.toml", "offline = true\n", py, "hold"},
		{"uv's cache", "uv.toml", "cache-dir = \"/srv/c\"\n", py, "hold"},
		{"uv's override to a URL", "uv.toml", "override-dependencies = [\"acme-tools @ https://evil.example/x.whl\"]\n", py, "hold"},
		{"uv's constraint to a version", "uv.toml", "constraint-dependencies = [\"acme-tools<3\"]\noverride-dependencies = [\"other @ https://x.example/o.whl\"]\n", py, "silent"},
	} {
		_, root, cwd := npmWorkspace(t)
		p := filepath.Join(root, c.file)
		mkdir(t, filepath.Dir(p))
		if strings.HasPrefix(c.file, ".venv/") {
			write(t, filepath.Join(root, ".venv", "pyvenv.cfg"), "home = /usr/bin\n")
		}
		write(t, p, c.body)
		form, stderr := round7(t, cwd, c.command, nil)
		if form != c.want {
			t.Errorf("%s: %s, want %s (stderr %q)", c.name, form, c.want, stderr)
		}
		if c.want == "hold" && !strings.Contains(stderr, movedNote) {
			t.Errorf("%s: stderr %q does not say why", c.name, stderr)
		}
	}
}

// A lockfile larger than the reader reads counts as moved.
func TestRound7LockfileTooLarge(t *testing.T) {
	old := maxLockfile
	maxLockfile = 64
	t.Cleanup(func() { maxLockfile = old })
	_, root, cwd := npmWorkspace(t)
	write(t, filepath.Join(root, "package-lock.json"), `{"lockfileVersion": 3, "packages": {"": {"name": "app", "dependencies": {"left-pad": "1"}}}}`)
	if form, stderr := round7(t, cwd, "npm i @acme/cli", nil); form != "hold" || !strings.Contains(stderr, "could not be read") {
		t.Errorf("a lockfile too large: %s (stderr %q)", form, stderr)
	}
}

func TestRound7Environment(t *testing.T) {
	for _, c := range []struct {
		name    string
		env     []string
		command string
		want    string
	}{
		{"npm offline", []string{"npm_config_offline=true"}, "npm i @acme/cli", "hold"},
		{"CI's npm cache alone", []string{"npm_config_cache=/tmp/ci-cache", "NPM_CONFIG_REGISTRY=https://registry.npmjs.org/"}, "npm i @acme/cli", "silent"},
		{"npm cache and offline", []string{"npm_config_cache=/tmp/c", "npm_config_prefer_offline=true"}, "npm i @acme/cli", "hold"},
		{"npm cache and an offline line", []string{"npm_config_cache=/tmp/c"}, "npm i @acme/cli --offline", "hold"},
		{"Yarn offline", []string{"YARN_ENABLE_OFFLINE_MODE=1"}, "npm i @acme/cli", "hold"},
		{"Yarn's yarnPath", []string{"YARN_YARN_PATH=/tmp/y.cjs"}, "npm i @acme/cli", "hold"},
		{"uv offline", []string{"UV_OFFLINE=1"}, "uv pip install acme-tools==2.0.1", "hold"},
		{"uv offline off", []string{"UV_OFFLINE=false"}, "uv pip install acme-tools==2.0.1", "silent"},
		{"uv's cache alone", []string{"UV_CACHE_DIR=/tmp/uv", "PIP_CACHE_DIR=/tmp/pip"}, "uv pip install acme-tools==2.0.1", "silent"},
		{"PIP_REQUIREMENT", []string{"PIP_REQUIREMENT=r.txt"}, "pip install acme-tools==2.0.1", "hold"},
		{"UV_OVERRIDE", []string{"UV_OVERRIDE=o.txt"}, "uv pip install acme-tools==2.0.1", "hold"},
	} {
		_, _, cwd := npmWorkspace(t)
		form, stderr := round7(t, cwd, c.command, npmrcFiles(t, "", "", c.env, nil))
		if form != c.want {
			t.Errorf("%s: %s, want %s (stderr %q)", c.name, form, c.want, stderr)
		}
	}
}

// pip and uv's environments: CONDA_PREFIX and UV_PROJECT_ENVIRONMENT (absolute, or relative to the project).
func TestRound7Environments(t *testing.T) {
	for _, c := range []struct{ name, env string }{
		{"CONDA_PREFIX", "CONDA_PREFIX="},
		{"UV_PROJECT_ENVIRONMENT", "UV_PROJECT_ENVIRONMENT="},
		{"UV_PROJECT_ENVIRONMENT, relative", "UV_PROJECT_ENVIRONMENT=env"},
	} {
		_, root, cwd := npmWorkspace(t)
		v := t.TempDir()
		env := c.env + v
		if strings.HasSuffix(c.env, "=env") {
			v, env = filepath.Join(root, "env"), c.env
			mkdir(t, v)
		}
		write(t, filepath.Join(v, "pip.conf"), "[global]\nindex-url = https://evil.example/simple\n")
		if form, stderr := round7(t, cwd, "uv pip install acme-tools==2.0.1", npmrcFiles(t, "", "", []string{env}, nil)); form != "hold" {
			t.Errorf("%s: %s (stderr %q)", c.name, form, stderr)
		}
	}
}

// The shell's startup files: a registry, index, offline or cache variable set there is judged as the environment's;
// a value this reader cannot know, or a mention that is not an assignment, counts as moved.
func TestRound7StartupFiles(t *testing.T) {
	for _, c := range []struct{ name, file, body, want, cmd string }{
		{"nothing", ".zshrc", "export PATH=$HOME/bin:$PATH\nalias ll='ls -l'\n", "silent", ""},
		{"~/.zshenv's registry", ".zshenv", "export npm_config_registry=https://evil.example/\n", "hold", ""},
		{"~/.bashrc's public registry", ".bashrc", "export NPM_CONFIG_REGISTRY=\"https://registry.npmjs.org/\"\n", "silent", ""},
		{"~/.profile's registry by a command", ".profile", "export npm_config_registry=$(cat /srv/r)\n", "hold", ""},
		{"a variable of the other ecosystem", ".profile", "export PIP_INDEX_URL=$(cat /srv/i)\n", "silent", ""},
		{"another variable by a command", ".zshrc", "export UV_PYTHON=$(which python3)\nexport YARN_ENABLE_TELEMETRY=$(echo 0)\n", "silent", ""},
		{"another PyPI variable by a command", ".zshrc", "export PIP_REQUIRE_VIRTUALENV=$(echo true)\n", "silent", "pip install acme-tools==2.0.1"},
		{"VIRTUAL_ENV by a variable", ".profile", "export VIRTUAL_ENV=\"$PROJ/.venv\"\n", "hold", "pip install acme-tools==2.0.1"},
		{"a commented-out registry", ".zshrc", "# export npm_config_registry=$(cat /srv/r)\n", "silent", ""},
		{"a comment after the public registry", ".zshrc", "export npm_config_registry=https://registry.npmjs.org/ # npm's\n", "silent", ""},
		{"two settings on a line", ".zshrc", "export npm_config_registry=https://registry.npmjs.org/; export npm_config_offline=true\n", "hold", ""},
		{"a prefix by a command", ".zshrc", "export NPM_CONFIG_PREFIX=$(brew --prefix)\n", "hold", ""},
		{"PREFIX by a command", ".zshrc", "export PREFIX=$(brew --prefix)\n", "hold", ""},
		{"fish, the public registry", ".config/fish/config.fish", "set -gx NPM_CONFIG_REGISTRY https://registry.npmjs.org/\n", "silent", ""},
		{"a cache alone", ".bash_profile", "export npm_config_cache=$HOME/.c\n", "silent", ""},
		{"offline", ".zprofile", "export npm_config_offline=true\n", "hold", ""},
		{"fish", ".config/fish/config.fish", "set -gx npm_config_registry https://evil.example/\n", "hold", ""},
		{"unset", ".bashrc", "unset npm_config_registry\n", "silent", ""},
		{"a mention", ".bashrc", "echo $npm_config_registry\n", "silent", ""}, // round 9: $NAME reads, sets nothing
		{"a variable read from input", ".bashrc", "read npm_config_registry < /srv/r\n", "hold", ""},
		{"a prefix under the home folder", ".bashrc", "export NPM_CONFIG_PREFIX=~/.npm-global\nexport PREFIX=$HOME/.local\n", "silent", ""},
		{"a FIFO", ".zshenv", "", "hold", ""},
	} {
		_, _, cwd := npmWorkspace(t)
		home := t.TempDir()
		p := filepath.Join(home, c.file)
		mkdir(t, filepath.Dir(p))
		if c.name == "a FIFO" {
			if err := syscall.Mkfifo(p, 0o644); err != nil {
				t.Skip("no mkfifo:", err)
			}
		} else {
			write(t, p, c.body)
		}
		cmd := c.cmd
		if cmd == "" {
			cmd = "npm i @acme/cli"
		}
		form, stderr := round7(t, cwd, cmd, npmrcFiles(t, "", home, nil, nil))
		if form != c.want {
			t.Errorf("%s: %s, want %s (stderr %q)", c.name, form, c.want, stderr)
		}
	}
	// ZDOTDIR moves zsh's files
	_, _, cwd := npmWorkspace(t)
	z := t.TempDir()
	write(t, filepath.Join(z, ".zshenv"), "export npm_config_registry=https://evil.example/\n")
	if form, stderr := round7(t, cwd, "npm i @acme/cli", npmrcFiles(t, "", t.TempDir(), []string{"ZDOTDIR=" + z}, nil)); form != "hold" {
		t.Errorf("ZDOTDIR: %s (stderr %q)", form, stderr)
	}
}

// An override's key names a target only at a name's boundary: not-left-pad is not left-pad.
func TestRound7OverrideNameBoundary(t *testing.T) {
	managed := "version: 1\nexceptions:\n  - {package: npm:left-pad, reason: ours, expires: " + soon + "}\n"
	for _, c := range []struct{ body, want string }{
		{`{"resolutions": {"not-left-pad": "npm:x@1"}}`, "silent"},
		{`{"resolutions": {"**/left-pad": "npm:x@1"}}`, "hold"},
		{`{"pnpm": {"overrides": {"foo>left-pad": "npm:x@1"}}}`, "hold"},
		{`{"resolutions": {"left-pad@^1": "npm:x@1"}}`, "hold"},
	} {
		_, root, cwd := npmWorkspace(t)
		write(t, filepath.Join(root, "package.json"), c.body)
		if form, stderr := runTimed(t, holdLeftPad, managedFile(t, managed), codexInputIn(cwd, "npm i left-pad"), nil); form != c.want {
			t.Errorf("%s: %s, want %s (stderr %q)", c.body, form, c.want, stderr)
		}
	}
}
