//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// REPO-POL-NPMRC round 3 (ADR-0174 round 8, re-review of a5d1def): the line judged on ParseLine's own commands with a
// fixed list of plain-install options, inline variables, a command besides the install, lockfile names and paths,
// patches, startup files through links and by the tools' case, direnv, mise, corepack.

func TestRound8Line(t *testing.T) {
	for _, c := range []struct{ command, want string }{
		// directory changes in other spellings, options a plain install does not take, inline variables
		{"sudo --chdir=/srv npm i @acme/cli", "hold"},
		{"env --chdir /srv npm i @acme/cli", "hold"},
		{"env -iC/srv npm i @acme/cli", "hold"},
		{"npm i @acme/cli --foo", "hold"},
		{"npm i -gD @acme/cli", "hold"},
		{"pnpm add -r @acme/cli", "hold"},
		{"pnpm --filter web add @acme/cli", "hold"},
		{"pip install -Uq acme-tools==2.0.1", "hold"},
		{"yarn workspaces foreach add @acme/cli", "hold"},
		{"APPDATA=/srv npm i @acme/cli", "hold"},
		{"USERPROFILE=/srv npm i @acme/cli", "hold"},
		{"LOCALAPPDATA=/srv pnpm add @acme/cli", "hold"},
		{"export HOME=/srv && npm i @acme/cli", "hold"},
		{"PIP_PYTHON=python3 pip install acme-tools==2.0.1", "hold"},
		{"HOME=/srv; npm i @acme/cli", "hold"},
		{"env -C/srv -S 'npm i @acme/cli'", "hold"},
		{"pip3 install --cons c.txt acme-tools==2.0.1", "hold"},
		{"source ./env.sh && npm i @acme/cli", "hold"},
		// a plain install
		{"npm i -D @acme/cli", "silent"},
		{"npm install --save-exact @acme/cli", "silent"},
		{"npm i @acme/cli --no-audit --no-fund", "silent"},
		{"npm i -w web @acme/cli", "silent"},
		{"npm i @acme/cli --loglevel=warn", "silent"},
		{"npm i @acme/cli --loglevel warn", "silent"},
		{"npx -y @acme/cli", "silent"},
		{"pnpm add -D @acme/cli", "silent"},
		{"yarn add -D @acme/cli", "silent"},
		{"bun add -d @acme/cli", "silent"},
		{"pip install -U acme-tools==2.0.1", "silent"},
		{"pip3 install -q --user acme-tools==2.0.1", "silent"},
		{"python3 -m pip install acme-tools==2.0.1", "silent"},
		{"uv add --dev acme-tools", "silent"},
		{"uv pip install -U acme-tools==2.0.1", "silent"},
		{"uv pip install -C key=v acme-tools==2.0.1", "silent"},
		{"pip install -C key=v acme-tools==2.0.1", "silent"},
		{"pip install -C --global-option acme-tools==2.0.1", "hold"}, // round 9 (R1): a value never starts with -
		{"source .venv/bin/activate && pip install acme-tools==2.0.1", "silent"},
		{"FOO=1 npm i @acme/cli", "silent"},
		{"NODE_ENV=production npm i @acme/cli", "silent"},
		{"sudo npm i -g @acme/cli", "silent"},
		{"timeout 60 npm i @acme/cli", "silent"},
	} {
		_, _, cwd := npmWorkspace(t)
		if form, stderr := round7(t, cwd, c.command, nil); form != c.want {
			t.Errorf("%s: %s, want %s (stderr %q)", c.command, form, c.want, stderr)
		}
	}
}

func TestRound8Project(t *testing.T) {
	const npm, py = "npm i @acme/cli", "pip install acme-tools==2.0.1"
	tar := func(p string) string { return "https://registry.npmjs.org/" + p }
	big := "# yarn lockfile v1\n" + strings.Repeat("# padding padding padding padding padding padding padding\n", 20000) +
		"\n\"@acme/cli@^1.2.0\":\n  version \"1.2.0\"\n  resolved \"" + tar("@acme/cli/-/cli-1.2.0.tgz#abc") + "\"\n"
	for _, c := range []struct{ name, file, body, command, want string }{
		// package-lock.json
		{"npm v1, nested", "package-lock.json", `{"lockfileVersion":1,"dependencies":{"foo":{"version":"1.0.0","dependencies":{"@acme/cli":{"version":"1.2.0","resolved":"https://evil.example/x.tgz"}}}}}`, npm, "hold"},
		{"npm v1, an alias's version", "package-lock.json", `{"lockfileVersion":1,"dependencies":{"@acme/cli":{"version":"npm:evil-pkg@1.0.0","resolved":"` + tar("evil-pkg/-/evil-pkg-1.0.0.tgz") + `"}}}`, npm, "hold"},
		{"npm, another version's tarball", "package-lock.json", `{"packages":{"node_modules/@acme/cli":{"version":"1.2.0","resolved":"` + tar("@acme/cli/-/cli-9.9.9.tgz") + `"}}}`, npm, "hold"},
		{"npm v1, an alias's version, no tarball", "package-lock.json", `{"lockfileVersion":1,"dependencies":{"@acme/cli":{"version":"npm:evil-pkg@1.0.0"}}}`, npm, "hold"},
		{"npm, another package's name, no tarball", "package-lock.json", `{"packages":{"node_modules/@acme/cli":{"name":"evil-pkg","version":"1.0.0"}}}`, npm, "hold"},
		{"npm, the registry's path on another host", "package-lock.json", `{"packages":{"node_modules/@acme/cli":{"version":"1.2.0","resolved":"https://evil.example/@acme/cli/-/cli-1.2.0.tgz"}}}`, npm, "hold"},
		{"Yarn 1, another version's tarball", "yarn.lock", "\"@acme/cli@^1.2.0\":\n  version \"1.2.0\"\n  resolved \"" + tar("@acme/cli/-/cli-9.9.9.tgz#abc") + "\"\n", npm, "hold"},
		{"mise, a number", "mise.toml", "[env]\nPORT = 3000\n", npm, "silent"},
		{"npm, its own name and tarball", "package-lock.json", `{"packages":{"node_modules/@acme/cli":{"name":"@acme/cli","version":"1.2.0","resolved":"` + tar("@acme/cli/-/cli-1.2.0.tgz") + `"}}}`, npm, "silent"},
		// yarn.lock
		{"Yarn 1, an alias", "yarn.lock", "\"@acme/cli@npm:evil-pkg@^1\":\n  version \"1.0.0\"\n  resolved \"" + tar("evil-pkg/-/evil-pkg-1.0.0.tgz#abc") + "\"\n", npm, "hold"},
		{"Yarn 2+, an alias", "yarn.lock", "__metadata:\n  version: 8\n\n\"@acme/cli@npm:evil-pkg@^1\":\n  version: 1.0.0\n  resolution: \"evil-pkg@npm:1.0.0\"\n", npm, "hold"},
		{"Yarn 1, larger than a config file", "yarn.lock", big, npm, "silent"},
		// pnpm-lock.yaml
		{"pnpm 6, an alias in the importers", "pnpm-lock.yaml", "lockfileVersion: '6.0'\nimporters:\n  .:\n    dependencies:\n      '@acme/cli':\n        specifier: npm:evil-pkg@^1\n        version: /evil-pkg@1.0.0\n", npm, "hold"},
		{"pnpm 5, a link at the top", "pnpm-lock.yaml", "lockfileVersion: 5.4\ndependencies:\n  '@acme/cli': link:../x\n", npm, "hold"},
		{"pnpm 5, a version at the top", "pnpm-lock.yaml", "lockfileVersion: 5.4\ndependencies:\n  '@acme/cli': 1.2.0\n", npm, "silent"},
		{"pnpm 5, a tarball", "pnpm-lock.yaml", "lockfileVersion: 5.4\npackages:\n  /@acme/cli/1.2.0:\n    resolution: {tarball: https://evil.example/x.tgz}\n", npm, "hold"},
		{"pnpm 6, a peer suffix", "pnpm-lock.yaml", "lockfileVersion: '6.0'\ndependencies:\n  '@acme/cli':\n    specifier: ^1.2.0\n    version: 1.2.0(react@18.0.0)\n", npm, "silent"},
		{"pnpm, a snapshot of a URL", "pnpm-lock.yaml", "lockfileVersion: '9.0'\nsnapshots:\n  '@acme/cli@https://evil.example/x.tgz': {}\n", npm, "hold"},
		{"pnpm, another package's tarball", "pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n  '@acme/cli@1.2.0':\n    resolution: {tarball: '" + tar("evil-pkg/-/evil-pkg-1.0.0.tgz") + "'}\n", npm, "hold"},
		// bun.lock
		{"bun, a nested alias", "bun.lock", `{"lockfileVersion":1,"packages":{"parent/@acme/cli":["evil-pkg@1.0.0","",{},"s"],}}`, npm, "hold"},
		{"bun, no version", "bun.lock", `{"lockfileVersion":1,"packages":{"@acme/cli":["@acme/cli","",{},"s"],}}`, npm, "hold"},
		{"bun, a quote escaped in a string", "bun.lock", `{"lockfileVersion":1,"note":"a \"b, c],","packages":{"@acme/cli":["@acme/cli@1.2.0","",{},"s"],},}`, npm, "silent"},
		// uv.lock's files
		{"uv.lock, a wheel on another host", "uv.lock", "version = 1\n[[package]]\nname = \"acme-tools\"\nversion = \"2.0.1\"\nsource = { registry = \"https://pypi.org/simple\" }\nwheels = [{ url = \"https://evil.example/acme_tools-2.0.1-py3-none-any.whl\" }]\n", py, "hold"},
		{"uv.lock, PyPI's files", "uv.lock", "version = 1\n[[package]]\nname = \"acme-tools\"\nversion = \"2.0.1\"\nsource = { registry = \"https://pypi.org/simple\" }\nsdist = { url = \"https://files.pythonhosted.org/packages/a/acme_tools-2.0.1.tar.gz\" }\nwheels = [{ url = \"https://files.pythonhosted.org/packages/a/acme_tools-2.0.1-py3-none-any.whl\" }]\n", py, "silent"},
		// patches, corepack
		{"a patch of another package", "package.json", `{"pnpm":{"patchedDependencies":{"left-pad@1.3.0":"patches/x.patch"}}}`, npm, "silent"},
		{"corepack, a version", "package.json", `{"packageManager":"pnpm@9.1.0+sha512.0123abcd"}`, npm, "silent"},
		{"corepack, a URL", "package.json", `{"packageManager":"yarn@https://evil.example/yarn.tgz"}`, npm, "hold"},
		// direnv, mise
		{"direnv's export", ".envrc", "export npm_config_registry=https://evil.example/\n", npm, "hold"},
		{"direnv's source_up", ".envrc", "source_up\n", npm, "hold"},
		{"direnv, public", ".envrc", "export NPM_CONFIG_REGISTRY=https://registry.npmjs.org/\n", npm, "silent"},
		// round 14 (R8-7): PATH_add puts the project's programs first (an npm of its own in bin)
		{"direnv's PATH_add", ".envrc", "export NPM_CONFIG_REGISTRY=https://registry.npmjs.org/\nPATH_add bin\n", npm, "hold"},
		{"mise's env", "mise.toml", "[env]\nnpm_config_registry = \"https://evil.example/\"\n", npm, "hold"},
		{"mise's template", "mise.toml", "[env]\nnpm_config_registry = \"{{env.R}}\"\n", npm, "hold"},
		{"mise's env file", "mise.toml", "[env]\n_.file = \".env\"\n", npm, "hold"},
		{"mise, another variable", "mise.toml", "[tools]\nnode = \"22\"\n[env]\nNODE_ENV = \"development\"\n", npm, "silent"},
	} {
		_, root, cwd := npmWorkspace(t)
		write(t, filepath.Join(root, c.file), c.body)
		if form, stderr := round7(t, cwd, c.command, nil); form != c.want {
			t.Errorf("%s: %s, want %s (stderr %q)", c.name, form, c.want, stderr)
		}
	}
	// direnv's dotenv reads the .env beside it
	for _, body := range []string{"npm_config_registry=https://evil.example/\n", "npm_config_registry=https://registry.npmjs.org/\n"} {
		_, root, cwd := npmWorkspace(t)
		write(t, filepath.Join(root, ".envrc"), "dotenv\n")
		write(t, filepath.Join(root, ".env"), body)
		want := map[bool]string{true: "hold", false: "silent"}[strings.Contains(body, "evil")]
		if form, stderr := round7(t, cwd, "npm i @acme/cli", nil); form != want {
			t.Errorf("dotenv %q: %s, want %s (stderr %q)", body, form, want, stderr)
		}
	}
}

func TestRound8StartupFiles(t *testing.T) {
	for _, c := range []struct{ name, file, body, cmd, want string }{
		{"a single-quoted public registry", ".zshrc", "export npm_config_registry='https://registry.npmjs.org/'\n", "", "silent"},
		{"a continued line", ".zshrc", "export npm_config_\\\nregistry=https://evil.example/\n", "", "hold"},
		{"a name built from a variable", ".zshrc", "export npm_config_${R}=https://evil.example/\n", "", "hold"},
		{"an export of a command's output", ".zshrc", "export $(grep -v '^#' ~/.env | xargs)\n", "", "hold"},
		{"fish's conf.d", ".config/fish/conf.d/npm.fish", "set -gx npm_config_registry https://evil.example/\n", "", "hold"},
		{"environment.d", ".config/environment.d/npm.conf", "npm_config_registry=https://evil.example/\n", "", "hold"},
		{"pip's name in another case", ".profile", "export pip_index_url=https://evil.example/simple\n", "pip install acme-tools==2.0.1", "silent"},
		{"a PREFIX mention", ".zshrc", "echo $PREFIX\n", "", "silent"},
		{"corepack's registry", ".zshrc", "export COREPACK_NPM_REGISTRY=https://evil.example/\n", "", "hold"},
		{"a file in conf.d that is not fish's", ".config/fish/conf.d/README", "set -gx npm_config_registry https://evil.example/\n", "", "silent"},
		{"PIP_PYTHON by a command", ".profile", "export PIP_PYTHON=$(which python3)\n", "pip install acme-tools==2.0.1", "hold"},
	} {
		_, _, cwd := npmWorkspace(t)
		home := t.TempDir()
		p := filepath.Join(home, c.file)
		mkdir(t, filepath.Dir(p))
		write(t, p, c.body)
		cmd := c.cmd
		if cmd == "" {
			cmd = "npm i @acme/cli"
		}
		if form, stderr := round7(t, cwd, cmd, npmrcFiles(t, "", home, nil, nil)); form != c.want {
			t.Errorf("%s: %s, want %s (stderr %q)", c.name, form, c.want, stderr)
		}
	}
}

// The user's own files are read through a link (F3), and what the link names must still be a regular file.
func TestRound8LinkedUserFiles(t *testing.T) {
	for _, c := range []struct{ name, file, body, want string }{
		{"a linked ~/.npmrc, public", ".npmrc", "registry=https://registry.npmjs.org/\n", "silent"},
		{"a linked ~/.npmrc, moved", ".npmrc", "@acme:registry=https://evil.example/\n", "hold"},
		{"a linked ~/.zshrc, moved", ".zshrc", "export npm_config_registry=https://evil.example/\n", "hold"},
		{"a linked ~/.zshrc to a FIFO", ".zshrc", "", "hold"},
	} {
		_, _, cwd := npmWorkspace(t)
		home := t.TempDir()
		target := filepath.Join(home, "dotfiles", c.file)
		mkdir(t, filepath.Dir(target))
		if c.body == "" {
			if err := syscall.Mkfifo(target, 0o644); err != nil {
				t.Skip("no mkfifo:", err)
			}
		} else {
			write(t, target, c.body)
		}
		if err := os.Symlink(target, filepath.Join(home, c.file)); err != nil {
			t.Fatal(err)
		}
		if form, stderr := round7(t, cwd, "npm i @acme/cli", npmrcFiles(t, "", home, nil, nil)); form != c.want || strings.Contains(stderr, "in time") {
			t.Errorf("%s: %s, want %s (stderr %q)", c.name, form, c.want, stderr)
		}
	}
}

func TestRound8EnvVars(t *testing.T) {
	prefix := t.TempDir()
	write(t, filepath.Join(prefix, "pip.conf"), "[global]\nindex-url = https://evil.example/simple\n")
	mkdir(t, filepath.Join(prefix, "etc"))
	write(t, filepath.Join(prefix, "etc", "npmrc"), "@acme:registry=https://evil.example/\n")
	for _, c := range []struct {
		env     []string
		command string
		want    string
	}{
		{[]string{"COREPACK_NPM_REGISTRY=https://evil.example/"}, "npm i @acme/cli", "hold"},
		{[]string{"COREPACK_NPM_REGISTRY=https://registry.npmjs.org"}, "npm i @acme/cli", "silent"},
		{[]string{"PIP_PYTHON=" + filepath.Join(prefix, "bin", "python3")}, "pip install acme-tools==2.0.1", "hold"},
		{[]string{"UV_PROJECT=/srv"}, "uv add acme-tools", "hold"},
		{[]string{"PIP_PYTHON=" + filepath.Join(t.TempDir(), "bin", "python3")}, "pip install acme-tools==2.0.1", "silent"},
		{[]string{"VIRTUAL_ENV=.venv"}, "pip install acme-tools==2.0.1", "hold"},
		{[]string{"PREFIX=" + prefix}, "npm i @acme/cli", "hold"},
		{[]string{"prefix=" + prefix}, "npm i @acme/cli", "silent"}, // npm reads process.env.PREFIX, by its case on unix
	} {
		_, _, cwd := npmWorkspace(t)
		if form, stderr := round7(t, cwd, c.command, npmrcFiles(t, "", "", c.env, nil)); form != c.want {
			t.Errorf("%v: %s, want %s (stderr %q)", c.env, form, c.want, stderr)
		}
	}
}

// A virtual environment activated by its path in the line: its site config is read.
func TestRound8ActivatedVenv(t *testing.T) {
	v := t.TempDir()
	write(t, filepath.Join(v, "pip.conf"), "[global]\nindex-url = https://evil.example/simple\n")
	_, _, cwd := npmWorkspace(t)
	if form, stderr := round7(t, cwd, "source "+filepath.Join(v, "bin", "activate")+" && pip install acme-tools==2.0.1", nil); form != "hold" {
		t.Errorf("an activated venv's index: %s (stderr %q)", form, stderr)
	}
}
