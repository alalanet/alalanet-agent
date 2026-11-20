package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// REPO-POL-NPMRC (ADR-0174 round 6): a package manager's config file in the workspace that moves the target's registry
// (its scope's, or the default one) away from the public registry alalanet judged makes the hold one no exception
// covers. The server's verdict is never loosened: a hold stays at least a hold, an allow an allow, a block a block.

const holdPyPIAt = `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"alalanet install_check: HOLD. pypi:acme-tools@2.0.1 — new_package. Install only if the user confirms."}}`

// npmWorkspace makes base/repo, a checkout of github.com/acme/app with the repository's exceptions, and the
// subdirectory the agent works in: base (above the git root), root and cwd.
func npmWorkspace(t *testing.T) (base, root, cwd string) {
	t.Helper()
	base = t.TempDir()
	root = filepath.Join(base, "repo")
	cwd = filepath.Join(root, "pkg", "cli")
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cwd, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, ".git", "config"), "[remote \"origin\"]\n\turl = git@github.com:acme/app.git\n")
	write(t, filepath.Join(root, ".alalanet.yml"), exceptOurs)
	return base, root, cwd
}

func TestNpmrcRedirectInTheWorkspace(t *testing.T) {
	for _, c := range []struct {
		name  string
		where string // base, root or cwd
		file  string
		body  string
		want  string
	}{
		{"no config file", "", "", "", "silent"},
		{"the scope moved in the repository's .npmrc", "root", ".npmrc", "@acme:registry=https://evil.example/\n", "hold"},
		{"the scope moved, quoted, with spaces", "root", ".npmrc", "\"@ACME:registry\" = \"https://evil.example/\"\n", "hold"},
		{"the default registry moved", "root", ".npmrc", "registry=https://evil.example/\n", "hold"},
		{"the default registry over plain http", "root", ".npmrc", "registry=http://registry.npmjs.org/\n", "hold"},
		{"the default registry with a path", "root", ".npmrc", "registry=https://registry.npmjs.org/evil/\n", "hold"},
		{"the default registry with a user", "root", ".npmrc", "registry=https://u:p@registry.npmjs.org/\n", "hold"},
		{"the default registry by a variable", "root", ".npmrc", "registry=${REGISTRY}\n", "hold"},
		{"the scope by a variable", "root", ".npmrc", "${SCOPE}:registry=https://registry.npmjs.org/\n", "hold"},
		{"a key by a variable", "root", ".npmrc", "${KEY}=https://evil.example/\n", "hold"},
		{"the default registry on another port", "root", ".npmrc", "registry=https://registry.npmjs.org:8443/\n", "hold"},
		{"the default registry with a query", "root", ".npmrc", "registry=https://registry.npmjs.org/?a=b\n", "hold"},
		{"the public registry with its port written", "root", ".npmrc", "registry=https://registry.npmjs.org:443/\n", "hold"},
		{"the public registry in capitals", "root", ".npmrc", "registry=https://Registry.NPMJS.org/\n", "silent"},
		{"a registry's token by variables", "root", ".npmrc", "//${HOST}/:_authToken=${TOKEN}\n", "silent"},
		{"a comment after the public registry", "root", ".npmrc", "registry=https://registry.npmjs.org/ # the default\n[section]\n", "silent"},
		{"registries in an npmrc", "root", ".npmrc", "registries=x\n", "hold"},
		{"the public registry, written out", "root", ".npmrc", "registry=https://registry.npmjs.org/\n@acme:registry = https://registry.npmjs.org\n", "silent"},
		{"Yarn's alias of the public registry", "root", ".npmrc", "registry=https://registry.yarnpkg.com\n", "silent"},
		{"another scope moved", "root", ".npmrc", "@corp:registry=https://npm.corp.example/\n//npm.corp.example/:_authToken=${TOKEN}\n", "silent"},
		{"comments and sections are not settings", "root", ".npmrc", "; registry=https://evil.example/\n# @acme:registry=https://evil.example/\n# the token: ${NPM_TOKEN}\n", "silent"},
		{"in the directory the agent works in", "cwd", ".npmrc", "@acme:registry=https://evil.example/\n", "hold"},
		{"above the git root", "base", ".npmrc", "@acme:registry=https://evil.example/\n", "hold"},
		{"a relative userconfig", "root", ".npmrc", "userconfig=./other\n", "hold"},
		{"Yarn 1's .yarnrc", "root", ".yarnrc", "\"@acme:registry\" \"https://evil.example/\"\n", "hold"},
		{"Yarn 1's default registry", "root", ".yarnrc", "registry \"https://evil.example/\"\n", "hold"},
		{"Yarn 1's flag for a command", "root", ".yarnrc", "--install.registry \"https://evil.example/\"\n", "hold"},
		{"Yarn 1, the public registry", "root", ".yarnrc", "registry \"https://registry.yarnpkg.com\"\n", "silent"},
		{"Yarn 1, a quote left open", "root", ".yarnrc", "\"@acme:registry https://evil.example/\n", "hold"},
		{"Yarn 1, key and colon", "root", ".yarnrc", "registry: \"https://evil.example/\"\n", "hold"},
		{"Yarn's empty .yarnrc.yml", "root", ".yarnrc.yml", "", "silent"},
		{"Yarn's npmScopes not a mapping", "root", ".yarnrc.yml", "npmScopes: acme\n", "hold"},
		{"Yarn's scope not a mapping", "root", ".yarnrc.yml", "npmScopes:\n  \"@acme\": https://evil.example\n", "hold"},
		{"Yarn's .yarnrc.yml scope", "root", ".yarnrc.yml", "npmScopes:\n  acme:\n    npmRegistryServer: \"https://evil.example\"\n", "hold"},
		{"Yarn's .yarnrc.yml default", "root", ".yarnrc.yml", "npmRegistryServer: https://evil.example\n", "hold"},
		{"Yarn's .yarnrc.yml, by a variable", "root", ".yarnrc.yml", "npmRegistryServer: \"${REG}\"\n", "hold"},
		{"Yarn's .yarnrc.yml, another scope", "root", ".yarnrc.yml", "npmScopes:\n  corp:\n    npmRegistryServer: https://npm.corp.example\nnpmRegistryServer: https://registry.yarnpkg.com\n", "silent"},
		{"Yarn's .yarnrc.yml that does not parse", "root", ".yarnrc.yml", "npmScopes: [\n", "hold"},
		{"Yarn's .yarnrc.yml, a second document", "root", ".yarnrc.yml", "enableTelemetry: false\n---\nnpmRegistryServer: https://evil.example\n", "hold"},
		{"pnpm-workspace.yaml registry", "root", "pnpm-workspace.yaml", "registry: https://evil.example/\n", "hold"},
		{"pnpm-workspace.yaml, the default moved", "root", "pnpm-workspace.yaml", "registries:\n  default: https://evil.example/\n", "hold"},
		{"pnpm-workspace.yaml, the scope's key", "root", "pnpm-workspace.yaml", "\"@acme:registry\": https://evil.example/\n", "hold"},
		{"pnpm-workspace.yaml, a URL to a URL", "root", "pnpm-workspace.yaml", "registries:\n  https://evil.example/: https://evil.example/\n", "hold"},
		{"pnpm-workspace.yaml, registries not a mapping", "root", "pnpm-workspace.yaml", "registries: https://evil.example/\n", "hold"},
		{"pnpm-workspace.yaml, an entry of another form", "root", "pnpm-workspace.yaml", "registries:\n  \"@acme\": [https://evil.example/]\n", "hold"},
		{"pnpm-workspace.yaml, scope to URL", "root", "pnpm-workspace.yaml", "registries:\n  default: https://registry.npmjs.org/\n  \"@acme\": https://evil.example/\n", "hold"},
		{"pnpm-workspace.yaml, URL to scopes", "root", "pnpm-workspace.yaml", "registries:\n  https://evil.example/:\n    scopes: [\"@acme\"]\n", "hold"},
		{"pnpm-workspace.yaml, URL for the default", "root", "pnpm-workspace.yaml", "registries:\n  https://evil.example/:\n    scopes: [\"@\"]\n", "hold"},
		{"pnpm-workspace.yaml, URL with no scopes", "root", "pnpm-workspace.yaml", "registries:\n  https://evil.example/:\n    serverType: artifactory\n", "hold"},
		{"pnpm-workspace.yaml, another scope", "root", "pnpm-workspace.yaml", "packages: [\"pkg/*\"]\nregistries:\n  https://npm.corp.example/:\n    scopes: [\"@corp\"]\n", "silent"},
		{"bunfig.toml scope", "root", "bunfig.toml", "[install.scopes]\nacme = \"https://evil.example/\"\n", "hold"},
		{"bunfig.toml scope as a table", "root", "bunfig.toml", "[install.scopes]\n\"@acme\" = { url = \"https://evil.example/\", token = \"$TOKEN\" }\n", "hold"},
		{"bunfig.toml registry", "root", "bunfig.toml", "[install]\nregistry = \"https://evil.example/\"\n", "hold"},
		{"bunfig.toml registry as a table", "root", "bunfig.toml", "[install.registry]\nurl = \"https://evil.example/\"\n", "hold"},
		{"bunfig.toml, the public registry as a table", "root", "bunfig.toml", "[install.registry]\nurl = \"https://registry.npmjs.org/\"\ntoken = \"$NPM_TOKEN\"\n", "silent"},
		{"bunfig.toml, another scope", "root", "bunfig.toml", "[install]\nregistry = \"https://registry.npmjs.org/\"\n[install.scopes]\ncorp = \"https://npm.corp.example/\"\n", "silent"},
		{"bunfig.toml, install not a table", "root", "bunfig.toml", "install = 1\n", "hold"},
		{"bunfig.toml, scopes not a table", "root", "bunfig.toml", "[install]\nscopes = \"x\"\n", "hold"},
		{"bunfig.toml that does not parse", "root", "bunfig.toml", "[install\n", "hold"},
	} {
		base, root, cwd := npmWorkspace(t)
		if c.file != "" {
			write(t, filepath.Join(map[string]string{"base": base, "root": root, "cwd": cwd}[c.where], c.file), c.body)
		}
		form, stderr := runTimed(t, holdAnswer, managedFile(t, trustAcme), codexInputIn(cwd, "npm i @acme/cli"), nil)
		if form != c.want {
			t.Errorf("%s: %s, want %s (stderr %q)", c.name, form, c.want, stderr)
		}
		if c.want == "hold" && !strings.Contains(stderr, "registry may not be the public one") {
			t.Errorf("%s: stderr %q does not say the registry moved", c.name, stderr)
		}
		if strings.Contains(stderr, "evil.example") || strings.Contains(stderr, "u:p") {
			t.Errorf("%s: stderr %q shows a value (an address may carry a token)", c.name, stderr)
		}
	}
}

// The organisation's own exception (no repository needed) is bound the same way, and the registry is read only to keep
// an exception from covering: the server's hold stays a hold, a deny a deny, an allow an allow, a block a block.
func TestNpmrcNeverLoosens(t *testing.T) {
	for _, c := range []struct {
		name, managed, answer, want string
		note                        bool // the registry kept an exception from covering
	}{
		{"the organisation's exception", "version: 1\nexceptions:\n  - {package: npm:@acme/cli, reason: ours, expires: " + soon + "}\n", holdAnswer, "hold", true},
		{"the organisation's deny", trustAcme + "on_hold:\n  packages: deny\n", holdAnswer, "deny", false},
		{"a block", trustAcme, blockAnswer, "deny", false},
		{"an allow is not this row's", trustAcme, "", "silent", false},
		{"another package held, no exception for it", trustAcme, holdLeftPad, "hold", false},
	} {
		_, root, cwd := npmWorkspace(t)
		write(t, filepath.Join(root, ".npmrc"), "@acme:registry=https://evil.example/\nregistry=https://evil.example/\n")
		form, stderr := runTimed(t, c.answer, managedFile(t, c.managed), codexInputIn(cwd, "npm i @acme/cli"), nil)
		if form != c.want {
			t.Errorf("%s: %s, want %s (stderr %q)", c.name, form, c.want, stderr)
		}
		// the registry is read, and said, only where an exception would otherwise let the hold go
		if strings.Contains(stderr, "registry may not be the public one") != c.note {
			t.Errorf("%s: stderr %q", c.name, stderr)
		}
	}
}

// An unreadable config file counts as a redirect: fail closed, for exceptions only.
func TestNpmrcUnreadableCountsAsMoved(t *testing.T) {
	for _, c := range []struct {
		name string
		make func(t *testing.T, path string)
	}{
		{"a link", func(t *testing.T, path string) {
			other := filepath.Join(t.TempDir(), "npmrc")
			write(t, other, "registry=https://registry.npmjs.org/\n")
			if err := os.Symlink(other, path); err != nil {
				t.Fatal(err)
			}
		}},
		{"a directory", func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{"larger than a config file", func(t *testing.T, path string) {
			write(t, path, strings.Repeat("; a comment\n", 1<<17))
		}},
	} {
		_, root, cwd := npmWorkspace(t)
		c.make(t, filepath.Join(root, ".npmrc"))
		if form, stderr := runTimed(t, holdAnswer, managedFile(t, trustAcme), codexInputIn(cwd, "npm i @acme/cli"), nil); form != "hold" || !strings.Contains(stderr, "could not be read") {
			t.Errorf("%s: %s (stderr %q)", c.name, form, stderr)
		}
	}
}

// pip and uv: the index a venv in the workspace, a uv.toml or a pyproject.toml's [tool.uv] names; the command line's
// --index-url is the server's reader's (it reports custom_registry, which no exception covers).
func TestPipIndexRedirectInTheWorkspace(t *testing.T) {
	for _, c := range []struct {
		name, file, body, command, want string
	}{
		{"no config file", "", "", "pip install acme-tools==2.0.1", "silent"},
		{"a venv's pip.conf", ".venv/pip.conf", "[global]\nindex-url = https://evil.example/simple\n", "pip install acme-tools==2.0.1", "hold"},
		{"a venv's pip.conf, colon and underscores", ".venv/pip.conf", "[install]\nindex_url: https://evil.example/simple\n", "pip install acme-tools==2.0.1", "hold"},
		{"a venv's pip.ini, an extra index", ".venv/pip.ini", "[global]\nextra-index-url =\n    https://pypi.org/simple\n    https://evil.example/simple\n", "pip install acme-tools==2.0.1", "hold"},
		{"a venv's find-links", ".venv/pip.conf", "[global]\nfind-links = /srv/wheels\n", "pip install acme-tools==2.0.1", "hold"},
		{"a venv's no-index", ".venv/pip.conf", "[global]\nno-index = yes\n", "pip install acme-tools==2.0.1", "hold"},
		{"comments in a venv's pip.conf", ".venv/pip.conf", "[global]\n# index-url = https://evil.example/simple\n; find-links = /srv/wheels\n", "pip install acme-tools==2.0.1", "silent"},
		{"a comment inside a value", ".venv/pip.conf", "[global]\nextra-index-url =\n    https://pypi.org/simple\n# the corporate one\n    https://evil.example/simple\n", "pip install acme-tools==2.0.1", "hold"},
		{"PyPI's host with another path", ".venv/pip.conf", "[global]\nindex-url = https://pypi.org/legacy/\n", "pip install acme-tools==2.0.1", "hold"},
		{"a venv's public index", ".venv/pip.conf", "[global]\nindex-url = https://pypi.org/simple/\nno-index = false\ntimeout = 60\n", "pip install acme-tools==2.0.1", "silent"},
		{"a folder that is not a venv", "notvenv/pip.conf", "[global]\nindex-url = https://evil.example/simple\n", "pip install acme-tools==2.0.1", "silent"},
		{"a .venv above the git root (uv looks in the parents)", "../.venv/pip.conf", "[global]\nindex-url = https://evil.example/simple\n", "pip install acme-tools==2.0.1", "hold"},
		{"a venv not named .venv, not the command's", "venv/pip.conf", "[global]\nindex-url = https://evil.example/simple\n", "pip install acme-tools==2.0.1", "silent"},
		{"a venv's no-index alone", ".venv/pip.conf", "[global]\nno-index\n", "pip install acme-tools==2.0.1", "hold"},
		{"the venv the command runs", "tools/env/pip.conf", "[global]\nindex-url = https://evil.example/simple\n", "../../tools/env/bin/pip install acme-tools==2.0.1", "hold"},
		{"the venv the command runs, its index public", "tools/env/pip.conf", "[global]\nindex-url = https://pypi.org/simple\n", "../../tools/env/bin/pip install acme-tools==2.0.1", "silent"},
		{"uv.toml", "uv.toml", "index-url = \"https://evil.example/simple\"\n", "uv pip install acme-tools==2.0.1", "hold"},
		{"uv.toml [[index]]", "uv.toml", "[[index]]\nname = \"corp\"\nurl = \"https://evil.example/simple\"\n", "uv pip install acme-tools==2.0.1", "hold"},
		{"uv.toml [pip]", "uv.toml", "[pip]\nextra-index-url = [\"https://evil.example/simple\"]\n", "uv pip install acme-tools==2.0.1", "hold"},
		{"uv.toml, an index not a string", "uv.toml", "index-url = 1\n", "uv pip install acme-tools==2.0.1", "hold"},
		{"uv.toml no-index", "uv.toml", "no-index = true\n", "uv pip install acme-tools==2.0.1", "hold"},
		{"uv.toml no-index not a boolean", "uv.toml", "no-index = \"yes\"\n", "uv pip install acme-tools==2.0.1", "hold"},
		{"uv.toml no-index off", "uv.toml", "no-index = false\n[pip]\nindex-url = \"https://pypi.org/simple\"\n", "uv pip install acme-tools==2.0.1", "silent"},
		{"uv.toml, index inline", "uv.toml", "index = [{ name = \"corp\", url = \"https://evil.example/simple\" }]\n", "uv pip install acme-tools==2.0.1", "hold"},
		{"uv.toml, index of another form", "uv.toml", "index = \"https://evil.example/simple\"\n", "uv pip install acme-tools==2.0.1", "hold"},
		{"uv.toml, index entries of another form", "uv.toml", "index = [1]\n", "uv pip install acme-tools==2.0.1", "hold"},
		{"uv.toml, pip not a table", "uv.toml", "pip = 1\n", "uv pip install acme-tools==2.0.1", "hold"},
		{"uv.toml, sources not a table", "uv.toml", "sources = 1\n", "uv pip install acme-tools==2.0.1", "hold"},
		{"uv.toml that does not parse", "uv.toml", "[pip\n", "uv pip install acme-tools==2.0.1", "hold"},
		{"pyproject.toml, tool.uv not a table", "pyproject.toml", "[tool]\nuv = 1\n", "uv pip install acme-tools==2.0.1", "hold"},
		{"pyproject.toml, another package's source", "pyproject.toml", "[tool.uv.sources]\nother = { index = \"corp\" }\n", "uv pip install acme-tools==2.0.1", "silent"},
		{"pyproject.toml [tool.uv]", "pyproject.toml", "[project]\nname = \"app\"\n[[tool.uv.index]]\nurl = \"https://evil.example/simple\"\n", "uv pip install acme-tools==2.0.1", "hold"},
		{"pyproject.toml [tool.uv.sources]", "pyproject.toml", "[tool.uv.sources]\nAcme_Tools = { index = \"corp\" }\n", "uv pip install acme-tools==2.0.1", "hold"},
		{"pyproject.toml without [tool.uv]", "pyproject.toml", "[project]\nname = \"app\"\n[tool.ruff]\nline-length = 100\n", "pip install acme-tools==2.0.1", "silent"},
		{"the command line's index is the server's", "", "", "pip install --index-url https://evil.example/simple acme-tools==2.0.1", "hold"},
	} {
		_, root, cwd := npmWorkspace(t)
		if c.file != "" {
			p := filepath.Join(root, c.file)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if (strings.HasSuffix(c.file, "pip.conf") || strings.HasSuffix(c.file, "pip.ini")) && !strings.HasPrefix(c.file, "notvenv/") {
				write(t, filepath.Join(filepath.Dir(p), "pyvenv.cfg"), "home = /usr/bin\n")
			}
			write(t, p, c.body)
		}
		managed := "version: 1\nexceptions:\n  - {package: pypi:acme-tools, reason: ours, expires: " + soon + "}\n"
		form, stderr := runTimed(t, holdPyPIAt, managedFile(t, managed), codexInputIn(cwd, c.command), nil)
		if form != c.want {
			t.Errorf("%s: %s, want %s (stderr %q)", c.name, form, c.want, stderr)
		}
		// the command line's index is the server's reader's: held as custom_registry, before any file is read
		if moved := strings.Contains(stderr, "registry may not be the public one"); c.want == "hold" && moved == strings.Contains(c.command, "--index-url") {
			t.Errorf("%s: stderr %q", c.name, stderr)
		}
	}
}
