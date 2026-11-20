//go:build unix

package main

// REPO-POL-NPMRC round 11 (ADR-0174 round 16): mise by an allow-list, a source of /dev/stdin, the user's own
// UV_PYTHON.

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestRound16MiseAllowList(t *testing.T) {
	for _, c := range []struct{ name, file, body, want string }{
		{"registry names and versions", "mise.toml", "[tools]\nnode = \"22\"\npython = [\"3.12\", \"3.13\"]\nterraform = \"latest\"\n\"core:go\" = \"1.23\"\n", "silent"},
		{"inert options", "mise.toml", "[tools]\nnode = { version = \"22\", os = [\"macos\"], depends = [\"python\"], prerelease = false }\n", "silent"},
		{"prefix: version", "mise.toml", "[tools]\nnode = \"prefix:22\"\n", "silent"},
		{"env, vars, tasks, min_version", "mise.toml", "min_version = \"2026.1.0\"\n[vars]\nx = \"1\"\n[env]\nFOO = \"bar\"\n[tasks.test]\nrun = \"npm test\"\n", "silent"},
		{"tool_config locked", "mise.toml", "[tool_config]\nlocked = true\n", "silent"},
		{"tool_config other", "mise.toml", "[tool_config]\nfoo = 1\n", "hold"},
		{"cargo backend", "mise.toml", "[tools]\n\"cargo:x\" = \"1\"\n", "hold"},
		{"go backend", "mise.toml", "[tools]\n\"go:example.com/x\" = \"1\"\n", "hold"},
		{"a name with a slash", "mise.toml", "[tools]\n\"evil/npm\" = \"1\"\n", "hold"},
		{"ref: version", "mise.toml", "[tools]\nnode = \"ref:main\"\n", "hold"},
		{"version table path", "mise.toml", "[tools]\nnode = { version = \"path:/x\" }\n", "hold"},
		{"install_env", "mise.toml", "[tools]\nnode = { version = \"22\", install_env = { X = \"1\" } }\n", "hold"},
		{"lazy", "mise.toml", "[tools]\nnode = { version = \"22\", lazy = true }\n", "hold"},
		{"empty list", "mise.toml", "[tools]\nnode = []\n", "hold"},
		{"a number", "mise.toml", "[tools]\nnode = 22\n", "hold"},
		{"tools not a table", "mise.toml", "tools = \"node\"\n", "hold"},
		{"settings", "mise.toml", "[settings]\nexperimental = true\n", "hold"},
		{"alias", "mise.toml", "[alias]\nnode.lts = \"20\"\n", "hold"},
		{"tool_alias", "mise.toml", "[tool_alias]\nmynode = \"node\"\n", "hold"},
		{"shell_alias", "mise.toml", "[shell_alias]\nnpm = \"/x/npm\"\n", "hold"},
		{"include", "mise.toml", "include = [\"x.toml\"]\n", "hold"},
		{"env_file", "mise.toml", "env_file = \".env\"\n", "hold"},
		{"watch_files", "mise.toml", "[[watch_files]]\npatterns = [\"x\"]\nrun = \"x\"\n", "hold"},
		{"conf.d", ".config/mise/conf.d/a.toml", "[settings]\nx = 1\n", "hold"},
		{"MISE_ENV file not set", "mise.ci.toml", "[settings]\nx = 1\n", "silent"},
		{".tool-versions plain", ".tool-versions", "nodejs 22.1.0\npython 3.12 3.13 # two\n", "silent"},
		{".tool-versions path", ".tool-versions", "nodejs path:/x/node\n", "hold"},
		{".tool-versions ref", ".tool-versions", "nodejs ref:main\n", "hold"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, _, cwd := npmWorkspace(t)
			mkdir(t, filepath.Dir(filepath.Join(cwd, c.file)))
			write(t, filepath.Join(cwd, c.file), c.body)
			if form, stderr := round7(t, cwd, "npm i @acme/cli", nil); form != c.want {
				t.Errorf("%s, want %s (stderr %q)", form, c.want, stderr)
			}
		})
	}
	// MISE_ENV names more files
	_, _, cwd := npmWorkspace(t)
	write(t, filepath.Join(cwd, "mise.ci.toml"), "[settings]\nx = 1\n")
	if why := registryMoved(npmrcFiles(t, "", "", []string{"MISE_ENV=dev,ci"}, nil), cwd, "npm i @acme/cli", []string{"npm:@acme/cli"}); !strings.Contains(why, "mise.ci.toml sets settings") {
		t.Errorf("MISE_ENV: %q", why)
	}
	// the user's own mise files
	home := t.TempDir()
	write(t, filepath.Join(home, ".tool-versions"), "nodejs path:/x\n")
	if why := registryMoved(npmrcFiles(t, "", home, nil, nil), cwd, "npm i @acme/cli", []string{"npm:@acme/cli"}); !strings.Contains(why, ".tool-versions takes the tool") {
		t.Errorf("~/.tool-versions: %q", why)
	}
}

func TestRound16SourceDevStdin(t *testing.T) {
	for _, form := range []string{`source /dev/stdin <<<"$(@P@ shellenv)"`, "@P@ completion bash | source /dev/stdin", ". /dev/fd/0 <<< $(@P@ x)"} {
		home := t.TempDir()
		prog := filepath.Join(t.TempDir(), "tool")
		write(t, prog, "#!/bin/sh\n")
		write(t, filepath.Join(home, ".bashrc"), strings.ReplaceAll(form, "@P@", prog)+"\n")
		why := pinThenChange(t, home, nil, func() { write(t, prog, "#!/bin/sh\necho x\n") })
		if !strings.HasPrefix(why, prog+" is a shell startup file that changed") {
			t.Errorf("%s: %q", form, why)
		}
	}
	// a program by no path: moved, with what to do; policy-approve pins the rest and does not refuse
	home := t.TempDir()
	write(t, filepath.Join(home, ".bashrc"), "source /dev/stdin <<<\"$(kubectl completion bash)\"\n")
	_, _, cwd := npmWorkspace(t)
	dir := filepath.Join(t.TempDir(), "pin")
	if why := r14(t, cwd, home, dir, nil, false); !strings.Contains(why, "sources the output of a program by /dev/stdin and names that program by no path") || !strings.Contains(why, "write the program's full path") {
		t.Errorf("%q", why)
	}
	if err := policyApprove(&bytes.Buffer{}, pinned(t, home, dir), (&codeTTY{}).open); err != nil {
		t.Errorf("policy-approve: %v", err)
	}
}

func TestRound16UsersOwnUvPython(t *testing.T) {
	_, _, cwd := npmWorkspace(t)
	home := t.TempDir()
	write(t, filepath.Join(home, ".zshenv"), "export UV_PYTHON=/opt/homebrew/bin/python3.13\nexport UV_TOOL_DIR=$HOME/tools\n")
	if why := r14(t, cwd, home, filepath.Join(t.TempDir(), "pin"), nil, true); why != "" {
		t.Errorf("a startup file's UV_PYTHON: %q", why)
	}
	// a project's still counts
	write(t, filepath.Join(cwd, ".envrc"), "export UV_PYTHON=/x/bin/python\n")
	if why := r14(t, cwd, home, filepath.Join(t.TempDir(), "pin"), nil, true); !strings.Contains(why, "names the interpreter uv runs by its path") {
		t.Errorf("a project's UV_PYTHON: %q", why)
	}
}
