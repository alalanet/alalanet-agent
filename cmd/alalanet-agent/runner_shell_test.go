package main

import (
	"path/filepath"
	"testing"
)

// ADR-0159 round 43, P2-1: a line whose package runner starts a shell or another manager is an install line, so the hook
// sends it (before, `pnpm exec sh -c 'npm i x'` was not even sent).
func TestHookSendsRunnerStartedInstalls(t *testing.T) {
	f := &fakeHook{}
	srv := f.server(t)
	for _, cmd := range []string{
		"pnpm exec sh -c 'npm i zz-evil'", "pnpm exec -- bash -c 'npm i zz-evil'", "yarn exec -- sh -c 'npm i zz-evil'",
		"pnpm exec npx zz-evil", "npx -p zz-a sh -c 'npm i zz-evil'", "pn exec sh -c 'pip install zz-evil'",
		"uv run sh -c 'pip install zz-evil'",
	} {
		before := len(f.calls())
		_ = runCodex(t, srv.URL, codexInput("Bash", cmd))
		if len(f.calls()) != before+1 {
			t.Errorf("not sent: %q", cmd)
		}
	}
	for _, cmd := range []string{"pnpm exec tsc --noEmit", "pnpm exec vitest run", "uv run pytest -q"} {
		before := len(f.calls())
		_ = runCodex(t, srv.URL, codexInput("Bash", cmd))
		if len(f.calls()) != before {
			t.Errorf("sent although not an install: %q", cmd)
		}
	}
}

// ADR-0159 round 43, P3-3: a project's pnpm-workspace.yaml with shellMode: true makes pnpm exec run its words through a
// shell (pnpm 10.34.9 and 11.28.12 ran 'probe X;probe Y' for `pnpm exec '<string>'`; work-1116/reader-runner-shell/probe/
// probe43.out w1). For a line that runs pnpm exec the setting holds, as script-shell does; shellMode: false, pnpm add (the
// setting is exec's) and a line that does not run pnpm do not.
func TestPnpmWorkspaceShellMode(t *testing.T) {
	for _, c := range []struct{ name, body, line, want string }{
		{"shellMode true, pnpm exec", "packages: []\nshellMode: true\n", "pnpm exec sh -c 'npm i @acme/cli'", "hold"},
		{"shellMode true, pnpm exec npm", "packages: []\nshellMode: true\n", "pnpm exec npm i @acme/cli", "hold"},
		{"shell-mode true, pnpm exec", "packages: []\nshell-mode: true\n", "pnpm exec npm i @acme/cli", "hold"},
		{"shellMode true, pnpm add", "packages: []\nshellMode: true\n", "pnpm add @acme/cli", "silent"}, // exec only
		{"shellMode false", "packages: []\nshellMode: false\n", "pnpm exec npm i @acme/cli", "silent"},
		{"shellMode true, npm only", "packages: []\nshellMode: true\n", "npm i @acme/cli", "silent"},
	} {
		_, root, cwd := npmWorkspace(t)
		write(t, filepath.Join(root, "pnpm-workspace.yaml"), c.body)
		if form, stderr := round7(t, cwd, c.line, nil); form != c.want {
			t.Errorf("%s: %s, want %s (stderr %q)", c.name, form, c.want, stderr)
		}
	}
}
