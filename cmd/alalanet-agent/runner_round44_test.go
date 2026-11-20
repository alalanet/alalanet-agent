package main

import "testing"

// ADR-0159 round 44, P2-1 and P3-1: a line whose runner starts a shell through uv's global options or uv run's value
// options, a program named by an expansion, or an env wrapper under any runner spelling is an install line, so the hook
// sends it; a uv server line as MCP configs write it, and uv run with its options around a test runner, are not sent.
func TestHookSendsRound44RunnerLines(t *testing.T) {
	f := &fakeHook{}
	srv := f.server(t)
	for _, cmd := range []string{
		"uv --directory /srv run sh -c 'npm i zz-evil'", "uv run --env-file .env pip install zz-evil",
		"uv -q tool run zz-evil", "pnpm exec $SHELL -c 'npm i zz-evil'", "npm exec -- cross-env A=1 npm i zz-evil",
		"yarn dlx -p zz-pkg sh -c 'npm i zz-evil'",
	} {
		before := len(f.calls())
		_ = runCodex(t, srv.URL, codexInput("Bash", cmd))
		if len(f.calls()) != before+1 {
			t.Errorf("not sent: %q", cmd)
		}
	}
	for _, cmd := range []string{"uv --directory /srv run zz-server", "uv run --group dev pytest -q", "uv -q run --frozen pytest",
		"pnpm exec cross-env NODE_ENV=test vitest run"} {
		before := len(f.calls())
		_ = runCodex(t, srv.URL, codexInput("Bash", cmd))
		if len(f.calls()) != before {
			t.Errorf("sent although not an install: %q", cmd)
		}
	}
}
