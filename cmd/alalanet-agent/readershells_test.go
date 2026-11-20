package main

import "testing"

// READER-SHELLS (ADR-0159, round 5): the agent's own filter embeds the reader, so on 7b53831 none of these lines was
// sent to alalanet (Codex, Cursor, Copilot, Antigravity).
func TestReaderShellsAgentSends(t *testing.T) {
	for _, line := range []string{
		"ksh -c 'npm i zz-shells-pkg'",
		"su -c 'npm i zz-shells-pkg'",
		"watch 'npm i zz-shells-pkg'",
		"fish -c 'npm i zz-shells-pkg'",
		"iex 'npm i zz-shells-pkg'",
		"echo 'npm i zz-shells-pkg' | sh",
		`eval "$(echo npx -y zz-shells-pkg)"`,
		"${NPX:-npx} -y zz-shells-pkg",
	} {
		if !isInstall(line) {
			t.Errorf("%q: not sent to alalanet", line)
		}
	}
}
