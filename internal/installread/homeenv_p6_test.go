package installread

import (
	"strings"
	"testing"
)

func homeP6Reasons(line string) []string {
	tg, un, _, s := ParseLine(line)
	return append(append([]string{}, un...), HookExtra(line, tg, un, s)...)
}

// ADR-0243 round 6, P2-A: ~name, for any name (one no user has is literal in bash and dash: the repository's ./~xq7; one
// a user has is that user's home, whose config alalanet does not see; ~root too), is held as whyDirUser, written as the
// line wrote it (no ./), wherever a folder is judged: the package managers' config folders, the go folders, the search
// paths and the second reader's path levers, at the start, as a list element and through another variable.
func TestHomeP6UserTildeHeld(t *testing.T) {
	for _, line := range []string{
		"HOME=~xq7 npm i left-pad", "HOME=~root npm i left-pad", "HOME=~postgres/x npm i left-pad", "export HOME=~nouser; npm i left-pad",
		"declare -x HOME=~u; npm i left-pad", "XDG_CONFIG_DIRS=/etc:~nouser pip install requests", "XDG_CONFIG_HOME=~a.b-c/.config pip install requests",
		"GOMODCACHE=~u/m go install golang.org/x/tools/cmd/goimports@v0.30.0", "GOPATH=/go:~u go install golang.org/x/tools/cmd/goimports@v0.30.0",
		"PATH=~u/bin:/usr/bin npm i left-pad", "PATH=/usr/bin:~u/bin npm i left-pad", "NODE_EXTRA_CA_CERTS=~u/ca.pem npm i left-pad",
		"PYTHONUSERBASE=~u pip install requests", "UV_PYTHON=~u/bin/python uv pip install requests", "D=~xq7; HOME=$D npm i left-pad",
		"D=/usr/bin:~u/bin; PATH=$D npm i left-pad",
		// P3-2: real names outside POSIX's portable set (SSSD's user@domain, a machine account, a digit first) and names
		// no user can have: the same reason, which fits them all
		"HOME=~x@y npm i left-pad", "HOME=~m$ npm i left-pad", "HOME=~9z npm i left-pad", "HOME=~~ npm i left-pad",
		"HOME=~=x npm i left-pad", "XDG_CONFIG_DIRS=/etc:~. pip install requests",
	} {
		rs := homeP6Reasons(line)
		if len(rs) == 0 {
			t.Errorf("%q reads clean", line)
			continue
		}
		user := false
		for _, r := range rs {
			user = user || strings.Contains(r, whyDirUser)
			if strings.Contains(r, "./~") {
				t.Errorf("%q: written as a folder of the project: %q", line, r)
			}
		}
		if !user {
			t.Errorf("%q: no %q in %q", line, whyDirUser, rs)
		}
	}
}

// P2-A: the home itself and the directory stack keep their rules.
func TestHomeP6HomeAndStackUnchanged(t *testing.T) {
	for _, line := range []string{"HOME=~ npm i left-pad", "HOME=~/x npm i left-pad", "XDG_CONFIG_DIRS=/etc:~/x pip install requests",
		"PATH=~/bin:/usr/bin npm i left-pad", "GOMODCACHE=~/m go install golang.org/x/tools/cmd/goimports@v0.30.0", "D=~/b; PATH=$D:/usr/bin npm i left-pad",
		"HOME=~:x npm i left-pad", "PATH=~:/opt/bin npm i left-pad"} {
		if rs := homeP6Reasons(line); len(rs) != 0 {
			t.Errorf("%q: %q", line, rs)
		}
	}
	// round 7: only ~+, ~- and ~0 (~+0, ~-0) are the current folder; ~1, ~+2, ~+x, ~-lead are ~name (TestHomeP7…)
	for _, line := range []string{"HOME=~+ npm i left-pad", "HOME=~- npm i left-pad", "HOME=~0/x npm i left-pad", "HOME=~+0 npm i left-pad"} {
		rs := homeP6Reasons(line)
		if len(rs) != 1 || !strings.Contains(rs[0], whyDirRelative) || strings.Contains(rs[0], whyDirUser) || strings.Contains(rs[0], "zsh and dash") {
			t.Errorf("%q: %q", line, rs)
		}
	}
}

// P3-1: the note is exact. --env=K=V and -eK=V are no assignment-shaped words, which bash leaves as they are: no note;
// a ~name of an argument word gets the note for another user's home.
func TestHomeP6NoteExact(t *testing.T) {
	for line, want := range map[string]string{
		"claude mcp add x --env=HOME=~ -- npx -y left-pad": "", "claude mcp add x -eHOME=~ -- npx -y left-pad": "",
		"claude mcp add x -e=HOME=~ -- npx -y left-pad": "", "claude mcp add x -e HOME=~ -- npx -y left-pad": whyArgTildeNote,
		"claude mcp add x --env HOME=~/x -- npx -y left-pad": whyArgTildeNote, "env HOME=~ npm i left-pad": whyArgTildeNote,
		"env HOME=~xq7 npm i left-pad": whyArgTildeUserNote, "sudo HOME=~root/x npm i left-pad": whyArgTildeUserNote,
		"claude mcp add x -e HOME=~nouser -- npx -y left-pad": whyArgTildeUserNote, "env PATH=~/a:~u/b npm i left-pad": whyArgTildeBothNote,
		"codex mcp add x --env=HOME=~ -- npx -y left-pad": "", "codex mcp add x --env HOME=~ -- npx -y left-pad": whyArgTildeNote,
		"gemini mcp add x -e=HOME=~ npx -y left-pad": "", "gemini mcp add x -e HOME=~u npx -y left-pad": whyArgTildeUserNote,
	} {
		rs := homeP6Reasons(line)
		if len(rs) == 0 {
			t.Errorf("%q reads clean", line)
			continue
		}
		for _, r := range rs {
			got := ""
			for _, n := range []string{whyArgTildeNote, whyArgTildeUserNote, whyArgTildeBothNote} {
				if strings.Contains(r, n) {
					got = n
				}
			}
			if got != want {
				t.Errorf("%q: note %q, want %q, in %q", line, got, want, r)
			}
		}
	}
}

// P2-A in the first reader alone, and in its text; a Windows list split at ";"; PowerShell's and cmd's ~name is the
// folder (no shell expands it there), not another user's home.
func TestHomeP6FirstReaderAndWindows(t *testing.T) {
	for v, want := range map[string]bool{"~u/bin:/usr/bin": true, "/usr/bin:~u": true, `C:\bin;~u\bin`: true, "~/bin:/usr/bin": false,
		"%PATH:~0,3%": false, "~+:/usr/bin": true, "/a;~u": true, `C:\bin`: false} {
		if got := untrustedPathIn(v, true); got != want {
			t.Errorf("untrustedPathIn(%q, true) = %v, want %v", v, got, want)
		}
	}
	for v, want := range map[string]string{"/a:~u/b": ": " + whyDirUser, `C:\a;~u`: ": " + whyDirUser, "~/a:/b": "", "%P:~0,3%": "",
		"~u;b:/c": ": " + whyDirUser} {
		if got := tildeWhy(v); got != want {
			t.Errorf("tildeWhy(%q) = %q, want %q", v, got, want)
		}
	}
	_, un, _, _ := ParseLine("PATH=~u/bin:/usr/bin npm i left-pad")
	if len(un) != 1 || !strings.Contains(un[0], "PATH points at ~u/bin:/usr/bin: "+whyDirUser) {
		t.Errorf("the first reader: %q", un)
	}
	for _, line := range []string{`$env:PATH = "~u\bin;C:\bin"; npm i left-pad`, `set PATH=~u\bin;%PATH% && npm i left-pad`, `$env:HOME = "~u"; npm i left-pad`} {
		rs := homeP6Reasons(line)
		if len(rs) == 0 {
			t.Errorf("%q reads clean", line)
		}
		for _, r := range rs {
			if strings.Contains(r, whyDirUser) {
				t.Errorf("%q: %q", line, r)
			}
		}
	}
}

func TestHomeP6TildeUser(t *testing.T) {
	for d, want := range map[string]bool{"~u": true, "~u/x": true, `~u\x`: true, "~": false, "~/x": false, `~\x`: false, "~:x": false,
		"~+": false, "~-": false, "~0": false, "~+0": false, "~-0/x": false, "~12": true, "~1": true, "~+3/x": true, "~+x": true, "~-lead": true,
		"~9z": true, "~x@y": true, "u": false, "": false} {
		if got := tildeUser(d); got != want {
			t.Errorf("tildeUser(%q) = %v, want %v", d, got, want)
		}
	}
}
