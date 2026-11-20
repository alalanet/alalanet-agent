package installread

import (
	"strings"
	"testing"
)

// ADR-0243 round 7 (the home-p6 review, P2-1 and P2-2): a search path trusts a ~ entry only when its tilde-prefix is
// empty (~, ~/…). ~+, ~- and ~0 (~+0, ~-0) are the current or previous folder (bash and zsh), held as a folder of the
// project; every other prefix — ~+x, ~-lead, ~1, ~12, ~+1 (a name a directory service may have: bash's stack has one
// entry, so ~1 goes to getpwnam) and ~name — is held as whyDirUser. Every reader, every spelling.
func TestHomeP7SearchPathTilde(t *testing.T) {
	cwd := []string{"~+", "~-", "~0", "~+0", "~-0"}
	user := []string{"~+x", "~-lead", "~1", "~12", "~+1", "~-1", "~+x1", "~u"}
	for _, pre := range append(append([]string{}, cwd...), user...) {
		want := whyDirUser
		for _, c := range cwd {
			if pre == c {
				want = whyDirRelative
			}
		}
		for _, line := range []string{
			"PATH=" + pre + "/bin:/usr/bin go install example.com/x@latest", "PATH=/usr/bin:" + pre + "/bin cargo install x",
			"export PATH=" + pre + "/bin && npm i x", "declare -x LD_LIBRARY_PATH=" + pre + "; go install example.com/x@latest",
			"env NODE_PATH=" + pre + " npm i x", "sudo PYTHONPATH=" + pre + "/lib pip install requests",
			"claude mcp add s -e PATH=" + pre + "/bin:/usr/bin -- npx -y y", "HOME=" + pre + " npm i x",
			"GOMODCACHE=" + pre + "/m go install example.com/x@latest", "XDG_CONFIG_DIRS=/etc:" + pre + " pip install requests",
		} {
			rs := homeP6Reasons(line)
			if len(rs) == 0 {
				t.Errorf("%q reads clean", line)
				continue
			}
			if want == whyDirUser && !strings.Contains(strings.Join(rs, "|"), whyDirUser) && !strings.Contains(strings.Join(rs, "|"), "./~") {
				t.Errorf("%q: no %q in %q", line, want, rs)
			}
			if want == whyDirRelative && strings.Contains(strings.Join(rs, "|"), whyDirUser) {
				t.Errorf("%q: the current folder read as another user's: %q", line, rs)
			}
		}
	}
	// the home stays the home; cmd's %NAME:~n,m% is no tilde
	for _, line := range []string{"PATH=~/bin:/usr/bin go install example.com/x@latest", "PATH=~:/usr/bin npm i x", "HOME=~ npm i x",
		"set PATH=%PATH:~0,3%;C:\\bin && go install example.com/x@latest"} {
		if rs := homeP6Reasons(line); len(rs) != 0 && !strings.Contains(line, "%PATH") {
			t.Errorf("%q: %q", line, rs)
		}
	}
	// the reason says which: the first reader's PATH text
	for line, want := range map[string]string{"PATH=~+/bin:/usr/bin go install example.com/x@latest": whyDirRelative,
		"PATH=~1/bin:/usr/bin go install example.com/x@latest": whyDirUser, "PATH=~0:~u go install example.com/x@latest": whyDirUser} {
		if _, un, _, _ := ParseLine(line); len(un) != 1 || !strings.Contains(un[0], "points at") || !strings.HasSuffix(un[0], ": "+want+")") {
			t.Errorf("%q: %q, want %q", line, un, want)
		}
	}
	if untrustedPathIn("%PATH:~0,3%", true) {
		t.Error("cmd's %PATH:~0,3% read as a ~ entry")
	}
}

// P3-1: a word whose name, "=" or ~ is quoted is no assignment-shaped word: every shell keeps its ~. Held, no note.
func TestHomeP7QuotedWordNoNote(t *testing.T) {
	for _, line := range []string{`env "HOME=~/x" npm i x`, `sudo 'HOME=~/x' npm i x`, `claude mcp add s -e "HOME=~u" -- npx -y y`,
		`codex mcp add s --env "HOME=~/x" -- npx -y y`, `env "PATH=/a:~/b" npm i x`, `env HOME"=~" npm i x`, `env HOME="~u" npm i x`,
		`env 'HOME'=~/x npm i x`} {
		rs := homeP6Reasons(line)
		if len(rs) == 0 {
			t.Errorf("%q reads clean", line)
		}
		for _, r := range rs {
			if strings.Contains(r, "zsh and dash keep") {
				t.Errorf("%q: %q", line, r)
			}
		}
	}
	// unquoted, the note stays
	for _, line := range []string{"env HOME=~/x npm i x", "claude mcp add s -e HOME=~u -- npx -y y"} {
		if !strings.Contains(strings.Join(homeP6Reasons(line), "|"), "zsh and dash keep") {
			t.Errorf("%q: no note", line)
		}
	}
}
