package installread

import (
	"strings"
	"testing"
)

// ADR-0243 round 5 (the home-p3 review, P2-1): a tilde-prefix no login name can have (~~, ~=x, ~@, ~#, ~,, ~%, ~., ~.x,
// ~+x, ~-x, ~$X …) is literal in bash, dash and zsh: a folder of that name under the current one. The table is the
// review's p2 probes with bash's own value (review-1117/home-p3/h/truthrun/p2-truth.jsonl, bash 5.2 in a --network
// none container, HOME=/home/u, cwd /w): held is whether bash leaves a ~ or $ at the start of an element or gives the
// current folder (/w: ~0, ~+0, ~-0), except where the rule decides otherwise on purpose (homeP5Decided).
func TestHomeP5TildePrefixTable(t *testing.T) {
	for _, c := range []struct {
		line string
		held bool
	}{
		{"HOME=~~ npm i left-pad", true},
		{"export HOME=~~; npm i left-pad", true},
		{"XDG_CONFIG_DIRS=/etc:~~ pip install requests", true},
		{"HOME=~=x npm i left-pad", true},
		{"export HOME=~=x; npm i left-pad", true},
		{"XDG_CONFIG_DIRS=/etc:~=x pip install requests", true},
		{"HOME=~. npm i left-pad", true},
		{"export HOME=~.; npm i left-pad", true},
		{"XDG_CONFIG_DIRS=/etc:~. pip install requests", true},
		{"HOME=~.x npm i left-pad", true},
		{"export HOME=~.x; npm i left-pad", true},
		{"XDG_CONFIG_DIRS=/etc:~.x pip install requests", true},
		{"HOME=~@ npm i left-pad", true},
		{"export HOME=~@; npm i left-pad", true},
		{"XDG_CONFIG_DIRS=/etc:~@ pip install requests", true},
		{"HOME=~, npm i left-pad", true},
		{"export HOME=~,; npm i left-pad", true},
		{"XDG_CONFIG_DIRS=/etc:~, pip install requests", true},
		{"HOME=~% npm i left-pad", true},
		{"export HOME=~%; npm i left-pad", true},
		{"XDG_CONFIG_DIRS=/etc:~% pip install requests", true},
		{"HOME=~0 npm i left-pad", true},
		{"export HOME=~0; npm i left-pad", true},
		{"XDG_CONFIG_DIRS=/etc:~0 pip install requests", true},
		{"HOME=~1 npm i left-pad", true},
		{"export HOME=~1; npm i left-pad", true},
		{"XDG_CONFIG_DIRS=/etc:~1 pip install requests", true},
		{"HOME=~+0 npm i left-pad", true},
		{"export HOME=~+0; npm i left-pad", true},
		{"XDG_CONFIG_DIRS=/etc:~+0 pip install requests", true},
		{"HOME=~-0 npm i left-pad", true},
		{"export HOME=~-0; npm i left-pad", true},
		{"XDG_CONFIG_DIRS=/etc:~-0 pip install requests", true},
		{"HOME=~xq7 npm i left-pad", true},
		{"export HOME=~xq7; npm i left-pad", true},
		{"XDG_CONFIG_DIRS=/etc:~xq7 pip install requests", true},
		{"HOME=~nouser npm i left-pad", true},
		{"export HOME=~nouser; npm i left-pad", true},
		{"XDG_CONFIG_DIRS=/etc:~nouser pip install requests", true},
		{"HOME=~~/x npm i left-pad", true},
		{"export HOME=~~/x; npm i left-pad", true},
		{"XDG_CONFIG_DIRS=/etc:~~/x pip install requests", true},
		{"HOME=~=/x npm i left-pad", true},
		{"export HOME=~=/x; npm i left-pad", true},
		{"XDG_CONFIG_DIRS=/etc:~=/x pip install requests", true},
		{"HOME=~./.npmrc npm i left-pad", true},
		{"export HOME=~./.npmrc; npm i left-pad", true},
		{"XDG_CONFIG_DIRS=/etc:~./.npmrc pip install requests", true},
		{"HOME=~root npm i left-pad", false},
		{"export HOME=~root; npm i left-pad", false},
		{"XDG_CONFIG_DIRS=/etc:~root pip install requests", false},
		{"HOME=~u npm i left-pad", false},
		{"export HOME=~u; npm i left-pad", false},
		{"XDG_CONFIG_DIRS=/etc:~u pip install requests", false},
		{"HOME=~%x npm i left-pad", true},
		{"export HOME=~%x; npm i left-pad", true},
		{"XDG_CONFIG_DIRS=/etc:~%x pip install requests", true},
		{"HOME=~+x npm i left-pad", true},
		{"export HOME=~+x; npm i left-pad", true},
		{"XDG_CONFIG_DIRS=/etc:~+x pip install requests", true},
		{"HOME=~-x npm i left-pad", true},
		{"export HOME=~-x; npm i left-pad", true},
		{"XDG_CONFIG_DIRS=/etc:~-x pip install requests", true},
		{"HOME=~# npm i left-pad", true},
		{"export HOME=~#; npm i left-pad", true},
		{"XDG_CONFIG_DIRS=/etc:~# pip install requests", true},
		{"D='/usr/bin:~'; PATH=$D npm i left-pad", true},
		{"D=/usr/bin:'~/b'; PATH=$D npm i left-pad", true},
		{"D='$X'; PATH=$D:/usr/bin npm i left-pad", true},
		{"D='$X'; HOME=$D npm i left-pad", true},
		{"D='/etc:~'; XDG_CONFIG_DIRS=$D pip install requests", true},
		{"D=~~; HOME=$D npm i left-pad", true},
	} {
		want := c.held
		if d, ok := homeP5Decided[c.line]; ok {
			want = d
		}
		if got := homeR3Holds(c.line); got != want {
			t.Errorf("%q: held %v, want %v (bash: %v)", c.line, got, want, c.held)
		}
	}
}

// homeP5Decided: the probes the rule decides apart from bash's run. ~1 with an empty directory stack is literal in
// bash, and the rule holds every ~N as a cwd alias anyway (held, as bash). ~xq7 and ~nouser are names a user can have:
// the line cannot tell that none exists, so they stay the home (clean, where bash, finding no such user, leaves them).
var homeP5Decided = map[string]bool{
	// ADR-0243 round 6, P2-A: ~name for any name, a user's who exists (~root, ~u) too, is held
	"HOME=~root npm i left-pad": true, "export HOME=~root; npm i left-pad": true, "XDG_CONFIG_DIRS=/etc:~root pip install requests": true,
	"HOME=~u npm i left-pad": true, "export HOME=~u; npm i left-pad": true, "XDG_CONFIG_DIRS=/etc:~u pip install requests": true,
}

// P3-1: a ~ of an argument word after env or sudo (and an MCP add's -e) is held as the folder ./~ — zsh, dash and bash
// --posix keep it — and the reason says that bash outside POSIX mode would give the home; cmd's set and PowerShell
// never expand it, and their reason is the plain folder's.
func TestHomeP5ArgumentWordWording(t *testing.T) {
	for line, note := range map[string]bool{
		"env HOME=~ npm i left-pad": true, "sudo GOMODCACHE=~/x go install golang.org/x/tools/cmd/goimports@v0.30.0": true,
		"claude mcp add x -e HOME=~ -- npx -y left-pad": true, "env PATH=~/bin:/usr/bin npm i left-pad": true,
		"set HOME=~ && npm i left-pad": false, `$env:HOME = "~"; npm i left-pad`: false, `HOME=""~ npm i left-pad`: false,
	} {
		tg, un, _, s := ParseLine(line)
		rs := append(append([]string{}, un...), HookExtra(line, tg, un, s)...)
		if len(rs) == 0 {
			t.Errorf("%q reads clean", line)
			continue
		}
		has := false
		for _, r := range rs {
			has = has || strings.Contains(r, whyArgTildeNote)
		}
		if has != note {
			t.Errorf("%q: the argument-word note %v, want %v: %q", line, has, note, rs)
		}
	}
}

// P3-2: an argument word's list elements after ":" by the same rule as its start.
func TestHomeP5ArgumentWordListElements(t *testing.T) {
	for _, line := range []string{"env XDG_CONFIG_DIRS=/a:~ pip install requests", "env PATH=/a:~ npm i left-pad",
		"sudo GOPATH=/a:~/x go install golang.org/x/tools/cmd/goimports@v0.30.0", "claude mcp add x -e XDG_CONFIG_DIRS=/a:~ -- uvx black"} {
		if !homeR3Holds(line) {
			t.Errorf("%q reads clean", line)
		}
	}
	if homeR3Holds("env HOME=/home/u:~ npm i left-pad") {
		t.Error("a single folder's value after a : was taken as a list in an argument word")
	}
}

// P3-3: another variable's list elements after ":" by the same rule (a later PATH may bind them); bash expands an
// unquoted ~ after an unquoted ":", which stays the home.
func TestHomeP5OtherVariableListElements(t *testing.T) {
	for line, held := range map[string]bool{
		"D='/usr/bin:~'; PATH=$D npm i left-pad": true, "D=/usr/bin:'~/b'; PATH=$D npm i left-pad": true,
		"D=/usr/bin:~~; PATH=$D npm i left-pad": true, "D=/usr/bin:~/b; PATH=$D npm i left-pad": false,
	} {
		if got := homeR3Holds(line); got != held {
			t.Errorf("%q: held %v, want %v", line, got, held)
		}
	}
}

// P3-4: one reason for env HOME=~+, the cwd alias both readers name the same way.
func TestHomeP5CwdAliasOneReason(t *testing.T) {
	for _, line := range []string{"env HOME=~+ npm i left-pad", "env HOME=~- npm i left-pad", "sudo XDG_CONFIG_HOME=~+/c pip install requests"} {
		tg, un, _, s := ParseLine(line)
		if rs := append(append([]string{}, un...), HookExtra(line, tg, un, s)...); len(rs) != 1 {
			t.Errorf("%q: %d reasons %q, want 1", line, len(rs), rs)
		}
	}
}

// P3-1: the note goes inside the reason that names the argument word's folder, once, and on no other reason.
func TestHomeP5ArgumentWordNotePlace(t *testing.T) {
	line := "env HOME=~ NODE_OPTIONS=--require=./x.js bash -c 'env HOME=~ npm i left-pad'"
	tg, un, _, s := ParseLine(line)
	rs := append(append([]string{}, un...), HookExtra(line, tg, un, s)...)
	home, other := 0, 0
	for _, r := range rs {
		switch n := strings.Count(r, whyArgTildeNote); {
		case strings.Contains(r, "HOME moves"):
			home++
			if n != 1 || !strings.HasSuffix(r, "./~: "+whyDirRelative+"; "+whyArgTildeNote+")") {
				t.Errorf("the home reason %q", r)
			}
		case n > 0:
			other++
			t.Errorf("the note on another reason: %q", r)
		}
	}
	if home == 0 {
		t.Errorf("no home reason: %q", rs)
	}
}

// cmd's %NAME:~n,m% is no tilde: one reason, the variable's (the corpus line of round 5).
func TestHomeP5CmdSubstring(t *testing.T) {
	line := "set PATH=%PATH:~0,3%;%PATH% && npx -y ok-pkg"
	tg, un, _, s := ParseLine(line)
	if rs := append(append([]string{}, un...), HookExtra(line, tg, un, s)...); len(rs) != 1 || strings.Contains(rs[0], "./~") {
		t.Errorf("%q: %q", line, rs)
	}
}

// P3-1: env -S's words, which env splits itself, keep the ~ in every shell: held, without the bash note.
func TestHomeP5EnvSplitNoNote(t *testing.T) {
	for _, line := range []string{"env -S 'HOME=~ npm i left-pad'", "env -S 'PATH=/a:~ npm i left-pad'"} {
		tg, un, _, s := ParseLine(line)
		rs := append(append([]string{}, un...), HookExtra(line, tg, un, s)...)
		if len(rs) == 0 {
			t.Errorf("%q reads clean", line)
		}
		for _, r := range rs {
			if strings.Contains(r, whyArgTildeNote) {
				t.Errorf("%q: %q", line, r)
			}
		}
	}
}

// P3-2 and P3-4 on Windows: a PowerShell list's elements after ";", and one reason with one spelling for both readers.
func TestHomeP5WindowsValues(t *testing.T) {
	for line, want := range map[string]string{
		`$env:XDG_CONFIG_DIRS = "C:\a;~"; pip install requests`: `C:\a;./~`, `$env:HOME=" ~"; npm i left-pad`: "to ./~:",
		`$env:HOME="~"; npm i left-pad`: "to ./~:", `$env:XDG_CONFIG_DIRS="C:\a;~"; pip install requests`: `C:\a;./~`, "set HOME=~ && npm i left-pad": "to ./~:",
	} {
		tg, un, _, s := ParseLine(line)
		if rs := append(append([]string{}, un...), HookExtra(line, tg, un, s)...); len(rs) != 1 || !strings.Contains(rs[0], want) {
			t.Errorf("%q: %q, want one reason with %q", line, rs, want)
		}
	}
}

// P3-4: the current folder's names are read as the current folder, not as a folder named ~+.
func TestHomeP5CwdAliasSpelling(t *testing.T) {
	for _, line := range []string{"HOME=~+ npm i left-pad", "env HOME=~- npm i left-pad", "HOME=~+0/x npm i left-pad"} {
		tg, un, _, s := ParseLine(line)
		rs := append(append([]string{}, un...), HookExtra(line, tg, un, s)...)
		if len(rs) != 1 || strings.Contains(rs[0], "./~") || !strings.Contains(rs[0], whyDirRelative) {
			t.Errorf("%q: %q", line, rs)
		}
	}
}

func TestHomeP5ArgTildeValue(t *testing.T) {
	for _, c := range []struct{ k, v, sep, want string }{
		{"PATH", "/a:~:~+:~/b", ":", "/a:./~:~+:./~/b"}, {"HOME", "/h:~", ":", "/h:~"}, {"HOME", "~/h", ":", "./~/h"},
		{"PATH", `C:\a;~`, ";", `C:\a;./~`}, {"PATH", "/a:~", ";", "/a:~"}, {"GOPATH", "~-:x", ":", "~-:x"},
	} {
		if got, _ := argTildeValue(c.k, c.v, c.sep); got != c.want {
			t.Errorf("argTildeValue(%q, %q, %q) = %q, want %q", c.k, c.v, c.sep, got, c.want)
		}
	}
	if _, wrote := argTildeValue("PATH", "/a:~+", ":"); wrote != 0 {
		t.Error("a cwd alias was written")
	}
}

func TestHomeP5MarkTildeCmdSubstring(t *testing.T) {
	// round 6: an unquoted ~name stays as written (dirWhy holds it); a quoted ~ (its segment: start, end, kind) after
	// an element is written as the folder, except after cmd's %NAME:
	for w, want := range map[string]string{"PATH=%PATH:~0,3%": "PATH=%PATH:~0,3%", "PATH=%a.b:~": "PATH=%a.b:./~",
		"PATH=%a%:~": "PATH=%a%:./~", "PATH=%PATH:~": "PATH=%PATH:~", "D=/usr/bin:~": "D=/usr/bin:./~", "PATH=/a:%PATH:~": "PATH=/a:%PATH:~"} {
		var segs [][3]int
		if !strings.HasSuffix(w, ",3%") {
			segs = [][3]int{{len(w) - 1, len(w), 1}}
		}
		if got, _ := markTilde(w, segs); got != want {
			t.Errorf("markTilde(%q) = %q, want %q", w, got, want)
		}
	}
	if got, _ := markTilde("D=/usr/bin:~~", nil); got != "D=/usr/bin:~~" {
		t.Errorf("an unquoted ~~ was written: %q", got)
	}
}

// P3-4: an argument word's list after env or sudo reads the same in both readers: one reason.
func TestHomeP5ArgumentWordOneReason(t *testing.T) {
	for _, line := range []string{"env PATH=a:~ npm i left-pad", "sudo XDG_CONFIG_DIRS=a:~ pip install requests",
		"env PATH=$X:~ npm i left-pad", "env -S 'PATH=a:~ npm i left-pad'", "fish -c 'env PATH=a:~ npm i left-pad'",
		"pwsh -c 'env PATH=a:~ npm i left-pad'", "sh -c 'env PATH=a:~ npm i left-pad'", "iex 'env PATH=a:~ npm i left-pad'",
		"Invoke-Expression 'env PATH=a:~ npm i left-pad'"} {
		tg, un, _, s := ParseLine(line)
		n := 0
		for _, r := range append(append([]string{}, un...), HookExtra(line, tg, un, s)...) {
			if strings.Contains(r, "PATH points at") || strings.Contains(r, "XDG_CONFIG_DIRS moves") {
				n++
			}
		}
		if n != 1 {
			rs := append(append([]string{}, un...), HookExtra(line, tg, un, s)...)
			t.Errorf("%q: %d PATH reasons in %q", line, n, rs)
		}
	}
}
