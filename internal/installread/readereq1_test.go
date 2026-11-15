package installread

import (
	"slices"
	"strings"
	"testing"
)

// READER-EQ-1 (ADR-0159, round 4): eval joins its arguments with blanks and runs the result as a shell line, so
// both readers read the joined words as that line — as sh -c reads the same script. Before, a script word that
// held an "=" was taken for one VAR=value word (no install read, and the second reader's "through eval" reason
// asked in its place), and a script split across words (eval 'npx -y' pkg) was read as a program named
// "npx -y": no install, no reason, and the hook silent.
func TestReaderEq1EvalReadsItsScript(t *testing.T) {
	const pkg = "zz-eq1-pkg"
	for _, script := range []string{
		"A=1 npx -y " + pkg,
		"A=1 B=2 npm install " + pkg,
		"npx -y " + pkg + " --zz=1",
		"npm install " + pkg + " --zz=1",
		"pip install " + pkg + " --zz=1",
		"uvx " + pkg + " --zz=1",
	} {
		want, _, _, _ := ParseLine("sh -c '" + script + "'")
		if len(want) != 1 {
			t.Fatalf("sh -c %q: targets %q; the fixture is wrong", script, want)
		}
		for _, line := range []string{"eval '" + script + "'", `eval "` + script + `"`, "eval -- '" + script + "'",
			"builtin eval '" + script + "'", "command eval '" + script + "'", "eval eval '" + script + "'",
			"if eval '" + script + "'; then :; fi"} {
			tg, un, _, s := ParseLine(line)
			if !slices.Equal(tg, want) || len(un) != 0 {
				t.Errorf("ParseLine(%q) = %q %q; want %q, as sh -c reads the script", line, tg, un, want)
			}
			for _, x := range HookExtra(line, tg, un, s) {
				if strings.HasPrefix(x, whyThrough) {
					t.Errorf("%q: second reader %q; the first reader checks this install", line, x)
				}
			}
		}
	}
	// The script split across eval's words: eval runs the words joined (eval 'npx -y' pkg runs npx -y pkg).
	for _, line := range []string{"eval 'A=1 npx' -y " + pkg, "eval A=1 'npx -y' " + pkg, "eval 'npx -y' " + pkg,
		"eval npx '-y " + pkg + "'", "eval 'A=1' 'npx -y' " + pkg} {
		if tg, un, _, _ := ParseLine(line); !slices.Equal(tg, []string{"npm:" + pkg}) || len(un) != 0 {
			t.Errorf("ParseLine(%q) = %q %q; want npm:%s, the line eval runs", line, tg, un, pkg)
		}
	}
	// A script with no install keeps the answer sh -c gives; a bare eval reads nothing.
	for _, script := range []string{"A=1 cargo install x", "A=1 echo hi", "A=1"} {
		t1, u1, o1, s1 := ParseLine("eval '" + script + "'")
		t2, u2, o2, s2 := ParseLine("sh -c '" + script + "'")
		if len(t1) != len(t2) || len(u1) != len(u2) || o1 != o2 || s1 != s2 {
			t.Errorf("eval %q: %q %q %v %v; sh -c gives %q %q %v %v", script, t1, u1, o1, s1, t2, u2, o2, s2)
		}
	}
	for _, line := range []string{"eval", "eval --"} {
		if tg, un, _, _ := ParseLine(line); len(tg) != 0 || len(un) != 0 {
			t.Errorf("ParseLine(%q) = %q %q; want nothing", line, tg, un)
		}
	}
	// The second reader reads the joined words too: its own reasons for the line eval runs are those of that line.
	for _, pair := range [][2]string{
		{"eval npx '-c echo-zz'", "npx -c echo-zz"},
		{"eval A=1 'npx -c' echo-zz", "A=1 npx -c echo-zz"},
		{"eval A=1 'npm i " + pkg + "' --registry=http://zz.invalid", "A=1 npm i " + pkg + " --registry=http://zz.invalid"},
		// eval takes no options (F1 of the review): a leading -x word is part of the line in zsh and dash, and zsh
		// ends eval's options at a lone "-", bash at "--"
		{"eval '-x; npx -c echo-zz'", "-x; npx -c echo-zz"},
		{"eval - 'npx -c echo-zz'", "npx -c echo-zz"},
		{"eval -- 'npx -c echo-zz'", "npx -c echo-zz"},
	} {
		te, ue, _, se := ParseLine(pair[0])
		tp, up, _, sp := ParseLine(pair[1])
		got, want := HookExtra(pair[0], te, ue, se), HookExtra(pair[1], tp, up, sp)
		if !slices.Equal(te, tp) || !slices.Equal(ue, up) || !slices.Equal(got, want) {
			t.Errorf("%q: %q %q %q; %q gives %q %q %q", pair[0], te, ue, got, pair[1], tp, up, want)
		}
	}
	// The words are read once, as the joined line: a harmless command in it names no program, and the first program
	// OtherProgram names is the line's (before, the words were read again as a command: "true" here).
	for line, want := range map[string]string{"eval true; cargo install x": "cargo", "eval echo hi": "", "eval cd d && cargo install x": "cargo"} {
		if got := OtherProgram(line); got != want {
			t.Errorf("OtherProgram(%q) = %q; want %q", line, got, want)
		}
	}
	// xargs eval keeps xargs's reading: the packages come from the input.
	tx, ux, _, _ := ParseLine("xargs npm i")
	if tg, un, _, _ := ParseLine("xargs eval 'npm i'"); !slices.Equal(tg, tx) || !slices.Equal(un, ux) {
		t.Errorf("xargs eval 'npm i': %q %q; want %q %q, as xargs npm i", tg, un, tx, ux)
	}
}
