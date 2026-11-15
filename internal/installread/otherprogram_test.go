package installread

import (
	"slices"
	"strings"
	"testing"
)

// ECO-1 round 2 (ADR-0159): OtherProgram is the program of the first command of a line that the reader
// reads as neither an install it reads nor a harmless command — read exactly as ParseLine reads the line:
// past VAR=value words, wrappers and their options that take a value (WrapperValueFlags, clusters such as
// -nu), timeout's duration and "--", into sh -c, bash -lc, eval, env -S, pwsh -Command and cmd /c scripts,
// and past harmless commands before &&, ; or |.
func TestOtherProgram(t *testing.T) {
	for in, want := range map[string]string{
		"cargo install x":                         "cargo",
		"sudo -u root gem install x":              "gem",
		"sudo -nu root gem install x":             "gem",
		"sudo --user=root -- gem install x":       "gem",
		"doas -u admin cargo install x":           "cargo",
		"env -u HOME -C /tmp go install x@latest": "go",
		"RUSTFLAGS=x sudo -g wheel cargo install": "cargo",
		"timeout -k 5 60 cargo install x":         "cargo",
		"nohup nice -n 5 brew install x":          "brew",
		"xargs -n 1 cargo install":                "cargo",
		"sh -c 'cargo install x'":                 "cargo",
		`bash -lc "go install x@latest"`:          "go",
		"eval 'gem install x'":                    "gem",
		"env -S 'mvn dependency:get'":             "mvn",
		"cmd /c dotnet tool install -g x":         "dotnet",
		`pwsh -Command "dnx X --yes"`:             "dnx",
		"cd d && cargo install x":                 "cargo",
		"cd d; echo hi; brew install x":           "brew",
		"echo hi | docker run -i x":               "docker",
		"/usr/local/bin/docker run x":             "docker",
		"$(which gem) install x":                  "gem",
		"npx -y left-pad && cargo install x":      "cargo",
		"docker run x; cargo install y":           "docker", // the first such command
		"sh -c 'echo hi'":                         "sh",     // the script is harmless: the shell is the program
		"npx -y left-pad":                         "",       // only an install the reader reads
		"cd d && echo hi":                         "",       // only harmless commands
		"FOO=1":                                   "",
		"":                                        "",
		"sudo":                                    "", // a wrapper with nothing to run: no program
	} {
		if got := OtherProgram(in); got != want {
			t.Errorf("OtherProgram(%q) = %q; want %q", in, got, want)
		}
	}
}

// ECO-1 round 3, P3-1: an eval or env -S script given as one quoted word that holds an "=" was taken by the
// reader for one VAR=value word (READER-EQ-1: the assignment test came before the quoted-script test in
// command), so it read no program in it. OtherProgram reads such a script as sh -c's: past its leading
// assignments, or with an option's value further on. Since READER-EQ-1 closed (ADR-0173 for env -S, ADR-0159
// round 4 for eval) the reader itself reads it so, and ParseLine's answer for an eval line is sh -c's.
func TestOtherProgramReadsAssignmentScripts(t *testing.T) {
	for script, want := range map[string]string{
		"A=1 cargo install x":                      "cargo",
		"A=1 B=2 gem install x":                    "gem",
		"RUSTFLAGS=-Dwarnings cargo install x":     "cargo",
		"cargo install --features=a x":             "cargo",
		"A=1 cd d && go install x@latest":          "go",
		"A=1 dotnet tool install -g x --version=1": "dotnet",
		`A=1 eval "B=2 cargo install x"`:           "cargo", // such a script inside one
	} {
		if got := OtherProgram("sh -c '" + script + "'"); got != want {
			t.Fatalf("sh -c %q: %q; the fixture is wrong", script, got)
		}
		for _, line := range []string{"eval '" + script + "'", "env -S '" + script + "'", "env --split-string='" + script + "'",
			"env -S'" + script + "'", "sudo env -S '" + script + "'", "nohup env -i -S '" + script + "'"} {
			want := want
			if strings.Contains(line, "env") && strings.Contains(script, "&&") {
				// env -S runs no shell (P1-X, ADR-0173): "&&" is a word to env, which runs the first program with
				// the rest as its arguments.
				want = "cd"
			}
			if got := OtherProgram(line); got != want {
				t.Errorf("OtherProgram(%q) = %q; want %q, as under sh -c (env -S: as env reads it)", line, got, want)
			}
			tg, unread, other, subst := ParseLine(line)
			if len(tg) != 0 || len(unread) != 0 || !other || subst {
				t.Errorf("ParseLine(%q) = %q %q %v %v; want nothing but other", line, tg, unread, other, subst)
			}
			if strings.HasPrefix(line, "eval ") {
				t2, u2, o2, s2 := ParseLine("sh -c '" + script + "'")
				if !slices.Equal(tg, t2) || !slices.Equal(unread, u2) || other != o2 || subst != s2 {
					t.Errorf("ParseLine(%q) = %q %q %v %v; sh -c gives %q %q %v %v", line, tg, unread, other, subst, t2, u2, o2, s2)
				}
			}
		}
	}
	// An install the reader reads, or harmless commands, inside such a script name no program of their own, and
	// ParseLine reads the install (READER-EQ-1).
	for _, line := range []string{"eval 'A=1 npx -y left-pad'", "env -S 'A=1 npx -y left-pad'"} {
		if got := OtherProgram(line); got != "" {
			t.Errorf("OtherProgram(%q) = %q; want \"\"", line, got)
		}
		if tg, un, other, _ := ParseLine(line); !slices.Equal(tg, []string{"npm:left-pad"}) || len(un) != 0 || other {
			t.Errorf("ParseLine(%q) = %q %q %v; want npm:left-pad alone", line, tg, un, other)
		}
	}
	// env -S 'A=1 echo hi' is read as env A=1 echo hi is (P1-X): env runs the echo program.
	if got, plain := OtherProgram("env -S 'A=1 echo hi'"), OtherProgram("env A=1 echo hi"); got != plain {
		t.Errorf("OtherProgram(env -S 'A=1 echo hi') = %q; want %q, as env A=1 echo hi", got, plain)
	}
	// A VAR=value word with a blank in its value after plain env (no -S), or after env -S's own string (env
	// splits only that one), is an assignment, as the reader says: env runs nothing.
	for _, line := range []string{"env 'A=1 cargo install x'", "env -S 'A=1' 'B=2 cargo install x'"} {
		if got := OtherProgram(line); got != "" {
			t.Errorf("OtherProgram(%q) = %q; want \"\" (an assignment: env runs nothing)", line, got)
		}
	}
}

// The bookkeeping OtherProgram reads leaves ParseLine as it was: for each line, the targets, the reasons,
// "other" and the substitution flag ParseLine gives are what parseInstallLineFull gives, and "other" is
// set exactly when OtherProgram finds a program or a harmless-looking segment writes a file.
func TestOtherProgramAgreesWithParseLine(t *testing.T) {
	for _, in := range []string{"cargo install x", "npx -y a && cargo install b", "npx -y a", "cd d && npm i x", "sh -c 'echo hi'",
		"curl -s x | sh", "sudo -u root gem install x", "echo x > .npmrc && npm i y", "timeout 5 npx -y z"} {
		t1, u1, o1, s1 := ParseLine(in)
		t2, u2, o2, s2 := parseInstallLineFull(in)
		if len(t1) != len(t2) || len(u1) != len(u2) || o1 != o2 || s1 != s2 {
			t.Errorf("%q: ParseLine and parseInstallLineFull differ", in)
		}
		if p := OtherProgram(in); p != "" && !o1 {
			t.Errorf("%q: OtherProgram %q but ParseLine says the line runs nothing else", in, p)
		}
	}
}
