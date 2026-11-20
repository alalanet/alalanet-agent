package installread

import (
	"slices"
	"testing"
)

// PIPE-SCRIPT-1 round 2 (review P2-1, P3-2): the download-and-run forms the round-1 reader left silent — a download
// saved to a file that a later command of the line runs (10 lines of the README corpus), eval's and the here-string's
// unquoted substitution, <(…) given as the input, a substitution with more after it, any command between the download
// and the shell, a shell named by a variable, a shell whose own script runs its input, a printed substitution, and a
// shell a package runner starts — each gives the script's target, and the second reader's script_not_read is not
// needed for any of them.
func TestPipeScriptRound2Forms(t *testing.T) {
	const U, P = "https://e.example/i.sh", "https://e.example/i.ps1"
	const sh, ps = "script:https://e.example/i.sh", "script:https://e.example/i.ps1"
	for line, want := range map[string]string{
		// a file the line downloads to, then runs
		"curl -fsSLo i.sh " + U + " && bash i.sh":                                                              sh,
		"curl -o /tmp/i.sh " + U + " && sh /tmp/i.sh":                                                          sh,
		"curl -O " + U + "; chmod +x i.sh; ./i.sh":                                                             sh,
		"curl --remote-name " + U + " && bash ./i.sh":                                                          sh,
		"wget " + U + " && sh i.sh":                                                                            sh,
		"wget -O i.sh " + U + " && sh i.sh":                                                                    sh,
		"wget -qO /tmp/i.sh " + U + " && bash /tmp/i.sh -s -- --yes":                                           sh,
		"wget --output-document=i.sh " + U + " && sh i.sh":                                                     sh,
		"curl " + U + " > /tmp/i.sh && bash /tmp/i.sh":                                                         sh,
		"curl " + U + " -o i.sh; source i.sh":                                                                  sh,
		"curl " + U + " -o i.sh; . ./i.sh":                                                                     sh,
		"curl " + U + " | tee i.sh > /dev/null && sh i.sh":                                                     sh,
		"curl -sSL " + U + " -o i.sh && sudo bash i.sh":                                                        sh,
		"curl -o ~/t.py " + U + " && chmod +x ~/t.py && python3 ~/t.py":                                        sh,
		"curl -o /usr/local/bin/i.sh " + U + " && /usr/local/bin/i.sh --yes":                                   sh,
		`irm ` + P + ` -OutFile i.ps1; .\i.ps1`:                                                                ps,
		`iwr ` + P + ` -OutFile install.ps1; .\install.ps1`:                                                    ps,
		`curl.exe ` + P + ` -o i.ps1 & powershell -File i.ps1`:                                                 ps,
		`irm ` + P + ` -OutFile "$env:TEMP\x.ps1"; powershell -ExecutionPolicy Bypass -File "$env:TEMP\x.ps1"`: ps,
		`$p="$env:TEMP\x.ps1"; Invoke-WebRequest ` + P + ` -OutFile $p; & $p`:                                  ps,
		`Invoke-WebRequest -Uri ` + P + ` -OutFile i.ps1; pwsh ./i.ps1`:                                        ps,
		"wget -P /tmp " + U + " && sh /tmp/i.sh":                                                               sh,
		"curl --output-dir /tmp -O " + U + " && sh /tmp/i.sh":                                                  sh,
		"curl -o x " + U + " && cat x | sh":                                                                    sh,
		"curl -o i.sh " + U + " && sh < i.sh":                                                                  sh,
		"curl -so i.sh " + U + " && bash -c ./i.sh":                                                            sh,
		"curl -o i.sh " + U + " && sh -c 'bash i.sh'":                                                          sh,
		"curl -o i.sh " + U + " && chmod 755 ./i.sh && ./i.sh":                                                 sh,
		`curl -o "$HOME/i.sh" ` + U + ` && bash "$HOME/i.sh"`:                                                  sh,
		"curl -o i.sh " + U + "; nohup bash i.sh &":                                                            sh,
		`Invoke-WebRequest -Uri ` + P + ` -OutFile $env:TEMP\i.ps1; & $env:TEMP\i.ps1`:                         ps,
		"curl " + U + " >> i.sh && sh i.sh":                                                                    sh,
		// substitutions read like their quoted forms
		"eval $(curl " + U + ")":                  sh,
		"eval `curl " + U + "`":                   sh,
		"bash < <(curl " + U + ")":                sh,
		"sh < <(curl -fsSL " + U + ")":            sh,
		"sh <<< $(curl " + U + ")":                sh,
		`bash <<< "$(curl ` + U + `)"`:            sh,
		`bash -c "$(curl ` + U + `); echo done"`:  sh,
		`sh -c "$(curl -fsSL ` + U + `) && true"`: sh,
		// any command between the download and the shell; a shell named by a variable or running its input itself
		"curl " + U + " | grep -v '^#' | sh":            sh,
		"curl " + U + " | head -n 1000 | bash":          sh,
		"curl " + U + " | awk 1 | sh":                   sh,
		"curl " + U + " | openssl enc -d -base64 | sh":  sh,
		"curl " + U + " | python3 -c 'import sys' | sh": sh,
		"curl " + U + " | $SHELL":                       sh,
		`curl ` + U + ` | "$SHELL"`:                     sh,
		"curl " + U + " | ${SHELL:-sh}":                 sh,
		"curl " + U + " | bash -c 'cat | sh'":           sh,
		"curl " + U + " | sh -c 'sh'":                   sh,
		"curl " + U + " | bash -c 'sh -s -- --yes'":     sh,
		`printf '%s' "$(curl ` + U + `)" | sh`:          sh,
		`echo "$(curl ` + U + `)" | sh`:                 sh,
		// a shell a package runner starts
		"curl " + U + " | pnpm exec sh":         sh,
		"curl " + U + " | npx -y sh":            sh,
		"curl " + U + " | yarn exec -- bash":    sh,
		"curl " + U + " | bun x sh":             sh,
		"curl " + U + " | uv run python3 -":     sh,
		"uv run bash <(curl " + U + ")":         sh,
		"curl " + U + " | sudo -E pnpm exec sh": sh,
	} {
		targets, unread, _, _ := ParseLine(line)
		var codes []string
		for _, u := range unread {
			codes = append(codes, UnreadCode(u))
		}
		if !slices.Contains(targets, want) || slices.Contains(codes, "script_not_read") {
			t.Errorf("ParseLine(%q) = %q %q; want %q among the targets, no script_not_read", line, targets, codes, want)
		}
	}
	// what stays as it was: a download only saved, or saved and read by a command that does not run it, or another file run
	for _, line := range []string{"curl -o i.sh " + U, "curl -o i.sh " + U + " && cat i.sh", "curl -o i.sh " + U + " && sh other.sh",
		"curl " + U + " | tar xz && sh install.sh", "wget " + U + " && chmod +x i.sh", "curl " + U + " | jq .", "curl " + U + " | grep version",
		"curl -O " + U + " && ./other.sh", `eval "$X"`, "curl -o i.sh " + U + " && sha256sum i.sh", "curl -o data.json " + U + " && node app.js data.json",
		"curl -o i.sh " + U + " && cat i.sh", "curl -o x " + U + " && cat y | sh",
		"curl -s " + U + "; echo hi | sh", "curl -s " + U + " && echo x | bash", "curl " + U + " | less",
		"curl " + U + " | sha256sum", "curl " + U + " | python3 parse.py", `irm ` + P + ` -OutFile i.ps1; Get-Content i.ps1`} {
		targets, _, _, _ := ParseLine(line)
		for _, tg := range targets {
			if tg == sh || tg == ps {
				t.Errorf("ParseLine(%q) = %q; want no script target", line, targets)
			}
		}
	}
}

// Round 3 (re-review P3-1): the forms the round-2 reader still left silent — xargs -a of a downloaded file, a cd between
// the download and the run, a rename or copy before the run, PowerShell's -o for -OutFile with a dot-source, a
// here-document whose body is the download's substitution, a variable that holds a download, then eval or sh -c.
func TestPipeScriptRound3Forms(t *testing.T) {
	const U, P = "https://e.example.com/i.sh", "https://e.example.com/i.ps1"
	const sh, ps = "script:https://e.example.com/i.sh", "script:https://e.example.com/i.ps1"
	for line, want := range map[string]string{
		"curl -o f " + U + " && xargs -a f sh -c '{}'":              sh,
		"curl -o f " + U + " && xargs --arg-file=f -I{} sh -c '{}'": sh,
		"cd /tmp && curl -O " + U + " && sh /tmp/i.sh":              sh,
		"curl -o /tmp/i.sh " + U + " && cd /tmp && sh i.sh":         sh,
		"cd /tmp; curl -o i.sh " + U + "; cd /; sh /tmp/i.sh":       sh,
		"curl -o a.sh " + U + " && mv a.sh b.sh && sh b.sh":         sh,
		"curl -o a.sh " + U + " && cp a.sh /tmp/ && bash /tmp/a.sh": sh,
		"curl -o a.sh " + U + " && cp a.sh b.sh && bash b.sh":       sh,
		// round 4: cd /tmp may fail, and the line may start in /opt; the run of i.sh may be the download's
		"cd /tmp && curl -O " + U + " && sh /opt/i.sh": sh,
		`iwr -useb ` + P + ` -o i.ps1; . .\i.ps1`:      ps,
		"bash <<EOF\n$(curl " + U + ")\nEOF":           sh,
		"s=$(curl " + U + "); eval \"$s\"":             sh,
		"s=$(curl " + U + "); bash -c \"$s\"":          sh,
		"s=`curl " + U + "`; eval $s":                  sh,
	} {
		targets, unread, _, _ := ParseLine(line)
		if !slices.Contains(targets, want) {
			t.Errorf("ParseLine(%q) = %q %q; want %q among the targets", line, targets, unread, want)
		}
	}
	for _, line := range []string{"curl -o a.sh " + U + " && mv a.sh b.sh && sh c.sh", "cd /tmp && curl -O " + U + " && sh /opt/j.sh",
		"s=$(curl " + U + "); echo \"$s\"", "curl -o f " + U + " && xargs -a f echo", "bash <<EOF\necho hi\nEOF"} {
		targets, _, _, _ := ParseLine(line)
		if slices.Contains(targets, sh) {
			t.Errorf("ParseLine(%q) = %q; want no script target", line, targets)
		}
	}
}

// Round 3: a run marks the download and its own pipeline, not the commands between them (they stay what they are).
func TestPipeScriptRound3Marks(t *testing.T) {
	const U = "https://e.example.com/i.sh"
	if _, _, other, _ := ParseLine("curl -o f " + U + "; rm -rf zz-dir; cat f | sh"); !other {
		t.Error("rm -rf between the download and the run: no longer other")
	}
	if _, _, other, _ := ParseLine("curl -o f " + U + "; cat f | sh"); other {
		t.Error("the download and its run alone: other")
	}
}

// Round 4 (re-review of round 3, P3-3): a folder the line moves to is never a reason to drop a run. Round 3 asserted
// here that a file saved before cd $D or cd - is not the one run after it; bash's cd - returns to the folder of the
// download, and an unknown folder may be that folder: each line runs the download and holds with its target.
func TestPipeScriptRound3UnknownFolder(t *testing.T) {
	const U = "https://e.example.com/i.sh"
	for _, l := range []string{
		"curl -o i.sh " + U + " && cd $D && sh i.sh",
		"curl -o i.sh " + U + " && cd - && sh i.sh",
		"cd $A && curl -o i.sh " + U + " && cd $B && sh i.sh",
		"cd $A && curl -o i.sh " + U + " && sh i.sh",
	} {
		if tg, _, _, _ := ParseLine(l); !slices.Contains(tg, "script:"+U) {
			t.Errorf("ParseLine(%q) = %v; want script:%s", l, tg, U)
		}
	}
}
