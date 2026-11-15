package installread

import "testing"

// Review round 2 of reader-env-opts (d6b739e), untracked. Each line below makes GNU env 9.12 and macOS env run
// npm with the package named zz-review-evil (checked with a stand-in npm). The hook must name it as a target, or give a
// reason; checking only zz-review-ok is not enough.
func TestZZReviewR2EnvGaps(t *testing.T) {
	for _, line := range []string{
		// env's comment: a word that starts with # ends the split string, not the words after it
		`env -S 'npm i zz-review-ok #' zz-review-evil`,
		`env -S '-i npm i zz-review-ok #c' zz-review-evil`,
		`env -S '#' npm i zz-review-evil`,
		`env -S '-i #' npm i zz-review-evil`,
		// bash's $'…' hex and octal escapes: the dash of the option
		`env -S $'\x2di npm i zz-review-evil'`,
		`env -S $'\055i npm i zz-review-evil'`,
		// env -S expands ${NAME} itself, inside single quotes, anywhere in the value (an unset name is empty)
		`env -S 'n${E}pm i zz-review-evil'`,
		`env -S '-i n${E}pm i zz-review-evil'`,
		`env -S '-i ${CMD} i zz-review-evil'`,
		// xargs appends its input words after the split string's words: xargs env -i npm i < list asks
		`xargs env -S '-i npm i' < list`,
		`xargs env -S 'npm i' < list`,
	} {
		tg, un, _, s := ParseLine(line)
		x := HookExtra(line, tg, un, s)
		evil := false
		for _, t := range tg {
			evil = evil || t == "npm:zz-review-evil"
		}
		if !evil && len(un) == 0 && len(x) == 0 {
			t.Errorf("%q: targets %q, no reason: zz-review-evil is never checked", line, tg)
		}
	}
}

// The new reasons fire where they must and only there (mutation proofs for d6b739e).
func TestZZReviewR2Reasons(t *testing.T) {
	for _, line := range []string{
		`env --frob val npm i zz-review-pkg`, // an option env does not have may take the next word
		`env -Z val npm i zz-review-pkg`,
		`env -S "$X" npm i zz-review-pkg`, // the value is not in the line
		`env -S ' $X' npm i zz-review-pkg`,
		`env -S "	$X" npm i zz-review-pkg`,
	} {
		tg, un, _, s := ParseLine(line)
		if len(tg) == 0 && len(un) == 0 && len(HookExtra(line, tg, un, s)) == 0 {
			t.Errorf("%q: the hook says nothing", line)
		}
	}
	for _, line := range []string{`env -u`, `env -C`, `env --unset`, `env -a`, `env -S`, `env -iS`, `env --split`} {
		ParseLine(line) // a value option last on the line: no panic
	}
	// honest lines: no reason at all
	for _, line := range []string{"env", "env -i", "env -0", "env -v", "env --null", "env | grep PATH", "env -i HOME=/h bash -l",
		"env VAR=x make build", "env -u X ls", "env -- ls", "env - ls", "env -i PATH=/usr/bin:/bin ls -la", "env --help",
		"env --version", "env -iv ls", "env --ignore-environment ls", "env --unset=X --chdir=/tmp ls", "env -C /tmp ls",
		"env --debug ls", "env --default-signal ls", "env --ignore-signal=INT ls", "env -S 'node app.js'",
		"env -S '-i node app.js'", "env -S'python3 -u' script.py", "env NODE_ENV=production node server.js",
		`env -i PATH="$PATH" npm run build`, "env -i npm --version"} {
		tg, un, _, s := ParseLine(line)
		if x := HookExtra(line, tg, un, s); len(tg) != 0 || len(un) != 0 || len(x) != 0 {
			t.Errorf("%q: asks without cause: %q %q %q", line, tg, un, x)
		}
	}
}

// The second reader reads env's value options as the first one does (envOptionWords), so its reasons behind them are
// the same: env -a foo cross-env … is env -i cross-env … with an argv0.
func TestZZReviewR2SecondReaderValueOptions(t *testing.T) {
	for _, pair := range [][2]string{
		{`env -a foo cross-env A=1 npx -y zz-review-pkg`, `env -i cross-env A=1 npx -y zz-review-pkg`},
		{`env -P /bin cross-env A=1 npx -y zz-review-pkg`, `env -i cross-env A=1 npx -y zz-review-pkg`},
		{`env --argv0 foo cross-env A=1 npx -y zz-review-pkg`, `env -i cross-env A=1 npx -y zz-review-pkg`},
		{`env -L root npm i zz-review-pkg --registry http://zz.invalid`, `env -i npm i zz-review-pkg --registry http://zz.invalid`},
	} {
		ts, us, _, ss := ParseLine(pair[0])
		tp, up, _, sp := ParseLine(pair[1])
		got, want := HookExtra(pair[0], ts, us, ss), HookExtra(pair[1], tp, up, sp)
		if len(got) != len(want) || len(ts) != len(tp) || len(us) != len(up) {
			t.Errorf("%s: %q %q %q; %s gives %q %q %q", pair[0], ts, us, got, pair[1], tp, up, want)
		}
	}
}
