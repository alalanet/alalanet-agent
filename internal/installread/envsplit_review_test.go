package installread

import "testing"

// Review of 84d3a7f (P1-X, ADR-0173), untracked. Every line below runs `npm i zz-review-pkg` (or npx) under GNU
// coreutils env 9.12 and/or macOS /usr/bin/env, as checked with a stand-in npm that prints its arguments. The hook
// must not be silent on any of them: a target, a reason from ParseLine, or a reason from HookExtra.
func TestZZReviewEnvGapsHookNotSilent(t *testing.T) {
	groups := map[string][]string{
		// A. in the fix's own class: env -S whose split string starts with env's options, spelled another way
		"A cluster ending in S (GNU+BSD)": {
			`env -iS '-u HOME npm i zz-review-pkg'`,
			`env -vS '-i npm i zz-review-pkg'`,
			`env -iS'-u HOME npm i zz-review-pkg'`,
		},
		"A quoted or escaped leading option (GNU+BSD)": {
			`env -S '"-i" npm i zz-review-pkg'`,
			`env -S "'-i' npm i zz-review-pkg"`,
			`env -S '\_-i npm i zz-review-pkg'`,
			`env -S '-i\_npm\_i\_zz-review-pkg'`,
		},
		"A leading separator other than space/tab (GNU+BSD)": {
			"env -S $'\\n-i npm i zz-review-pkg'", // the shell gives env a real newline
			"env -S '\n-i npm i zz-review-pkg'",
			"env -S '\v-i npm i zz-review-pkg'",
			"env -S '\f-i npm i zz-review-pkg'",
			"env -S '\r-i npm i zz-review-pkg'",
		},
		"A long-option abbreviation (GNU getopt_long)": {
			`env --split '-i npm i zz-review-pkg'`,
			`env --spl='-i npm i zz-review-pkg'`,
		},
		"A value options the env table lacks, inside -S": {
			`env -S '-a foo npm i zz-review-pkg'`,                // GNU 9.x --argv0
			`env -S '--argv0 foo npm i zz-review-pkg'`,           // GNU
			`env -S '--env0-from /dev/null npm i zz-review-pkg'`, // GNU 9.12
			`env -S '-P /bin npm i zz-review-pkg'`,               // BSD/macOS
			`env -S '-L root npm i zz-review-pkg'`,               // FreeBSD (man page; not run here)
		},
		// B. env -S without an option: unchanged by the fix, silent before and after
		"B value then more words": {
			`env -S 'npm i' zz-review-pkg`,
			`env -S 'npx -y' zz-review-pkg`,
			`env -S 'npx -y zz-review-pkg' extra`,
			`env -S '' npm i zz-review-pkg`,
			`env -S 'npm\_i\_zz-review-pkg'`,
		},
		// C. env without -S: the same value options, silent before and after
		"C env value options without -S": {
			`env -a foo npm i zz-review-pkg`,
			`env --argv0 foo npm i zz-review-pkg`,
			`env --env0-from /dev/null npm i zz-review-pkg`,
			`env -P /bin npm i zz-review-pkg`,
		},
	}
	for g, lines := range groups {
		for _, line := range lines {
			tg, un, _, s := ParseLine(line)
			if x := HookExtra(line, tg, un, s); len(tg) == 0 && len(un) == 0 && len(x) == 0 {
				t.Errorf("%s: %q: the hook says nothing", g, line)
			}
		}
	}
}

// The second reader kept its "the production reader takes such a script for one assignment word" rule for a value
// that starts with an option, which the production reader now reads as env's arguments: a clean install was asked about
// with a sentence that said nothing checked it. (The rule is gone for eval too since READER-EQ-1, ADR-0159 round 4.)
func TestZZReviewSecondReaderNoFalseThrough(t *testing.T) {
	for _, pair := range [][2]string{
		{`env -S '--unset=HOME npm i zz-review-pkg'`, `env --unset=HOME npm i zz-review-pkg`},
		{`env -S '-i FOO=1 npm i zz-review-pkg'`, `env -i FOO=1 npm i zz-review-pkg`},
		{`env -S '-i npx -y zz-review-pkg --foo=bar'`, `env -i npx -y zz-review-pkg --foo=bar`},
		{`env -S '-u X' npm i zz-review-pkg`, `env -u X npm i zz-review-pkg`},
	} {
		ts, us, _, ss := ParseLine(pair[0])
		tp, up, _, sp := ParseLine(pair[1])
		got, want := HookExtra(pair[0], ts, us, ss), HookExtra(pair[1], tp, up, sp)
		if len(got) != len(want) {
			t.Errorf("%s: second reader %q; %s gives %q", pair[0], got, pair[1], want)
		}
	}
}

// Mutation proofs for the new conditions the commit's tests leave alive (leading blanks, the depth step, the empty
// value): each passes on 84d3a7f.
func TestZZReviewEnvSKillsSurvivors(t *testing.T) {
	for _, line := range []string{`env -S '  -i npm i zz-review-pkg'`, "env -S '\t-i npm i zz-review-pkg'"} {
		if tg, _, _, _ := ParseLine(line); len(tg) != 1 || tg[0] != "npm:zz-review-pkg" {
			t.Errorf("%q: targets %q (leading blanks before the option)", line, tg)
		}
		tg, un, _, s := ParseLine(line)
		if x := HookExtra(line, tg, un, s); len(x) != 0 {
			t.Errorf("%q: second reader %q", line, x)
		}
	}
	// the second reader skips the same blanks: its reasons for the value are those without them
	a, b := `env -S '  -i npm i zz-review-pkg --registry http://zz.invalid'`, `env -S '-i npm i zz-review-pkg --registry http://zz.invalid'`
	ta, ua, _, sa := ParseLine(a)
	tb, ub, _, sb := ParseLine(b)
	if xa, xb := HookExtra(a, ta, ua, sa), HookExtra(b, tb, ub, sb); len(xa) != len(xb) || len(xb) == 0 {
		t.Errorf("second reader with leading blanks %q, without %q", xa, xb)
	}
	// five nested option-led values: past the depth, a reason (the depth+1 step is what bounds it)
	line := `env -S '-S -S -S -S -S -i npm i zz-review-pkg'`
	if _, un, _, _ := ParseLine(line); len(un) == 0 {
		t.Errorf("%q: no depth reason", line)
	}
	for _, line := range []string{`env -S`, `env --split-string`, `env -S ''`, `env --split-string=`} {
		ParseLine(line) // must not panic (the len(w) > 0 guard)
	}
	// rest words keep their quoting: one argument of npm, not a second command
	if tg, _, other, _ := ParseLine(`env -S '-i npm i' 'zz-review-pkg;touch x'`); other || len(tg) != 1 {
		t.Errorf("rest word re-split: targets %q other %v", tg, other)
	}
	// a re-read value does not leave its words to be read again as a command (the return)
	if _, _, other, _ := ParseLine(`env -S '-i npm i zz-review-pkg'`); other {
		t.Errorf("the value read twice: other set")
	}
}
