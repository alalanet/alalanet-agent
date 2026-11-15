package installread

import "testing"

// Review round 3 of reader-env-opts (9385e12), untracked. Under GNU env 9.12 and macOS env, each line runs npm with
// zz-review-evil (stand-in npm); under zsh and bash >= 4.2 the $'\u…' lines do too. The hook must name zz-review-evil
// or give a reason.
func TestZZReviewR3Gaps(t *testing.T) {
	for _, line := range []string{
		// \_ is a separator: a # after it begins a word, env's comment (envUncomment runs before \_ is replaced)
		`env -S 'npm i zz-review-ok\_#' zz-review-evil`,
		`env -S '-i npm i zz-review-ok\_#x zz-review-evil2' zz-review-evil`,
		`env -S '-i -S npm\_i\_zz-review-ok\_# zz-review-evil2' zz-review-evil`,
		// bash/zsh $'\uHHHH' and $'\UHHHHHHHH'
		"env -S $'\\u002di npm i zz-review-evil'",
		"$'\\u006epm' i zz-review-evil",
		"npm i $'zz-review-\\u0065vil'",
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

// The second reader takes GNU's unique prefixes of env's value options too (--argv for --argv0, --env0 for
// --env0-from), as envOptionWords does for the first.
func TestZZReviewR3SecondReaderPrefixes(t *testing.T) {
	want := `env -i cross-env A=1 npx -y zz-review-pkg`
	tw, uw, _, sw := ParseLine(want)
	xw := HookExtra(want, tw, uw, sw)
	for _, line := range []string{`env --argv foo cross-env A=1 npx -y zz-review-pkg`, `env --env0 F cross-env A=1 npx -y zz-review-pkg`} {
		tg, un, _, s := ParseLine(line)
		if x := HookExtra(line, tg, un, s); len(x) != len(xw) {
			t.Errorf("%s: second reader %q; %s gives %q", line, x, want, xw)
		}
	}
}
