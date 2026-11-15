package installread

import (
	"os/exec"
	"strings"
	"testing"
)

// Independent review of READER-EQ-1 round 4 (9024dd1). zsh (the default shell on macOS) and dash (Debian's sh) take
// no options for eval: they join every word, a leading "-x" included, and run the line, so eval '-x; npx -y pkg' runs
// "-x" (not found) and then npx -y pkg. bash and ksh refuse such a word as an invalid option and run nothing. Both
// readers drop every leading "-" word after eval as one of its options, the install in it with it: no target, no
// reason, and the hook is silent. Reading the words (bar one leading "--") as the joined line is right for zsh and
// dash and only over-reads for bash.
func TestZZReviewEvalDashWordNotSilent(t *testing.T) {
	const pkg = "zz-review-eq1"
	// The shells' own reading, on harmless commands only.
	for _, sh := range []string{"zsh", "dash"} {
		if _, err := exec.LookPath(sh); err != nil {
			continue
		}
		out, _ := exec.Command(sh, "-c", "eval '-x; echo zz-ran'").CombinedOutput()
		if !strings.Contains(string(out), "zz-ran") {
			t.Fatalf("%s: eval '-x; echo zz-ran' gave %q; the fixture assumes %s runs the line after -x", sh, out, sh)
		}
	}
	for _, line := range []string{
		"eval '-x; npx -y " + pkg + "'",
		"eval '-; npx -y' " + pkg,
		"eval '-x && npm i " + pkg + "'",
		"command eval '-x; npx -y " + pkg + "'",
		"if eval '-x; npx -y " + pkg + "'; then :; fi",
		"eval - 'npx -y " + pkg + "'", // zsh: "-" ends eval's options and the line runs (a fix that reads every - word must keep this)
		"eval -- 'npx -y " + pkg + "'",
	} {
		tg, un, _, s := ParseLine(line)
		ex := HookExtra(line, tg, un, s)
		if len(tg) == 0 && len(un) == 0 && len(ex) == 0 {
			t.Errorf("%q: no target and no reason from either reader: the hook is silent on an install zsh and dash run", line)
		}
	}
}
