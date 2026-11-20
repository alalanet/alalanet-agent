package installread

import (
	"slices"
	"testing"
)

// READER-ESCAPE-1 in the own-shell allowlist (ADR-0159 round 29): a builtin receives its options and operands after
// quote removal, so a quoted or escaped option is the same option. Each pair {respelled, plain} must read alike; the
// round-29 reader compared the raw words, and the respelled forms of the holding ones read clean or differently.
// Grammar (if, for, case, in, [[ … ]] operators) is the shell's only unquoted, and stays so.
func TestReaderEscapeOwnShellOptions(t *testing.T) {
	for _, p := range [][2]string{
		{`[ '-v' 'a[PATH=1]' ]; pip install zz-pkg`, `[ -v 'a[PATH=1]' ]; pip install zz-pkg`},
		{`[ \-v 'a[PATH=1]' ]; pip install zz-pkg`, `[ -v 'a[PATH=1]' ]; pip install zz-pkg`},
		{`test "-v" 'a[PATH=1]'; pip install zz-pkg`, `test -v 'a[PATH=1]'; pip install zz-pkg`},
		{`a=PA; declare $'-n' r=${a}TH; r=./bin; npx -y zz-pkg`, `a=PA; declare -n r=${a}TH; r=./bin; npx -y zz-pkg`},
		{`a=PA; printf '-v' ${a}TH ./bin; npx -y zz-pkg`, `a=PA; printf -v ${a}TH ./bin; npx -y zz-pkg`},
		{`hash '-r'; pip install zz-pkg`, `hash -r; pip install zz-pkg`},
		{`set '-o' errexit; pip install zz-pkg`, `set -o errexit; pip install zz-pkg`},
		{`read '-r' x; pip install zz-pkg`, `read -r x; pip install zz-pkg`},
		{`mapfile '-C' f -c 1 a < /dev/null; pip install zz-pkg`, `mapfile -C f -c 1 a < /dev/null; pip install zz-pkg`},
		{`unset 'x'; pip install zz-pkg`, `unset x; pip install zz-pkg`},
		{`sleep 0 & wait -n '-pPATH'; npx -y zz-pkg`, `sleep 0 & wait -n -pPATH; npx -y zz-pkg`},
		{`t=ev; u=al; sh '-c' "${t}${u} PATH=./bin; pip install zz-pkg"`, `t=ev; u=al; sh -c "${t}${u} PATH=./bin; pip install zz-pkg"`},
		{`exit '0'; pip install zz-pkg`, `exit 0; pip install zz-pkg`},
		{`trap '--' 'export PATH=./bin' EXIT; npx -y zz-pkg`, `trap -- 'export PATH=./bin' EXIT; npx -y zz-pkg`},
		{`[ 1 '-eq' x+1 ]; pip install zz-pkg`, `[ 1 -eq x+1 ]; pip install zz-pkg`},
		{`set '-k'; pip install zz-pkg`, `set -k; pip install zz-pkg`},
		{`set -o 'errexit'; pip install zz-pkg`, `set -o errexit; pip install zz-pkg`},
		{`read '-a' x; pip install zz-pkg`, `read -a x; pip install zz-pkg`},
		{`sh '-c' "$X"; pip install zz-pkg`, `sh -c "$X"; pip install zz-pkg`},
	} {
		etg, ewhy := readEscape(p[0])
		ptg, pwhy := readEscape(p[1])
		if !slices.Equal(etg, ptg) || !slices.Equal(ewhy, pwhy) {
			t.Errorf("%q reads %v %v,\n  its plain twin %q reads %v %v", p[0], etg, ewhy, p[1], ptg, pwhy)
		}
	}
	// the [ -v a[PATH=1] ] hold itself (its arithmetic assigns PATH) survives every spelling of -v
	for _, l := range []string{`[ '-v' 'a[PATH=1]' ]; pip install zz-pkg`, `[ $'-v' 'a[PATH=1]' ]; pip install zz-pkg`, `[ -\v 'a[PATH=1]' ]; pip install zz-pkg`} {
		if _, why := readEscape(l); len(why) == 0 {
			t.Errorf("%q: not held", l)
		}
	}
}
