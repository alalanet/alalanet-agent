package installread

import (
	"strings"
	"testing"
)

// env -S (--split-string) splits its value into arguments and reads them as its own: options first, then the
// command. A split string that starts with one of env's options must be read the same way, so the install behind
// the options is a target, as it is without them (P1-X, the install-p2s round-3 re-review; ADR-0173). Before, the
// reader took the option for the command and found nothing: the hook said nothing, which Claude Code takes as an allow.
func TestEnvSplitStringWithOptionsIsRead(t *testing.T) {
	const want = "npm:zz-envsplit-pkg"
	lines := []string{
		`env -S 'npm i zz-envsplit-pkg'`, // the control: no option inside
		`env -S '-i npm i zz-envsplit-pkg'`,
		`env -S '-u HOME npm i zz-envsplit-pkg'`,
		`env -S '-C /tmp npm i zz-envsplit-pkg'`,
		`env -S '-i -u HOME -- npm i zz-envsplit-pkg'`,
		`env -S '--ignore-environment npm i zz-envsplit-pkg'`,
		`env -S '--unset=HOME npm i zz-envsplit-pkg'`,
		`env --split-string='-i npm i zz-envsplit-pkg'`,
		`env --split-string '-i npm i zz-envsplit-pkg'`,
		`env -S'-i npm i zz-envsplit-pkg'`,
		`env -S '-i FOO=1 npm i zz-envsplit-pkg'`,
		`env -S '-i env -S "-u X npm i zz-envsplit-pkg"'`,
		`env -i -S '-u HOME npm i zz-envsplit-pkg'`,
		`sudo env -S '-i npm i zz-envsplit-pkg'`,
		`env -S '-i npx -y zz-envsplit-pkg'`,
	}
	for _, line := range lines {
		targets, unread, _, _ := ParseLine(line)
		found := false
		for _, tg := range targets {
			if strings.HasPrefix(tg, want) {
				found = true
			}
		}
		if !found && len(unread) == 0 {
			t.Errorf("%s: targets %q, unread %q: the install is neither read nor a reason, so the hook would say nothing", line, targets, unread)
		}
		if !found && !strings.Contains(line, "npx") {
			t.Errorf("%s: targets %q, unread %q; want %s read as it is without env's options", line, targets, unread, want)
		}
	}
}

// The second reader reads such a value as env does too: its reasons for `env -S '-i <cmd>'` are those for
// `env -i <cmd>` (P1-X, ADR-0173).
func TestEnvSplitStringWithOptionsSecondReaderAgrees(t *testing.T) {
	for _, pair := range [][2]string{
		{`env -S '-i npm i zz-envsplit-pkg --registry http://zz.invalid'`, `env -i npm i zz-envsplit-pkg --registry http://zz.invalid`},
		{`env -S '-i npm i zz-envsplit-pkg'`, `env -i npm i zz-envsplit-pkg`},
	} {
		ts, us, _, ss := ParseLine(pair[0])
		tp, up, _, sp := ParseLine(pair[1])
		got, want := HookExtra(pair[0], ts, us, ss), HookExtra(pair[1], tp, up, sp)
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("%s: second reader %q; %s gives %q", pair[0], got, pair[1], want)
		}
		if strings.Join(ts, "|") != strings.Join(tp, "|") || strings.Join(us, "|") != strings.Join(up, "|") {
			t.Errorf("%s: targets %q unread %q; %s gives %q %q", pair[0], ts, us, pair[1], tp, up)
		}
	}
}
