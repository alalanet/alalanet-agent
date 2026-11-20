package installread

import (
	"slices"
	"testing"
)

// Independent re-review of READER-VAR-OPT-1 round 2 (fd79c5e, rebased as b20c2d9 on bd17ee4; the reader code is the
// same), 2026-11-15. Placeholders zz-var-pkg only. uv 0.13.7 checked offline with a hand-made wheel in a local
// find-links folder; npx from npm 10.8.2's bin/npx-cli.js; pipx 1.17.2 from its own argparse parser.

// Q1 (P2, a regression: hold on bd17ee4, silent on b20c2d9). uvLongValue has --script, which takes a path in uv add
// but is a switch in uv run ("-s, --script"). pkgs now skips the word after it as its value, so an index option
// there is not read. uv run --with zz-q --script -f DIR s.py installed zz-q from DIR (offline, local wheel).
func TestReviewR2UvRunScriptIsASwitch(t *testing.T) {
	for _, line := range []string{
		"uv run --with zz-var-pkg --script --index-url /srv/simple app.py",
		"uv run --with zz-var-pkg --script -f /srv/wheels app.py",
	} {
		if _, codes := codesOn(line); !slices.Contains(codes, "custom_registry") {
			t.Errorf("%q: codes %v, want custom_registry", line, codes)
		}
	}
}

// Q2 (P2, the R4 rule). Before the command a stop-at-command runner (uvx, uv run, uv tool run, pipx run, npx -p)
// reads options, so of two hidden words the first can be an option and the second the command: uvx --from zz-q
// "$Q" "$C" with Q=--find-links=DIR and C=zzbin ran the local wheel. hasShownCommand skips hidden words, so with no
// shown word after them the line is plain. One hidden word alone is the command and stays plain; a shown command
// first keeps its hidden arguments plain.
func TestReviewR2TwoHiddenWordsBeforeTheCommand(t *testing.T) {
	for _, line := range []string{
		`uvx --from zz-var-pkg "$P" "$C"`,
		`uv tool run --from zz-var-pkg "$P" "$C"`,
		`uv run --with zz-var-pkg "$P" "$S"`,
		`pipx run --spec zz-var-pkg "$P" "$A"`,
		`npx -p zz-var-pkg "$P" "$C"`,
	} {
		if reasonless(line) {
			t.Errorf("%q: read as a plain install", line)
		}
	}
	for _, line := range []string{
		`uvx --from zz-var-pkg "$C"`,
		`uv run --with zz-var-pkg "$S"`,
		`uv run --with zz-var-pkg ./x.py $A $B`,
		`npx -p zz-var-pkg zzbin "$A" "$B"`,
	} {
		if !reasonless(line) {
			tg, codes := codesOn(line)
			t.Errorf("%q: targets %v, codes %v; want a plain install", line, tg, codes)
		}
	}
}

// Q3 (P2, the R4 rule). The command a runner starts can follow an option: uv run's -m/--module is a switch and the
// module after it is the command (uv run --with zz-q -f DIR -m zz_q installed zz-q from DIR), npx's -c/--call takes
// the command as its value (npx-cli.js lists "call"/"c" among the options with a value and inserts no "--", so npm
// reads every option before it). uvTakesValue and npmRunnerTakesValue read both as a value, so no shown command is
// found and a hidden option before it is silent.
func TestReviewR2CommandAfterAnOption(t *testing.T) {
	for _, line := range []string{
		`uv run --with zz-var-pkg "$P" -m zzmod`,
		`uv run --with zz-var-pkg "$P" --module zzmod`,
		`npx -p zz-var-pkg "$P" -c zzbin`,
		`npx -p zz-var-pkg "$P" --call zzbin`,
		`npx -p zz-var-pkg "$P" --call=zzbin`,
	} {
		if reasonless(line) {
			t.Errorf("%q: read as a plain install", line)
		}
	}
	for _, line := range []string{`uv run --with zz-var-pkg -m zzmod "$A"`} { // npx -c "$CMD" is command_string already
		if !reasonless(line) {
			tg, codes := codesOn(line)
			t.Errorf("%q: targets %v, codes %v; want a plain install", line, tg, codes)
		}
	}
}

// Q4 (P3). uv run's -m is a switch, so in a cluster an index letter after it is read by uv: -mf DIR is --module
// with --find-links DIR. pyShortValue stops uv clusters at m for every subcommand ("stopping a cluster early only
// drops holds" — a dropped hold here is a silent index).
func TestReviewR2UvRunModuleCluster(t *testing.T) {
	if line := "uv run --with zz-var-pkg -mf /srv/wheels zzmod"; reasonless(line) {
		t.Errorf("%q: read as a plain install", line)
	}
}

// Q5 (P3, R7's argument). pipx on Windows splits --pip-args with shlex posix=False: a backslash is literal and does
// not join words, so a backslash at the end of the word before "-i" leaves "-i DIR" whole for pip, while the POSIX
// reading joins them into one value. Python 3.15: shlex.split(r"--cache-dir=C:\pc\ -i C:\idx", posix=False) is
// ['--cache-dir=C:\\pc\\', '-i', 'C:\\idx']; posix=True gives ['--cache-dir=C:pc -i', 'C:idx'].
func TestReviewR2PipArgsWindowsSplit(t *testing.T) {
	if line := `pipx install zz-var-pkg --pip-args="--cache-dir=C:\pc\ -i C:\idx"`; reasonless(line) {
		t.Errorf("%q: read as a plain install", line)
	}
}
