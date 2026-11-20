package installread

import (
	"strings"
	"testing"
	"time"
)

// Independent review of READER-SHELLS (5248631, ADR-0159 round 5). Each line runs `npm i zz-review-pkg` or
// `npx -y zz-review-pkg` (a placeholder) the way the shell named runs it; the shell behaviour of the P2 forms was
// checked in golang:1.27.4-bookworm (bash 5.2, dash, util-linux script) with echo in place of the install.

// silentOn: the hook's decision for a line (internal/app InstallHook, alalanet-agent isInstall): no target from
// ParseLine and no reason from either reader is silence, which Claude Code takes for allow.
func silentOn(line string) bool {
	tg, un, _, s := ParseLine(line)
	return len(tg)+len(un)+len(HookExtra(line, tg, un, s)) == 0
}

// P2-1. POSIX: sh -c [options…] command_string. bash, dash, ksh and busybox sh take more options after -c and an
// end of options "--"; the script is the first word that is no option. Both readers join the words after -c, so the
// script reads as a command named "--", "-e" or "-o". Silent on 7b53831 for sh/bash/zsh/dash, and now for every shell
// of posixShells.
func TestReaderShellsReviewOptionsAfterC(t *testing.T) {
	for _, line := range []string{
		"bash -c -- 'npm i zz-review-pkg'",
		"sh -c -- 'npm i zz-review-pkg'",
		"dash -c -- 'npx -y zz-review-pkg'",
		"zsh -c -- 'npm i zz-review-pkg'",
		"ksh -c -- 'npm i zz-review-pkg'",
		"mksh -c -- 'npm i zz-review-pkg'",
		"busybox sh -c -- 'npm i zz-review-pkg'",
		"bash -c -e 'npm i zz-review-pkg'",
		"bash -c -x 'npm i zz-review-pkg'",
		"sh -c -e 'npm i zz-review-pkg'",
		"bash -c -o pipefail 'npm i zz-review-pkg'",
		"bash -c +x 'npm i zz-review-pkg'",
		"bash -c -l 'npm i zz-review-pkg'",
		"ksh -c -e 'npm i zz-review-pkg'",
		"su -c \"bash -c -- 'npm i zz-review-pkg'\"",
	} {
		if silentOn(line) {
			t.Errorf("%q: silent on an install", line)
		}
	}
}

// P2-2. util-linux script permutes its options (getopt without "+"): the log file may come before -c, and
// script -a log -c CMD runs CMD. scriptCommand takes the first word that is no option for BSD's file and reads
// "-c" as the command.
func TestReaderShellsReviewScriptFileBeforeC(t *testing.T) {
	for _, line := range []string{
		"script log -c 'npm i zz-review-pkg'",
		"script -a log -c 'npm i zz-review-pkg'",
		"script -q log -c 'npx -y zz-review-pkg'",
		"script log --command='npm i zz-review-pkg'",
		"script log --command 'npm i zz-review-pkg'",
	} {
		if silentOn(line) {
			t.Errorf("%q: silent on an install", line)
		}
	}
}

// P2-3. A program name that is one parameter expansion with an assigning default (${X:=npm}, ${X=npm}) or a quoted
// default (${X:-"npm"}): the shell runs npm. The first reader takes a word with "=" for a VAR=value prefix
// (command()'s assignment case), and expandUnset keeps the quotes of a default; the second reader's paramDefault
// is only for a word alone.
func TestReaderShellsReviewParamDefaults(t *testing.T) {
	for _, line := range []string{
		"${X:=npm} i zz-review-pkg",
		"${X=npm} i zz-review-pkg",
		"${NPX:=npx} -y zz-review-pkg",
		"n${E:=p}m i zz-review-pkg",
		`${NPX:-"npx"} -y zz-review-pkg`,
		"${NPX:-'npx'} -y zz-review-pkg",
		`${NPM-"npm"} i zz-review-pkg`,
		"sh -c '${X:=npm} i zz-review-pkg'",
	} {
		if silentOn(line) {
			t.Errorf("%q: silent on an install", line)
		}
	}
}

// P2-4. The second reader's command_substitution rule substitutes every printed text into every command named by a
// mark and reads it again: K commands against one long printed text cost K times its length. 7b53831 read this
// line in about the production reader's time; 5248631 took 23 s for 108 KB without -race (2.4 s at 50 KB / 200).
// The bound is TestExtraBounded's (costWithin): production's time plus 250 ms.
func TestReaderShellsReviewSubstitutedNamesBounded(t *testing.T) {
	for name, line := range map[string]string{
		"a script printed once, many named commands": "$(echo sh -c '" + strings.Repeat("a;", 25_000) + "'); " + strings.Repeat("$(:) x; ", 200),
		"many words printed once, many commands":     "$(echo " + strings.Repeat("a ", 25_000) + "); " + strings.Repeat("$(:) x; ", 200),
		"one name of many marks":                     "$(echo " + strings.Repeat("a", 50_000) + "); " + strings.Repeat("$(:)", 1000) + " x",
	} {
		// The best of three attempts against the first reader's time plus a second: a loaded -race VM varies by
		// hundreds of milliseconds (round 9, R4-6), while the P2-4 regression took 2.5 s here without -race and 23 s at
		// 108 KB, so it still fails clearly.
		var de, dp time.Duration
		for try := 0; try < 3; try++ {
			start := time.Now()
			tg, un, _, s := ParseLine(line)
			p := time.Since(start)
			start = time.Now()
			HookExtra(line, tg, un, s)
			if e := time.Since(start); try == 0 || e-p < de-dp {
				de, dp = e, p
			}
		}
		if limit := dp + time.Second; de > limit {
			t.Errorf("%s (%d bytes): the second reader took %v, production %v, the bound is %v", name, len(line), de, dp, limit)
		}
	}
}

// P3-1. A shell that reads its script from its input without being named sh: su with no -c (the user's shell),
// sudo -s and sudo -i with no command, doas -s. fed reads only posixShells, foreignShells, source and iex.
func TestReaderShellsReviewImplicitShellInput(t *testing.T) {
	for _, line := range []string{
		"echo 'npm i zz-review-pkg' | su",
		"echo 'npm i zz-review-pkg' | su root",
		"echo 'npm i zz-review-pkg' | su -",
		"echo 'npm i zz-review-pkg' | sudo su",
		"echo 'npm i zz-review-pkg' | sudo -s",
		"echo 'npm i zz-review-pkg' | sudo -i",
		"echo 'npm i zz-review-pkg' | doas -s",
		"su <<< 'npm i zz-review-pkg'",
		"sudo -s <<< 'npm i zz-review-pkg'",
	} {
		if silentOn(line) {
			t.Errorf("%q: silent on an install", line)
		}
	}
}

// P3-2. False reasons on honest lines. varCommand counts q.hits, which also counts install forms with nothing to
// check (npm ci, python -m venv, uv run): the same line without the variable is silent. substRuns asks for any
// command named by a substitution that looks up python or a package manager, whatever the command does: python
// -m pytest is silent, $(pyenv which python) -m pytest asks. Each line below is silent without the expansion.
func TestReaderShellsReviewNoReasonWithoutAnInstall(t *testing.T) {
	for _, line := range []string{
		"${NPM:-npm} ci",
		"${PYTHON:-python3} -m venv .venv",
		"${UV:-uv} run pytest",
		"$(pyenv which python) -m pytest",
		"$(pyenv which python) -V",
		"type -P npm && $(type -P npm) run build",
	} {
		if !silentOn(line) {
			tg, un, _, s := ParseLine(line)
			t.Errorf("%q: asks without an install: targets %q, unread %q, extra %q", line, tg, un, HookExtra(line, tg, un, s))
		}
	}
}

// P3-4 of the review, taken into round 6: macOS arch (Rosetta, arch -x86_64 npm install on Apple silicon) and zsh's
// nocorrect (a precommand modifier like noglob) run the command in their words.
func TestReaderShellsReviewArchNocorrect(t *testing.T) {
	for _, line := range []string{
		"arch -x86_64 npm i zz-review-pkg",
		"arch -arm64 pip install zz-review-pkg",
		"arch -arch arm64 npx -y zz-review-pkg",
		"nocorrect npm i zz-review-pkg",
	} {
		if silentOn(line) {
			t.Errorf("%q: silent on an install", line)
		}
	}
}

// For READER-RUNNERS (a plan row of its own, not this round): programs that run the command in their words, silent on
// 7b53831 and here. Skipped until that row; the list is the review's (P3-4).
func TestReaderShellsReviewRunnersFollowUp(t *testing.T) {
	t.Skip("READER-RUNNERS: not read yet")
	for _, line := range []string{
		"coproc npm i zz-review-pkg",
		"wsl npm i zz-review-pkg",
		"wsl -e sh -c 'npm i zz-review-pkg'",
		"wsl -- npx -y zz-review-pkg",
		"pkexec npm i zz-review-pkg",
		"runuser -u node -- npm i zz-review-pkg",
		"gosu node npm i zz-review-pkg",
		"su-exec node npm i zz-review-pkg",
	} {
		if silentOn(line) {
			t.Errorf("%q: silent on an install", line)
		}
	}
}
