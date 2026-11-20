package installread

import (
	"slices"
	"testing"
)

// READER-PNPM-CALL-CLUSTER (ADR-0159 round 40): pnpm dlx, pnpm exec and pnpx run their command words in a shell under
// --shell-mode (short -c) in every spelling @pnpm/nopt (pnpm 8 to 11) or clap (pnpm 12) reads: before the command word,
// between dlx and its command (pnpm 10.x and later), after exec's command word (pnpm 12), in a cluster with c anywhere,
// as a prefix of --shell-mode from --she on. Each "ran" line ran 'probe X;probe Y' through a shell in at least one of
// the real pnpm 8.15.9, 9.15.9, 10.0.0, 10.34.9, 11.28.12 and 12.21.0, offline (work-1116/reader-pnpm/probe/probe2.out).
func TestReaderPnpmShellMode(t *testing.T) {
	for _, line := range []string{
		// ran
		"pnpm -c exec 'sh x.sh'",
		"pnpm -cs exec 'sh x.sh'",
		"pnpm -dc exec 'sh x.sh'",
		"pnpm -rc exec 'sh x.sh'",
		"pnpm -qc exec 'sh x.sh'",
		"pnpm -pc exec 'sh x.sh'",
		"pnpm -Cc exec 'sh x.sh'",
		"pnpm -C /w -wc exec 'sh x.sh'",
		"pnpm --shell-mode exec 'sh x.sh'",
		"pnpm --shell exec 'sh x.sh'",
		"pnpm --shell-m exec 'sh x.sh'",
		"pnpm --she exec 'sh x.sh'",
		"pnpm -shell-mode exec 'sh x.sh'",
		"pnpm -c=true exec 'sh x.sh'",
		"pnpm --shell-mode true exec 'sh x.sh'",
		"pnpm -c true exec 'sh x.sh'",
		"pnpm -C . -c exec 'sh x.sh'",
		"pnpm --dir . -c exec 'sh x.sh'",
		"pnpm --filter . -c exec 'sh x.sh'",
		"pnpm -F . -c exec 'sh x.sh'",
		"pnpm --reporter silent -c exec 'sh x.sh'",
		"pnpm -r -c exec 'sh x.sh'",
		"pnpm -c recursive exec 'sh x.sh'",
		"pnpm -c -- exec 'sh x.sh'",
		"pnpm -c -C . exec 'sh x.sh'",
		"pnpm -c multi exec 'sh x.sh'",
		"pnpm -c exec -- 'sh x.sh'",
		"pnpm --package=zz-pkg -c dlx 'sh x.sh'",
		"pnpm --package=zz-pkg --she dlx 'sh x.sh'",
		"pnpm -c dlx 'sh x.sh'",
		"pnpm --package=zz-pkg dlx -c 'sh x.sh'",
		"pnpm --package=zz-pkg dlx -sc 'sh x.sh'",
		"pnpm --package=zz-pkg dlx -cs 'sh x.sh'",
		"pnpm --package=zz-pkg dlx --shell-mode 'sh x.sh'",
		"pnpm --package=zz-pkg dlx --sc 'sh x.sh'",
		"pnpm dlx --package=zz-pkg -c 'sh x.sh'",
		"pnpm dlx --package zz-pkg -c 'sh x.sh'",
		"pnpm dlx -c --package=zz-pkg 'sh x.sh'",
		"pnpm --package=zz-pkg dlx --reporter silent -c 'sh x.sh'",
		"pnpx -y true -c --package=zz-pkg 'sh x.sh'",
		"pnpx --package=zz-pkg -c 'sh x.sh'",
		"pnpx -c --package=zz-pkg 'sh x.sh'",
		"pnpx -sc --package=zz-pkg 'sh x.sh'",
		"pnpx --shell-mode --package=zz-pkg 'sh x.sh'",
		"pnpx --shell-mode=true --package=zz-pkg 'sh x.sh'",
		"pnpm exec -c 'sh x.sh'",
		"pnpm exec --shell-mode 'sh x.sh'",
		"pnpm exec -sc 'sh x.sh'",
		// pnpm refuses these in some versions or reads them otherwise; held all the same
		"pnpm -sc exec 'sh x.sh'",
		"pnpm --sc exec 'sh x.sh'",
		"pnpm -yc exec 'sh x.sh'",
		"pnpm -cC . exec 'sh x.sh'",
		"pnpm --fil web -c exec 'sh x.sh'",
		"pnpm -C web -sc exec 'sh x.sh'",
		"pnpm -c m exec 'sh x.sh'",
		"pnpx -yc --package=zz-pkg 'sh x.sh'",
		"pnpm --package=zz-pkg dlx -C . -c 'sh x.sh'",
		"pnpm --package=zz-pkg dlx -rF web -c 'sh x.sh'",
		"pnpm --package=zz-pkg dlx -C -c", // nopt gives -C no option word: -c is read, and no command is left
	} {
		if _, codes := codesOn(line); !slices.Contains(codes, "command_string") {
			t.Errorf("%q: codes %v, want command_string", line, codes)
		}
	}
	for _, line := range []string{
		"pnpm dlx zz-pkg",
		"pnpm dlx -s zz-pkg",
		"pnpx -y zz-pkg",
		"pnpx zz-pkg -c 'sh x.sh'", // the package's own words
		"pnpm dlx zz-pkg -sc x",
		"pnpm --package=zz-pkg dlx zzbin -c x",
		"pnpm exec zzbin -c x",
		"pnpm exec -- -c x",
		"pnpm dlx -- -c x",
		"pnpx -- -c x",
		"pnpm -c run build", // not dlx or exec
		"pnpm -c add zz-pkg",
		"pnpm -c build exec x",
		"pnpm -c -- run 'sh x.sh'",
		"pnpm -- -c exec 'sh x.sh'",
		"pnpm -c --filter=web build exec x", // build is the command: --filter=web carries its value
		"pnpm -c --dir web build exec x",
		"pnpm --shell-mode=false exec 'sh x.sh'",
		"pnpm --no-shell-mode exec 'sh x.sh'",
		"pnpm --shellmode exec 'sh x.sh'",
		"pnpm --sh exec 'sh x.sh'", // --reporter=silent --help
		"pnpm -cx exec 'sh x.sh'",  // x is no shorthand
		"pnpm --cache-dir /tmp/c exec zzbin",
		"pnpm -C web exec zzbin",
		"pnpm --package=zz-pkg dlx -F web zzbin", // web is -F's value
	} {
		if _, codes := codesOn(line); slices.Contains(codes, "command_string") {
			t.Errorf("%q: codes %v, want no command_string", line, codes)
		}
	}
	for x, want := range map[string]bool{
		"-c": true, "-sc": true, "-cs": true, "--sc": true, "-yc": true, "-Cc": true, "-cC": true, "-c=true": true,
		"-c=false": true, "--shell-mode": true, "-shell-mode": true, "--she": true, "--shell-": true, "--shell-mode=1": true,
		"---shell-mode": true, "--shell-mode=true": true,
		"--sh": false, "-s": false, "--shellmode": false, "--shell-mode=false": false, "--no-shell-mode": false,
		"--no-no-shell-mode": true, "--NO-shell-mode": false, "-cx": false, "--cache": false, "-": false, "--": false,
		"c": false, "--shell-modes": false, "-y": false, "--call": false, "-=x": false, "--no-no-sh": true,
		"--no-no-she": true, "--no-no-s": false, "--no-sh": false, "-no-no-sh": true,
	} {
		if got := pnpmShellWord(x); got != want {
			t.Errorf("pnpmShellWord(%q) = %v, want %v", x, got, want)
		}
	}
	for x, want := range map[string]bool{
		"-C": true, "-F": true, "-rF": true, "-cC": true, "--dir": true, "--filter": true, "--package": true,
		"-c": false, "-Cc": false, "-C=x": false, "-xF": false, "-cC=x": false, "--dir=x": false, "--shell-mode": false, "-s": false, "--": false,
	} {
		if got := pnpmTakesNext(x); got != want {
			t.Errorf("pnpmTakesNext(%q) = %v, want %v", x, got, want)
		}
	}
}
