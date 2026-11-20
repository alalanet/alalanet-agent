package installread

import (
	"slices"
	"testing"
)

// READER-NPX-SC-1 (ADR-0159 round 36): npm's --call in every spelling nopt reads (a cluster of one-letter shorthands
// that ends in c, -c=…, -call), after an option that takes a value, and before npm's exec command as well as after it.
// Each "ran" line (and npx -sc … --yes, npm -p exec -c …) ran its command string through the real npm 10.8.2, offline, with empty configs
// (work-1116/reader-af/npm.out).
func TestReaderNpxCallCluster(t *testing.T) {
	for _, line := range []string{
		// ran
		"npx -sc 'sh x.sh'",
		"npx -yc 'sh x.sh'",
		"npx -qc 'sh x.sh'",
		"npx -Sc 'sh x.sh'",
		"npx -cc 'sh x.sh'",
		"npx --sc 'sh x.sh'",
		"npx --yc 'sh x.sh'",
		"npx -c='sh x.sh'",
		"npx -sc='sh x.sh'",
		"npx --script-shell sh -sc 'sh x.sh'",
		"npx --script-shell sh -c 'sh x.sh'",
		"npm exec -sc 'sh x.sh'",
		"npm x -yc 'sh x.sh'",
		"npm exec --loglevel warn -sc 'sh x.sh'",
		"npm -c 'sh x.sh' exec",
		"npm -sc 'sh x.sh' x",
		"npm --call='sh x.sh' exec",
		// npm refuses these (a package word with the string) or reads them otherwise; held all the same
		"npx -sc 'sh x.sh' zz-pkg",
		"npx -p zz-pkg -sc 'sh x.sh'",
		"npx -call 'sh x.sh'",
		"npm -dd exec -c 'sh x.sh'",
		"npm -sw ws1 exec -c 'sh x.sh'",
		"npm -s exe -c 'sh x.sh'",
		"npx -sc 'sh x.sh' --yes",
		"npm -p exec -c 'sh x.sh'",
	} {
		if _, codes := codesOn(line); !slices.Contains(codes, "command_string") {
			t.Errorf("%q: codes %v, want command_string", line, codes)
		}
	}
	for _, line := range []string{
		"npx -y zz-pkg",
		"npx -sy zz-pkg",
		"npx -s zz-pkg",
		"npx -y zz-pkg -sc x", // the package's own words
		"npx -y zz-pkg -c x",
		"npm exec zz-pkg",
		"npm -s exec zz-pkg",
		"npm exec -- zz-pkg -c x",
		"npx -- -c x",
		"npm -c x install zz-pkg", // a command string only npm exec runs
		"npm --cache /tmp/c exec zz-pkg",
		// a c before the cluster's end sets an empty call (npm 10.8.2: npx --cal 'echo x' fetched the package 'echo x')
		"npx --cal 'sh x.sh'",
		"npx -cs 'sh x.sh'",
		"npx --caf zz-pkg",
	} {
		if _, codes := codesOn(line); slices.Contains(codes, "command_string") {
			t.Errorf("%q: codes %v, want no command_string", line, codes)
		}
	}
	for x, want := range map[string]bool{
		"-sc": true, "-c": true, "--call": true, "-call": true, "-c=x": true, "--sc": true, "-yc=x": true, "-cc": true,
		"-cs": false, "--cal": false, "--caf": false, "-s": false, "--cache": false, "-desc": false, "--no-call": false,
		"-sxc": false, "-": false, "--": false, "-ca": false,
	} {
		if got := npmCallWord(x); got != want {
			t.Errorf("npmCallWord(%q) = %v, want %v", x, got, want)
		}
	}
	for x, want := range map[string]bool{
		"-sc": true, "-c": true, "-call": true, "--call": true, "-sw": true, "-w": true, "-registry": true,
		"-cs": false, "-s": false, "-dd": false, "-n": false, "-y": false, "-c=x": false, "--cal": false, "-sxc": false,
		"-": false, "-q": false, "-d": false, "-ddd": false, "--quiet": false, "--silent": false, "--verbose": false,
		"--no": false, "--local": false, "--loglev": true, "--reg": true,
	} {
		if got := npmTakesNext(x); got != want {
			t.Errorf("npmTakesNext(%q) = %v, want %v", x, got, want)
		}
	}
}
