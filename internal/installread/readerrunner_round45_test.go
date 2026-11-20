package installread

import (
	"slices"
	"strings"
	"testing"
)

// ADR-0159 round 45, re-review of round 44 (review-1117/rrs44/review.md).
//
// P2-1: uv's global options written between "tool" and its subcommand (uv tool -q run x, uv tool --directory D run x):
// clap takes global arguments at every level, so uv runs these as uv tool run x. They move after "tool <subcommand>" with
// the ones written before "tool".
func TestReaderUvToolGlobals(t *testing.T) {
	for line, want := range map[string][]string{
		"uv tool -q run zz-pkg":                                     {"pypi:zz-pkg"},
		"uv tool --offline run zz-pkg":                              {"pypi:zz-pkg"},
		"uv tool --directory /srv run zz-pkg":                       {"pypi:zz-pkg"},
		"uv tool --directory=/srv run zz-pkg":                       {"pypi:zz-pkg"},
		"uv tool --cache-dir /tmp/c run zz-pkg":                     {"pypi:zz-pkg"},
		"uv tool -q uvx zz-pkg":                                     {"pypi:zz-pkg"},
		"uv -q tool -q run zz-pkg":                                  {"pypi:zz-pkg"},
		"uv --directory /srv tool --color never run zz-pkg":         {"pypi:zz-pkg"},
		"uv tool -q run sh -c 'npm i zz-evil'":                      {"npm:zz-evil", "pypi:sh"}, // uv tool run fetches the package sh too
		"uv tool --offline run --from zz-pkg sh -c 'npm i zz-evil'": {"npm:zz-evil", "pypi:zz-pkg"},
		"uv tool -q install zz-pkg":                                 {"pypi:zz-pkg"},
	} {
		if tg, _ := codesOn(line); !slices.Equal(sorted(tg), want) {
			t.Errorf("%q: targets %v, want %v", line, tg, want)
		}
	}
	for line, want := range map[string][]string{
		"uv tool -q list":                 nil,
		"uv tool --directory /srv dir":    nil,
		"uv tool -q run --from zz-pkg zz": {"pypi:zz-pkg"},
	} {
		if tg, codes := codesOn(line); !slices.Equal(tg, want) || len(codes) > 0 {
			t.Errorf("%q: targets %v codes %v, want %v and no reason", line, tg, codes, want)
		}
	}
	for in, want := range map[string]string{
		"tool -q run x":                        "tool run -q x",
		"tool --directory /srv run x":          "tool run --directory /srv x",
		"tool --directory=/srv run x":          "tool run --directory=/srv x",
		"-q tool --offline run x":              "tool run -q --offline x",
		"--directory /a tool --project /b run": "tool run --directory /a --project /b",
		"tool -q uvx x":                        "tool run -q x",
		"-q tool -q uvx x":                     "tool run -q -q x",
		"tool -q":                              "tool -q",
		"tool --directory":                     "tool --directory",
		"tool --directory /srv":                "tool --directory /srv",
		"tool -- run x":                        "tool -- run x",
		"-q tool -- run x":                     "-q tool -- run x",
		"tool run -q x":                        "tool run -q x",
	} {
		_, got := canonCommand("uv", strings.Fields(in))
		if strings.Join(got, " ") != want {
			t.Errorf("canonCommand(uv %s) = %v, want %s", in, got, want)
		}
	}
}

// P3-1: a runner's program named by a variable holds with one variable_argument reason, not two texts saying it.
func TestReaderRunnerExpandedProgramOneReason(t *testing.T) {
	for _, line := range []string{
		`npx -y "$SHELL" -c 'npm i zz-evil'`,
		"npm exec -- $SHELL -c 'npm i zz-evil'",
		"bunx $SHELL -c 'npm i zz-evil'",
		"uv run $SHELL -c 'pip install zz-evil'",
		`uv --directory /srv run "$SHELL" -c 'pip install zz-evil'`,
		`yarn dlx -p zz-pkg "$SHELL" -c 'npm i zz-evil'`,
		"pnpm exec $SHELL -c 'npm i zz-evil'",
		"npx -y ${SHELL:-sh} -c 'npm i zz-evil'",
	} {
		_, codes := codesOn(line)
		if n := strings.Count(strings.Join(codes, " "), "variable_argument"); n != 1 {
			t.Errorf("%q: codes %v, want variable_argument once", line, codes)
		}
	}
}

func sorted(s []string) []string {
	s = slices.Clone(s)
	slices.Sort(s)
	return s
}
