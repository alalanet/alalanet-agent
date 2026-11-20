package installread

import (
	"slices"
	"strings"
	"testing"
)

// ADR-0159 round 44, review of round 43 (review-1117/reader43/review.md).
//
// P2-1: uv's global options before run and tool run (uv --directory D run …, the spelling MCP configs use for uv
// servers), uv run's and uv tool run's options that take a word (--env-file .env, --group dev …), and a program named by
// an expansion, a backquote or a backslash ($SHELL, "$SHELL", ${SHELL:-sh}, s\h) under a runner are read as at the top.
func TestReaderRunnerUvAndExpandedProgram(t *testing.T) {
	for line, want := range map[string]string{
		"uv --directory /srv run sh -c 'npm i zz-evil'":                      "npm:zz-evil",
		"uv --directory=/srv run sh -c 'npm i zz-evil'":                      "npm:zz-evil",
		"uv -q run sh -c 'npm i zz-evil'":                                    "npm:zz-evil",
		"uv --color never --offline run sh -c 'npm i zz-evil'":               "npm:zz-evil",
		"uv --project /x run pip install zz-evil":                            "pypi:zz-evil",
		"uv --offline tool run --from zz-pkg sh -c 'npm i zz-evil'":          "npm:zz-evil",
		"uv --directory /srv tool run zz-evil":                               "pypi:zz-evil",
		"uv -q tool run zz-evil":                                             "pypi:zz-evil",
		"uv -q tool uvx zz-evil":                                             "pypi:zz-evil",
		"uv --directory /srv run --with zz-evil app":                         "pypi:zz-evil",
		"uv run --env-file .env pip install zz-evil":                         "pypi:zz-evil",
		"uv run --directory /srv sh -c 'npm i zz-evil'":                      "npm:zz-evil",
		"uv run --group dev pip install zz-evil":                             "pypi:zz-evil",
		"uv run --extra x pip install zz-evil":                               "pypi:zz-evil",
		"uv run --with-requirements r.txt sh -c 'npm i zz-evil'":             "npm:zz-evil",
		"uv run --only-group dev sh -c 'npm i zz-evil'":                      "npm:zz-evil",
		"uv run --with-editable . sh -c 'npm i zz-evil'":                     "npm:zz-evil",
		"uv run --package app sh -c 'npm i zz-evil'":                         "npm:zz-evil",
		"uv run --no-group dev sh -c 'npm i zz-evil'":                        "npm:zz-evil",
		"uv tool run --env-file .env --from zz-pkg sh -c 'npm i zz-evil'":    "npm:zz-evil",
		"uvx --env-file .env --from zz-pkg sh -c 'npm i zz-evil'":            "npm:zz-evil",
		"uvx --exclude-newer 2026-01-01 --from zz-pkg sh -c 'npm i zz-evil'": "npm:zz-evil",
		`pnpm exec s\h -c 'npm i zz-evil'`:                                   "npm:zz-evil",
		`npx -p zz-a b\ash -c 'npm i zz-evil'`:                               "npm:zz-evil",
		"pnpm exec `which sh` -c 'npm i zz-evil'":                            "npm:zz-evil", // as `which sh` -c '…' at the top
		"pnpm exec $(command -v sh) -c 'npm i zz-evil'":                      "npm:zz-evil",
		// P3-2: Yarn 2+'s dlx -p is --package; the package's own word is not the program
		"yarn dlx -p zz-pkg sh -c 'npm i zz-evil'": "npm:zz-evil",
	} {
		if tg, _ := codesOn(line); !slices.Contains(tg, want) {
			t.Errorf("%q: targets %v, want %s", line, tg, want)
		}
	}
	// a program named by an expansion: held as the same command is at the top ($SHELL -c '…' is a variable command)
	for line, code := range map[string]string{
		"pnpm exec $SHELL -c 'npm i zz-evil'":        "variable_argument",
		`pnpm exec "$SHELL" -c 'npm i zz-evil'`:      "variable_argument",
		"pnpm exec ${SHELL:-sh} -c 'npm i zz-evil'":  "variable_argument",
		"npx -p zz-a $SHELL -c 'npm i zz-evil'":      "variable_argument",
		"uv run $SHELL -c 'pip install zz-evil'":     "variable_argument",
		"uv run --env-file .env pip install zz-evil": "env_file",
	} {
		if _, codes := codesOn(line); !slices.Contains(codes, code) {
			t.Errorf("%q: codes %v, want %s", line, codes, code)
		}
	}
	// lines that start no program alalanet reads stay as they were: an MCP config's uv server, uv's own options
	for line, want := range map[string][]string{
		"uv --directory /srv run zz-server":               nil,
		"uv --directory /srv/mcp run server.py":           nil,
		"uv run --frozen pytest -q":                       nil,
		"uv run --env-file .env python app.py":            nil,
		"uv run --group dev pytest":                       nil,
		"uv -q run --with zz-pkg pytest":                  {"pypi:zz-pkg"},
		"uv --directory /srv run --with mcp mcp run x.py": {"pypi:mcp"},
		"uv --directory /srv pip install zz-pkg":          {"pypi:zz-pkg"},
		"uv --directory /srv sync":                        nil,
		"uv --version":                                    nil,
		"yarn dlx -p zz-pkg zz-bin":                       {"npm:zz-pkg"},
		"pnpm exec $X":                                    nil,
		"pnpm exec tsc --outDir $OUT":                     nil,
	} {
		if tg, codes := codesOn(line); !slices.Equal(tg, want) || len(codes) > 0 {
			t.Errorf("%q: targets %v codes %v, want %v and no reason", line, tg, codes, want)
		}
	}
	for in, want := range map[string]string{
		"--directory /srv run sh -c x":   "run --directory /srv sh -c x",
		"-q --offline tool run x":        "tool run -q --offline x",
		"--directory=/srv run x":         "run --directory=/srv x",
		"-q tool uvx x":                  "tool run -q x",
		"--directory /srv pip install x": "--directory /srv pip install x",
		"--directory /srv":               "--directory /srv",
		"--directory":                    "--directory",
		"-q tool":                        "-q tool",
		"run --directory /srv x":         "run --directory /srv x",
		"-- run x":                       "-- run x",
	} {
		_, got := canonCommand("uv", strings.Fields(in))
		if strings.Join(got, " ") != want {
			t.Errorf("canonCommand(uv %s) = %v, want %s", in, got, want)
		}
	}
}

// P3-1: cross-env and dotenv under a runner hold in every runner spelling, with one reason (the runner's and the wrapper's
// reading do not both say it).
func TestReaderRunnerEnvWrappers(t *testing.T) {
	for _, line := range []string{
		"npm exec -- cross-env A=1 npm i zz-evil",
		"npx --package=x -- cross-env A=1 npm i zz-evil",
		"uv run -- cross-env A=1 npm i zz-evil",
		"bunx --cwd /x cross-env A=1 npm i zz-evil",
		"bun --bun x cross-env A=1 npm i zz-evil",
		"pnpm --package=x dlx cross-env A=1 npm i zz-evil",
		"npx -y cross-env A=1 npm i zz-evil",
		"npx -y cross-env@7.0.3 A=1 npm i zz-evil",
		"pnpm exec cross-env A=1 npm i zz-evil",
		"npm exec -- dotenv -e .env -- npm i zz-evil",
		"npx dotenv -- npm i zz-evil",
		"npx -y dotenv-cli@7.4.2 -- npm i zz-evil",
		"pnpm exec ./node_modules/.bin/cross-env A=1 npm i zz-evil",
		"pnpm exec ./node_modules/.bin/dotenv -- npm i zz-evil",
	} {
		_, codes := codesOn(line)
		if n := strings.Count(strings.Join(codes, " "), "install_through_wrapper"); n != 1 {
			t.Errorf("%q: codes %v, want install_through_wrapper once", line, codes)
		}
	}
	if _, codes := codesOn("npm exec -- dotenv -e .env -- npm i zz-evil"); !slices.Contains(codes, "env_file") {
		t.Errorf("dotenv under npm exec: codes %v, want env_file", codes)
	}
	for _, line := range []string{"npx -y cross-env A=1 tsc", "pnpm exec cross-env NODE_ENV=test vitest run", "npm exec -- dotenv -- jest"} {
		if _, codes := codesOn(line); len(codes) > 0 {
			t.Errorf("%q: codes %v, want none", line, codes)
		}
	}
}
