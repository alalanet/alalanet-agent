package installread

import (
	"net/url"
	"strings"
)

// MCP-ADD-NO-DASH-1: the words of "<client> mcp add …" after "add", read in each client's own grammar (read
// 2026-11-17: code.claude.com/docs/en/mcp; gemini-cli docs/tools/mcp-server.md; codex-rs/cli/src/mcp_cmd.rs; round 2,
// 2026-11-18, from the review's sources: claude 2.1.326's own definition, commander 12.1 parseOptions, gemini's add.ts
// with yargs-parser 21.1, codex-rs utils/cli config_override.rs and cli main.rs):
//
//	claude mcp add [options] <name> <commandOrUrl> [args...]   commander: options anywhere before "--"; -e/--env and
//	                                                           -H/--header given as a separate word take every
//	                                                           following non-option word, given as --env=V, -eV or
//	                                                           -e=V they take that one value; --client-secret, --xaa
//	                                                           and --web take none; "--" ends the options, and the words
//	                                                           after it are more positionals
//	gemini mcp add [options] <name> <commandOrUrl> [args...]   yargs (packages/cli/src/commands/mcp/add.ts): unknown
//	                                                           options are the server's args ('unknown-options-as-args'),
//	                                                           -e/--env and -H/--header take one value each (nargs 1),
//	                                                           --no-<option> takes none, --trust takes a following true
//	                                                           or false, includeTools/excludeTools are the camelCase
//	                                                           names; the words after "--" are not positionals there
//	                                                           ("NAME -- CMD" fails on the real client), and reading
//	                                                           them as the launch over-judges harmlessly
//	codex mcp add [OPTIONS] <NAME> (--url <URL> | -- <COMMAND>...)   clap: the command is a trailing positional — from
//	                                                           its first word on, every word is the server's; the
//	                                                           global -c/--config, --enable and --disable take a value
//
// The server's launch is the positionals after the name, with or without "--": "claude mcp add zz go run x@v" starts
// "go run x@v" as "claude mcp add zz -- go run x@v" does. Both readers, the hook, install_check and
// check_repo_config read it through this one function.

// mcpAdd is what an MCP add command gives the server it adds.
type mcpAdd struct {
	env []string // the -e/--env words, as MCPAddEnvWords gives them
	// envGlued: for each, whether it was glued to its option (--env=K=V, -eK=V): a word no shell takes for an
	// assignment, whose ~ bash keeps too (HOME-CONFIG-ENV-1 round 6, P3-1)
	envGlued []bool
	launch   []string // the command and its arguments
	url      string   // a remote server's https URL (--transport http|sse, codex's --url, or a URL as the command)
	// why: an option the client's grammar does not have: the line is not read. The launch is still given when it is
	// known without that option — the words after "--" — so a hold never replaces the verdict on them (round 2, P2-2).
	why  string
	help bool // -h/--help: the client prints its help and adds nothing
}

// mcpAddOptions: per client, the options that take one value, those that take several (until the next option) and
// those that take none.
var mcpAddOptions = map[string]struct{ one, many, none map[string]bool }{
	"claude": {wordSet("-s --scope -t --transport --callback-port --client-id"), wordSet("-e --env -H --header"),
		wordSet("--client-secret --xaa --web")},
	"gemini": {wordSet("-s --scope -t --transport --type --timeout --description -e --env -H --header"),
		wordSet("--include-tools --exclude-tools --includeTools --excludeTools"), wordSet("--trust " + geminiGlobal)},
	"codex": {wordSet("--env --url --bearer-token-env-var --oauth-client-id --oauth-client-secret --oauth-client-registration " +
		"--oauth-resource -c --config --enable --disable"), wordSet(""), wordSet("")},
}

// geminiGlobal: gemini-cli's root options (packages/cli/src/config/config.ts, parseArguments: --isCommand and
// --debug/-d, booleans), global in yargs and so valid after "mcp" and "add" too (round 3, P2-1). --help/-h prints and
// adds nothing. The launch command's options (--model, --prompt, --yolo …) are the $0 command's own and unknown in
// "mcp add": the server's arguments there. geminiTop: yargs's --version/-v, the root's only: "mcp" is built with
// .version(false) (commands/mcp.ts), and yargs 17.7.2's version(false) deletes the option and its aliases from the
// parser (yargs-factory.js, kDeleteFromParserHintObject), so under "mcp" and "add" they are unknown — the server's
// name or arguments there (round 4, P2-1).
const (
	geminiGlobal = "--debug -d --isCommand --is-command"
	geminiTop    = "--version -v"
)

// mcpRootOptions: per client, the options its root program (and its "mcp" command) takes before "add", by how many
// values: gemini's global booleans; codex's global -c/--config, --enable and --disable (clap's global = true). claude's
// root and its "mcp" command call enablePositionalOptions (2.1.327, read from the binary): the root's options are its
// own before "mcp", and alalanet lists none of them, so any option there is unread — the fail-safe: a hold, and the
// launch after "--" judged as well (round 3, P3-1). codex's other root options (its TUI's) are unread the same way.
// top: the options the root takes before "mcp" only.
var mcpRootOptions = map[string]struct{ one, none, top map[string]bool }{
	"claude": {wordSet(""), wordSet(""), wordSet("")},
	"gemini": {wordSet(""), wordSet(geminiGlobal), wordSet(geminiTop)},
	"codex":  {wordSet("-c --config --enable --disable"), wordSet(""), wordSet("")},
}

// clientOf: the client a program word names — its program name (a path's last part, .exe and .cmd and a version
// aside) or its npm package — or "" for any other word. The name is matched whole: "gemini-tools" or
// "/opt/codex-tools/run" are no client (round 2, P3).
func clientOf(prog string) string {
	p := strings.ToLower(prog)
	switch {
	case strings.HasPrefix(p, "@"):
		switch stripVersion(p) { // a scoped package: the client's own only
		case "@anthropic-ai/claude-code":
			return "claude"
		case "@openai/codex":
			return "codex"
		case "@google/gemini-cli":
			return "gemini"
		}
		return ""
	default:
		p = stripVersion(launchBase(p)) // codex@1.2
	}
	switch p {
	case "claude":
		return "claude"
	case "codex":
		return "codex"
	case "gemini", "gemini-cli":
		return "gemini"
	}
	return ""
}

// mcpAddClient: the client whose grammar a program's "mcp add" follows (clientOf); any other program, path or
// wrapper is read as claude's.
func mcpAddClient(prog string) string {
	if c := clientOf(prog); c != "" {
		return c
	}
	return "claude"
}

// findMCPAdd is the one entry point of both readers for "<client> [root options] mcp [options] add …": prog is the
// line's program word, w the words after it. A client program (clientOf) starts at w[0]; any other program (npx,
// bunx, a wrapper) after a word that names a client, or, with none, at "mcp add" itself in claude's grammar. The options before "mcp" and before "add" are the client's root options (mcpRootOptions); one alalanet does
// not list makes the line unread from there on, its launch after "--" judged as well (readMCPAdd's why). A word
// that is no option there (claude zz mcp add: a prompt) or -h/--help: no "mcp add". found false: none.
func findMCPAdd(prog string, w []string) (m mcpAdd, found bool) {
	if client := clientOf(prog); client != "" {
		return mcpAddFrom(client, w, 0)
	}
	// a runner: each word that names a client in turn (a runner's option value may name one too: npx -p
	// @openai/codex codex mcp add …), its root options read from the next word; with none, the first "mcp add" read in
	// claude's grammar, with no root options, as before
	for j, x := range w {
		if c := clientOf(x); c != "" {
			if m, ok := mcpAddFrom(c, w, j+1); ok {
				return m, true
			}
		}
	}
	for at := 0; at+1 < len(w); at++ {
		if w[at] == "mcp" && w[at+1] == "add" {
			return readMCPAdd("claude", w[at+2:]), true
		}
	}
	return m, false
}

// mcpAddFrom is findMCPAdd for a client whose root options start at w[i].
func mcpAddFrom(client string, w []string, i int) (m mcpAdd, found bool) {
	root := mcpRootOptions[client]
	why := ""
	for _, want := range []string{"mcp", "add"} {
		for ; i < len(w) && w[i] != want; i++ {
			x := w[i]
			switch {
			case why != "":
				continue // past an option alalanet cannot read: the first "mcp", then "add", is taken (fail-safe)
			case x == "-h" || x == "--help":
				return m, false
			case !strings.HasPrefix(x, "-") || x == "-" || x == "--":
				return m, false // a positional word: the program's own (a prompt), no subcommand
			}
			name, _, eq := strings.Cut(x, "=")
			attached := len(x) > 2 && x[1] != '-' && root.one[x[:2]]
			none := func(n string) bool { return root.none[n] || want == "mcp" && root.top[n] }
			neg := strings.HasPrefix(name, "--no-") && none("--"+name[5:])
			switch {
			case root.one[name] || attached:
				if !eq && !attached && i+1 < len(w) {
					i++ // its value
				}
			case none(name) || neg:
				if client == "gemini" && !eq && !neg && i+1 < len(w) && (w[i+1] == "true" || w[i+1] == "false") {
					i++ // yargs: a boolean takes a following true or false
				}
			default:
				why = mcpAddWhy + client + " mcp add " + clip(x, 40) + ")"
			}
		}
		if i >= len(w) {
			return m, false
		}
		i++
	}
	return readMCPAddWhy(client, w[i:], why), true
}

// MCPAddLaunch: whether a line's words (its fields, the program first) are a client's "mcp add", by the one entry
// point (findMCPAdd) with its runner fallback, as the hook reads them — a quoted or prefixed program word ("claude",
// A=1 claude, builtin claude) or another client's "mcp add" too (round 4, P3-1) — and the server's launch it reads (nil
// for a remote server or none). install_check and the unread tool's insight ask it, so every reader agrees on what an
// MCP add line is (round 3).
func MCPAddLaunch(words []string) ([]string, bool) {
	if len(words) < 2 {
		return nil, false
	}
	m, ok := findMCPAdd(words[0], words[1:])
	return m.launch, ok
}

// readMCPAdd reads the words after "mcp add".
func readMCPAdd(client string, w []string) mcpAdd { return readMCPAddWhy(client, w, "") }

// readMCPAddWhy is readMCPAdd with an option before "add" already unread (findMCPAdd): why, if not "".
func readMCPAddWhy(client string, w []string, why string) mcpAdd {
	opts, ok := mcpAddOptions[client]
	if !ok {
		client, opts = "claude", mcpAddOptions["claude"]
	}
	m := mcpAdd{why: why}
	var pos []string
	transport := ""
	dash, before := false, -1 // before: the positionals before the first "--"
	for i := 0; i < len(w); i++ {
		x := w[i]
		if x == "--" && before < 0 {
			before = len(pos)
		}
		switch {
		case dash, client == "codex" && len(pos) > 1:
			pos = append(pos, x) // after "--", and codex's command from its first word on: the server's own words
			continue
		case x == "--":
			dash = true
			continue
		case !strings.HasPrefix(x, "-") || x == "-":
			pos = append(pos, x)
			continue
		case x == "-h" || x == "--help":
			m.help = true
			return m
		}
		name, val, eq := strings.Cut(x, "=")
		if len(x) > 2 && x[1] != '-' && (opts.one[x[:2]] || opts.many[x[:2]]) {
			// -suser, -thttp, -eK=V, -HV, -e=K=V: a short option with its value attached (commander keeps the "=",
			// which only an env word's reading drops)
			name, val, eq = x[:2], strings.TrimPrefix(x[2:], "="), true
		}
		neg := client == "gemini" && strings.HasPrefix(name, "--no-") &&
			(opts.one["--"+name[5:]] || opts.many["--"+name[5:]] || opts.none["--"+name[5:]])
		env := name == "-e" || name == "--env"
		switch {
		case neg:
			// yargs's boolean-negation: --no-trust, --no-description set the option false and take no value
		case opts.one[name]:
			if !eq && i+1 < len(w) {
				i++
				val = w[i]
			}
			if name == "-t" || name == "--transport" || name == "--type" {
				transport = strings.ToLower(val)
			}
			if name == "--url" {
				m.url = httpsURL(val)
			}
			if client != "claude" && env {
				m.env, m.envGlued = append(m.env, val), append(m.envGlued, eq) // clap's --env and yargs's -e (nargs 1): one KEY=VALUE each
			}
		case opts.many[name]:
			// commander continues a variadic option only when it is given as a separate word (-e A=1 B=2, -H 'X: v'
			// zz): --env=K=V, -eK=V, --header=V and -HV take that one value (round 2, P1-1)
			n := 1
			for !eq && i+n < len(w) && !strings.HasPrefix(w[i+n], "-") &&
				(strings.Contains(w[i+n], "=") || unseenWord(w[i+n]) || name == "-H" || name == "--header") {
				n++
			}
			if env {
				kvs, glued := mcpAddEnvWords(w[i : i+n]) // the one reading of the pairs, attached ones too
				m.env, m.envGlued = append(m.env, kvs...), append(m.envGlued, glued...)
			}
			i += n - 1
		case opts.none[name]:
			if client == "gemini" && !eq && i+1 < len(w) && (w[i+1] == "true" || w[i+1] == "false") {
				i++ // yargs: a boolean takes a following true or false (--trust true)
			}
		case client == "gemini":
			pos = append(pos, x) // yargs's 'unknown-options-as-args': the server's own option
		default:
			// an option the client's grammar does not have: commander and yargs would read it as the client's own
			// (claude mcp add zz npx -y pkg), and where the launch ends is not known
			if m.why == "" {
				m.why = mcpAddWhy + client + " mcp add " + clip(x, 40) + ")"
			}
		}
	}
	if m.why != "" {
		// the launch is known only as the words after the first "--" (a codex command that began before it, with an
		// option unread, may be the option's value): the name is the last positional before it, or the first after it
		// (round 2, P2-2); a line without "--" is not read
		switch {
		case before < 0:
			return m
		case before > 0:
			pos = pos[before-1:]
		}
		if before > 0 && !dash {
			pos = append(pos[:1], pos[2:]...) // codex took the "--" as a command word
		}
	}
	if len(pos) < 2 || m.url != "" {
		return m // no name, or no command: nothing to launch; or codex's --url
	}
	m.launch = pos[1:]
	if transport == "http" || transport == "sse" || transport == "streamable-http" || strings.Contains(m.launch[0], "://") {
		m.url = httpsURL(m.launch[0])
		m.launch = nil
	}
	return m
}

const mcpAddWhy = "an install command alalanet could not read ("

// MCPAddUnreadOnly: every reason (there is at least one) is an MCP add option the client's grammar does not have
// (readMCPAdd's why) — the only reasons for which install_check still judges the launch after "--" the line names
// (round 2, P2-2).
func MCPAddUnreadOnly(unread []string) bool {
	for _, u := range unread {
		rest, ok := strings.CutPrefix(u, mcpAddWhy)
		if !ok || !strings.HasPrefix(rest, "claude mcp add ") && !strings.HasPrefix(rest, "codex mcp add ") &&
			!strings.HasPrefix(rest, "gemini mcp add ") {
			return false
		}
	}
	return true
}

// httpsURL: an https URL with a host, as the readers judge a remote server; "" for any other word (http:// to a local
// server is not judged, as before; a README's https://<your-app>/mcp names no server, round 2).
func httpsURL(x string) string {
	if u, err := url.Parse(x); err == nil && u.Scheme == "https" && u.Host != "" && !strings.ContainsAny(u.Host, "<>") {
		return x
	}
	return ""
}
