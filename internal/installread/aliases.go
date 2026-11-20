package installread

import (
	"regexp"
	"slices"
	"strings"
)

// READER-NPM-ALIAS-1 (ADR-0159 round 12): the names and subcommand words the tools accept for the forms the reader
// reads. `npm isntall x`, `bun a x` and `pip3.12 install x` install x as `npm install x`, `bun add x` and `pip install
// x` do; read word for word they named nothing, and the hook and install_check gave no verdict.

// pipScript: the console scripts pip installs itself as — pip, pipX and pipX.Y (pip's wheel.py,
// get_console_script_specs: "pip{major}" and "pip{major}.{minor}"; pip 26.2.2, read 2026-11-15) — with pip's own pattern
// for them (re.match(r"pip(\d+(\.\d+)?)?$")).
var pipScript = regexp.MustCompile(`^pip[0-9]+(\.[0-9]+)?$`)

// progName: a command's program as the reader reads it, from the name launchBase gives: a versioned pip (pip3.12,
// pip2) is pip; pip3 stays pip3, which the reader reads as pip already. pn is pnpm and pnx is pnpx (pnpm dlx): pnpm 11
// and 12 install them as bins of their own (package.json "bin" of pnpm@11.28.12: pn bin/pnpm.mjs, pnx bin/pnpx.mjs;
// of pnpm@12.21.0: pn, pnx; READER-PNPM-ALIAS-PN, ADR-0159 round 41). Any other name is returned unchanged.
func progName(cmd string) string {
	switch {
	case cmd == "pn":
		return "pnpm"
	case cmd == "pnx":
		return "pnpx"
	case cmd != "pip3" && pipScript.MatchString(cmd):
		return "pip"
	}
	return cmd
}

// npmCommand: the subcommand npm reads a word as, when it is one the reader reads (npmCommandWords: install,
// install-test, install-ci-test, ci, exec, init, config), or "". npm's deref turns camelCase into its dashed spelling
// first (installTest is install-test); the table holds every alias, listed typo and unambiguous prefix of npm 9.9.4 to
// 12.2.2 (tools/installread_npmopts.js).
func npmCommand(w string) string {
	if strings.ContainsAny(w, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		var b strings.Builder
		for _, r := range w {
			if r >= 'A' && r <= 'Z' {
				b.WriteByte('-')
				r += 'a' - 'A'
			}
			b.WriteRune(r)
		}
		w = b.String()
	}
	return npmCommandWords[w]
}

// npmReadWords: the npm subcommand words the reader's forms read by name.
var npmReadWords = wordSet("i install add exec x init create innit ci clean-install c config")

// pmVerb: the word the reader reads for subcommand word w of package manager cmd — the form's own name for an alias
// the tool accepts, w itself otherwise:
//   - npm: npmCommand; install-test takes install's words (npm install, then npm test), install-ci-test is ci's;
//   - pnpm: it and install-test (pnpm's installTest: commandNames ['install-test', 'it'], pnpm v12.21.0) are install;
//   - bun: a is add, c is create (bun 1.4.4, src/runtime/cli/mod.rs which(): case "add" | "a", "create" | "c").
//
// Yarn has no alias of its install forms (yarn 1 src/cli/aliases.js; Yarn 2+ commands have one path each).
func pmVerb(cmd, w string) string {
	switch cmd {
	case "npm":
		if npmReadWords[w] {
			return w // a word the reader's forms name already (npm i, npm create, npm clean-install): its messages keep it
		}
		switch c := npmCommand(w); c {
		case "install", "install-test":
			return "install"
		case "install-ci-test":
			return "ci"
		case "":
		default:
			return c
		}
	case "pnpm":
		if w == "it" || w == "install-test" {
			return "install"
		}
	case "bun":
		switch w {
		case "a":
			return "add"
		case "c":
			return "create"
		}
	}
	return w
}

// canonCommand gives a command's program and words in the names the reader's forms use: progName's program, and the
// subcommand word of npm, pnpm and bun (their first positional, pmFirstPositional) as pmVerb reads it, and uv's
// hidden `uv tool uvx` (clap's alias of `uv tool run`, the form the uvx binary runs; uv 0.13.7) as `uv tool run`. pnpm
// 11's and 12's `with <version>` runs the words after the version as that pnpm (pnpm with current -c exec '<shell>' ran
// the string; ADR-0159 round 43, P3-2): the two words are left out. uv's global options before run or tool (uv
// --directory D run …, uv -q tool run …) and between tool and its subcommand (uv tool -q run …) go after the
// subcommand's words (uvGlobalsAfter). The words are a copy when one
// changes. Both readers call it before they read the command.
func canonCommand(cmd string, rest []string) (string, []string) {
	cmd = progName(cmd)
	switch cmd {
	case "pnpm":
		if w := pmFirstPositional(cmd, rest); w >= 0 && rest[w] == "with" && w+1 < len(rest) {
			rest = slices.Concat(rest[:w], rest[w+2:])
		}
	case "uv":
		rest = uvGlobalsAfter(rest)
	}
	at, v := -1, ""
	switch {
	case verbManagers[cmd]:
		if at = pmFirstPositional(cmd, rest); at >= 0 {
			v = pmVerb(cmd, rest[at])
		}
	case cmd == "uv" && len(rest) >= 2 && rest[0] == "tool" && rest[1] == "uvx":
		at, v = 1, "run"
	}
	if at < 0 || rest[at] == v {
		return cmd, rest
	}
	out := slices.Clone(rest)
	out[at] = v
	return cmd, out
}

// uvGlobalsAfter: uv's words with the global options written before run or tool (uv --directory D run …, the spelling
// MCP configs use for uv servers; uv -q tool run x), and those written between tool and its subcommand (uv tool -q run x,
// uv tool --directory D run x), moved after "run" or "tool <subcommand>", in their order: clap takes global arguments
// at every level and uv reads them there the same (the "uv run" and "uv tool run" tables have each of them), so every
// form reads run and tool run at their usual place (ADR-0159 round 44, P2-1; between tool and its subcommand round 45,
// P2-1). pyOptions["uv"]: uv's global options and whether each takes a value (uv 0.13.7). Any other subcommand, or
// words that end (or reach "--") before one, stay as they are.
func uvGlobalsAfter(rest []string) []string {
	globals := func(g int) int { // the index of the first word from g on that is no global option or an option's value
		for g < len(rest) && strings.HasPrefix(rest[g], "-") && rest[g] != "--" {
			if !strings.Contains(rest[g], "=") && pyOptions["uv"][rest[g]] {
				g++ // the option's value
			}
			g++
		}
		return g
	}
	g := globals(0)
	switch {
	case g >= len(rest):
	case rest[g] == "run":
		return slices.Concat(rest[g:g+1], rest[:g], rest[g+1:])
	case rest[g] == "tool":
		if h := globals(g + 1); h < len(rest) && rest[h] != "--" {
			return slices.Concat(rest[g:g+1], rest[h:h+1], rest[:g], rest[g+1:h], rest[h+1:])
		}
	}
	return rest
}
