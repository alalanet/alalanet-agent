package installread

import (
	"regexp"
	"strings"
)

// READER-VAR-OPT-1 (ADR-0159 round 9): the words where a package manager reads its options or its subcommand, and
// the registry, index and config options in the spellings the tools accept. With P=--registry=URL, `npm $P i x`
// installs x from URL while install_check judges it on the public registry; the same $P after the target was a reason
// already (spec), before the subcommand it was a plain install.

// whyVarArgument: a word of an install the line does not show (spec; unseenLead; an option's name).
const whyVarArgument = "an install argument comes from a variable or an escape alalanet cannot see"

// unseenWord: a word the shell builds from what the line does not show — a parameter expansion ($P, "$P", ${P:+…}) —
// or one with a backslash the shell drops outside quotes (--re\gistry is --registry to bash). A line with a command
// substitution is the second reader's (substInstall, HookExtra).
func unseenWord(x string) bool {
	return strings.ContainsAny(x, `$\`)
}

// unseenOption: an option word whose name the line does not show: a long option's before "=" (--$P, --re\gistry=URL),
// a short option's letter (-$P). Its value may be a variable or a Windows path (--loglevel=$L, -tC:\libs): what the
// value is, is the option's own reading.
func unseenOption(x string) bool {
	if name, ok := strings.CutPrefix(x, "--"); ok {
		name, _, _ = strings.Cut(name, "=")
		return unseenWord(name)
	}
	return len(x) > 1 && x[0] == '-' && unseenWord(x[1:2])
}

// leadVerbs: per program, the subcommands the reader reads an install, a runner or an initializer from (commandTargets
// and command's init branch); leadGroups: the words that only group a subcommand (uv pip install, uv tool run).
var leadVerbs = map[string]map[string]bool{
	"npm":  wordSet("i install add exec x init create innit"),
	"pnpm": wordSet("i install add dlx init create innit"),
	"yarn": wordSet("i install add dlx init create innit"),
	"bun":  wordSet("i install add x init create innit"),
	"pip":  wordSet("install"),
	"uv":   wordSet("install add run uvx"),
}

var leadGroups = map[string]map[string]bool{"uv": wordSet("pip tool")}

func wordSet(s string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(s) {
		m[w] = true
	}
	return m
}

// emptyDefaultExp: an expansion that is empty by default — the positional parameters ($@, $*, $1..$9, ${N}, ${@}, ${*};
// not $0, the shell's own name) and ${NAME-}, ${NAME:-}, ${NAME+}, ${NAME:+} with no default word (a bare ${NAME} or
// $NAME is the session's value, not read away) — optionally in double quotes.
var emptyDefaultExp = regexp.MustCompile(`"?\$(?:[@*1-9]|\{[1-9][0-9]*\}|\{[@*]\}|\{[A-Za-z_][A-Za-z0-9_]*:?[-+]\})"?`)

// emptyExpansionRemainder: the word with its empty-by-default expansions removed, when nothing else of it is an
// expansion or escape; "" otherwise. npm $@i -> i, pip $*install -> install.
func emptyExpansionRemainder(x string) string {
	if !strings.Contains(x, "$") {
		return ""
	}
	r := emptyDefaultExp.ReplaceAllString(x, "")
	if r == x || strings.ContainsAny(r, "$`\\") {
		return ""
	}
	return r
}

// stripEmptyExpansions reads every word's empty-by-default expansions away, as the shell does: $@-g -> -g, $@i -> i,
// $@claude -> claude; a word that becomes empty ($@ alone) is dropped (READER-ESCAPE-1 round 2, R4).
func stripEmptyExpansions(w []string) []string {
	changed := false
	for _, x := range w {
		if strings.Contains(x, "$") && emptyDefaultExp.MatchString(x) {
			changed = true
			break
		}
	}
	if !changed {
		return w
	}
	out := make([]string, 0, len(w))
	for _, x := range w {
		if strings.ContainsAny(x, " \t\n") {
			// a word with a blank in it was quoted: the shell does not split it, and a script in it (sh -c '… $1') is the
			// inner shell's to expand when the reader reads that script again
			out = append(out, x)
		} else if lit := emptyExpansionRemainder(x); lit != "" {
			out = append(out, lit)
		} else if r := emptyDefaultExp.ReplaceAllString(x, ""); r == "" && strings.Contains(x, "$") {
			// $@ or "$@" alone: the shell makes no word
		} else {
			out = append(out, x)
		}
	}
	return out
}

// unseenLead reads an npm, pnpm, Yarn, bun, pip or uv command's words up to its subcommand: a word the line does not
// show there — where the tool reads an option, or the subcommand itself — is a reason when a subcommand the reader
// reads follows (npm $P i x, npm "$P" install x, pnpm --$O add x, pip $P install x, uv pip $P install x). A known
// option's value is the option's (npm -w "$WS" i x, pip --cache-dir "$D" install x); a word that is the subcommand
// ends the reading (yarn workspace "$WS" add x: the workspace's name); with no subcommand read after it the line is
// what it was (npm $P x, npm $P run build: the line does not show an install, as $CMD i x does not).
func (p *hookParse) unseenLead(cmd string, rest []string) {
	prog := cmd
	if prog == "pip3" {
		prog = "pip"
	}
	verbs := leadVerbs[prog]
	if verbs == nil {
		return
	}
	takesValue := func(x string) bool {
		switch prog {
		case "pip", "uv": // the options pip and uv read before the subcommand (pyOptions: their main parsers)
			return pyOptions[prog][x]
		}
		return pmTakesValue(cmd, x)
	}
	hidden := ""
	for i := 0; i < len(rest); i++ {
		x := rest[i]
		switch {
		case unseenWord(x) && (!strings.HasPrefix(x, "-") || unseenOption(x)):
			hidden = x
			if lit := emptyExpansionRemainder(x); lit != "" && verbs[pmVerb(prog, lit)] {
				// npm $@i x, npm ${9}i x, pip $*install requests: the empty-by-default expansion vanishes and the
				// word's remainder IS the subcommand, so the line installs (READER-ESCAPE-1 round 2, R4)
				p.miss(whyVarArgument + " (" + clip(x, 60) + ")")
				return
			}
		case strings.HasPrefix(x, "-") && len(x) > 1:
			if takesValue(x) { // --prefix=x is no value-taking option (pmTakesValue)
				i++
			}
		case leadGroups[prog][x]:
		case verbs[pmVerb(prog, x)]: // npm $P isntall x, bun $P a x: the alias is the subcommand (READER-NPM-ALIAS-1)
			if hidden != "" {
				p.miss(whyVarArgument + " (" + clip(hidden, 60) + ")")
			}
			return
		case hidden == "":
			return // the subcommand, one the reader does not read
		}
	}
}

// abbrevOf: whether option name x is full or an abbreviation of it the tool takes, from shortest on (npm's nopt and
// pip's optparse expand a long option's unambiguous prefix; pipx's argparse too).
func abbrevOf(x, full, shortest string) bool {
	return len(x) >= len(shortest) && strings.HasPrefix(full, x)
}

// npmConfigFileOption: --userconfig or --globalconfig, in any case and any abbreviation npm takes (--userc,
// --globalc: npm 10.8.2, whose config keys user-agent and global/global-style share the shorter prefixes).
func npmConfigFileOption(x string) bool {
	name, _, _ := strings.Cut(strings.ToLower(npmTwoDash(x)), "=")
	return abbrevOf(name, "--userconfig", "--userc") || abbrevOf(name, "--globalconfig", "--globalc")
}

// pipxSwitches: pipx's short options that take no value where valueFlags (pip's) take one: -f is --force, -e
// --editable (pipx 1.17's parser, read 2026-11-15). pipx install -f x was held as an index named x.
var pipxSwitches = map[string]bool{"-f": true, "-e": true}

// pyShortValue: the letters of the short options that take a value, in the form the line is (pyForm): pip's -C
// (--config-settings: -Cbuild-dir=build, which meson-python and scikit-build-core document) and uv's -C -P -b take one,
// uv tool install's -e is a switch where uv pip install's takes a path, uv run's -m is the module switch where uv
// add's is --marker. pyShortRegistry stops a cluster at the first of them, so a value attached to it is not read as an
// index letter, and reads on past a switch (uv run -mf DIR: --module, then find-links). Outside a form the tables have,
// valueFlags' letters.
func pyShortValue(cmd string, rest []string) map[string]bool {
	t := pyTable(cmd, rest)
	m := map[string]bool{}
	for k, v := range t {
		if v && len(k) == 2 && k[0] == '-' {
			m[k[1:]] = true
		}
	}
	if t == nil {
		for k := range valueFlags {
			if len(k) == 2 {
				m[k[1:]] = true
			}
		}
	}
	return m
}

// pyShortRegistry: a cluster of short options that ends in an index option — one of indexShort's letters (pyIndexOptions:
// -i and -f for pip and uv, -i for pipx, whose -f is --force) — with its value attached (-ihttps://…, -qihttps://…) or in
// the next word (-Ui URL: next is true). valueShort are the letters that take a value: the scan stops at the first of
// those (its value is the rest of the cluster, so an index letter in it is part of a value). ok is false for a cluster
// with no index option (-qU) or one whose value-taking option comes first (-rrequirements.txt: the rest is -r's file).
func pyShortRegistry(x string, valueShort, indexShort map[string]bool) (val string, next, ok bool) {
	for k := 1; k < len(x); k++ { // x: "-" then short option letters (pkgs)
		switch f := x[k : k+1]; {
		case indexShort[f]:
			v := x[k+1:]
			return v, v == "", true
		case valueShort[f]:
			return "", false, false
		}
	}
	return "", false, false
}

// pipxPipArgs: the values of pipx's --pip-args in each spelling argparse takes (--pip-args=V, --pip-args V, and the
// abbreviations from --pi on: --pi is --pip-args alone in install and run).
func pipxPipArgs(rest []string) []string {
	var out []string
	for j := 0; j < len(rest); j++ {
		name, v, eq := strings.Cut(rest[j], "=")
		if !abbrevOf(name, "--pip-args", "--pi") {
			continue
		}
		if !eq {
			if j+1 >= len(rest) {
				continue
			}
			j++
			v = rest[j]
		}
		out = append(out, v)
	}
	return out
}

// pipArgs reads one value of pipx's --pip-args as the words pipx gives pip install: its registry and index options, a
// variable or a URL package are the reasons pip install's own would be. A bare word in it is not read as a package
// (--no-binary :all: takes one as its value): only the reasons are kept.
func (p *hookParse) pipArgs(v string) {
	// pipx on Windows splits with posix=False (get_pip_args: posix=not WINDOWS): a backslash is literal there and a quote
	// inside a word is an ordinary character, so --cache-dir=C:\pc\ -i C:\idx and --src=x"y -i C:/idx --src=z" give pip
	// -i whole while the POSIX split joins it into one word. Every value is read both ways and the reasons of both kept
	// (Q5, S3).
	p.commandTargets("pip", append([]string{"install"}, shlexWords(v)...))
	p.commandTargets("pip", append([]string{"install"}, shlexWordsWin(v)...))
}

// shlexWordsWin splits a value as pipx on Windows does: the single quotes at either end stripped, then Python's
// shlex.split with posix=False (shlex.read_token, Python 3.15). Blanks separate words; a backslash is an ordinary
// character; a quote that begins a word opens a quoted word that keeps its quotes and ends at the closing quote (the
// next character starts a new word); a quote inside a word is an ordinary character. A quote left open fails pipx;
// here the word runs to the end.
func shlexWordsWin(v string) []string {
	v = strings.Trim(v, "'")
	var out []string
	var cur strings.Builder
	state := byte(' ') // ' ' between words, 'a' in a word, or the open quote
	for i := 0; i < len(v); i++ {
		c := v[i]
		blank := c == ' ' || c == '\t' || c == '\r' || c == '\n'
		switch state {
		case ' ':
			switch {
			case blank:
			case c == '\'' || c == '"':
				cur.WriteByte(c)
				state = c
			default:
				cur.WriteByte(c)
				state = 'a'
			}
		case 'a':
			if blank {
				out = append(out, cur.String())
				cur.Reset()
				state = ' '
			} else {
				cur.WriteByte(c)
			}
		default:
			cur.WriteByte(c)
			if c == state {
				out = append(out, cur.String())
				cur.Reset()
				state = ' '
			}
		}
	}
	if state != ' ' {
		out = append(out, cur.String())
	}
	return out
}

// shlexWords splits a value as pipx 1.17 splits --pip-args (get_pip_args): the single quotes at either end stripped,
// then Python's shlex.split in POSIX mode. Blanks separate words; '…' is literal; in "…" a backslash escapes only "
// and \; outside quotes it escapes any character. There are no comments, and ; | & ( ) < > are ordinary characters
// (--proxy=a;b -i URL is two options to pip). A quote left open fails pipx before anything installs; here the word
// runs to the end.
func shlexWords(v string) []string { return shlexSplit(strings.Trim(v, "'")) }

// shlexSplit is Python's shlex.split in POSIX mode, the reading shlexWords describes, of v as it is (pip reads a
// requirements file's option line with it: req_file.parse_line).
func shlexSplit(v string) []string {
	var out []string
	var cur strings.Builder
	in := false
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			if in {
				out = append(out, cur.String())
				cur.Reset()
				in = false
			}
		case c == '\'':
			in = true
			for i++; i < len(v) && v[i] != '\''; i++ {
				cur.WriteByte(v[i])
			}
		case c == '"':
			in = true
			for i++; i < len(v) && v[i] != '"'; i++ {
				if v[i] == '\\' && i+1 < len(v) && (v[i+1] == '"' || v[i+1] == '\\') {
					i++
				}
				cur.WriteByte(v[i])
			}
		case c == '\\' && i+1 < len(v):
			in = true
			i++
			cur.WriteByte(v[i])
		default:
			in = true
			cur.WriteByte(c)
		}
	}
	if in {
		out = append(out, cur.String())
	}
	return out
}

// pyTool: pip, pip3, pipx, uv and uvx, whose short options cluster as getopt's do.
func pyTool(cmd string) bool {
	return cmd == "pip" || cmd == "pip3" || cmd == "pipx" || cmd == "uv" || cmd == "uvx"
}

// unseenCommandWord flags a word the line does not show that a launcher reads as its own option, after the
// subcommand and before the command it runs (READER-VAR-OPT-1 R4). With P=--registry=…, npm exec PKG $P, npx -p PKG
// $P cmd, uvx --from PKG $P cmd and pipx run --spec PKG $P cmd move the registry while the package is judged on the
// public one; the same $P in a package position is a reason already (spec). nopt (npm exec, create, init) reads
// options anywhere before "--", so any bare hidden word before "--" is a reason; the others (npx, uv, pipx) read
// options up to the command, so a hidden word is a reason when something the tool can take for its command follows
// it (commandAfter). A hidden word that is a known option's value is that value, read elsewhere. cmdOpt names the
// options whose word or value is the command (npx -c CMD, uv run -m MOD).
func (p *hookParse) unseenCommandWord(rest []string, start int, nopt bool, takesValue, cmdOpt func(string) bool) {
	for j := start; j < len(rest); j++ {
		x := rest[j]
		switch {
		case x == "--":
			return
		case cmdOpt != nil && cmdOpt(x):
			return // the command follows: words from here are its own
		case strings.HasPrefix(x, "-") && len(x) > 1:
			if takesValue(x) { // an --opt=value word takes none
				j++
			}
		case unseenWord(x):
			// a hidden word that is itself the command (uv run --with pkg "$script") is handed on, not an option
			if nopt || commandAfter(rest, j+1, takesValue, cmdOpt) {
				p.miss(whyVarArgument + " (" + clip(x, 60) + ")")
			}
			return
		case !nopt:
			return // the command: words from here are its own
		}
	}
}

// commandAfter reports whether, at or after j, past options and their values, stands something a stop-at-command
// launcher can take for its command: a bare word the line shows; a second word it does not show (Q2: of "$P" "$C"
// the first can be an option and the second the command); an option that carries the command or is followed by it
// (cmdOpt: npx -c CMD, --call=CMD, uv run -m MOD, Q3); or a word after "--".
func commandAfter(rest []string, j int, takesValue, cmdOpt func(string) bool) bool {
	for ; j < len(rest); j++ {
		x := rest[j]
		switch {
		case x == "--":
			return j+1 < len(rest)
		case cmdOpt != nil && cmdOpt(x):
			return strings.Contains(x, "=") || j+1 < len(rest)
		case strings.HasPrefix(x, "-") && len(x) > 1:
			if takesValue(x) { // an --opt=value word takes none
				j++
			}
		default: // a shown word, or a second hidden one
			return true
		}
	}
	return false
}

// npmCommandOption: npm exec's and npx's -c/--call (and nopt's spellings of it: --cal, -call, --call=CMD), whose value
// is the command run (npx-cli.js lists call/c among the options with a value and inserts no "--" before it).
func npmCommandOption(x string) bool {
	name, _, _ := strings.Cut(npmTwoDash(x), "=")
	return x == "-c" || abbrevOf(name, "--call", "--cal")
}

// uvRunCommandOption: uv run's -m/--module, a switch after which the module named is the command run.
func uvRunCommandOption(x string) bool { return x == "-m" || x == "--module" }

// npmRunnerTakesValue: whether an npm-family runner or installer option (pm: npm, pnpm, Yarn, bun) leaves its value
// to the next word, with npx/pnpx/bunx's -p/--package (the package before the bin) added.
func npmRunnerTakesValue(pm string) func(string) bool {
	return func(x string) bool { return pmTakesValue(pm, x) || x == "-p" || x == "--package" }
}

// pyForm: the key of pyOptions for a pip, pipx, uv or uvx command — the tool and the subcommand its words name
// ("pip install", "pipx run", "uv tool install", uvx: "uv tool run") — or "" when the tables have no such form.
func pyForm(cmd string, rest []string) string {
	tool, main := cmd, cmd
	switch cmd {
	case "pip3":
		tool, main = "pip", "pip"
	case "uvx":
		return "uv tool run"
	case "pipx":
		main = "" // pipx's main parser takes -h and --version only
	}
	key := tool
	for i, n := 0, 0; i < len(rest) && n < 2; i++ {
		x := rest[i]
		if strings.HasPrefix(x, "-") {
			if !strings.Contains(x, "=") && pyOptions[main][x] {
				i++
			}
			continue
		}
		key += " " + x // uv tool install, uv pip install: the forms with two words
		n++
		if _, ok := pyOptions[key]; ok {
			return key
		}
	}
	return ""
}

// pyTable: the generated options of a command's form (pyOptions), nil outside the forms the tables have.
func pyTable(cmd string, rest []string) map[string]bool {
	if f := pyForm(cmd, rest); f != "" {
		return pyOptions[f]
	}
	return nil
}

// pyTakesValue: whether option word x of a pip, pipx or uv command leaves its value to the next word, from the
// generated tables of its form. pip's optparse and pipx's argparse take a long option by any unambiguous prefix
// (pip install --upgrade-st eager), uv's clap by its full name only. Outside the forms the tables have, valueFlags.
func pyTakesValue(t map[string]bool, cmd, x string) bool {
	if t == nil {
		return valueFlags[x]
	}
	if v, ok := t[x]; ok { // a --opt=value word matches no option name, full or abbreviated: it takes no next word
		return v
	}
	return t[pyAbbrev(t, cmd, x)]
}

// pyAbbrev: the option of the form that a pip or pipx long-option word abbreviates — the one option it is a prefix
// of — or "" (no such option, an ambiguous prefix the parser refuses, or uv, whose clap takes full names only).
func pyAbbrev(t map[string]bool, cmd, x string) string {
	if !strings.HasPrefix(x, "--") || len(x) < 3 || cmd == "uv" || cmd == "uvx" {
		return ""
	}
	match, n := "", 0
	for k := range t {
		if strings.HasPrefix(k, x) {
			match, n = k, n+1
		}
	}
	if n == 1 {
		return match
	}
	return ""
}

// pyIndexOption: whether option name x says where a pip, pipx or uv command's packages come from, in its form: an
// option whose parser destination is an index or a find-links location (pyIndexOptions: pip's -i, --index-url and
// its hidden alias --pypi-url, --extra-index-url, -f, --find-links; pipx's -i, --index-url; uv's index options and
// their aliases), by its full name or an abbreviation the parser takes (pip install --pyp URL). Outside the forms
// the tables have, registryFlags. READER-VAR-OPT-1 round 4 (S1).
func pyIndexOption(cmd string, t, idx map[string]bool, x string) bool {
	switch {
	case t == nil:
		return registryFlags[x] && !(cmd == "pipx" && pipxSwitches[x])
	case idx[x]:
		return true
	}
	return idx[pyAbbrev(t, cmd, x)] // an exact option name abbreviates itself, or is ambiguous
}

// pyIndexShort: the letters of a form's short index options (pyIndexOptions); outside the tables -i and -f, and for
// pipx -i only.
func pyIndexShort(cmd string, idx map[string]bool) map[string]bool {
	m := map[string]bool{}
	for k := range idx {
		if len(k) == 2 && k[0] == '-' {
			m[k[1:]] = true
		}
	}
	if idx == nil {
		m["i"] = true
		if cmd != "pipx" {
			m["f"] = true
		}
	}
	return m
}

// registryFlags: outside the forms the tables have, every option that names an index in any of them (the union of
// pyIndexOptions), so no hand list can miss an alias.
var registryFlags = func() map[string]bool {
	m := map[string]bool{}
	for _, idx := range pyIndexOptions {
		for k := range idx {
			m[k] = true
		}
	}
	return m
}()
