package installread

import (
	"path"
	"regexp"
	"strings"
)

// ADR-0159 round 29 (P2-W): the line's own shell, by allowlist. Rounds 26 to 28 closed the ways a line assigns a
// variable in its own shell form by form (8, then 30, then 23 more); a list of forms does not converge. A line that
// installs is judged only when every part its own shell runs — each POSIX script the walk reads as one (the line, sh
// -c, eval, trap, a substitution's body) — is a construct the readers fully read; any other construct holds the line
// with one reason (whyOwnShell, code line_shell_not_read). The allowlist:
//   - separators ; & && || | and newlines, subshells ( … ), groups { …; }, if/then/elif/else/fi, while/until/do/done,
//     ! and time;
//   - assignment words NAME=value, NAME+=value and NAME=( … ) with a literal name (an index only of digits), judged by
//     their value as before;
//   - export, declare, typeset, local and readonly with names that are literal or plain $NAME expansions (the second
//     reader judges those by their literal tail) and only the options that neither type nor tie a name (-x -r -g -p
//     -f -F; -i with values that are numbers);
//   - cd, pushd, popd, pwd, echo, true, false, :, type, which, whence, where, dirs, jobs, times, help, kill, umask,
//     ulimit, hash (no option but -r), unset (literal names), set (-e -u -x -v -a -E, -o with a known name, positional
//     words), shift/exit/return/break/continue with a number, wait with no option but -n/-f, printf without options
//     (with a numeric conversion only numbers or plain names), test/[ and [[ … ]] (an -eq operand only a number or a
//     plain name), read with -r -s -e -p -t -n -N -d -u -i and names that are no lever;
//   - eval, trap, source and . (the walk reads what eval and trap run as a script of its own; a sourced file is read
//     by the rules of rounds 20 to 22);
//   - command, builtin, exec, noglob, nocorrect and - before a command, which is judged as the command;
//   - for NAME [in WORDS], the words as the name's values;
//   - arithmetic $(( … )), (( … )) without an assignment: numbers, names, plain $NAME and the operators that read;
//   - a program named by a plain $NAME the line gives no value that may name a builtin, or by the output of a
//     substitution that runs only package managers (whose output is the package's, not the line's);
//   - any other program, whose words the shell only expands: $NAME, ${NAME}, ${NAME[@]}, ${NAME:-word} (and -, :+,
//     +, :?, ?), ${NAME:OFFSET:LENGTH} of numbers or names, ${!NAME} (when the line gives NAME only names), $( … ),
//     backticks, <( … ), quotes; zsh's (…) patterns, unless an attached (…) is a list of qualifiers that runs code;
//   - redirections and here-documents (an unquoted one's body expands as a double-quoted word);
//   - a line that starts with | & ; or ) is rejected by bash and zsh before it runs and is not judged (README prose).
//
// Everything else holds: $[ ], arithmetic that assigns, ${…} with any other operator or flag, an index that is not
// @, * or a number, zsh's $~ $= $^ $+, let, getopts, mapfile, printf -v, print, vared, zparseopts, wait -p, set -A,
// alias, case, select, coproc, function definitions, {NAME}> redirections, a name built from anything but plain
// expansions, a command named by any other expansion, and every other builtin of bash or zsh.

// whyOwnShell: the reason for a construct of the line's own shell that is not on the allowlist.
const whyOwnShell = "runs in the line's own shell what alalanet does not read"

// shellFacts: what the allowlist reader found in the scripts of one line — the first construct it does not read, and
// for its last judgement the names arithmetic, ${!NAME} and a $NAME program read, and the kinds of the values the
// line gives names.
type shellFacts struct {
	why               string
	vals              map[string]uint8
	arith, ind, progs nameList
	paths             nameList // names a program word joins with other text: their values must be paths
	// setsIFS: the line sets IFS; bareRun: an unquoted expansion is a command's name or a word eval or trap runs —
	// which IFS splits into words alalanet does not see (round 31)
	setsIFS, bareRun bool
	// sets: the line has set a variable by now — a setup pair's output follows the tool's root variable (round 32);
	// cvars: the names a -c script word expands, which the line may not set
	sets  bool
	cvars nameList
}

// nameList: names in the order the line first gives them, each once. final holds for the first name a check fails
// on, so the reason names the variable a reader of the line meets first — the same one on every run, where a map's
// order named either (READER-REASON-ORDER-1, ADR-0159 round 48).
type nameList struct {
	order []string
	has   map[string]bool
}

func (l *nameList) add(n string) {
	if l.has[n] {
		return
	}
	if l.has == nil {
		l.has = map[string]bool{}
	}
	l.has[n] = true
	l.order = append(l.order, n)
}

const (
	valNotInt  uint8 = 1 // a value that is not a number: arithmetic that reads the name evaluates it
	valNotName uint8 = 2 // a value that is not a name: ${!NAME} that reads it may evaluate an index
	valUnknown       = valNotInt | valNotName
)

func (f *shellFacts) hold(why string) {
	if f.why == "" {
		f.why = why
	}
}

// lineGroup: the line has a group on a word (a ( right after a character that is no blank, operator or $) that is not
// a plain address (urlGroup). zsh may run a glob qualifier's text as code (ls *(e#npm i x#)), so the own shell's hold
// stands for such a line though it names no install of its own. Which text may install is not judged: the delimiter of
// e may be any character, a letter too (*(eznpm i xz) ran npm), and a glob, a brace or an alias the line defines hides
// a name (round 38).
func lineGroup(line string) bool {
	for i := 1; i < len(line); i++ {
		if line[i] != '(' || strings.IndexByte(" \t\r\n;&|<>()$", line[i-1]) >= 0 {
			continue
		}
		d, j := 0, i
		for ; j < len(line); j++ {
			if line[j] == '(' {
				d++
			} else if line[j] == ')' {
				if d--; d == 0 {
					break
				}
			}
		}
		if !urlGroup.MatchString(line[i+1 : min(j, len(line))]) {
			return true
		}
	}
	return false
}

func (f *shellFacts) val(n string, kind uint8) {
	if f.vals == nil {
		f.vals = map[string]uint8{}
	}
	f.vals[n] |= kind
	if rootLever(n) || n == "IFS" {
		f.sets = true // a value the line does not show (read, arithmetic …)
	}
}

// setVal records a value the line gives a name (IFS: the line sets it).
func (f *shellFacts) setVal(n, v string, expanded bool) {
	if f.vals == nil {
		f.vals = map[string]uint8{}
	}
	f.vals[n] |= valueKind(v, expanded)
	switch {
	case n == "IFS":
		f.setsIFS, f.sets = true, true
	case rootLever(n) && !homeRelative(v) && !systemRoot(v):
		f.sets = true
	}
}

// rootLever: a variable a setup pair's output follows — the tools' roots (pyenv init - prints
// "<PYENV_ROOT>/shims"), conda's, direnv's and the XDG folders (round 33, P3-AF).
func rootLever(n string) bool {
	return rootLevers[n] || strings.HasPrefix(n, "CONDA_") || strings.HasPrefix(n, "DIRENV_") || strings.HasPrefix(n, "XDG_")
}

var rootLevers = wordSet("PYENV_ROOT RBENV_ROOT NODENV_ROOT GOENV_ROOT FNM_DIR")

// homeRelative: a value in the user's home, as the tools' own READMEs set their roots (PYENV_ROOT="$HOME/.pyenv").
func homeRelative(v string) bool {
	for _, h := range []string{"$HOME", "${HOME}", "~"} {
		if (v == h || strings.HasPrefix(v, h+"/")) && !strings.Contains(v, "..") && !strings.ContainsAny(v[len(h):], "$`") {
			return true
		}
	}
	return false
}

// systemRoot: an absolute folder outside the temporary ones and without .. (export PYENV_ROOT=/opt/pyenv, round 34).
func systemRoot(v string) bool {
	return strings.HasPrefix(v, "/") && !strings.Contains(v, "..") && !strings.ContainsAny(v, "$`") && !tmpDir(v)
}

// progNames: the names a command may be named by (a $NAME of the user's environment the line does not set, round
// 33): the shell sets others itself ($_, REPLY, MAPFILE, OPTARG, BASH_REMATCH, zsh's MATCH).
var progNames = wordSet("HOME VIRTUAL_ENV CONDA_PREFIX PYTHON PIP NODE NPM PNPM YARN UV CARGO_HOME GOPATH GOBIN JAVA_HOME " +
	"VENV_PATH " + // widened from the corpora: VENV_PATH ($VENV_PATH/bin/pip install, README)
	"PNPM_HOME BUN_INSTALL PYENV_ROOT NVM_BIN NVM_DIR VOLTA_HOME POETRY_HOME DENO_INSTALL PIPX_BIN_DIR") // round 34: the tools' installers export them

func (f *shellFacts) arithRef(n string) { f.arith.add(n) }

// final: arithmetic that reads a name the line sets to what is not a number, ${!NAME} of a name the line sets to what
// is not a name, and $NAME as a program that the line sets to what may be a builtin run that value as code.
func (f *shellFacts) final() {
	if f.why != "" {
		return
	}
	for _, n := range f.arith.order {
		if f.vals[n]&valNotInt != 0 {
			f.hold("arithmetic reads " + clip(n, 40) + ", which the line sets to what is not a number")
			return
		}
	}
	for _, n := range f.ind.order {
		if f.vals[n]&valNotName != 0 {
			f.hold("${!" + clip(n, 40) + "} reads a name the line sets to what is not a name")
			return
		}
	}
	for _, n := range f.progs.order { // the command's name must be literal: a $NAME only of the user's environment (rounds 32, 33)
		if _, set := f.vals[n]; set || !progNames[n] {
			f.hold("a command named by $" + clip(n, 40) + ", which the line or the shell may set")
			return
		}
	}
	for _, n := range f.cvars.order {
		if _, set := f.vals[n]; set {
			f.hold("a -c script that expands $" + clip(n, 40) + ", which the line sets")
			return
		}
	}
	if f.setsIFS && f.bareRun {
		f.hold("sets IFS and runs an unquoted expansion as a command, which IFS splits")
		return
	}
	for _, n := range f.paths.order {
		if _, set := f.vals[n]; set || !progNames[n] {
			f.hold("a command named by $" + clip(n, 40) + " and more, which the line sets to what is not one path")
			return
		}
	}
}

// scan reads one script of the line.
func (f *shellFacts) scan(s string) {
	if f.why != "" {
		return
	}
	sc := &ownScan{s: s, f: f}
	sc.list(0)
	if f.why == "" && len(sc.docs) > 0 {
		sc.readDocs() // a here-document whose line is the script's last
	}
}

// ownScan reads a script as the shell does, as far as the allowlist needs.
type ownScan struct {
	s     string
	i     int
	f     *shellFacts
	depth int
	docs  []hereDoc // here-documents whose bodies start after the next newline
	// inCase: the case … esac the reader is inside; casePat: the next words are a case arm's patterns (round 30)
	inCase  int
	casePat bool
}

type hereDoc struct {
	delim        string
	quoted, tabs bool
}

// rawWord: a word as written (raw) and with its quotes removed (text; an expansion stays as written).
type rawWord struct {
	raw, text        string
	quoted, expanded bool   // a quote or backslash in it; an expansion outside single quotes
	array            bool   // NAME=( … )
	bare             bool   // an expansion outside quotes, which the shell splits into words
	pattern, brace   bool   // an unquoted * ? [ or a zsh group; an unquoted {a,b} or {1..3} (round 32)
	litb             []byte // the word's literal characters, quoted or not, outside every expansion (round 34)
	groupSlash       bool   // a / in a zsh pattern group, which zsh refuses
	subs             int    // the command substitutions in it
	sub              string
}

// word modes: a command's word, a word of [[ … ]] (only a blank ends it), a word that starts with zsh's ( pattern.
const (
	wordCmd = iota
	wordCond
	wordGlob
)

const maxOwnDepth = 16

func ownName(s string) bool {
	if s == "" || !(s[0] == '_' || s[0] >= 'A' && s[0] <= 'Z' || s[0] >= 'a' && s[0] <= 'z') {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !nameChar(s[i]) {
			return false
		}
	}
	return true
}

func nameChar(c byte) bool {
	return c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

var intLit = regexp.MustCompile(`^[+-]?[0-9]+$`)

// leverName: a name a variable lever answers to (riskyName in either case, npm's npm_config_ names; zsh's path is
// PATH in upper case).
func leverName(n string) bool {
	return ownName(n) && (riskyName(n) || riskyName(strings.ToUpper(n)) || strings.HasPrefix(strings.ToLower(n), "npm_config_"))
}

// noSet: the names the builtins that set a value alalanet does not see (arithmetic, read, printf -v, mapfile,
// getopts) may not set: the levers, the names the shell reads again, and IFS, which splits the words of an unquoted
// expansion (round 31).
func noSet(n string) bool { return leverName(n) || ownReread[n] || n == "IFS" }

// ownReread: names whose value the shell itself reads again as code; path is zsh's PATH, which no reader judges.
var ownReread = wordSet("PS0 PS1 PS2 PS3 PS4 PROMPT_COMMAND PROMPT PROMPT2 PROMPT3 PROMPT4 RPROMPT RPROMPT2 RPS1 RPS2 path")

// list reads commands up to stop (')' for a substitution's body) or the end.
func (sc *ownScan) list(stop byte) {
	paren := 0
	lineStart := true
	for sc.i < len(sc.s) && sc.f.why == "" {
		c := sc.s[sc.i]
		if lineStart && paren == 0 && stop == 0 && strings.IndexByte("|&;)", c) >= 0 {
			// | … , && …, ; …, ) …: bash and zsh refuse the line before they run any of it (prose, a table row)
			for sc.i < len(sc.s) && sc.s[sc.i] != '\n' {
				sc.i++
			}
			continue
		}
		if lineStart && paren == 0 && stop == 0 && c != ' ' && c != '\t' && sc.mdBullet() {
			continue
		}
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			sc.i++
			continue
		case c == '\n':
			sc.i++
			sc.readDocs()
			lineStart = true
			continue
		case c == '#':
			for sc.i < len(sc.s) && sc.s[sc.i] != '\n' {
				sc.i++
			}
			continue
		case c == '\\' && sc.i+1 < len(sc.s) && sc.s[sc.i+1] == '\n':
			sc.i += 2
			continue
		}
		lineStart = false
		switch {
		case c == ';' && sc.inCase > 0 && sc.i+1 < len(sc.s) && (sc.s[sc.i+1] == ';' || sc.s[sc.i+1] == '&'):
			sc.i += 2 // ;; ;& ;;&: the next words are an arm's patterns
			if sc.i < len(sc.s) && sc.s[sc.i] == '&' {
				sc.i++
			}
			sc.casePat = true
		case c == ';' || c == '&' || c == '|':
			sc.i++
		case c == '(' && strings.HasPrefix(sc.s[sc.i:], "(("):
			sc.i += 2
			sc.arith()
		case c == '(':
			paren++
			sc.i++
		case c == ')':
			sc.i++
			if paren > 0 {
				paren--
			} else if stop == ')' {
				return
			}
		default:
			sc.command()
		}
	}
}

// arith reads (( … )) or $(( … )) from just inside it.
func (sc *ownScan) arith() {
	start, d := sc.i, 0
	for ; sc.i < len(sc.s); sc.i++ {
		switch sc.s[sc.i] {
		case '(':
			d++
		case ')':
			if d > 0 {
				d--
				continue
			}
			if sc.i+1 < len(sc.s) && sc.s[sc.i+1] == ')' {
				body := sc.s[start:sc.i]
				sc.i += 2
				sc.f.arithBody(body)
				return
			}
			sc.i = len(sc.s) // ")" alone: bash and zsh refuse it
			return
		}
	}
	// arithmetic that does not close: bash and zsh refuse it
}

// arithBody: arithmetic that reads numbers, names, plain $NAME, ${NAME}, $1, $#, $? with any operator, and assigns
// (=, +=, …, ++, --) only to a literal name that is no lever (round 30): its value is then a number. A name it reads
// is recorded: its value is evaluated as arithmetic in turn.
func (f *shellFacts) arithBody(b string) {
	type tok struct {
		kind byte // 'n' a number, 'i' a name, '$' a plain expansion, 'o' an operator
		s    string
	}
	var ts []tok
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
		case c >= '0' && c <= '9':
			j := i
			for j < len(b) && nameChar(b[j]) {
				j++
			}
			ts = append(ts, tok{'n', b[i:j]})
			i = j - 1
		case nameChar(c):
			j := i
			for j < len(b) && nameChar(b[j]) {
				j++
			}
			ts = append(ts, tok{'i', b[i:j]})
			i = j - 1
		case c == '$':
			n, j := plainDollar(b, i)
			if j < 0 {
				f.hold("arithmetic with an expansion alalanet does not read (" + clip(b, 40) + ")")
				return
			}
			ts = append(ts, tok{'$', n})
			i = j - 1
		case strings.IndexByte(arithOpChars, c) >= 0:
			o := string(c)
			for _, op := range arithOps {
				if strings.HasPrefix(b[i:], op) {
					o = op
					break
				}
			}
			ts = append(ts, tok{'o', o})
			i += len(o) - 1
		default:
			f.hold("arithmetic alalanet does not read (" + clip(b, 40) + ")")
			return
		}
	}
	for k, t := range ts {
		switch {
		case t.kind == 'i' || t.kind == '$' && t.s != "":
			f.arithRef(t.s)
		case t.kind == 'o' && arithAssignOps[t.s]:
			if k == 0 || ts[k-1].kind != 'i' {
				f.hold("arithmetic that assigns to what is not a name (" + clip(b, 40) + ")")
				return
			}
			f.arithSet(ts[k-1].s)
		case t.kind == 'o' && (t.s == "++" || t.s == "--"):
			switch {
			case k > 0 && ts[k-1].kind == 'i':
				f.arithSet(ts[k-1].s)
			case k+1 < len(ts) && ts[k+1].kind == 'i':
				f.arithSet(ts[k+1].s)
			default:
				f.hold("arithmetic that assigns to what is not a name (" + clip(b, 40) + ")")
				return
			}
		}
	}
}

const arithOpChars = "*/%<>!&|^~?:(),=+-"

// arithOps: the operators of more than one character, longest first.
var arithOps = []string{"<<=", ">>=", "**=", "++", "--", "==", "!=", "<=", ">=", "&&", "||", "<<", ">>", "**", "+=", "-=",
	"*=", "/=", "%=", "&=", "^=", "|="}

var arithAssignOps = wordSet("= += -= *= /= %= <<= >>= &= ^= |= **=")

// arithSet: arithmetic assigns n, which is then a number — unless n is a lever or a name the shell reads again.
func (f *shellFacts) arithSet(n string) {
	if noSet(n) {
		f.hold("arithmetic assigns " + clip(n, 40))
		return
	}
	f.val(n, valNotName)
}

// plainDollar: at s[i] == '$', a plain expansion — $NAME or ${NAME} (the name), $1, $#, $?, $$, $! ("") — and the
// index past it; -1 for any other.
func plainDollar(s string, i int) (string, int) {
	j := i + 1
	if s[i] != '$' || j >= len(s) {
		return "", -1
	}
	brace := s[j] == '{'
	if brace {
		j++
	}
	k := j
	switch {
	case k < len(s) && nameChar(s[k]) && !(s[k] >= '0' && s[k] <= '9'):
		for k < len(s) && nameChar(s[k]) {
			k++
		}
	case k < len(s) && s[k] >= '0' && s[k] <= '9':
		k++
		for brace && k < len(s) && s[k] >= '0' && s[k] <= '9' {
			k++
		}
	case k < len(s) && strings.IndexByte("#?$!@*-", s[k]) >= 0:
		k++
	default:
		return "", -1
	}
	n := s[j:k]
	if brace {
		if k >= len(s) || s[k] != '}' {
			return "", -1
		}
		k++
	}
	if !ownName(n) {
		n = ""
	}
	return n, k
}

// arithOperand: a word arithmetic evaluates whole (printf %d's argument, [[ … -eq … ]]'s operand) that only reads:
// a number, a name, or a plain expansion, double quotes allowed around it.
func (sc *ownScan) arithOperand(w rawWord) bool {
	r := w.raw
	if len(r) >= 2 && r[0] == '"' && r[len(r)-1] == '"' {
		r = r[1 : len(r)-1]
	}
	switch {
	case intLit.MatchString(r):
		return true
	case ownName(r):
		sc.f.arithRef(r)
		return true
	case strings.HasPrefix(r, "$"):
		if n, j := plainDollar(r, 0); j == len(r) {
			if n != "" {
				sc.f.arithRef(n)
			}
			return true
		}
	}
	return false
}

// readDocs reads the bodies of the here-documents the line before opened; an unquoted one's body is expanded.
func (sc *ownScan) readDocs() {
	docs := sc.docs
	sc.docs = nil
	for _, d := range docs {
		start := sc.i
		end := len(sc.s)
		for sc.i < len(sc.s) {
			e := strings.IndexByte(sc.s[sc.i:], '\n')
			line := sc.s[sc.i:]
			next := len(sc.s)
			if e >= 0 {
				line, next = sc.s[sc.i:sc.i+e], sc.i+e+1
			}
			l := strings.TrimSuffix(line, "\r")
			if d.tabs {
				l = strings.TrimLeft(l, "\t")
			}
			if l == d.delim {
				end = sc.i
				sc.i = next
				break
			}
			sc.i = next
		}
		if !d.quoted && sc.f.why == "" {
			ds := &ownScan{s: sc.s[start:end], f: sc.f, depth: sc.depth + 1}
			ds.docText()
		}
	}
}

// docText: an unquoted here-document's body, which expands as a double-quoted word does (quotes are text).
func (sc *ownScan) docText() {
	var w rawWord
	var b strings.Builder
	for sc.i < len(sc.s) && sc.f.why == "" {
		switch c := sc.s[sc.i]; {
		case c == '\\':
			sc.i += 2
		case c == '$':
			sc.dollar(&b, &w, true)
		case c == '`':
			if !sc.backtick(&b, &w) {
				sc.i++
			}
		default:
			sc.i++
		}
	}
}

// mdBullet: a line that starts with a Markdown bullet (* , - , + , 1. ) and has backtick code spans is prose: only
// its spans are read, as scripts (round 30). One whose first word after the bullet is a builtin is read as it is.
func (sc *ownScan) mdBullet() bool {
	end := strings.IndexByte(sc.s[sc.i:], '\n')
	if end < 0 {
		end = len(sc.s) - sc.i
	}
	line := sc.s[sc.i : sc.i+end]
	m := mdBulletRe.FindString(line)
	if m == "" || !strings.Contains(line, "`") {
		return false
	}
	if b := m[0]; b == '*' || b == '-' {
		// zsh runs - WORD as WORD, and * as the folder's first file: the bullet is prose only when the first word,
		// with its quotes removed, is no builtin and no expansion (round 31)
		ws := &ownScan{s: line[len(m):], f: &shellFacts{}}
		for ws.i < len(ws.s) && (ws.s[ws.i] == ' ' || ws.s[ws.i] == '\t') {
			ws.i++
		}
		first := ws.word(wordCmd)
		if first.expanded || mayRun(first.text) {
			return false
		}
	}
	parts := strings.Split(line[len(m):], "`")
	for k := 0; k < len(parts); k += 2 {
		// zsh expands the prose's words too, before it finds no such command (1. see /bin/ls(e#…#) runs the code): a
		// word whose reading holds makes the line a script, read as it is (round 36)
		if proseHolds(parts[k]) {
			return false
		}
	}
	for k := 1; k < len(parts) && sc.f.why == ""; k += 2 { // the spans; an unclosed last one runs to the line's end
		in := &ownScan{s: parts[k], f: sc.f, depth: sc.depth + 1}
		in.list(0)
	}
	sc.i += end
	return true
}

var mdBulletRe = regexp.MustCompile(`^([*+-]|[0-9]+[.)])[ \t]+`)

// proseHolds: whether one of the words of a bullet's prose holds as a word (an attached zsh group). A blank, a
// separator or a parenthesis ends a word before it starts (an empty word): it is passed over.
func proseHolds(p string) bool {
	ws := &ownScan{s: p, f: &shellFacts{}}
	for ws.i < len(ws.s) && ws.f.why == "" {
		if w := ws.word(wordCmd); w.raw == "" {
			ws.i++
		}
	}
	return ws.f.why != ""
}

// mayRun: a word, quotes removed, that names a builtin or a reserved word.
func mayRun(w string) bool {
	return ownBuiltins[w] || ownPrefix[w] || ownHeld[w] || w == "for" || w == "case" || w == "[[" || w == "esac"
}

// pattern reads a case arm's patterns up to its ): words the shell expands, never run.
func (sc *ownScan) pattern() {
	first := true
	for sc.i < len(sc.s) && sc.f.why == "" {
		switch c := sc.s[sc.i]; {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '|':
			sc.i++
		case c == ')':
			sc.i++
			sc.casePat = false
			return
		case c == '(':
			if !first {
				sc.f.hold("a case pattern alalanet does not read")
				return
			}
			sc.i++
		default:
			w := sc.word(wordCmd)
			if first && w.raw == "esac" {
				sc.inCase--
				sc.casePat = false
				return
			}
			if w.raw == "" {
				sc.i++
			}
		}
		first = false
	}
}

// command reads one simple command and judges it.
func (sc *ownScan) command() {
	if sc.casePat {
		sc.pattern()
		return
	}
	var ws []rawWord
	prefixOnly := func() bool {
		for _, w := range ws {
			if w.quoted || !ownPrefix[w.raw] {
				return false
			}
		}
		return true
	}
	for sc.i < len(sc.s) && sc.f.why == "" {
		c := sc.s[sc.i]
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			sc.i++
			continue
		case c == '\\' && sc.i+1 < len(sc.s) && sc.s[sc.i+1] == '\n':
			sc.i += 2
			continue
		case c == '&' && sc.i+1 < len(sc.s) && sc.s[sc.i+1] == '>':
			sc.redirect()
			continue
		case c == '<' || c == '>':
			if sc.i+1 < len(sc.s) && sc.s[sc.i+1] == '(' { // <( … ), >( … ): a word whose command runs apart
				sc.i += 2
				sc.sub()
				ws = append(ws, rawWord{raw: "<()", text: "<()", expanded: true})
				continue
			}
			sc.redirect()
			continue
		case c == '(' && strings.HasPrefix(sc.s[sc.i:], "((") && prefixOnly():
			sc.i += 2
			sc.arith()
			continue
		case c == '(' && !prefixOnly():
			// ( after a command's words: bash refuses it; zsh reads a pattern, whose groups run what they expand
			ws = append(ws, sc.word(wordGlob))
			continue
		case c == '#' && len(ws) > 0:
			// a comment ends the command (a word that starts with # after a blank)
		case strings.IndexByte(";&|\n()", c) >= 0:
		default:
			w := sc.word(wordCmd)
			if sc.f.why != "" {
				return
			}
			if w.raw == "" {
				continue
			}
			if sc.i < len(sc.s) && (sc.s[sc.i] == '<' || sc.s[sc.i] == '>') && !w.quoted && !w.expanded {
				if strings.Trim(w.raw, "0123456789") == "" {
					continue // a descriptor's number: 2>&1
				}
				if len(w.raw) > 2 && w.raw[0] == '{' && w.raw[len(w.raw)-1] == '}' && ownName(w.raw[1:len(w.raw)-1]) {
					sc.f.hold("a redirection that sets " + clip(w.raw, 40))
					return
				}
			}
			if w.raw == "[[" && !w.quoted && prefixOnly() {
				sc.cond()
				continue
			}
			ws = append(ws, w)
			continue
		}
		break
	}
	if sc.f.why == "" {
		sc.judge(ws)
	}
}

// redirect reads a redirection and the word it names (a here-document's delimiter is kept for its body).
func (sc *ownScan) redirect() {
	s := sc.s
	if strings.HasPrefix(s[sc.i:], "<<<") {
		sc.i += 3
		sc.target()
		return
	}
	if strings.HasPrefix(s[sc.i:], "<<") {
		sc.i += 2
		tabs := false
		if sc.i < len(s) && s[sc.i] == '-' {
			tabs = true
			sc.i++
		}
		for sc.i < len(s) && (s[sc.i] == ' ' || s[sc.i] == '\t') {
			sc.i++
		}
		d := sc.word(wordCmd)
		sc.docs = append(sc.docs, hereDoc{delim: d.text, quoted: d.quoted, tabs: tabs})
		return
	}
	for sc.i < len(s) && strings.IndexByte("<>&|", s[sc.i]) >= 0 {
		sc.i++
	}
	if sc.i > 0 && s[sc.i-1] == '&' {
		for sc.i < len(s) && (s[sc.i] >= '0' && s[sc.i] <= '9' || s[sc.i] == '-') {
			sc.i++
		}
		if sc.i >= len(s) || strings.IndexByte(" \t\r\n;&|)", s[sc.i]) >= 0 {
			return // >&2, 2>&1, <&-
		}
	}
	sc.target()
}

func (sc *ownScan) target() {
	for sc.i < len(sc.s) && (sc.s[sc.i] == ' ' || sc.s[sc.i] == '\t') {
		sc.i++
	}
	if sc.i < len(sc.s) && strings.IndexByte(";&|\n()<>", sc.s[sc.i]) < 0 {
		sc.word(wordCmd)
	}
}

// cond reads [[ … ]] after its [[: an -eq operand only reads; its other words expand as any word does.
func (sc *ownScan) cond() {
	var ts []rawWord
	for sc.f.why == "" {
		for sc.i < len(sc.s) && strings.IndexByte(" \t\r\n", sc.s[sc.i]) >= 0 {
			sc.i++
		}
		if sc.i >= len(sc.s) {
			return // bash and zsh refuse a [[ that does not close
		}
		rest := sc.s[sc.i:]
		if strings.HasPrefix(rest, "]]") && (len(rest) == 2 || strings.IndexByte(" \t\r\n;&|)", rest[2]) >= 0) {
			sc.i += 2
			break
		}
		switch {
		case strings.HasPrefix(rest, "&&") || strings.HasPrefix(rest, "||"):
			sc.i += 2
			ts = append(ts, rawWord{raw: rest[:2], text: rest[:2]})
		case rest[0] == '(' || rest[0] == ')' || rest[0] == '!':
			sc.i++
			ts = append(ts, rawWord{raw: rest[:1], text: rest[:1]})
		default:
			w := sc.word(wordCond)
			if w.raw == "" {
				sc.i++
				continue
			}
			ts = append(ts, w)
		}
	}
	for i, t := range ts {
		if !t.quoted && arithTestOps[t.raw] {
			if i == 0 || i+1 >= len(ts) || !sc.arithOperand(ts[i-1]) || !sc.arithOperand(ts[i+1]) {
				sc.f.hold("[[ … " + t.raw + " … ]] with an operand that is not a number or a name")
				return
			}
		}
		// -v NAME, -R NAME: an index other than digits is arithmetic (round 30)
		if !t.quoted && (t.raw == "-v" || t.raw == "-R") && (i+1 >= len(ts) || ts[i+1].expanded || !nameIndex.MatchString(ts[i+1].text)) {
			sc.f.hold("[[ " + t.raw + " ]] with what is not a literal name")
			return
		}
	}
}

var arithTestOps = wordSet("-eq -ne -lt -le -gt -ge")

// urlGroup: a group that is a plain http:// or https:// address — a Markdown link's ([x](https://…)). zsh reads it as
// glob qualifiers and refuses the line at its h ("unknown file attribute: h"; with NO_BARE_GLOB_QUAL, "bad pattern":
// a / in a group); sh emulation leaves the word as it is; bash refuses the line. A group with a group, a quote, an
// escape or an expansion in it is not plain. Any other attached group holds: zsh's qualifiers run code (e with any
// delimiter, +name), add words (P) and rewrite the word (:s), and sets of their characters missed three times
// (rounds 34-36).
var urlGroup = regexp.MustCompile("^https?://[^()$`'\"\\\\\\s]*$")

// word reads a word: quotes, escapes, expansions and zsh's pattern groups.
func (sc *ownScan) word(mode int) (w rawWord) {
	var b, u strings.Builder // u: the unquoted characters as written, others as a placeholder
	start := sc.i
	s := sc.s
	groups := 0
	defer func() {
		w.pattern = w.pattern || strings.ContainsAny(u.String(), "*?[")
		w.brace = braceExp.MatchString(u.String())
	}()
loop:
	for sc.i < len(s) && sc.f.why == "" {
		c := s[sc.i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			break loop
		case mode != wordCond && strings.IndexByte(";&|<>)", c) >= 0:
			break loop
		case c == '(' && mode != wordCond:
			t := b.String()
			if t == "" && groups == 0 && mode != wordGlob {
				break loop
			}
			if t != "" && groups == 0 && strings.HasSuffix(t, "=") && !w.quoted && !w.expanded { // NAME=( … ): an array
				sc.i++
				sc.array(t)
				w.array = true
				b.WriteString("()")
				groups++
				continue
			}
			attached := t != "" || groups > 0
			g, closed := sc.group(&b, &w)
			groups++
			w.pattern = true // a zsh pattern group
			// a / in a pattern group: zsh refuses the pattern ("grouping cannot extend over multiple directories"),
			// bash the line — the word names no builtin (round 34; the round-29 rule read the / in w.text)
			w.groupSlash = w.groupSlash || closed && strings.Contains(g, "/")
			switch {
			case !closed:
				break loop // bash and zsh refuse it
			case strings.TrimSpace(g) == "":
				sc.f.hold("a function definition (" + clip(t, 40) + ")")
			case attached && !urlGroup.MatchString(g):
				// a group attached to a word: zsh reads its last as glob qualifiers, on the command's name and on any
				// other word it globs (round 36)
				sc.f.hold("a zsh glob qualifier, which may run code (" + clip(t+"("+g+")", 40) + ")")
			}
		case c == '\\':
			if sc.i+1 < len(s) && s[sc.i+1] == '\n' {
				sc.i += 2
				continue
			}
			w.quoted = true
			if sc.i+1 < len(s) {
				b.WriteByte(s[sc.i+1])
				w.litb = append(w.litb, s[sc.i+1])
			}
			sc.i += 2
		case c == '\'':
			w.quoted = true
			j := strings.IndexByte(s[sc.i+1:], '\'')
			if j < 0 {
				sc.i = len(s) // a quote that does not close: bash and zsh refuse the line (the readers hold it)
				break loop
			}
			b.WriteString(s[sc.i+1 : sc.i+1+j])
			w.litb = append(w.litb, s[sc.i+1:sc.i+1+j]...)
			sc.i += j + 2
		case c == '"':
			w.quoted = true
			sc.i++
			sc.dquote(&b, &w)
		case c == '$':
			if sc.i+1 < len(s) && s[sc.i+1] != '\'' && s[sc.i+1] != '"' {
				w.bare = true
			}
			sc.dollar(&b, &w, false)
		case c == '`':
			w.bare = true
			if !sc.backtick(&b, &w) { // a backtick that does not close: a separator, as the readers read it (prose)
				if sc.i == start {
					sc.i++
					start = sc.i
					continue
				}
				break loop
			}
		default:
			b.WriteByte(c)
			u.WriteByte(c)
			w.litb = append(w.litb, c)
			sc.i++
			continue
		}
		u.WriteByte(0) // a quote, an escape or an expansion: no pattern or brace character of its own
	}
	if sc.i > len(s) {
		sc.i = len(s)
	}
	w.raw, w.text = s[start:sc.i], b.String()
	return w
}

// braceExp: an unquoted brace expansion, {a,b} or {1..3}, which bash expands into the words it names.
var braceExp = regexp.MustCompile(`\{[^{}\x00]*(,|\.\.)[^{}]*\}`)

// group reads a pattern group ( … ) from its (, judging what it expands; the text inside, and whether it closes.
func (sc *ownScan) group(b *strings.Builder, w *rawWord) (string, bool) {
	s := sc.s
	open := sc.i
	sc.i++
	d := 0
	for sc.i < len(s) && sc.f.why == "" {
		switch c := s[sc.i]; {
		case c == '(':
			d++
			sc.i++
		case c == ')':
			if d > 0 {
				d--
				sc.i++
				continue
			}
			g := s[open+1 : sc.i]
			sc.i++
			b.WriteString("(" + g + ")")
			return g, true
		case c == '\n':
			return "", false
		case c == '\\':
			sc.i += 2
		case c == '\'':
			j := strings.IndexByte(s[sc.i+1:], '\'')
			if j < 0 {
				return "", false
			}
			sc.i += j + 2
		case c == '"':
			sc.i++
			sc.dquote(b, w)
		case c == '$':
			sc.dollar(b, w, false)
		case c == '`':
			if !sc.backtick(b, w) {
				sc.i++
			}
		default:
			sc.i++
		}
	}
	if sc.i > len(s) {
		sc.i = len(s)
	}
	return "", false
}

// array reads NAME=( … )'s elements after its (: an element [index]=value has an arithmetic index.
func (sc *ownScan) array(t string) {
	name := strings.TrimSuffix(strings.TrimSuffix(t, "="), "+")
	for sc.f.why == "" {
		for sc.i < len(sc.s) && strings.IndexByte(" \t\r\n", sc.s[sc.i]) >= 0 {
			sc.i++
		}
		if sc.i >= len(sc.s) {
			return // bash and zsh refuse an array that does not close
		}
		if sc.s[sc.i] == ')' {
			sc.i++
			break
		}
		e := sc.word(wordCmd)
		if e.raw == "" {
			sc.f.hold("an array alalanet does not read")
			return
		}
		if strings.HasPrefix(e.raw, "[") {
			sc.f.hold("an array element with an index, which is arithmetic (" + clip(e.raw, 40) + ")")
			return
		}
	}
	if ownName(name) {
		sc.f.val(name, valUnknown)
	}
}

// dquote reads a double-quoted string after its opening quote.
func (sc *ownScan) dquote(b *strings.Builder, w *rawWord) {
	s := sc.s
	for sc.i < len(s) && sc.f.why == "" {
		switch c := s[sc.i]; {
		case c == '"':
			sc.i++
			return
		case c == '\\' && sc.i+1 < len(s) && strings.IndexByte("$`\"\\\n", s[sc.i+1]) >= 0:
			if s[sc.i+1] != '\n' {
				b.WriteByte(s[sc.i+1])
				w.litb = append(w.litb, s[sc.i+1])
			}
			sc.i += 2
		case c == '$':
			sc.dollar(b, w, true)
		case c == '`':
			if !sc.backtick(b, w) {
				b.WriteByte(c)
				w.litb = append(w.litb, c)
				sc.i++
			}
		default:
			b.WriteByte(c)
			w.litb = append(w.litb, c)
			sc.i++
		}
	}
	// a quote that does not close: bash and zsh refuse the line (the readers hold it)
}

// dollar reads an expansion at $.
func (sc *ownScan) dollar(b *strings.Builder, w *rawWord, dq bool) {
	s := sc.s
	start := sc.i
	n := byte(0)
	if sc.i+1 < len(s) {
		n = s[sc.i+1]
	}
	switch {
	case n == '\'' && !dq: // $'…': a quote with escapes
		w.quoted = true
		j := sc.i + 2
		for ; j < len(s) && s[j] != '\''; j++ {
			if s[j] == '\\' {
				j++
			}
		}
		if j >= len(s) {
			sc.i = len(s) // a quote that does not close: bash and zsh refuse the line (the readers hold it)
			return
		}
		b.WriteString(s[sc.i+2 : j])
		w.litb = append(w.litb, s[sc.i+2:j]...)
		sc.i = j + 1
		return
	case n == '"' && !dq: // $"…": a double quote
		sc.i++
		return
	case n == '{' && sc.i+2 < len(s) && s[sc.i+2] == '{' && strings.Contains(s[sc.i:], "}}"):
		// ${{ … }}: a GitHub Actions expression, which the runner replaces before a shell runs; a shell refuses it
		sc.i += strings.Index(s[sc.i:], "}}") + 2
	case n == '{':
		w.expanded = true
		sc.brace(dq)
	case n == '(' && sc.i+2 < len(s) && s[sc.i+2] == '(':
		w.expanded = true
		sc.i += 3
		sc.arith()
	case n == '(':
		w.expanded = true
		sc.i += 2
		body := sc.i
		sc.sub()
		if end := sc.i - 1; end >= body && end < len(s) && s[end] == ')' {
			w.subs++
			w.sub = s[body:end]
		} else {
			w.subs += 2 // one that does not close: not a program the allowlist reads
		}
	case n == '[':
		sc.f.hold("$[…], arithmetic")
		return
	case nameChar(n) || n != 0 && strings.IndexByte("@*#?$!-", n) >= 0:
		w.expanded = true
		sc.i += 2
		if !(n >= '0' && n <= '9') && nameChar(n) {
			for sc.i < len(s) && nameChar(s[sc.i]) {
				sc.i++
			}
		}
	case n == '~' || n == '=' || n == '^' || n == '+':
		sc.f.hold("zsh's $" + string(n) + " expansion")
		return
	default:
		b.WriteByte('$')
		sc.i++
		return
	}
	if sc.i > len(s) {
		sc.i = len(s)
	}
	b.WriteString(s[start:sc.i])
}

// sub reads a substitution's commands after its $( or <(: they run in a shell of their own, and are judged as the
// line's.
func (sc *ownScan) sub() {
	if sc.depth >= maxOwnDepth {
		sc.f.hold("substitutions nested too deep")
		return
	}
	sc.depth++
	sc.list(')')
	sc.depth--
}

// backtick reads `…` (false, and nothing read, when it does not close): its body, with \` \\ \$ unescaped, is a
// script.
func (sc *ownScan) backtick(b *strings.Builder, w *rawWord) bool {
	s := sc.s
	var body strings.Builder
	j := sc.i + 1
	for ; j < len(s) && s[j] != '`'; j++ {
		if s[j] == '\\' && j+1 < len(s) && strings.IndexByte("`\\$", s[j+1]) >= 0 {
			j++
		}
		body.WriteByte(s[j])
	}
	if j >= len(s) {
		return false
	}
	w.expanded = true
	w.subs++
	w.sub = body.String()
	b.WriteString(s[sc.i : j+1])
	sc.i = j + 1
	if sc.depth >= maxOwnDepth {
		sc.f.hold("substitutions nested too deep")
		return true
	}
	in := &ownScan{s: w.sub, f: sc.f, depth: sc.depth + 1}
	in.list(0)
	return true
}

// brace reads ${…}: ${NAME}, ${#NAME}, ${!NAME}, ${!NAME@}, ${NAME[@]} (and [*], [N]), ${NAME:OFFSET[:LENGTH]} of
// numbers or names, and ${NAME:-word} (-, :+, +, :?, ?), whose word is read as any word is. Any other operator, a
// flag or an index holds.
func (sc *ownScan) brace(dq bool) {
	s := sc.s
	if !strings.Contains(s[sc.i:], "}") {
		sc.i = len(s) // an expansion that does not close: bash and zsh refuse the line (the readers hold it)
		return
	}
	j := sc.i + 2
	ind, length := false, false
	if j < len(s) && s[j] == '!' {
		ind = true
		j++
	} else if j+1 < len(s) && s[j] == '#' && s[j+1] != '}' {
		length = true
		j++
	}
	k := j
	switch {
	case k < len(s) && nameChar(s[k]) && !(s[k] >= '0' && s[k] <= '9'):
		for k < len(s) && nameChar(s[k]) {
			k++
		}
	case k < len(s) && s[k] >= '0' && s[k] <= '9':
		for k < len(s) && s[k] >= '0' && s[k] <= '9' {
			k++
		}
	case k < len(s) && strings.IndexByte("@*#?$!-", s[k]) >= 0:
		k++
	}
	name := s[j:k]
	shown := func() string {
		e := strings.IndexByte(s[sc.i:], '}')
		if e < 0 {
			return clip(s[sc.i:], 40)
		}
		return clip(s[sc.i:sc.i+e+1], 40)
	}
	bad := func() {
		sc.f.hold("an expansion alalanet does not read (" + shown() + ")")
		sc.i = len(s)
	}
	if name == "" || k >= len(s) {
		bad()
		return
	}
	if s[k] == '[' && ownName(name) { // ${a[@]}, ${a[*]}, ${a[0]}: an index of digits or all
		e := strings.IndexByte(s[k:], ']')
		if e < 0 || !(s[k+1:k+e] == "@" || s[k+1:k+e] == "*" || intLit.MatchString(s[k+1:k+e])) {
			bad()
			return
		}
		k += e + 1
		if k >= len(s) {
			bad()
			return
		}
	}
	switch {
	case s[k] == '}':
		if ind && ownName(name) {
			sc.f.ind.add(name)
		}
		sc.i = k + 1
		return
	case ind && (s[k] == '@' || s[k] == '*') && k+1 < len(s) && s[k+1] == '}': // ${!prefix@}: the names, read only
		sc.i = k + 2
		return
	case ind || length:
		bad()
		return
	}
	for _, o := range []string{":-", ":+", ":?", "-", "+", "?"} {
		if strings.HasPrefix(s[k:], o) {
			sc.i = k + len(o)
			sc.braceWord(dq)
			return
		}
	}
	if s[k] == ':' { // ${NAME:OFFSET[:LENGTH]}: arithmetic, here only numbers and names (PowerShell's ${env:NAME})
		e := strings.IndexByte(s[k:], '}')
		if e < 0 {
			bad()
			return
		}
		for _, part := range strings.Split(s[k+1:k+e], ":") {
			if strings.ContainsAny(part, "$`'\"\\[") {
				bad()
				return
			}
			if sc.f.arithBody(part); sc.f.why != "" {
				return
			}
		}
		sc.i = k + e + 1
		return
	}
	bad()
}

// braceWord reads ${NAME:-word}'s word up to the } that closes it.
func (sc *ownScan) braceWord(dq bool) {
	var w rawWord
	var b strings.Builder
	s := sc.s
	for sc.i < len(s) && sc.f.why == "" {
		switch c := s[sc.i]; {
		case c == '}':
			sc.i++
			return
		case c == '\\':
			sc.i += 2
		case c == '\'':
			j := strings.IndexByte(s[sc.i+1:], '\'')
			if j < 0 {
				sc.i = len(s)
				return
			}
			sc.i += j + 2
		case c == '"':
			sc.i++
			sc.dquote(&b, &w)
		case c == '$':
			sc.dollar(&b, &w, false)
		case c == '`':
			if !sc.backtick(&b, &w) {
				sc.i++
			}
		case c == '(' && !dq:
			// outside double quotes zsh globs the word it gives, with its groups: ${x:-a(e#…#)} runs the code (round 36)
			sc.f.hold("a zsh glob qualifier in ${NAME:-word}, which may run code (" + clip(s[sc.i:], 40) + ")")
		default:
			sc.i++
		}
	}
	// an expansion that does not close: bash and zsh refuse the line
}

// ownPrefix: reserved words that stand before a command, or close a compound one.
var ownPrefix = wordSet("if then elif else fi do done while until ! { } time")

// ownHeld: reserved words and zsh's loops the allowlist does not read.
var ownHeld = wordSet("select function coproc foreach repeat")

// ownBuiltins: bash's and zsh's builtins (zsh's modules that load themselves included). Only they run in the line's
// own shell; every other program runs apart, with words the shell only expands.
var ownBuiltins = wordSet(". : [ alias autoload bg bind bindkey break builtin bye caller cd chdir command compadd " +
	"comparguments compcall compctl compdescribe compfiles compgen compgroups complete compopt compquote comptags " +
	"comptry compvalues continue declare dirs disable disown echo echotc echoti emulate enable eval exec exit export " +
	"false fc fg float functions getcap getln getopts hash help history integer jobs kill let limit local logout " +
	"mapfile noglob nocorrect popd print printf private pushd pushln pwd read readarray readonly rehash return sched " +
	"set setcap setopt shift shopt source strftime suspend sysopen sysread sysseek syswrite syserror test times trap " +
	"true ttyctl type typeset ulimit umask unalias unfunction unhash unlimit unset unsetopt vared wait whence where " +
	"which zcompile zformat zle zmodload zparseopts zprof zpty zregexparse zselect zsocket zstat zstyle ztcp zsystem " +
	"zgetattr zsetattr zdelattr zlistattr zcurses zftp ztie zuntie zgdbmpath pcre_compile pcre_match pcre_study")

// ownFree: builtins that set nothing in the shell the readers do not read, whatever their (expanded) words.
var ownFree = wordSet("cd pushd popd pwd echo true false : type which whence where dirs jobs times help kill umask " +
	"ulimit source . logout bye")

// judge judges one simple command's words.
func (sc *ownScan) judge(ws []rawWord) {
	f := sc.f
	for len(ws) > 0 && !ws[0].quoted && (ownPrefix[ws[0].raw] || ws[0].raw == "esac" && sc.inCase > 0) {
		switch ws[0].raw {
		case "time":
			if len(ws) > 1 && ws[1].raw == "-p" {
				ws = ws[1:]
			}
		case "esac":
			sc.inCase--
		}
		ws = ws[1:]
	}
	if len(ws) == 0 {
		return
	}
	if w := ws[0]; !w.quoted && !w.expanded {
		if w.raw == "for" {
			sc.forLoop(ws[1:])
			return
		}
		if w.raw == "case" { // case WORD in PATTERNS) LIST ;; … esac (round 30)
			if len(ws) < 3 || ws[2].quoted || ws[2].raw != "in" || len(ws) > 3 && strings.HasPrefix(ws[3].raw, "(") {
				f.hold("a case alalanet does not read")
				return
			}
			sc.inCase++
			if len(ws) > 3 && sc.i < len(sc.s) && sc.s[sc.i] == ')' {
				sc.i++ // the first arm's patterns end here
			} else {
				sc.casePat = true
			}
			return
		}
		if ownHeld[w.raw] {
			f.hold(w.raw + ", which alalanet does not read")
			return
		}
	}
	for len(ws) > 0 {
		ok := sc.assignWord(ws[0])
		if f.why != "" {
			return
		}
		if !ok {
			break
		}
		ws = ws[1:]
	}
	if len(ws) > 0 {
		sc.program(ws)
	}
}

var assignHead = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)(\[[^\]]*\])?(\+?=)`)

// assignWord: an assignment word, judged by its name and recorded by the kind of its value; false for any other word.
func (sc *ownScan) assignWord(w rawWord) bool {
	m := assignHead.FindStringSubmatch(w.text) // the shell's word: a backslash or quote in the name is already gone
	if m == nil {
		return false
	}
	if m[2] != "" && !intLit.MatchString(strings.Trim(m[2], "[]")) {
		sc.f.hold("an assignment to an array element, whose index is arithmetic (" + clip(w.text, 40) + ")")
		return true
	}
	if ownReread[m[1]] {
		sc.f.hold("an assignment to " + m[1] + ", which the shell reads again")
		return true
	}
	if w.array {
		sc.f.val(m[1], valUnknown)
		return true
	}
	_, v, _ := strings.Cut(w.text, "=")
	sc.f.setVal(m[1], v, w.expanded)
	return true
}

// valueKind: what an assigned value is not — a number, a name. (Round 32: a $NAME the line sets holds as a
// command's name whatever its value.)
func valueKind(v string, expanded bool) uint8 {
	if expanded {
		if wholeArith(v) {
			return valNotName
		}
		return valUnknown
	}
	var k uint8
	if !intLit.MatchString(v) && v != "" {
		k |= valNotInt
	}
	if !ownName(v) {
		k |= valNotName
	}
	return k
}

// wholeArith: a value that is one $(( … )), a number.
func wholeArith(v string) bool {
	if !strings.HasPrefix(v, "$((") || !strings.HasSuffix(v, "))") {
		return false
	}
	d := 0
	for i := 1; i < len(v); i++ {
		switch v[i] {
		case '(':
			d++
		case ')':
			if d--; d == 0 && i < len(v)-1 {
				return false
			}
		}
	}
	return d == 0
}

var (
	psEnvWord = regexp.MustCompile(`(?i)^(\$env:[A-Za-z_][A-Za-z0-9_]*|\$\{env:[A-Za-z_][A-Za-z0-9_]*\})(\+?=.*)?$`)
	plainVar  = regexp.MustCompile(`^"?\$(\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)"?$`)
)

// program judges a command by its program.
func (sc *ownScan) program(ws []rawWord) {
	f := sc.f
	w := ws[0]
	sc.shellScripts(ws)
	if w.bare {
		f.bareRun = true // an unquoted expansion as the command's name: IFS splits it (final)
	}
	switch {
	case w.brace:
		// the command's name must be literal: a brace expansion ({eval,}) names any word it expands to (round 32)
		f.hold("a command named by a brace expansion (" + clip(w.text, 40) + ")")
		return
	case w.pattern && !strings.Contains(string(w.litb), "/") && !w.groupSlash && !ownBuiltins[w.text] && w.text != "[[" &&
		mayName(globGroups.ReplaceAllString(w.text, "*")):
		// a pattern names the files it matches: one that may match a builtin's name may run it (a / never matches one)
		f.hold("a command named by a pattern that may match a builtin's name (" + clip(w.text, 40) + ")")
		return
	}
	if w.expanded {
		lit := w.text
		if i := strings.IndexAny(lit, "$`"); i >= 0 {
			lit = lit[:i]
		}
		switch r := w.raw; {
		case psEnvWord.MatchString(r): // PowerShell's $env:NAME = value: the readers judge it
			return
		case lit != "" && !mayName(lit+"*"): // literal text before the expansion that no builtin's name starts with
		case plainVar.MatchString(r): // $NAME: what the line sets it to (final), or the user's environment
			f.progs.add(strings.Trim(r, `"${}`))
		case !w.bare && w.subs == 0 && strings.Contains(string(w.litb), "/"):
			// "$VENV/bin/pip": one word with a literal / — not one inside an expansion ("${NOPE:+/}eval", round 34)
		case w.subs == 1 && substOnly(r) && setupPair(w.sub) && !f.sets:
			// a setup pair's output, as eval "$(pyenv init -)" runs it (the walk reads eval's words as a script)
		case w.subs == 0 && plainParts.MatchString(r): // $HOME/.local/bin/pip: each name's value one path
			for _, m := range plainName.FindAllStringSubmatch(r, -1) {
				f.paths.add(m[1] + m[2])
			}
		default:
			f.hold("a command named by an expansion (" + clip(w.text, 40) + ")")
			return
		}
		sc.args(ws[1:])
		return
	}
	name := w.text
	rest := ws[1:]
	switch name {
	case "command", "builtin", "exec", "noglob", "nocorrect", "-":
		for len(rest) > 0 && strings.HasPrefix(rest[0].text, "-") && rest[0].text != "-" {
			o := rest[0].text
			if name == "command" && (o == "-v" || o == "-V") {
				return // a lookup
			}
			rest = rest[1:]
			if o == "--" {
				break
			}
			if name == "exec" && o == "-a" && len(rest) > 0 {
				rest = rest[1:]
			}
		}
		if len(rest) > 0 {
			sc.program(rest)
		}
		return
	}
	if !ownBuiltins[name] {
		sc.args(rest)
		return
	}
	if ownFree[name] {
		return
	}
	switch name {
	case "eval":
		for _, a := range rest {
			sc.evalWord(name, a)
		}
	case "trap":
		for len(rest) > 0 && !rest[0].expanded && (rest[0].text == "--" || rest[0].text == "-p" || rest[0].text == "-l") {
			rest = rest[1:]
		}
		if len(rest) > 0 {
			sc.evalWord(name, rest[0]) // its body; the words after it are signals
		}
	case "let":
		for _, a := range rest {
			if a.expanded {
				f.hold("let with an expansion alalanet does not read (" + clip(a.raw, 40) + ")")
				return
			}
			if f.arithBody(a.text); f.why != "" {
				return
			}
		}
	case "printf":
		if len(rest) > 0 && !rest[0].expanded && strings.HasPrefix(rest[0].text, "-v") {
			nw, n := rest[0], rest[0].text[2:]
			rest = rest[1:]
			if n == "" && len(rest) > 0 {
				nw, rest = rest[0], rest[1:]
			} else {
				nw.text, nw.raw = n, n
			}
			if !sc.setName(name, nw) {
				return
			}
		}
		sc.printf(rest)
	case "mapfile", "readarray":
		sc.mapfile(name, rest)
	case "getopts":
		if len(rest) >= 2 {
			sc.setName(name, rest[1])
		}
	case "test", "[":
		for i, a := range rest {
			if !a.expanded && arithTestOps[a.text] && (i == 0 || i+1 >= len(rest) || !sc.arithOperand(rest[i-1]) || !sc.arithOperand(rest[i+1])) {
				f.hold(name + " … " + a.text + " … with an operand that is not a number or a name")
				return
			}
			if !a.expanded && (a.text == "-v" || a.text == "-R") && (i+1 >= len(rest) || rest[i+1].expanded || !nameIndex.MatchString(rest[i+1].text)) {
				f.hold(name + " " + a.text + " with what is not a literal name")
				return
			}
		}
	case "export", "declare", "typeset", "local", "readonly":
		sc.declare(name, rest)
	case "unset":
		for _, a := range rest {
			if a.expanded || !(ownName(a.text) || unsetOpt.MatchString(a.text)) {
				f.hold("unset " + clip(a.text, 40) + ", which alalanet does not read")
				return
			}
		}
	case "set":
		sc.set(rest)
	case "read":
		sc.read(rest)
	case "shift", "exit", "return", "break", "continue":
		if len(rest) > 1 || len(rest) == 1 && !(!rest[0].expanded && intLit.MatchString(rest[0].text) || rest[0].raw == "$?" || rest[0].raw == `"$?"`) {
			f.hold(name + " with a word that is not a number (" + clip(rest[0].text, 40) + ")")
		}
	case "wait":
		for _, a := range rest {
			r := strings.Trim(a.raw, `"`)
			if !a.expanded {
				r = a.text // '-n', \-n: the builtin's word
			}
			if r == "-n" || r == "-f" || intLit.MatchString(r) || strings.HasPrefix(r, "%") && !a.expanded {
				continue
			}
			if n, j := plainDollar(r, 0); j == len(r) && (n != "" || r == "$!") {
				continue
			}
			f.hold("wait " + clip(r, 40) + ", which alalanet does not read")
			return
		}
	case "hash":
		for _, a := range rest {
			if (a.expanded || a.text != "-r") && (strings.HasPrefix(a.text, "-") || a.expanded) {
				f.hold("hash " + clip(a.text, 40) + ", which alalanet does not read")
				return
			}
		}
	default:
		f.hold(name + ", a builtin of the shell alalanet does not read")
	}
}

var (
	plainParts = regexp.MustCompile(`^("?(\$[A-Za-z_][A-Za-z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\}|[^$` + "`" + `"'\\])"?)+$`)
	plainName  = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)`)
	globGroups = regexp.MustCompile(`\([^)]*\)`)
	positional = regexp.MustCompile(`\$[0-9]|\$\{[0-9]+\}`)
)

// ownNames: every name the shell may run as its own (builtins and reserved words).
var ownNames = func() []string {
	var out []string
	for _, set := range []map[string]bool{ownBuiltins, ownPrefix, ownHeld} {
		for n := range set {
			out = append(out, n)
		}
	}
	return append(out, "for", "[[", "]]", "in")
}()

// mayName: a pattern that matches the name of a builtin or a reserved word (a malformed one may).
func mayName(pattern string) bool {
	if strings.Contains(pattern, "[:") || strings.Contains(pattern, "[=") || strings.Contains(pattern, "[.") {
		return true // a POSIX class, an equivalence class, a collating symbol: Go's path.Match has none (round 33)
	}
	pattern = strings.ReplaceAll(pattern, "[!", "[^") // the shells' negation; [! is a class of ! to Go
	if i := strings.LastIndexByte(pattern, '['); i >= 0 && !strings.Contains(pattern[i:], "]") && !strings.Contains(pattern[:i], "]") {
		pattern = strings.ReplaceAll(pattern, "[", "\\[") // a [ no ] closes is a [ to the shells
	}
	for _, n := range ownNames {
		if ok, err := path.Match(pattern, n); ok || err != nil {
			return true // a pattern Go cannot read ([]e], [e-]) may be one the shell reads
		}
	}
	return false
}

// nameIndex: a variable's name as a builtin takes it — an index only of digits (another index is arithmetic).
var nameIndex = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)(\[[0-9]+\])?$`)

// setName: a name a builtin sets to a value alalanet does not see (printf -v, mapfile, getopts): literal, no lever.
func (sc *ownScan) setName(builtin string, a rawWord) bool {
	m := nameIndex.FindStringSubmatch(a.text)
	switch {
	case a.expanded || m == nil:
		sc.f.hold(builtin + " with a name alalanet does not read (" + clip(a.raw, 40) + ")")
		return false
	case noSet(m[1]):
		sc.f.hold(builtin + " sets " + clip(m[1], 40))
		return false
	}
	sc.f.val(m[1], valUnknown)
	return true
}

// mapfile, readarray: their options that run no code (-C runs a callback), and one name.
func (sc *ownScan) mapfile(name string, rest []rawWord) {
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		t := a.text
		if !a.expanded && len(t) > 1 && t[0] == '-' { // a quoted option ('-C') is mapfile's option too
			switch {
			case t == "-t" || t == "--":
			case len(t) == 2 && strings.ContainsRune("dnOsuc", rune(t[1])):
				i++ // its value
			case len(t) > 2 && strings.ContainsRune("dnOsuc", rune(t[1])):
			default:
				sc.f.hold(name + " " + clip(t, 20) + ", which alalanet does not read")
				return
			}
			continue
		}
		if !sc.setName(name, a) {
			return
		}
	}
}

// evalWord: a word eval runs (or trap's body) whose text is an expansion: its value is code. A plain $NAME is read at
// the end as the values the line gives NAME (none shown: it holds); the output of an environment manager, or of a
// package manager found on PATH, is the tool's; any other holds (round 30).
func (sc *ownScan) evalWord(name string, a rawWord) {
	switch {
	case !a.expanded:
	case a.subs == 1 && setupPair(a.sub) && (quotedSubst(a.raw) || substOnly(a.raw)) && !sc.f.sets:
		// eval "$(pyenv init -)": the setup a tool on the user's machine prints for itself — unless the line has set a
		// variable before, such as PYENV_ROOT, which moves what the tool prints, or IFS, which splits it (round 32)
	default:
		sc.f.hold(name + " of a value alalanet does not see (" + clip(a.raw, 40) + ")")
	}
}

// quotedSubst: a word that is one command substitution in double quotes.
func quotedSubst(r string) bool {
	return len(r) > 2 && r[0] == '"' && r[len(r)-1] == '"' && substOnly(r[1:len(r)-1])
}

// setupPairs: the exact commands whose output is a tool's own shell setup — environment managers' init -, shellenv
// and hook (and fnm env, ssh-agent -s), package managers' completion scripts; SHELL stands for a shell's name.
var setupPairs = map[string][][]string{
	"pyenv": {{"init", "-"}, {"init", "-", "SHELL"}, {"virtualenv-init", "-"}, {"virtualenv-init", "-", "SHELL"}}, "rbenv": {{"init", "-"}, {"init", "-", "SHELL"}},
	"nodenv": {{"init", "-"}, {"init", "-", "SHELL"}}, "goenv": {{"init", "-"}, {"init", "-", "SHELL"}},
	"brew": {{"shellenv"}, {"shellenv", "SHELL"}}, "direnv": {{"hook", "SHELL"}},
	"conda": {{"shell.bash", "hook"}, {"shell.zsh", "hook"}, {"shell.posix", "hook"}},
	"fnm":   {{"env"}, {"env", "--use-on-cd"}}, "ssh-agent": {{}, {"-s"}},
	"npm": {{"completion"}}, "pnpm": {{"completion", "SHELL"}}, "pip": {{"completion", "--bash"}, {"completion", "--zsh"}},
	"uv":   {{"generate-shell-completion", "SHELL"}, {"tool", "run", "--generate-shell-completion", "SHELL"}},
	"uvx":  {{"--generate-shell-completion", "SHELL"}, {"--generate-shell-completion=SHELL"}},
	"deno": {{"completions", "SHELL"}}, "bun": {{"completions"}},
}

var setupShells = wordSet("bash zsh fish sh posix")

// fnmEnv: fnm env's options that change nothing but its shell and its hooks, each at most once.
func fnmEnv(opts []string) bool {
	seen := map[string]bool{}
	for i := 0; i < len(opts); i++ {
		o, v, hasV := strings.Cut(opts[i], "=")
		switch {
		case seen[o]:
			return false
		case !hasV && (o == "--use-on-cd" || o == "--corepack-enabled" || o == "--resolve-engines"):
		case o == "--shell" && hasV && setupShells[v]:
		case o == "--shell" && !hasV && i+1 < len(opts) && setupShells[opts[i+1]]:
			i++
		default:
			return false
		}
		seen[o] = true
	}
	return true
}

// setupDirs: the system folders a setup tool may be named from (Homebrew's own instructions: eval
// "$(/opt/homebrew/bin/brew shellenv)").
var setupDirs = []string{"/opt/homebrew/bin/", "/usr/local/bin/", "/home/linuxbrew/.linuxbrew/bin/", "/usr/bin/", "/bin/"}

// setupPair: a substitution's body that is exactly one setup pair (setupPairs), run by its name from PATH.
func setupPair(body string) bool {
	f := strings.Fields(body)
	if len(f) == 0 {
		return false
	}
	if len(f) >= 2 && f[0] == "fnm" && f[1] == "env" { // fnm env's options in any order (its README: --use-on-cd --shell bash)
		return fnmEnv(f[2:])
	}
	for _, d := range setupDirs { // a system install of the tool, never a file of the folder
		if t := strings.TrimPrefix(f[0], d); t != f[0] && !strings.Contains(t, "/") {
			f[0] = t
			body = strings.Join(f, " ")
			break
		}
	}
	if strings.ContainsAny(body, "$`'\"\\;|&<>(){}/\n") {
		return false
	}
next:
	for _, want := range setupPairs[progName(f[0])] { // pn completion bash is pnpm's
		if len(want) != len(f)-1 {
			continue
		}
		for i, w := range want {
			g := f[i+1]
			switch {
			case w == "SHELL" && setupShells[g]:
			case strings.HasSuffix(w, "=SHELL") && strings.HasPrefix(g, strings.TrimSuffix(w, "SHELL")) && setupShells[strings.TrimPrefix(g, strings.TrimSuffix(w, "SHELL"))]:
			case w == g:
			default:
				continue next
			}
		}
		return true
	}
	return false
}

// shellScripts: a POSIX shell's -c script word (sh, bash, zsh, dash, ksh … and after any wrapper or program, as in
// sudo bash -c, docker run … sh -c) that has an expansion holds: the child shell parses the expanded text as code,
// which the line does not show (round 31).
func (sc *ownScan) shellScripts(ws []rawWord) {
	for i := 0; i < len(ws); i++ {
		if ws[i].expanded || !posixShells[launchBase(ws[i].text)] {
			continue
		}
		for j := i + 1; j < len(ws); j++ {
			o := ws[j]
			if o.expanded || !strings.HasPrefix(o.text, "-") || o.text == "-" || o.text == "--" { // '-c' is -c to the shell
				break
			}
			if strings.HasPrefix(o.text, "--") || !strings.Contains(o.text, "c") {
				continue
			}
			for k := j + 1; k < len(ws); k++ { // the script: the first word after -c that is no option
				if !ws[k].expanded && strings.HasPrefix(ws[k].text, "-") {
					continue
				}
				if ws[k].expanded {
					sc.cScript(ws[i].text, ws[k])
				}
				return
			}
			return
		}
	}
}

// cScript: a -c script word with expansions: only plain $NAME or ${NAME} the line does not set (the user's
// environment, round 32); any other expansion holds.
func (sc *ownScan) cScript(shell string, w rawWord) {
	if strings.ContainsAny(plainName.ReplaceAllString(w.raw, ""), "$`") { // a substitution, an operator, $1 …
		sc.f.hold(shell + " -c with a script alalanet does not see (" + clip(w.raw, 40) + ")")
		return
	}
	for _, m := range plainName.FindAllStringSubmatch(w.raw, -1) {
		sc.f.cvars.add(m[1] + m[2])
	}
}

// substOnly: a word that is one command substitution, double quotes allowed around it.
func substOnly(r string) bool {
	r = strings.TrimSuffix(strings.TrimPrefix(r, `"`), `"`)
	return strings.HasPrefix(r, "$(") && strings.HasSuffix(r, ")") || len(r) > 1 && r[0] == '`' && r[len(r)-1] == '`'
}

var unsetOpt = regexp.MustCompile(`^-[fvn]+$`)

// args: an external program's words set nothing in the shell; a NAME=value among them (env, sudo) is noted as a
// value the name may have.
func (sc *ownScan) args(ws []rawWord) {
	for _, a := range ws {
		if m := assignHead.FindStringSubmatch(a.text); m != nil && m[2] == "" && !a.expanded {
			_, v, _ := strings.Cut(a.text, "=")
			sc.f.setVal(m[1], v, a.expanded)
		} else if m := assignHead.FindStringSubmatch(a.raw); m != nil && m[2] == "" {
			_, v, _ := strings.Cut(a.text, "=")
			sc.f.setVal(m[1], v, a.expanded)
		}
	}
}

var numericConv = regexp.MustCompile(`%([0-9]+\$)?[-+ #0']*(\*([0-9]+\$)?|[0-9]+)?(\.(\*([0-9]+\$)?|[0-9]*))?[diouxXeEfFgGaA*]`)

// printf: no option (-v sets a name); a format with a numeric conversion evaluates its arguments as arithmetic in zsh.
func (sc *ownScan) printf(rest []rawWord) {
	if len(rest) > 0 && rest[0].text == "--" {
		rest = rest[1:]
	} else if len(rest) > 0 && strings.HasPrefix(rest[0].text, "-") {
		sc.f.hold("printf " + clip(rest[0].text, 40) + ", which alalanet does not read")
		return
	}
	if len(rest) == 0 {
		return
	}
	if rest[0].expanded || numericConv.MatchString(rest[0].text) {
		for _, a := range rest[1:] {
			if !sc.arithOperand(a) {
				sc.f.hold("printf with a number format and an argument that is not a number or a name (" + clip(a.raw, 40) + ")")
				return
			}
		}
	}
}

// declOpts: the options of each that neither type nor tie a name (-i: values that are numbers only).
var declIndex = regexp.MustCompile(`(?s)^[A-Za-z_][A-Za-z0-9_]*\[[0-9]+\](\+?=.*)?$`)

var declOpts = map[string]string{"export": "pf", "declare": "xrgipfF", "typeset": "xrgipfF", "local": "xrgip", "readonly": "p"}

func (sc *ownScan) declare(name string, rest []rawWord) {
	f := sc.f
	intAttr := false
	for _, a := range rest {
		t := a.text
		if !a.expanded && len(t) > 1 && (t[0] == '-' || t[0] == '+') { // a quoted option is the builtin's option too
			if t == "--" {
				continue
			}
			for _, c := range t[1:] {
				if !strings.ContainsRune(declOpts[name], c) {
					f.hold(name + " " + clip(t, 20) + ", which alalanet does not read")
					return
				}
				if c == 'i' && t[0] == '-' {
					intAttr = true
				}
			}
			continue
		}
		if br, eq := strings.IndexByte(t, '['), strings.IndexByte(t, '='); br >= 0 && (eq < 0 || br < eq) {
			// NAME[INDEX]: an index other than digits is arithmetic
			if !declIndex.MatchString(t) {
				f.hold(name + " with an index that is arithmetic (" + clip(a.raw, 40) + ")")
				return
			}
			t = t[:br] + t[strings.IndexByte(t, ']')+1:]
		}
		n, v, assigns := strings.Cut(t, "=")
		n = strings.TrimSuffix(n, "+")
		literal := ownName(n)
		if !literal {
			// a name with plain expansions: the second reader judges it by its literal tail; one with another
			// character can never be a name, and the shell refuses it; anything else may name any variable
			rest := positional.ReplaceAllString(plainName.ReplaceAllString(n, ""), "")
			if strings.ContainsAny(rest, "$`") || intAttr {
				f.hold(name + " with a name alalanet does not read (" + clip(a.raw, 40) + ")")
				return
			}
			continue
		}
		if ownReread[n] {
			f.hold(name + " " + n + ", which the shell reads again")
			return
		}
		if intAttr {
			f.arithRef(n) // every value it is given is arithmetic
		}
		if assigns {
			if a.array {
				f.val(n, valUnknown)
				continue
			}
			f.setVal(n, v, a.expanded)
		}
	}
}

var setOptNames = wordSet("errexit nounset xtrace pipefail verbose allexport errtrace noclobber")

// set: the options that only make the shell stricter or louder, and positional words.
func (sc *ownScan) set(rest []rawWord) {
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		t := a.text
		if a.expanded || len(t) < 2 || t[0] != '-' && t[0] != '+' {
			continue // a positional word (cmd.exe's set NAME=value is the readers'); a quoted option is set's option too
		}
		if t == "--" {
			return
		}
		for j, c := range t[1:] {
			if c == 'o' && j == len(t)-2 {
				if i+1 < len(rest) && !rest[i+1].expanded && setOptNames[rest[i+1].text] {
					i++
					break
				}
				if i+1 == len(rest) {
					break
				}
			}
			if !strings.ContainsRune("euxvaE", c) {
				sc.f.hold("set " + clip(t, 20) + ", which alalanet does not read")
				return
			}
		}
	}
}

var readOpt = regexp.MustCompile(`^-[rse]*([ptnNdui])?$`)

// read: its options that set no name, and names that are no lever (each word's part before ?, zsh's prompt; in zsh
// -p takes no value, so its value word may be a name too). What it reads is not known.
func (sc *ownScan) read(rest []rawWord) {
	f := sc.f
	names := func(a rawWord) bool {
		if a.expanded {
			f.hold("read with a word alalanet cannot see (" + clip(a.raw, 40) + ")")
			return false
		}
		n, _, _ := strings.Cut(a.text, "?")
		if strings.Contains(n, "[") && !nameIndex.MatchString(n) {
			f.hold("read with an index that is arithmetic (" + clip(a.raw, 40) + ")")
			return false
		}
		if m := nameIndex.FindStringSubmatch(n); m != nil {
			n = m[1]
		}
		if noSet(n) {
			f.hold("read sets " + clip(n, 40))
			return false
		}
		if ownName(n) {
			f.val(n, valUnknown)
		}
		return true
	}
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		t := a.text
		if !a.expanded && len(t) > 1 && t[0] == '-' && t != "--" { // a quoted option is read's option too
			m := readOpt.FindStringSubmatch(t)
			if m == nil {
				f.hold("read " + clip(t, 20) + ", which alalanet does not read")
				return
			}
			if m[1] != "" && i+1 < len(rest) {
				i++
				if !names(rest[i]) {
					return
				}
			}
			continue
		}
		if t == "--" && !a.expanded {
			continue
		}
		if !names(a) {
			return
		}
	}
}

// forLoop: for NAME [in WORDS]: a literal name, whose values are its words (the second reader judges a lever's).
func (sc *ownScan) forLoop(rest []rawWord) {
	if len(rest) == 0 {
		return // a for with no name: bash and zsh refuse it (prose)
	}
	if rest[0].expanded || !ownName(rest[0].text) {
		sc.f.hold("a for loop alalanet does not read")
		return
	}
	n := rest[0].text
	if ownReread[n] {
		sc.f.hold("a for loop over " + n + ", which the shell reads again")
		return
	}
	if n == "IFS" {
		sc.f.setsIFS = true
	}
	if len(rest) < 2 || rest[1].raw != "in" {
		sc.f.val(n, valUnknown) // the positional words
		return
	}
	for _, a := range rest[2:] {
		sc.f.setVal(n, a.text, a.expanded)
	}
}
