// Package metamorph respells the words of a shell line the way a shell reads back as the same words
// (READER-METAMORPHIC-1): a backslash before a plain character, a word or a part of it in quotes, empty quotes, $'…',
// joined pieces, a backslash-newline. bash, dash and zsh hand such a word to the program unchanged, so a reader of
// install lines must answer the respelled line exactly as it answers the original; every difference is a finding.
//
// It has a lexer of its own, on purpose: it shares no code with internal/installread's splitter, which it tests. The
// lexer is strict. It models single quotes, double quotes, a backslash, comments, the operators that end a command and
// redirections, and refuses a line with anything else that changes how words are read (a substitution, a here-document,
// $'…' in the original, [[ … ]]). It respells only words made of plain characters, never a reserved word, the name
// after for/select/function or a function's name, and never a word of a command with a redirection.
//
// Whether a respelled command is the same to the shells is not this package's word: Oracle writes a script per shell
// that prints each command's words with the builtin printf (nothing of a line is ever run), and Verdicts reads what
// bash, dash and zsh printed. Shells is only what the generator expects; the sweep fails when the shells disagree
// with it.
package metamorph

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Word is one word of a simple command as the line spells it.
type Word struct {
	Start, End int  // the word's bytes in the line
	Plain      bool // only plain characters: no quote, no backslash, nothing a shell expands
}

// Command is one simple command: its words, how many of the first are assignments (NAME=value written plainly), and
// whether it may be respelled (no redirection in it).
type Command struct {
	Words   []Word
	Assigns int
	Redir   bool
	paren   bool // ended by "(": its last word is a function's name or an array's
}

// plain: the characters of a word this package respells. None of them is special to bash, dash or zsh inside a word.
func plain(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("_-./:@=+,%^", c) >= 0
}

func letter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// unmodelled: what makes the lexer refuse a line, in the order it is looked for.
var unmodelled = []string{"$(", "`", "<(", ">(", "<<", "$'", "$\"", "((", "[[", "\r", "\x00", "\x1e",
	// parameters whose value is the shell's state, not the line's: $_ is the last word of the command before (in the
	// oracle, the script of eval itself), $$ and $RANDOM the process and a counter
	"$_", "${_", "$$", "${$", "$!", "$RANDOM", "${RANDOM", "$SRANDOM", "${SRANDOM", "$BASHPID", "${BASHPID", "$SECONDS", "${SECONDS",
	"$EPOCH", "${EPOCH", "$LINENO", "${LINENO", "$PPID", "${PPID", "$BASH_COMMAND", "${BASH_COMMAND", "$HISTCMD", "${HISTCMD"}

var assignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\+?=`)

// reserved: words a shell reads as grammar only when they are spelled plainly (bash, dash, zsh).
var reserved = func() map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields("if then else elif fi case esac for select while until do done in function time coproc { } ! [[ ]] " +
		"repeat foreach end nocorrect noglob") {
		m[w] = true
	}
	return m
}()

// nameAfter: the next word is a name the grammar wants spelled plainly.
var nameAfter = map[string]bool{"for": true, "select": true, "function": true, "coproc": true}

// cmdShaped: a line the reader reads with cmd.exe's rules, not a POSIX shell's — a cmd "set NAME=value" with a %VAR%
// and a ";" list, or cmd /c … . The oracle is bash, dash and zsh, which cannot judge these, so the generator leaves
// them out (READER-ESCAPE-1: cmd and PowerShell are read from documentation, not this oracle).
func cmdShaped(line string) bool {
	low := strings.ToLower(line)
	if (strings.Contains(low, "set ") || strings.Contains(low, "set\t")) && strings.Contains(line, "%") && strings.Contains(line, ";") {
		return true
	}
	return strings.Contains(low, "cmd /c") || strings.Contains(low, "cmd /k") || strings.Contains(low, "cmd.exe")
}

// Lex splits a line into simple commands and words. why is not "" when the line has something the lexer does not
// model; then there are no commands.
func Lex(line string) (cmds []Command, why string) {
	for _, u := range unmodelled {
		if strings.Contains(line, u) {
			return nil, "has " + strconv.Quote(u)
		}
	}
	if cmdShaped(line) {
		return nil, "cmd.exe-shaped, outside the posix oracle"
	}
	var cur Command
	start, isPlain := -1, true
	endWord := func(i int) {
		if start >= 0 {
			cur.Words = append(cur.Words, Word{Start: start, End: i, Plain: isPlain})
			start, isPlain = -1, true
		}
	}
	endCmd := func(i int, paren bool) {
		endWord(i)
		if len(cur.Words) > 0 {
			for cur.Assigns < len(cur.Words) && assignment.MatchString(line[cur.Words[cur.Assigns].Start:cur.Words[cur.Assigns].End]) {
				cur.Assigns++
			}
			cur.paren = paren
			cmds = append(cmds, cur)
		}
		cur = Command{}
	}
	in := func(i int, p bool) {
		if start < 0 {
			start = i
		}
		isPlain = isPlain && p
	}
	for i := 0; i < len(line); i++ {
		switch c := line[i]; {
		case c == '$' && i+1 < len(line) && line[i+1] == '{':
			// ${VAR}, ${X:+word word}: the shell expands it at runtime, so the text inside is not argv words and is
			// never respelled. Absorb the whole expansion to its matching } as one non-plain part of the word.
			in(i, false)
			depth := 0
			for ; i < len(line); i++ {
				if line[i] == '{' {
					depth++
				} else if line[i] == '}' {
					if depth--; depth == 0 {
						break
					}
				}
			}
			if i >= len(line) {
				return nil, "an unclosed ${"
			}
		case c == '\\':
			if i+1 == len(line) {
				return nil, "ends in a backslash"
			}
			if line[i+1] == '\n' { // a line continuation: no character of a word, and no end of one
				if start >= 0 {
					isPlain = false
				}
				i++
				continue
			}
			in(i, false)
			i++
		case c == '\'':
			j := strings.IndexByte(line[i+1:], '\'')
			if j < 0 {
				return nil, "an open quote"
			}
			in(i, false)
			i += j + 1
		case c == '"':
			in(i, false)
			j := i + 1
			for ; j < len(line) && line[j] != '"'; j++ {
				if line[j] == '\\' {
					j++
				}
			}
			if j >= len(line) {
				return nil, "an open quote"
			}
			i = j
		case c == ' ' || c == '\t':
			endWord(i)
		case c == '#' && start < 0:
			for i+1 < len(line) && line[i+1] != '\n' {
				i++
			}
		case c == '<' || c == '>' || c == '&' && i+1 < len(line) && line[i+1] == '>':
			// a redirection: [n]>word, >>word, >|word, <word, <>word, n>&m, >&-, &>word. The command is not respelled.
			if start >= 0 && strings.Trim(line[start:i], "0123456789") == "" {
				start, isPlain = -1, true // the descriptor's number
			}
			endWord(i)
			cur.Redir = true
			if c == '&' {
				i++
			}
			for i+1 < len(line) && strings.IndexByte("<>|", line[i+1]) >= 0 {
				i++
			}
			if i+1 < len(line) && line[i+1] == '&' {
				i++
				for i+1 < len(line) && (line[i+1] >= '0' && line[i+1] <= '9' || line[i+1] == '-') {
					i++
				}
			}
		case (c == '(' || c == ')') && (start >= 0 || c == ')' && i+1 < len(line) && strings.IndexByte(" \t\n;&|)", line[i+1]) < 0):
			// a ( attached to a word, or a ) a word follows: a zsh glob group (./e?al(:t)) or a syntax error in bash, and
			// Markdown in prose ([Docs](https://…)) — no subshell, so its words are not argv words: not modelled
			return nil, "a parenthesis attached to a word"
		case c == '\n' || c == ';' || c == '&' || c == '|' || c == '(' || c == ')':
			endCmd(i, c == '(')
		default:
			in(i, plain(c))
		}
	}
	endCmd(len(line), false)
	return cmds, ""
}

// Rewrite is one respelling of one word of a line.
type Rewrite struct {
	Line string // the line with the word respelled
	Kind string // how: bs-first, bs-mid, bs-last, bs-sym, sq, dq, sq-part, dq-part, empty-start, empty-mid, empty-end, ansi, ansi-part, joined, cont
	Role string // the word in its command: program, option, assign-prefix, assign-arg, arg1, arg
	// Shells: the shells the generator expects to read the respelled command as the original: "all" (bash, dash, zsh),
	// "bash,zsh" ($'…', which dash does not have) or "none" (the name of an assignment before a command, which a quote
	// or a backslash turns into a command's name).
	Shells string
	// Orig and Dump: the oracle's units, the original command and the respelled one, each a script that only prints
	// words with the builtin printf.
	Orig, Dump string
}

// Kinds: every kind Rewrites gives, in the order it gives them.
var Kinds = []string{"bs-first", "bs-mid", "bs-last", "bs-sym", "sq", "dq", "sq-part", "dq-part", "empty-start", "empty-mid", "empty-end",
	"ansi", "ansi-part", "joined", "cont"}

// Rewrites gives the respellings of every plain word of a line; none for a line Lex refuses.
func Rewrites(line string) []Rewrite {
	cmds, why := Lex(line)
	if why != "" {
		return nil
	}
	var out []Rewrite
	for _, c := range cmds {
		if c.Redir {
			continue
		}
		orig := dump(line, c, -1, "")
		arg1 := false
		for i, w := range c.Words {
			text := line[w.Start:w.End]
			role := "arg"
			switch {
			case i < c.Assigns:
				role = "assign-prefix"
			case i == c.Assigns:
				role = "program"
			case strings.HasPrefix(text, "-"):
				role = "option"
			case assignment.MatchString(text):
				role = "assign-arg"
			case !arg1:
				role, arg1 = "arg1", true
			}
			if !w.Plain || text == "" || text[0] == '=' || reserved[text] || i > 0 && nameAfter[line[c.Words[i-1].Start:c.Words[i-1].End]] ||
				c.paren && i == len(c.Words)-1 {
				continue
			}
			for _, r := range spellings(text) {
				shells := "all"
				if strings.HasPrefix(r.kind, "ansi") {
					shells = "bash,zsh"
				}
				if role == "assign-prefix" && r.kind != "cont" && r.at <= strings.IndexByte(text, '=') {
					shells = "none" // the name or the "=" is quoted: the shell runs a command of that name
				}
				out = append(out, Rewrite{Line: line[:w.Start] + r.text + line[w.End:], Kind: r.kind, Role: role, Shells: shells,
					Orig: orig, Dump: dump(line, c, i, r.text)})
			}
		}
	}
	return out
}

type spelling struct {
	kind, text string
	at         int // the first byte of the word the spelling quotes or escapes (where empty quotes are put)
}

// spellings: the respellings of a plain word.
func spellings(w string) []spelling {
	var out []spelling
	add := func(kind string, at int, text string) { out = append(out, spelling{kind, text, at}) }
	var letters []int
	sym := -1
	for i := 0; i < len(w); i++ {
		if letter(w[i]) {
			letters = append(letters, i)
		} else if sym < 0 {
			sym = i
		}
	}
	bs := func(kind string, i int) { add(kind, i, w[:i]+`\`+w[i:]) }
	if n := len(letters); n > 0 {
		bs("bs-first", letters[0])
		if n > 2 {
			bs("bs-mid", letters[n/2])
		}
		if n > 1 {
			bs("bs-last", letters[n-1])
		}
	}
	if sym >= 0 {
		bs("bs-sym", sym)
	}
	h := len(w) / 2
	add("sq", 0, "'"+w+"'")
	add("dq", 0, `"`+w+`"`)
	if len(w) > 1 {
		add("sq-part", h, w[:h]+"'"+w[h:]+"'")
		add("dq-part", 0, `"`+w[:h]+`"`+w[h:])
	}
	add("empty-start", 0, "''"+w)
	if len(w) > 1 {
		add("empty-mid", h, w[:h]+`""`+w[h:])
	}
	add("empty-end", len(w), w+`""`)
	add("ansi", 0, "$'"+w+"'")
	if len(w) > 1 {
		add("ansi-part", h, w[:h]+"$'"+w[h:]+"'")
	}
	if len(w) > 2 { // i""n'st'all
		k := min(4, len(w))
		add("joined", 1, w[:1]+`""`+w[1:2]+"'"+w[2:k]+"'"+w[k:])
	}
	if len(w) > 1 {
		add("cont", h, w[:h]+"\\\n"+w[h:])
	}
	return out
}

// dump: the script that prints a command's words, word i respelled as text (i < 0: as written). All words as the
// arguments of printf; and, for a command with assignments before it, a second printf of the words after them with
// the assignments left where they are, so that a respelling the shell no longer takes as an assignment fails to
// print (the shell looks for a command of that name, and PATH has none).
func dump(line string, c Command, i int, text string) string {
	word := func(j int) string {
		if j == i {
			return text
		}
		return line[c.Words[j].Start:c.Words[j].End]
	}
	var all, pre, rest []string
	for j := range c.Words {
		all = append(all, word(j))
		if j < c.Assigns {
			pre = append(pre, word(j))
		} else {
			rest = append(rest, word(j))
		}
	}
	s := `printf '%s\0' ` + strings.Join(all, " ")
	if len(pre) > 0 {
		s += "\n" + strings.Join(pre, " ") + ` printf '%s\0' ` + strings.Join(rest, " ")
	}
	return s
}

// Corpus reads files of one JSON string a line (the reviewers' format) and gives the distinct lines in order.
func Corpus(files ...string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		for _, l := range bytes.Split(b, []byte("\n")) {
			var s string
			if json.Unmarshal(l, &s) != nil || s == "" || seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, s)
		}
	}
	return out, nil
}

// Units numbers the distinct dump scripts of a sweep.
type Units struct {
	id      map[string]int
	Scripts []string
}

// ID is the number of a dump script, a new one for a script not seen before.
func (u *Units) ID(script string) int {
	if u.id == nil {
		u.id = map[string]int{}
	}
	n, ok := u.id[script]
	if !ok {
		n = len(u.Scripts)
		u.id[script] = n
		u.Scripts = append(u.Scripts, script)
	}
	return n
}

// OracleShells: the shells of the oracle.
var OracleShells = []string{"bash", "dash", "zsh"}

const frame = "\n\x1e"

// Oracle writes the units as shell scripts, chunk-NNN.sh in dir, the same for bash, dash and zsh. Each unit is one
// eval of the dump script in a subshell, then a frame with its exit status: a unit that does not parse or fails
// cannot touch the next. The scripts set PATH to a folder that does not exist: only builtins can run.
func (u *Units) Oracle(dir string, chunks int) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	per := (len(u.Scripts) + chunks - 1) / chunks
	for c := 0; c < chunks; c++ {
		var b bytes.Buffer
		b.WriteString("PATH=/nonexistent\nexport PATH\n")
		for i := c * per; i < min((c+1)*per, len(u.Scripts)); i++ {
			b.WriteString("( eval '" + strings.ReplaceAll(u.Scripts[i], "'", `'\''`) + "' ) 2>/dev/null\nprintf '\\n\\036%s\\036\\n' \"$?\"\n")
		}
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("chunk-%03d.sh", c)), b.Bytes(), 0o644); err != nil {
			return err
		}
	}
	return os.WriteFile(filepath.Join(dir, "units.txt"), []byte(fmt.Sprintf("%d units, %d chunks, %x\n", len(u.Scripts), chunks, u.sum())), 0o644)
}

func (u *Units) sum() []byte {
	h := sha256.New()
	for _, s := range u.Scripts {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	return h.Sum(nil)[:8]
}

// Verdicts reads what a shell printed for the chunks (out-SHELL-NNN.bin in dir): for every unit, the hash of its
// output, "" for a unit that failed. An error when the outputs are not those of these units.
func (u *Units) Verdicts(dir, shell string, chunks int) ([]string, error) {
	want, err := os.ReadFile(filepath.Join(dir, "units.txt"))
	if err != nil {
		return nil, err
	}
	if got := fmt.Sprintf("%d units, %d chunks, %x\n", len(u.Scripts), chunks, u.sum()); got != string(want) {
		return nil, fmt.Errorf("the oracle's scripts are of other units: %q, these are %q", strings.TrimSpace(string(want)), strings.TrimSpace(got))
	}
	out := make([]string, 0, len(u.Scripts))
	per := (len(u.Scripts) + chunks - 1) / chunks
	for c := 0; c < chunks; c++ {
		f, err := os.Open(filepath.Join(dir, fmt.Sprintf("out-%s-%03d.bin", shell, c)))
		if err != nil {
			return nil, err
		}
		r := bufio.NewReaderSize(f, 1<<20)
		n := min((c+1)*per, len(u.Scripts)) - c*per
		for i := 0; i < n; i++ {
			body, status, err := readFrame(r)
			if err != nil {
				f.Close()
				return nil, fmt.Errorf("%s chunk %d unit %d of %d: %v", shell, c, i, n, err)
			}
			if status != "0" {
				out = append(out, "")
				continue
			}
			sum := sha256.Sum256(body)
			out = append(out, string(sum[:12]))
		}
		if _, err := r.ReadByte(); err == nil {
			f.Close()
			return nil, fmt.Errorf("%s chunk %d: output after its %d units", shell, c, n)
		}
		f.Close()
	}
	return out, nil
}

// readFrame: a unit's output up to the frame, and the status in the frame.
func readFrame(r *bufio.Reader) (body []byte, status string, err error) {
	for {
		part, err := r.ReadBytes(0x1e)
		if err != nil {
			return nil, "", fmt.Errorf("no frame: %v", err)
		}
		body = append(body, part...)
		if !bytes.HasSuffix(body, []byte(frame)) {
			continue
		}
		st, err := r.ReadBytes('\n')
		if err != nil || !bytes.HasSuffix(st, []byte("\x1e\n")) {
			return nil, "", fmt.Errorf("a broken frame")
		}
		return body[:len(body)-len(frame)], string(st[:len(st)-2]), nil
	}
}

// Item is one rewrite of a sweep: the original line's number, the rewrite (without its scripts) and its units.
type Item struct {
	Line         int
	Rewrite      Rewrite
	Orig, Dumped int
}

// Sweep: the rewrites of a corpus and the oracle's units for them.
type Sweep struct {
	Lines   []string
	Refused int // lines Lex refuses
	Items   []Item
	Units   Units
}

// NewSweep generates the rewrites of every line of the files.
func NewSweep(files ...string) (*Sweep, error) {
	lines, err := Corpus(files...)
	if err != nil {
		return nil, err
	}
	s := &Sweep{Lines: lines}
	for n, l := range lines {
		if _, why := Lex(l); why != "" {
			s.Refused++
			continue
		}
		for _, r := range Rewrites(l) {
			it := Item{Line: n, Orig: s.Units.ID(r.Orig), Dumped: s.Units.ID(r.Dump)}
			r.Orig, r.Dump = "", ""
			it.Rewrite = r
			s.Items = append(s.Items, it)
		}
	}
	return s, nil
}

// Judged: what the shells made of one rewrite.
type Judged struct {
	Item
	OrigOK  bool // every shell printed the original command's words
	Same    bool // bash, dash and zsh printed the rewrite's words exactly as the original's
	BashZsh bool // bash and zsh did (dash has no $'…')
	Unlike  bool // the shells disagree with the generator's Shells
}

// Judge reads the oracle's outputs for the sweep's units.
func (s *Sweep) Judge(dir string, chunks int) ([]Judged, error) {
	v := map[string][]string{}
	for _, sh := range OracleShells {
		got, err := s.Units.Verdicts(dir, sh, chunks)
		if err != nil {
			return nil, err
		}
		v[sh] = got
	}
	same := func(sh string, a, b int) bool { return v[sh][a] != "" && v[sh][a] == v[sh][b] }
	out := make([]Judged, len(s.Items))
	for i, it := range s.Items {
		j := Judged{Item: it, OrigOK: v["bash"][it.Orig] != "" && v["dash"][it.Orig] != "" && v["zsh"][it.Orig] != ""}
		j.BashZsh = same("bash", it.Orig, it.Dumped) && same("zsh", it.Orig, it.Dumped)
		j.Same = j.BashZsh && same("dash", it.Orig, it.Dumped)
		if j.OrigOK {
			switch it.Rewrite.Shells {
			case "all":
				j.Unlike = !j.Same
			case "bash,zsh":
				j.Unlike = !j.BashZsh || j.Same
			case "none":
				j.Unlike = j.BashZsh || same("dash", it.Orig, it.Dumped)
			}
		}
		out[i] = j
	}
	return out, nil
}
