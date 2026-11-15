package installread

import "strings"

// Command substitutions, read apart (ADR-0131, eighth round). The production splitter cuts a line at
// "$(", "`" and ")" outside quotes and keeps a substitution inside double quotes as text, so
// FOO=$(true)x npx -y pkg loses its install (its words are "FOO=", "true", "x npx -y pkg") and
// echo "$(npm i -g pkg)" runs one that nothing reads. The second reader used to ask whenever a
// substitution and an install shared a line, which held scripts that only compute a version or a
// folder (seventh review: about fifteen blocks of its README corpus). unnest reads the line the way a
// shell joins it instead: each substitution leaves a mark inside its word and its own text is read as
// a command, so a reason is given only for an install the production reader does not check.

// Marks left where a substitution stood. Each is a parameter expansion: the splitter keeps it inside
// the word, and both readers take it for a variable whose value they do not know.
const (
	markSubst = "${_s}"  // $(…) or `…`: a command's output
	markInit  = "${_e}"  // eval "$(pyenv init -)": the output of a toolchain's own init command
	markProc  = "${_p}"  // <(…): a file made of a command's output
	markPwd   = "${PWD}" // $(pwd)
)

// markText puts a substitution back into a reason shown to the user.
var markText = strings.NewReplacer(markSubst, "$(…)", markInit, "$(…)", markProc, "<(…)")

const (
	maxSubst     = 1024 // substitutions read apart in one command
	maxSubstNest = 16   // and how deep they nest; past either the rest stays as the production reader reads it
	maxHereWord  = 256  // bytes looked at for a here-document's delimiter
	maxEvalGap   = 16   // blanks between eval and its argument
)

// shellSpecial: what a backslash escapes outside quotes; the splitter's own list.
const shellSpecial = "'\"\\ $`;|&#()<>{}\n\t*?[]~!"

type substFrame struct {
	kind   byte   // 0 the line itself, '(' $(…), '<' <(…), '`' backticks
	q      byte   // an open quote: ' or ", or $ for $'…'
	word   bool   // inside a word, where "#" starts no comment
	eval   bool   // the argument of eval
	hdTabs bool   // <<-: the delimiter line may start with tabs
	paren  int    // plain parentheses open inside $(…)
	brace  int    // ${…} open: quotes and "#" inside belong to the expansion, as the splitter takes them
	hd     string // a here-document's delimiter, from "<<" to the end of that line
	buf    []byte
}

// unnest takes the command substitutions of a line apart. pieces[0] is the line with a mark in place
// of each substitution, the rest are the substitutions' own texts (their inner ones marked as well),
// innermost first. nil when the line has none. over: the line has more substitutions, or deeper ones,
// than are read apart; what follows the last one read stays in its piece as written.
//
// It keeps to the splitter's reading of quotes, escapes, comments, ${…}, redirections and here-
// documents (a body is copied as written: the splitter reads it line by line), so that a piece splits
// the way the line did. Where it differs, it is the shell's reading: "$(" inside double quotes opens a
// command with quotes of its own, $((1+2)) is read like $( … ), and a here-document inside $( … ) may
// end with "EOF)". Linear: each byte is written once, and a substitution's text is looked at once
// when it closes.
func unnest(line string) (pieces []string, over bool) {
	stack := make([]substFrame, 1, 8)
	var inner []string
	opened := 0
	pop := func() {
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		p := &stack[len(stack)-1]
		body := strings.TrimSpace(string(f.buf))
		mark := markSubst
		switch {
		case body == "":
			mark = "" // $(): nothing
		case f.kind == '<':
			mark = markProc
		case body == "pwd" || body == "pwd -P" || body == "pwd -L":
			mark, body = markPwd, ""
		case f.eval && initCommand(body):
			mark = markInit
		}
		if mark != "" {
			p.buf = append(p.buf, mark...)
			p.word = true
		}
		if body != "" {
			inner = append(inner, body)
		}
	}
	n := len(line)
	for i := 0; i < n; i++ {
		f := &stack[len(stack)-1]
		c := line[i]
		next := byte(0)
		if i+1 < n {
			next = line[i+1]
		}
		opens := c == '`' || c == '$' && next == '('
		switch {
		case f.kind == '`' && c == '\\' && next == '`': // an escaped backtick does not end the substitution
			f.buf = append(f.buf, c, next)
			f.word = true
			i++
		case f.kind == '`' && c == '`':
			pop() // the first backtick ends it, quoted or not
		case f.q == '\'':
			f.buf = append(f.buf, c)
			if c == '\'' {
				f.q = 0
			}
		case f.q == '$': // $'…': a backslash escapes the next character
			f.buf = append(f.buf, c)
			if c == '\\' && i+1 < n {
				f.buf = append(f.buf, next)
				i++
			} else if c == '\'' {
				f.q = 0
			}
		case f.q == '"' && c == '\\' && i+1 < n:
			f.buf = append(f.buf, c, next)
			i++
		case f.q == '"' && !opens:
			f.buf = append(f.buf, c)
			if c == '"' {
				f.q = 0
			}
		case f.brace > 0 && !opens:
			f.buf = append(f.buf, c)
			if c == '{' {
				f.brace++
			} else if c == '}' {
				f.brace--
			}
		case opens, c == '<' && next == '(':
			if opened >= maxSubst || len(stack) > maxSubstNest {
				over = true
				f.buf = append(f.buf, line[i:]...)
				i = n
				break
			}
			kind := byte('(')
			if c != '$' {
				kind = c
			}
			stack = append(stack, substFrame{kind: kind, eval: kind != '<' && afterEval(f.buf)})
			opened++
			if c != '`' {
				i++ // the "("
			}
		case c == '\\' && next == '\n': // a line continuation: no word starts or ends
			f.buf = append(f.buf, c, next)
			i++
		case c == '\\' && i+1 < n && strings.IndexByte(shellSpecial, next) >= 0:
			f.buf = append(f.buf, c, next)
			f.word = true
			i++
		case c == '$' && next == '\'':
			f.buf = append(f.buf, c, next)
			f.q, f.word = '$', true
			i++
		case c == '\'' || c == '"':
			f.buf = append(f.buf, c)
			f.q, f.word = c, true
		case c == '#' && !f.word: // a comment to the end of the line; a backtick still ends its substitution
			j := i
			for j < n && line[j] != '\n' && (line[j] != '`' || f.kind != '`') {
				j++
			}
			f.buf = append(f.buf, line[i:j]...)
			i = j - 1
		case c == '\n' && f.hd != "": // the here-document's body, up to its delimiter line
			f.buf = append(f.buf, c)
			f.word = false
			hd, tabs := f.hd, f.hdTabs
			f.hd, f.hdTabs = "", false
			pos := i + 1
			i = n // unless the body ends before the line does
			for pos < n {
				end := strings.IndexByte(line[pos:], '\n')
				if end < 0 {
					end = n
				} else {
					end += pos
				}
				l := line[pos:end]
				t := l
				if tabs {
					t = strings.TrimLeft(l, "\t")
				}
				if t == hd {
					f.buf = append(f.buf, l...)
					if end < n {
						f.buf = append(f.buf, '\n')
					}
					i = end
					break
				}
				if (f.kind == '(' || f.kind == '<') && strings.HasPrefix(t, hd) && t[len(hd)] == ')' {
					k := end - len(t) + len(hd) // $(cat <<EOF … EOF): the shell ends the body there
					f.buf = append(f.buf, line[pos:k]...)
					i = k - 1
					break
				}
				if k := strings.IndexByte(l, '`'); k >= 0 && f.kind == '`' {
					f.buf = append(f.buf, l[:k]...)
					i = pos + k - 1
					break
				}
				f.buf = append(f.buf, l...)
				if end < n {
					f.buf = append(f.buf, '\n')
				}
				pos = end + 1
			}
		case c == '$' && next == '{':
			f.buf = append(f.buf, c, next)
			f.brace, f.word = 1, true
			i++
		case c == '<' && next == '<':
			f.word = false
			if i+2 < n && line[i+2] == '<' { // <<< word: a here-string
				f.buf = append(f.buf, "<<<"...)
				i += 2
				break
			}
			f.buf = append(f.buf, "<<"...)
			i++
			if f.hdTabs = i+1 < n && line[i+1] == '-'; f.hdTabs {
				f.buf = append(f.buf, '-')
				i++
			}
			f.hd = hereWord(line[i+1:])
		case c == '(' && (f.kind == '(' || f.kind == '<'):
			f.buf = append(f.buf, c)
			f.paren++
			f.word = false
		case c == ')' && (f.kind == '(' || f.kind == '<'):
			if f.paren == 0 {
				pop()
				break
			}
			f.buf = append(f.buf, c)
			f.paren--
			f.word = false
		case c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ';' || c == '|' || c == '&' ||
			c == '(' || c == ')' || c == '{' || c == '}' || c == '<' || c == '>':
			f.buf = append(f.buf, c)
			f.word = false
		default:
			f.buf = append(f.buf, c)
			f.word = true
		}
	}
	if opened == 0 {
		return nil, false
	}
	for len(stack) > 1 {
		pop() // a substitution the line leaves open
	}
	return append([]string{string(stack[0].buf)}, inner...), over
}

// hereWord: the delimiter of a here-document, the word after "<<" with its quotes and backslashes
// removed (<<EOF, <<'EOF', <<\EOF); "" when no word ends within maxHereWord bytes.
func hereWord(s string) string {
	cut := len(s) > maxHereWord
	if cut {
		s = s[:maxHereWord]
	}
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r') {
		i++
	}
	var w []byte
	for q := byte(0); i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0 && c == q:
			q = 0
		case q != 0:
			w = append(w, c)
		case c == '\'' || c == '"':
			q = c
		case c == '\\':
		case c == ' ' || c == '\t' || c == '\r' || c == '\n' || strings.IndexByte(";|&(){}<>`", c) >= 0:
			return string(w)
		default:
			w = append(w, c)
		}
	}
	if cut {
		return ""
	}
	return string(w)
}

// afterEval: the text ends with the word eval and the start of its argument (eval $(…), eval "$(…)").
func afterEval(b []byte) bool {
	i := len(b)
	if i > 0 && b[i-1] == '"' {
		i--
	}
	j := i
	for j > 0 && i-j < maxEvalGap && (b[j-1] == ' ' || b[j-1] == '\t') {
		j--
	}
	if j == i || j < 4 || string(b[j-4:j]) != "eval" {
		return false
	}
	return j == 4 || strings.IndexByte(" \t\n;|&(){}", b[j-5]) >= 0
}

// initTools: programs whose output a shell profile evals to set up a toolchain installed on the
// machine, with the subcommand that prints it (each tool's own documentation; a name ending in "." is
// a prefix: conda shell.bash hook). Their output is the user's setup, not a file of the repository:
// eval "$(pyenv init -)" && pip install -r requirements.txt is no environment loaded from a file.
// Tools that load a file of the current folder into the environment (direnv, mise) are not here.
var initTools = map[string][]string{
	"pyenv": {"init", "virtualenv-init"}, "rbenv": {"init"}, "nodenv": {"init"}, "goenv": {"init"}, "jenv": {"init"},
	"conda": {"shell."}, "mamba": {"shell"}, "micromamba": {"shell"}, "fnm": {"env"}, "brew": {"shellenv"},
	"ssh-agent": nil, "starship": {"init"}, "zoxide": {"init"}, "minikube": {"docker-env", "podman-env"},
	"docker-machine": {"env"},
}

// initCommand: one simple command of an init tool, by a bare name or a path outside the current and
// the temporary folders, with nothing piped, chained or substituted into it.
func initCommand(body string) bool {
	if strings.ContainsAny(body, "\n\r") {
		return false
	}
	w := strings.Fields(body)
	if n := len(w); n >= 2 && w[n-2] == "2>" && w[n-1] == "/dev/null" {
		w = w[:n-2]
	} else if n >= 1 && w[n-1] == "2>/dev/null" {
		w = w[:n-1]
	}
	if len(w) == 0 {
		return false
	}
	tool := w[0]
	if strings.Contains(tool, "/") {
		rooted := false
		for _, p := range []string{"/", "~/", "$HOME/", "${HOME}/"} {
			if rest, ok := strings.CutPrefix(tool, p); ok {
				tool, rooted = rest, true
				break
			}
		}
		if !rooted || strings.Contains(tool, "..") || tmpMarker(strings.ToLower(w[0])) {
			return false // the current folder, a way out of a folder, a folder anyone can write to
		}
	}
	for _, x := range append([]string{tool}, w[1:]...) {
		if strings.ContainsAny(x, ";|&<>`$(){}\\\"'*?[]~") {
			return false
		}
	}
	subs, ok := initTools[tool[strings.LastIndexByte(tool, '/')+1:]]
	if !ok {
		return false
	}
	if subs == nil {
		return true
	}
	for _, x := range w[1:] {
		for _, s := range subs {
			if x == s || strings.HasSuffix(s, ".") && strings.HasPrefix(x, s) {
				return true
			}
		}
	}
	return false
}
