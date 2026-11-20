package installread

import "regexp"

// READER-EXPANSION-ENV-1 (ADR-0159 round 26): ${NAME:=word} and ${NAME=word} assign NAME in the shell that expands
// them — in any word, quoted or not — and under set -a (set -o allexport), or with a later export NAME, the install
// runs with it. As a class, both line readers judge such an assignment as they judge export NAME=word on the line
// (configEnv, the second reader's env), whether or not the line exports it; one whose name they cannot place
// (${!ref:=word}, ${!ref=word}) holds a line that installs. ${NAME:-word}, ${NAME+word} and the others assign nothing.

// expansionAssign: the start of an assigning parameter expansion, ${[!]NAME:=…}, ${[!]NAME=…} or zsh's
// ${NAME::=…}.
var expansionAssign = regexp.MustCompile(`\$\{(!?)[~=^]*([A-Za-z_][A-Za-z0-9_]*)(::=|:=|=)`) // zsh's ~ = ^ before the name (round 28)

// expansionFlagged: zsh's flagged expansion that assigns, ${(P)ref:=…}, ${(A)name::=…}: the name may be indirect, so
// it is held as ${!ref:=…} is (round 27).
var expansionFlagged = regexp.MustCompile(`\$\{\([^)}]*\)[^}=]*=`)

// expansionAssigns: the assignments a word's parameter expansions make, as (NAME, word) — the word up to the brace that
// closes the expansion, or to the end of the word when none does — and whether one assigns by an indirect name.
func expansionAssigns(w string) (pairs [][2]string, indirect bool) {
	indirect = expansionFlagged.MatchString(w)
	for _, m := range expansionAssign.FindAllStringSubmatchIndex(w, -1) {
		if m[3] > m[2] {
			indirect = true
			continue
		}
		depth, j := 1, m[1]
		for ; j < len(w); j++ {
			if w[j] == '{' {
				depth++
			} else if w[j] == '}' {
				if depth--; depth == 0 {
					break
				}
			}
		}
		pairs = append(pairs, [2]string{w[m[4]:m[5]], w[m[1]:j]})
	}
	return pairs, indirect
}

// CommandExpansionAssigns: the assignments the parameter expansions in one command's words and VAR=value words make
// (expansionAssigns), as (NAME, word): alalanet-agent sets them in the environment pip expands a requirements file's
// ${NAME} from, as it sets an export of the line (round 26).
func CommandExpansionAssigns(c Command) [][2]string {
	var out [][2]string
	for _, w := range append(append([]string{}, c.Assigns...), c.Words...) {
		pairs, _ := expansionAssigns(w)
		out = append(out, pairs...)
	}
	return out
}

// Round 27 (P2-U): the other ways one line assigns a variable in its own shell that these readers judge as an
// export: an expansion in a redirection's word (echo x > /dev/null${NAME:=word}); arithmetic — $(( … )), (( … )), let,
// and an indexed array's subscript (a[NAME=1]) — whose NAME=, NAME+= … (not ==, <=, >=, !=) and NAME++, --NAME set
// NAME to a number, judged as export NAME=1 (a number: a relative folder for PATH, a file name for a config lever).
// What the second reader judges besides (read, printf -v, for, select, getopts, nameref …) is its own (extra.go).

// segAssigns: the assignments one segment's words and redirection words make by expansion, and its let's.
func segAssigns(sg shellSeg) [][2]string {
	var out [][2]string
	for _, w := range append(append([]string{}, sg.words...), sg.redirs...) {
		pairs, _ := expansionAssigns(w)
		out = append(out, pairs...)
	}
	if cmd, rest := unwrapped(sg.words); cmd == "let" {
		for _, a := range rest {
			for _, n := range arithNames(a) {
				out = append(out, [2]string{n, "1"})
			}
		}
	}
	return out
}

// segIndirect: a segment's expansion assigns a variable by a name the line does not show.
func segIndirect(sg shellSeg) bool {
	for _, w := range append(append([]string{}, sg.words...), sg.redirs...) {
		if _, ind := expansionAssigns(w); ind {
			return true
		}
	}
	if cmd, rest := unwrapped(sg.words); cmd == "let" {
		for _, a := range rest {
			if arithIndirect.MatchString(a) { // let $n=1 (round 28)
				return true
			}
		}
	}
	return false
}

// arithAssign: an arithmetic assignment's name and operator (=, +=, -=, *=, /=, %=, <<=, >>=, &=, ^=, |=); arithStep:
// an increment or a decrement of a name.
var (
	arithAssign = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\])?\s*(<<|>>|[-+*/%^|&])?=`)
	arithStep   = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\s*(?:\+\+|--)|(?:\+\+|--)\s*([A-Za-z_][A-Za-z0-9_]*)`)
)

// arithIndirect: an arithmetic assignment to a name that is itself an expansion — (( $n = 1 )), let $n=1, ${n}+=1 — a
// name the line does not show (round 28, rule 2).
var arithIndirect = regexp.MustCompile(`\$\{?[A-Za-z_0-9!#@*]+\}?\s*(?:<<|>>|[-+*/%^|&])?=(?:[^=]|$)|(?:\+\+|--)\s*\$|\$\{?[A-Za-z_0-9]+\}?\s*(?:\+\+|--)`)

// arithNames: the names an arithmetic expression assigns.
func arithNames(e string) []string {
	var names []string
	for _, m := range arithAssign.FindAllStringSubmatchIndex(e, -1) {
		end := m[1]
		if m[4] < 0 && end < len(e) && e[end] == '=' {
			continue // ==
		}
		names = append(names, e[m[2]:m[3]])
	}
	for _, m := range arithStep.FindAllStringSubmatch(e, -1) {
		names = append(names, m[1]+m[2])
	}
	return names
}

// lineArith: the names the arithmetic of a shell text assigns — (( … )) and $(( … )), and an indexed array's
// subscript (NAME[…]) — read in the raw text outside single quotes (the tokenizer takes (( apart); a body that does
// not close runs to the end. Each is judged as export NAME=1.
func lineArith(s string) (out [][2]string, indirect bool) {
	add := func(body string) {
		for _, n := range arithNames(body) {
			out = append(out, [2]string{n, "1"})
		}
		indirect = indirect || arithIndirect.MatchString(body)
	}
	rs := []rune(s)
	q := rune(0)
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch {
		case q == '\'':
			if c == '\'' {
				q = 0
			}
			continue
		case c == '\\':
			i++
			continue
		case c == '$' && q == 0 && i+1 < len(rs) && rs[i+1] == '\'':
			// $'…': an ANSI-C string, in which \' does not close it (round 28: $'\'' hid the rest of the line)
			for i += 2; i < len(rs) && rs[i] != '\''; i++ {
				if rs[i] == '\\' {
					i++
				}
			}
			continue
		case c == '"':
			if q == '"' {
				q = 0
			} else {
				q = '"'
			}
			continue
		case c == '\'' && q == 0:
			q = '\''
			continue
		}
		var open, close rune
		start := -1
		switch {
		case c == '(' && i+1 < len(rs) && rs[i+1] == '(':
			open, close, start = '(', ')', i+2
		case c == '[' && i > 0 && (rs[i-1] == '_' || rs[i-1] >= 'A' && rs[i-1] <= 'Z' || rs[i-1] >= 'a' && rs[i-1] <= 'z' ||
			rs[i-1] >= '0' && rs[i-1] <= '9'):
			open, close, start = '[', ']', i+1
		default:
			continue
		}
		depth, j := 1, start
		if open == '(' {
			depth = 2
		}
		for ; j < len(rs) && depth > 0; j++ {
			switch rs[j] {
			case open:
				depth++
			case close:
				depth--
			}
		}
		add(string(rs[start:j]))
		i = j - 1 // the body is read, and what nests in it with it: one pass over the text
	}
	return out, indirect
}
