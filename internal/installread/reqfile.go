package installread

import (
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// READER-REQFILE-1 (ADR-0159 round 12): a requirements-format file named on an install line — pip install -r FILE,
// -c FILE, uv pip install -r, uv add -r, uv pip sync FILE, --with-requirements — can name an index of its own
// (--index-url, --extra-index-url, --find-links on an option line), which install_check never sees: it reads the line,
// not the user's files. RequirementFiles names those files. For install_check a named file is a fact, never a hold: it
// answers for what the line shows and says that the file was not read (RequirementFilesFact; the coordinator's
// decision, ADR-0159 round 13). alalanet-agent's hook runs on the machine and reads the files (ReqFileReasons). The
// hook's reading of the line itself is unchanged: pip install -r requirements.txt is the most common install line there
// is, and the server cannot read the file either.

// ReqFileNotRead: install_check's fact (an info code, which holds nothing) for a line that names a requirements-format
// file: the file was not read, so what it installs, and from where, is not in the answer.
const ReqFileNotRead = "requirements_file_not_read"

// RequirementFiles: the requirements-format files a line's installs read, as written, in order, each once — the
// values of the options of pyReqFileOptions in each command's form (pip install, uv pip install, uv add, uv run, uv
// tool install, uvx) in every spelling the tool takes (the full name, an abbreviation pip takes, =, the next word, a
// short option in a cluster), uv pip sync's file words, and the same inside pipx --pip-args and python -m pip.
func RequirementFiles(line string) []string {
	if lineTooLong(line) {
		return nil
	}
	var files []string
	p := &hookParse{seen: map[string]bool{}, reqs: &files}
	p.line(whichSubst.ReplaceAllString(line, "$1$2"), 0)
	return files
}

// RequirementFilesFact: install_check's fact for a line that names a requirements-format file — ReqFileNotRead — or
// "" when it names none. A fact, not a reason: the answer stays the one for what the line shows.
func RequirementFilesFact(line string) string {
	if len(RequirementFiles(line)) > 0 {
		return ReqFileNotRead
	}
	return ""
}

// CommandRequirementFiles is RequirementFiles for one command Commands gives (its program and words), so that a
// caller can place each file in the folder that command runs in.
func CommandRequirementFiles(c Command) []string {
	if c.Prog == "" || len(c.Words) == 0 {
		return nil
	}
	var files []string
	p := &hookParse{seen: map[string]bool{}, reqs: &files}
	p.commandTargets(c.Prog, c.Words[1:])
	return files
}

// UvDirectory: the folder a uv or uvx command changes to before it runs — its global --directory DIR or
// --directory=DIR, in any place the form reads its options (a runner's only before its command; uv 0.13.7: "Change to
// the given directory prior to running the command", and a relative -r is read there) — as written, and whether the
// command gives one. --project moves only where uv looks for the project: a relative -r is still read in the current
// folder (checked with uv 0.13.7). UV_WORKING_DIR, the option's variable, is the caller's to read.
func UvDirectory(c Command) (dir string, given bool) {
	if c.Prog != "uv" && c.Prog != "uvx" || len(c.Words) == 0 {
		return "", false
	}
	rest := c.Words[1:]
	form := pyForm(c.Prog, rest)
	t := pyOptions[form]
	stop := map[string]int{"uv run": 2, "uv tool run": 3}[form]
	if c.Prog == "uvx" {
		stop = 1
	}
	positional := 0
	for j := 0; j < len(rest); j++ {
		x := rest[j]
		name, val, eq := strings.Cut(x, "=")
		switch {
		case x == "--":
			return dir, given
		case name == "--directory":
			if !eq {
				if j+1 >= len(rest) {
					return dir, given
				}
				j++
				val = rest[j]
			}
			dir, given = val, true
		case strings.HasPrefix(x, "-") && len(x) > 1:
			if !eq && pyTakesValue(t, c.Prog, x) {
				j++
			}
		default:
			if positional++; positional == stop {
				return dir, given
			}
		}
	}
	return dir, given
}

// reqFile notes one requirements-format file the line names.
func (p *hookParse) reqFile(f string) {
	if !p.seen["\x00req"+f] {
		p.seen["\x00req"+f] = true
		*p.reqs = append(*p.reqs, f)
	}
}

// reqFileWords notes the files a pip, uv or uvx command names: the values of its form's requirements options
// (pyReqFileOptions), read as the tool reads its options (pyTakesValue, pyAbbrev, pyShortRegistry) — a runner's up to
// the command it runs — and uv pip sync's words after "pip sync".
func (p *hookParse) reqFileWords(cmd string, rest []string) {
	form := pyForm(cmd, rest)
	req := pyReqFileOptions[form]
	if len(req) == 0 && form != "uv pip sync" {
		return
	}
	t := pyOptions[form]
	short := shortLetters(req, false)
	shortVal := pyShortValue(cmd, rest)
	// a runner reads its options up to the command it runs; what follows is the command's (uvx ruff check -c x)
	stop := map[string]int{"uv run": 2, "uv tool run": 3}[form]
	if cmd == "uvx" {
		stop = 1
	}
	positional := 0
	for j := 0; j < len(rest); j++ {
		x := rest[j]
		name, val, eq := strings.Cut(x, "=")
		switch {
		case x == "--":
			if form == "uv pip sync" {
				for _, f := range rest[j+1:] {
					p.reqFile(f)
				}
			}
			return
		case strings.HasPrefix(x, "--"):
			switch {
			case req[name] || req[pyAbbrev(t, cmd, name)]:
				if eq {
					p.reqFile(val)
				} else if j+1 < len(rest) {
					j++
					p.reqFile(rest[j])
				}
			case !eq && pyTakesValue(t, cmd, x):
				j++
			}
		case len(x) > 1 && x[0] == '-':
			if v, next, ok := pyShortRegistry(x, shortVal, short); ok {
				if !next {
					p.reqFile(v)
				} else if j+1 < len(rest) {
					j++
					p.reqFile(rest[j])
				}
			} else if len(x) == 2 && shortVal[x[1:]] {
				j++
			}
		default:
			positional++
			switch {
			case positional == stop:
				return
			case form == "uv pip sync" && positional > 2: // uv pip sync FILE…: its words after "pip sync"
				p.reqFile(x)
			}
		}
	}
}

// shortLetters: the letters of a table's short options (-r: "r"); with value, only those that take a value.
func shortLetters(t map[string]bool, value bool) map[string]bool {
	m := map[string]bool{}
	for k, v := range t {
		if len(k) == 2 && k[0] == '-' && k[1] != '-' && (v || !value) {
			m[k[1:]] = true
		}
	}
	return m
}

// ReqFile is a requirements-format file another one names (-r, -c): Name as pip reads it (after ${NAME}), Shown as
// a reason may quote it — the file's own text, or which variables named it when the line had any: a value that comes
// from the environment is never quoted (it can be any secret of the hook's).
type ReqFile struct{ Name, Shown string }

// ReqFileReasons reads a requirements-format file as pip reads it (req_file.preprocess and parse_line, pip 26.2.2):
// lines split as Python's str.splitlines splits them, joined at a trailing backslash, comments removed, ${NAME} (upper
// case, digits, _) replaced by getenv's value when that is set; a line whose first word starts with "-" is an option
// line, parsed with pip's own requirements-file parser (pyOptions["pip -r"]: abbreviations, clusters, =). Its reasons,
// for the local hook: an index, an extra index or a find-links location other than the public index (as on the line),
// and a host trusted without TLS. The decision is on the expanded text, as pip's; a reason quotes the file's own text
// (or the host of a URL in it), and for a line ${NAME} changed only the names of the variables. files: the files it
// names in turn (-r, -c); pip reads a relative one from the folder of the file that names it. A requirement line's own
// options (--hash, --config-settings) name no source.
//
// The bytes are decoded as reqFileText decodes them, an allowlist (round 15): a file it does not read is a reason of its
// own, and nothing of it is read.
func ReqFileReasons(data []byte, getenv func(string) string) (reasons []string, files []ReqFile) {
	p := &hookParse{seen: map[string]bool{}}
	text, ok := reqFileText(data)
	if !ok {
		p.miss("installs from a requirements file in an encoding alalanet does not read")
		return p.unread, files
	}
	return p.unread, p.reqFileReading(text, getenv)
}

// reqFileReading: one reading of a decoded file's lines (ReqFileReasons); its reasons go to p, its nested files are
// returned.
func (p *hookParse) reqFileReading(text string, getenv func(string) string) (files []ReqFile) {
	t, idx, req := pyOptions["pip -r"], pyIndexOptions["pip -r"], pyReqFileOptions["pip -r"]
	for _, written := range reqFileLines(text) {
		line := expandReqEnv(written, getenv)
		if w, _, _ := strings.Cut(line, " "); !strings.HasPrefix(w, "-") {
			continue // a requirement (break_args_options: its options start at the first word with "-")
		}
		// shown: what a reason quotes of a value — nothing of it when ${NAME} changed the line
		var via []string
		if line != written {
			for _, m := range reqEnvVar.FindAllStringSubmatch(written, -1) {
				via = append(via, m[0])
			}
		}
		shown := func(v string) string {
			if via != nil {
				return "named through " + strings.Join(via, " ") + " in the file"
			}
			return clip(v, 60)
		}
		words := shlexSplit(line)
		for j := 0; j < len(words); j++ {
			x := words[j]
			if x == "--" {
				break // optparse: the rest are arguments
			}
			if !strings.HasPrefix(x, "-") || len(x) < 2 {
				continue
			}
			opt, val, has := x, "", false
			if strings.HasPrefix(x, "--") {
				name, v, eq := strings.Cut(x, "=")
				if _, ok := t[name]; !ok {
					name = pyAbbrev(t, "pip", name)
				}
				opt, val, has = name, v, eq
			} else {
				// a cluster: each letter an option; one that takes a value takes the rest of the word, or the next
				opt = ""
				for k := 1; k < len(x); k++ {
					if f := "-" + x[k:k+1]; t[f] {
						opt, val, has = f, x[k+1:], k+1 < len(x)
						break
					}
				}
			}
			if !t[opt] {
				continue // a switch, or no option pip's parser has (pip then fails the file)
			}
			if !has && j+1 < len(words) {
				j++
				val = words[j]
			}
			switch {
			case idx[opt]:
				host := val
				if u, err := url.Parse(val); err == nil && u.Host != "" {
					host = u.Hostname()
				}
				if !defaultRegistries[strings.ToLower(host)] {
					p.miss("installs from a custom registry or index (" + shown(host) + "): alalanet judges packages on the public registries only")
				}
			case req[opt]:
				f := ReqFile{Name: val, Shown: val}
				if via != nil {
					f.Shown = "a file " + shown(val)
				}
				files = append(files, f)
			case opt == "--trusted-host":
				p.miss("installs from a custom registry or index trusted without TLS (" + shown(val) + ")")
			}
		}
	}
	return files
}

// reqFileText decodes a requirements file when it is one of the forms pip reads the same everywhere (round 15: an
// allowlist): a byte-order mark (BOMS, in pip 26.2.2's order: UTF-8; UTF-32 — the platform's, little-endian here;
// UTF-32-BE; UTF-16 — little-endian here; UTF-16-BE), decoded as Python's codecs decode it — for "utf-32" and
// "utf-16" a second mark at the start is the codec's own (and its order), a mark-named "-be" codec keeps it as a
// character — or valid UTF-8 with no mark, whose PEP 263 coding line, if any, names UTF-8 or ASCII. Anything else is
// not read (ok false): a file that is no UTF-8 pip decodes in the locale's encoding (Windows' ANSI code page: cp1252,
// cp932, cp936, cp949 …), where a byte this reading cannot place may join or split pip's lines (rounds 13–15); a
// coding line naming another codec likewise. Text with U+0085, U+2028 or U+2029, where pip's str.splitlines breaks a
// line that a reading in another code page would not, is not read either.
func reqFileText(data []byte) (string, bool) {
	s := string(data)
	text, ok := s, true
	switch {
	case strings.HasPrefix(s, "\xef\xbb\xbf"):
		text, ok = s[3:], utf8.ValidString(s[3:])
	case strings.HasPrefix(s, "\xff\xfe\x00\x00"):
		text, ok = decodeUTF32(data[4:], false, true)
	case strings.HasPrefix(s, "\x00\x00\xfe\xff"):
		text, ok = decodeUTF32(data[4:], true, false)
	case strings.HasPrefix(s, "\xff\xfe"):
		text, ok = decodeUTF16(data[2:], false, true)
	case strings.HasPrefix(s, "\xfe\xff"):
		text, ok = decodeUTF16(data[2:], true, false)
	default:
		for i, line := range strings.SplitN(s, "\n", 3) {
			if i < 2 && strings.HasPrefix(line, "#") {
				if m := reqCoding.FindStringSubmatch(line); m != nil && !utf8Coding[strings.ToLower(strings.ReplaceAll(m[1], "_", "-"))] {
					return "", false
				}
			}
		}
		ok = utf8.ValidString(s)
	}
	if !ok || strings.ContainsAny(text, "\u0085\u2028\u2029") {
		return "", false
	}
	return text, true
}

// decodeUTF16 decodes UTF-16 as Python's codec does: be for big-endian; bom: the generic "utf-16" codec, which takes a
// mark at the start (FF FE or FE FF) as its own and its order. An odd length or a lone surrogate fails, as in Python.
func decodeUTF16(b []byte, be, bom bool) (string, bool) {
	if bom && len(b) >= 2 {
		switch {
		case b[0] == 0xff && b[1] == 0xfe:
			b, be = b[2:], false
		case b[0] == 0xfe && b[1] == 0xff:
			b, be = b[2:], true
		}
	}
	if len(b)%2 != 0 {
		return "", false
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		if be {
			u[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
		} else {
			u[i] = uint16(b[2*i+1])<<8 | uint16(b[2*i])
		}
	}
	var out strings.Builder
	for i := 0; i < len(u); i++ {
		switch c := rune(u[i]); {
		case c >= 0xd800 && c < 0xdc00:
			if i+1 >= len(u) || u[i+1] < 0xdc00 || u[i+1] >= 0xe000 {
				return "", false
			}
			out.WriteRune(utf16.DecodeRune(c, rune(u[i+1])))
			i++
		case c >= 0xdc00 && c < 0xe000:
			return "", false
		default:
			out.WriteRune(c)
		}
	}
	return out.String(), true
}

// decodeUTF32 decodes UTF-32 as Python's codec does (be, bom as for decodeUTF16; the marks 00 00 FE FF and FF FE 00
// 00). A length that is no multiple of four, a surrogate or a value past U+10FFFF fails.
func decodeUTF32(b []byte, be, bom bool) (string, bool) {
	if bom && len(b) >= 4 {
		switch string(b[:4]) {
		case "\xff\xfe\x00\x00":
			b, be = b[4:], false
		case "\x00\x00\xfe\xff":
			b, be = b[4:], true
		}
	}
	if len(b)%4 != 0 {
		return "", false
	}
	var out strings.Builder
	for i := 0; i < len(b); i += 4 {
		var c uint32
		if be {
			c = uint32(b[i])<<24 | uint32(b[i+1])<<16 | uint32(b[i+2])<<8 | uint32(b[i+3])
		} else {
			c = uint32(b[i+3])<<24 | uint32(b[i+2])<<16 | uint32(b[i+1])<<8 | uint32(b[i])
		}
		if c > 0x10ffff || c >= 0xd800 && c < 0xe000 {
			return "", false
		}
		out.WriteRune(rune(c))
	}
	return out.String(), true
}

// reqCoding: pip's PEP263_ENCODING_RE, the coding a line declares.
var reqCoding = regexp.MustCompile(`coding[:=]\s*([-\w.]+)`)

// utf8Coding: the names Python's codecs take for UTF-8 (and ASCII, a part of it), "_" read as "-".
var utf8Coding = wordSet("utf-8 utf8 u8 utf cp65001 ascii us-ascii 646")

// reqFileLines: pip's preprocess before the environment: split into lines (str.splitlines), join a line that ends
// in a backslash with the next (join_lines: the backslashes at either end stripped; a comment line is not joined on,
// and ends a joined line), then comments removed and blanks stripped (ignore_comments), empty lines dropped.
func reqFileLines(text string) []string {
	var out, joined []string
	flush := func(l string) {
		if l = strings.TrimFunc(reqComment(l), pySpace); l != "" {
			out = append(out, l)
		}
	}
	for _, line := range pySplitLines(text) {
		comment := reqCommentLine(line)
		if !strings.HasSuffix(line, `\`) || comment {
			if comment {
				line = " " + line
			}
			if joined != nil {
				flush(strings.Join(append(joined, line), ""))
				joined = nil
			} else {
				flush(line)
			}
			continue
		}
		joined = append(joined, strings.Trim(line, `\`))
	}
	if joined != nil {
		flush(strings.Join(joined, ""))
	}
	return out
}

// reqCommentLine: COMMENT_RE (`(^|\s+)#.*$`) matched at a line's start: blanks (Python's), then "#" — without a
// regular expression, which cost most of the time of a large hashed file (round 14, P3-C).
func reqCommentLine(line string) bool {
	return strings.HasPrefix(strings.TrimLeftFunc(line, pySpace), "#")
}

// reqComment removes a comment as COMMENT_RE.sub does: from the first "#" at the start of the line or after a blank,
// with the blanks before it, to the end.
func reqComment(l string) string {
	for i, r := range l {
		if r != '#' {
			continue
		}
		if i == 0 {
			return ""
		}
		if prev, _ := utf8.DecodeLastRuneInString(l[:i]); pySpace(prev) {
			return strings.TrimRightFunc(l[:i], pySpace)
		}
	}
	return l
}

// pySpace: Python's str.isspace for one character (\s of a str pattern): Go's unicode.IsSpace and the separators
// U+001C to U+001F.
func pySpace(r rune) bool { return unicode.IsSpace(r) || r >= 0x1c && r <= 0x1f }

// pySplitLines is Python's str.splitlines(): lines end at \n, \r, \r\n, \v, \f, U+001C to U+001E, U+0085, U+2028 and
// U+2029, which are not kept.
func pySplitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch r {
		case '\n', '\r', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
			out = append(out, s[start:i])
			if r == '\r' && i+1 < len(s) && s[i+1] == '\n' {
				n++
			}
			start = i + n
		}
		i += n
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// reqEnvVar: ENV_VAR_RE, ${NAME} with NAME of upper-case letters, digits and _.
var reqEnvVar = regexp.MustCompile(`\$\{([A-Z0-9_]+)\}`)

// expandReqEnv: pip's expand_env_variables — each ${NAME} whose variable is set and not empty is replaced by its value;
// any other is left as written.
func expandReqEnv(line string, getenv func(string) string) string {
	if getenv == nil || !strings.Contains(line, "${") {
		return line
	}
	for _, m := range reqEnvVar.FindAllStringSubmatch(line, -1) {
		if v := getenv(m[1]); v != "" {
			line = strings.ReplaceAll(line, m[0], v)
		}
	}
	return line
}
