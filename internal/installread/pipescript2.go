package installread

import (
	"net/url"
	"path"
	"slices"
	"strings"
)

// PIPE-SCRIPT-1 round 2 (review P2-1, P3-2): the download-and-run forms the first round left silent.
//   - A file the line downloads to (curl -o F, -O and --remote-name: the address's last segment, > F; wget -O F and
//     its default name; fetch -o F; tee F on the way; Invoke-WebRequest and Invoke-RestMethod -OutFile F) that a later
//     command of the same line runs (sh F, bash F, source F, . F, ./F, F, python3 F, node F, powershell -File F, & F)
//     is that download's script.
//   - The words of a substitution the walk cut out of a command (eval $(curl …), sh <<< $(curl …), sh < <(curl …)).
//   - A command a package runner starts (pnpm exec sh, npx -y sh, yarn exec -- bash, bun x sh, uv run python3 -).
//   - A shell whose own -c script runs what it reads (bash -c 'cat | sh', sh -c 'sh').
//   - A command that prints a download's substitution (echo "$(curl …)", printf '%s' "$(curl …)").

// runnerWords: the words a package runner (runnerProgram) starts, for as many runners as the words name (pnpm exec
// npx sh); the words themselves when they start none.
func runnerWords(words []string) []string {
	for depth := 0; depth < 4; depth++ {
		cmd, rest := unwrapped(words)
		i := runnerProgram(cmd, rest)
		if i < 0 {
			return words
		}
		words = rest[i:]
	}
	return words
}

// scriptReadsInput: a shell's -c script that runs what the shell reads as its input: its first command runs its input,
// or passes it on (cat, tee, a filter) to one that does (bash -c 'cat | sh', sh -c 'sh', bash -c 'sh -s -- --yes').
func scriptReadsInput(script string) bool {
	segs := splitShell(script).segs
	for j := 0; j < len(segs); j++ {
		if runsInput(segs[j].words) {
			return true
		}
		cmd, _ := unwrapped(segs[j].words)
		if !scriptFilters[cmd] || j+1 >= len(segs) || !segs[j+1].piped {
			return false
		}
	}
	return false
}

// variableProgram: words whose program is a variable's value ($SHELL, "$SHELL", ${SHELL:-sh}): downstream of a
// download, a program alalanet cannot name runs what it reads.
func variableProgram(words []string) bool {
	cmd, _ := unwrapped(words)
	return strings.HasPrefix(cmd, "$")
}

// cutBody: the words of a substitution the tokenizer cut into a segment of its own, its first word taken as the
// redirection's or the here-string's word (sh < <(curl URL), sh <<< $(curl URL)); the segment's words otherwise.
func cutBody(sg shellSeg) []string {
	if _, ok := downloads(sg.words); ok {
		return sg.words
	}
	for _, first := range [][]string{sg.here, sg.redirs} {
		if len(first) == 1 && first[0] != "" {
			w := append([]string{first[0]}, sg.words...)
			if _, ok := downloads(w); ok {
				return w
			}
		}
	}
	return sg.words
}

// printedDownload: a command that prints a download's substitution as one of its words (echo "$(curl …)", printf '%s'
// "$(curl …)"): that download's addresses and words.
func printedDownload(words []string) (urls, body []string, ok bool) {
	cmd, rest := unwrapped(words)
	switch cmd {
	case "echo", "print", "printf", "write-output", "write-host":
	default:
		return nil, nil, false
	}
	for _, x := range rest {
		if urls, body, ok := downloadCommand(substBody(x)); ok {
			return urls, body, true
		}
	}
	return nil, nil, false
}

// savedFile: a file a command downloads an address to.
type savedFile struct{ file, url string }

// savedFiles: the files a command downloads to, with the address each one holds.
func savedFiles(words []string) []savedFile {
	cmd, rest := unwrapped(words)
	switch cmd {
	case "curl":
		return curlFiles(rest)
	case "wget", "wget2", "fetch":
		return fetchFiles(cmd, rest)
	case "irm", "iwr", "invoke-webrequest", "invoke-restmethod":
		return psWebFiles(rest)
	}
	return nil
}

// remoteName: the name curl -O and wget give the file of an address: its path's last segment.
func remoteName(raw string) string {
	s := raw
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return ""
	}
	if b := path.Base(u.Path); b != "/" && b != "." && b != "" {
		return b
	}
	return ""
}

// curlFiles: curl's -o FILE (--output) and -O (--remote-name) paired with the addresses in order; --remote-name-all
// names every one.
func curlFiles(rest []string) []savedFile {
	var urls, outs []string // outs: a file name, or "" for the address's own name
	all, dir := false, ""   // dir: --output-dir, where the files go unless their name is absolute
	for i := 0; i < len(rest); i++ {
		x := rest[i]
		switch {
		case strings.HasPrefix(x, "--"):
			name, v, eq := strings.Cut(strings.TrimPrefix(x[2:], "expand-"), "=")
			switch {
			case name == "remote-name":
				outs = append(outs, "")
			case name == "remote-name-all":
				all = true
			case curlLongValued[name]:
				if !eq && i+1 < len(rest) {
					i++
					v = rest[i]
				}
				switch name {
				case "url":
					urls = append(urls, v)
				case "output":
					if !stdoutFile(v) {
						outs = append(outs, v)
					}
				case "output-dir":
					dir = v
				}
			}
		case len(x) > 1 && x[0] == '-':
			for j := 1; j < len(x); j++ {
				c := x[j : j+1]
				if c == "O" {
					outs = append(outs, "")
					continue
				}
				if curlShortValued["-"+c] {
					v := x[j+1:]
					if v == "" && i+1 < len(rest) {
						i++
						v = rest[i]
					}
					if c == "o" && !stdoutFile(v) {
						outs = append(outs, v)
					}
					break
				}
			}
		default:
			urls = append(urls, x)
		}
	}
	var out []savedFile
	for k, u := range urls {
		f := ""
		switch {
		case k < len(outs):
			f = outs[k]
		case !all:
			continue // to the output
		}
		if f == "" {
			f = remoteName(u)
		}
		if f != "" {
			out = append(out, savedFile{inDir(dir, f), u})
		}
	}
	return out
}

// inDir: a file name under a directory option (curl --output-dir, wget -P), unless it is absolute or none is given.
func inDir(dir, f string) string {
	if dir == "" || strings.HasPrefix(f, "/") || strings.HasPrefix(f, "~") || strings.HasPrefix(f, "$") {
		return f
	}
	return strings.TrimSuffix(dir, "/") + "/" + f
}

// fetchFiles: wget's -O FILE (--output-document; every address into it), else each address's own name; fetch's
// -o FILE (--output), else its own name.
func fetchFiles(cmd string, rest []string) []savedFile {
	var urls []string
	doc, docSet, dir := "", false, "" // dir: wget's -P (--directory-prefix)
	for i := 0; i < len(rest); i++ {
		x := rest[i]
		switch {
		case strings.HasPrefix(x, "--"):
			name, v, eq := strings.Cut(x[2:], "=")
			valued := cmd == "fetch" && name == "output" || cmd != "fetch" && wgetLongValued[name]
			if valued && !eq && i+1 < len(rest) {
				i++
				v = rest[i]
			}
			if name == "output-document" || cmd == "fetch" && name == "output" {
				doc, docSet = v, true
			}
			if cmd != "fetch" && name == "directory-prefix" {
				dir = v
			}
		case len(x) > 1 && x[0] == '-':
			for j := 1; j < len(x); j++ {
				c := x[j : j+1]
				valued := cmd == "fetch" && strings.Contains("BiNoSTw", c) || cmd != "fetch" && wgetShortValued["-"+c]
				if !valued {
					continue
				}
				v := x[j+1:]
				if v == "" && i+1 < len(rest) {
					i++
					v = rest[i]
				}
				if cmd != "fetch" && c == "O" || cmd == "fetch" && c == "o" {
					doc, docSet = v, true
				}
				if cmd != "fetch" && c == "P" {
					dir = v
				}
				break
			}
		default:
			urls = append(urls, x)
		}
	}
	if docSet && stdoutFile(doc) {
		return nil // to the output: downloads' reading
	}
	var out []savedFile
	for _, u := range urls {
		f := doc
		if !docSet {
			f = inDir(dir, remoteName(u))
		}
		if f != "" {
			out = append(out, savedFile{f, u})
		}
	}
	return out
}

// psWebFiles: Invoke-WebRequest's and Invoke-RestMethod's -OutFile FILE, with their address.
func psWebFiles(rest []string) []savedFile {
	var urls []string
	file := ""
	for i := 0; i < len(rest); i++ {
		x := rest[i]
		if !strings.HasPrefix(x, "-") || len(x) < 2 {
			urls = append(urls, x)
			continue
		}
		name, valued, v, has := psParam(x)
		if valued && !has && i+1 < len(rest) {
			i++
			v = rest[i]
		}
		switch name {
		case "uri":
			urls = append(urls, v)
		case "outfile":
			file = v
		}
	}
	if file == "" || len(urls) == 0 {
		return nil
	}
	return []savedFile{{file, urls[0]}}
}

// fileKey: a file's name as the line spells it, for comparing a download's file with one a command runs: ./F and .\F
// are F, a backslash is a slash.
func fileKey(f string) string {
	f = strings.ReplaceAll(strings.TrimSpace(f), `\`, "/")
	for strings.HasPrefix(f, "./") {
		f = f[2:]
	}
	return f
}

// The options with a value that runFiles steps over to a program's file word (sets made once: runFiles reads every
// command of a line).
var (
	shellValued    = wordSet("-o +o -O +O --rcfile --init-file")
	pwshFileValued = wordSet("-executionpolicy -ep -ex -windowstyle -w -configurationname -workingdirectory -wd -settingsfile")
	interpValued   = wordSet("-w -x -m -r -i -e -c -p --require --import --eval --print")
)

// runFiles: the files a command runs as a script: its program itself when it is no program name (./F, F after chmod,
// a path, $p), the script word of a shell, source or ., an interpreter's program file, PowerShell's -File; the names
// as written, through wrappers and package runners. fed: a shell or interpreter under xargs with no script word of its
// own, which runs the files its input names (ls i.sh | xargs sh; round 4).
func runFiles(words []string) (out []string, fed bool) {
	words = runnerWords(words)
	var prog string
	for _, w := range words { // the program word as written (unwrapped reads its base name)
		if wrapperName(w) == "" && !(strings.Contains(w, "=") && !strings.HasPrefix(w, "-")) {
			prog = w
			break
		}
	}
	cmd, rest := unwrapped(words)
	out = []string{prog}
	xargs := false
	for i, w := range words { // xargs -a F sh -c '{}': the lines of F are the scripts the shell runs (round 3)
		if launchBase(w) != "xargs" {
			continue
		}
		xargs = true
		if !posixShells[cmd] && !foreignShells[cmd] {
			break // F's lines are another command's words; its own program file is read below (round 4, P2-3)
		}
		for j := i + 1; j < len(words); j++ {
			x := words[j]
			switch {
			case (x == "-a" || x == "--arg-file") && j+1 < len(words):
				out = append(out, words[j+1])
			case strings.HasPrefix(x, "--arg-file="):
				out = append(out, strings.TrimPrefix(x, "--arg-file="))
			case strings.HasPrefix(x, "-a") && len(x) > 2:
				out = append(out, x[2:])
			}
		}
		break
	}
	firstArg := func(skipValued map[string]bool) string {
		for i := 0; i < len(rest); i++ {
			x := rest[i]
			if x == "--" {
				if i+1 < len(rest) {
					return rest[i+1]
				}
				return ""
			}
			if strings.HasPrefix(x, "-") && x != "-" {
				if skipValued[strings.ToLower(x)] && i+1 < len(rest) {
					i++
				}
				continue
			}
			return x
		}
		return ""
	}
	script := ""
	switch {
	case cmd == "&" || cmd == "." || cmd == "source":
		if len(rest) > 0 {
			out = append(out, rest[0])
		}
		return out, false
	case posixShells[cmd] || foreignShells[cmd]:
		body, ok := shellScript(rest, foreignShells[cmd])
		if !ok {
			script = firstArg(shellValued)
			break
		}
		for _, sg := range splitShell(body).segs { // bash -c ./i.sh, sh -c 'bash i.sh': the script's own commands
			out = append(out, runFilesShallow(sg.words)...)
		}
		return out, false
	case cmd == "pwsh" || cmd == "powershell": // -File F: its first word that is no option (-File is one)
		script = firstArg(pwshFileValued)
	case interpreterName(cmd):
		script = firstArg(interpValued)
	case strings.HasPrefix(cmd, "$"): // $SHELL i.sh: a program alalanet cannot name, read as a shell (round 4)
		script = firstArg(shellValued)
	default:
		return out, false
	}
	if script == "" {
		return out, xargs
	}
	return append(out, script), false
}

// runFilesShallow: the files a command of a -c script runs, its program or a shell's script word, not read deeper.
func runFilesShallow(words []string) []string {
	cmd, rest := unwrapped(words)
	out := []string{}
	if len(words) > 0 {
		out = append(out, words[len(words)-len(rest)-1])
	}
	if (posixShells[cmd] || cmd == "source" || cmd == ".") && len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		out = append(out, rest[0])
	}
	return out
}

// Round 4 (re-review of round 3, P2-1, P2-2): a saved download is matched to a run by its file's name alone, never by
// the folder. Round 3 followed cd and keyed a file by the folder it believed the line was in; a cd it could not follow,
// or one that did not persist or failed — in a subshell, a pipeline, a condition, cd -, popd, cd -P — made the run
// another file, and the line silent, though the shell ran the download. The folder a line runs in is never certain:
// it starts in one alalanet does not know, and any cd may fail, not persist or come back. So a run of a name is a run
// of every download the line saved under that name, wherever it was saved; a wrong match only asks. No folder is
// kept, so none is joined onto a later word (round 3's quadratic long folder is gone with it).

// maxNamed: the most downloads one name keeps; a name saved from more addresses also holds without a target.
const maxNamed = 16

// namedSaves: the downloads a line saved under one name, and whether there were more than maxNamed.
type namedSaves struct {
	runs []savedRun
	more bool
}

// savedNames: the downloads a line saved to files so far, by the files' names.
type savedNames map[string]*namedSaves

// fileName: the name a file word ends in, in lower case (a case-insensitive file system — Windows', macOS's — runs
// I.sh for i.sh), or "" when it names none: ./i.sh, /tmp//i.sh, "$PWD/i.sh", ~/i.sh and .\i.ps1 are all i.sh.
func fileName(f string) string {
	f = strings.TrimRight(fileKey(f), "/")
	if i := strings.LastIndexByte(f, '/'); i >= 0 {
		f = f[i+1:]
	}
	if f == "" || f == "." || f == ".." {
		return ""
	}
	return strings.ToLower(f)
}

// add notes a download saved under f's name; the same address under one name is kept once.
func (s savedNames) add(f string, r savedRun) {
	n := fileName(f)
	if n == "" {
		return
	}
	e := s[n]
	if e == nil {
		e = &namedSaves{}
		s[n] = e
	}
	for _, x := range e.runs {
		if x.url == r.url && slices.Equal(x.urls, r.urls) {
			return // also kept under allNames already
		}
	}
	if len(e.runs) >= maxNamed {
		e.more = true
	} else {
		e.runs = append(e.runs, r)
	}
	if n != allNames {
		s.addAll(r)
	}
}

// addAll notes a download under allNames.
func (s savedNames) addAll(r savedRun) {
	e := s[allNames]
	if e == nil {
		e = &namedSaves{}
		s[allNames] = e
	}
	for _, x := range e.runs {
		if x.url == r.url && slices.Equal(x.urls, r.urls) {
			return
		}
	}
	if len(e.runs) >= maxNamed {
		e.more = true
		return
	}
	e.runs = append(e.runs, r)
}

// copy notes the downloads of one name under f's name too (mv, cp, cat i.sh > j.sh).
func (s savedNames) copy(f string, e *namedSaves) {
	if e == nil || fileName(f) == "" {
		return
	}
	for _, r := range e.runs {
		s.add(f, r)
	}
	if n := fileName(f); e.more {
		for _, k := range []string{n, allNames} {
			if s[k] == nil {
				s[k] = &namedSaves{}
			}
			s[k].more = true
		}
	}
}

// computedName: a file word whose name the line computes — a variable or a substitution ($f, ${F}, "$(echo i.sh)"):
// it may be any file the line saved.
func computedName(f string) bool { return strings.ContainsAny(fileName(f), "$`") }

// allNames: the key of every download the line saved, whatever its name (a computed name runs any of them).
const allNames = "\x00"

// find: the downloads saved under f's name, or nil.
func (s savedNames) find(f string) *namedSaves {
	if n := fileName(f); n != "" {
		return s[n]
	}
	return nil
}

// printed: the downloads a command prints from saved files — cat F, cat < F, PowerShell's Get-Content F (gc, type) —
// one set per file it reads that a download wrote; nil for any other command.
func (s savedNames) printed(words, redirs []string) []*namedSaves {
	cmd, rest := unwrapped(words)
	if !catCommands[cmd] {
		return nil
	}
	var out []*namedSaves
	for _, list := range [2][]string{rest, redirs} {
		for _, f := range list {
			if e := s.find(f); e != nil && !strings.HasPrefix(f, "-") {
				out = append(out, e)
			}
		}
	}
	return out
}

// catCommands print the files they are given; teeCommands write their input to the files they are given.
var (
	catCommands = wordSet("cat gc get-content type")
	teeCommands = wordSet("tee set-content sc out-file add-content ac")
)

// runSet: the downloads one run runs, gathered from the names it reads (each name holds at most maxNamed): their
// addresses once each, a tool's name, the segments that downloaded them, and whether a name held more.
type runSet struct {
	urls []string
	what string
	segs []int
	runs []savedRun
	more bool
	seen map[string]bool
}

// gather: the run of the downloads saved under the names a command reads.
func gather(sets ...*namedSaves) *runSet {
	var c runSet
	for _, e := range sets {
		c.add(e)
	}
	return &c
}

func (c *runSet) add(e *namedSaves) {
	if e == nil {
		return
	}
	c.more = c.more || e.more
	for _, r := range e.runs {
		fresh := false
		for _, u := range r.addrs() {
			if c.seen == nil {
				c.seen = map[string]bool{}
			}
			if !c.seen[u] {
				c.seen[u], fresh = true, true
				c.urls = append(c.urls, u)
			}
		}
		if fresh {
			if c.what == "" {
				c.what = r.what
			}
			c.runs = append(c.runs, r)
			c.segs = append(c.segs, r.seg)
			c.segs = append(c.segs, r.segs...)
		}
	}
}

// script: the run as the walk adds it — more downloads of a name than kept is a reason without a target, a hold.
func (c *runSet) script() *scriptRun {
	urls := c.urls
	if c.more {
		urls = append(slices.Clip(urls), "more downloads saved under one name")
	}
	what := c.what
	if what == "" {
		what = "a saved download"
	}
	return &scriptRun{urls, what}
}

// copyFiles: mv, cp, ln and install of a file a download wrote give it the new name too — the last word, or (-t DIR,
// a folder) the same name, which it already has.
func copyFiles(saved savedNames, rest []string) {
	var args []string
	for _, x := range rest {
		if !strings.HasPrefix(x, "-") {
			args = append(args, x)
		}
	}
	if len(args) < 2 {
		return
	}
	dst := args[len(args)-1]
	for _, a := range args[:len(args)-1] {
		if e := saved.find(a); e != nil && !strings.HasSuffix(dst, "/") {
			saved.copy(dst, e)
		}
	}
}

// scriptWord: the one word a command runs as a script — eval's, or a POSIX shell's -c script — or "".
func scriptWord(words []string) string {
	for i, w := range words {
		if w == "eval" && i+2 == len(words) {
			return words[i+1]
		}
	}
	if cmd, rest := unwrapped(words); posixShells[cmd] {
		if script, ok := shellScript(rest, false); ok {
			return script
		}
	}
	return ""
}

// noteVars notes a variable a command assigns a download's substitution to — NAME=$(curl …) and NAME=`curl …` (the
// tokenizer cut the substitution into the next segment), NAME="$(curl …)" (one word), and the same after export,
// declare, local, readonly or typeset, and read NAME < <(curl …) (round 3; round 4: the quoted, declared and read forms).
func (p *hookParse) noteVars(vars map[string]savedRun, segs []shellSeg, i int) {
	words := segs[i].words
	if len(words) > 1 && strings.HasPrefix(words[0], "$") {
		// PowerShell: $s = irm URL, $s=irm URL (round 4)
		name, first, _ := strings.Cut(words[0][1:], "=")
		dl := words[1:]
		switch {
		case first != "":
			dl = append([]string{first}, words[1:]...)
		case !strings.HasSuffix(words[0], "=") && words[1] == "=":
			dl = words[2:]
		case !strings.HasSuffix(words[0], "="):
			dl = nil
		}
		if urls, ok := downloads(dl); ok && shellName.MatchString(name) && len(dl) > 0 {
			vars[strings.ToLower(name)] = savedRun{what: dl[0], seg: i, urls: urls, subst: dl, at: i}
		}
		return
	}
	if cmd, rest := unwrapped(words); cmd == "read" && segs[i].proc && segs[i].cut && i+1 < len(segs) && len(rest) > 0 {
		// read -r -d '' s < <(curl …): the variable is the download (round 4)
		if body := cutBody(segs[i+1]); shellName.MatchString(rest[len(rest)-1]) {
			if urls, ok := downloads(body); ok {
				vars[rest[len(rest)-1]] = savedRun{what: body[0], seg: i + 1, urls: urls, subst: body, at: i}
			}
		}
		return
	}
	if len(words) > 0 && declareCommands[words[0]] {
		words = words[1:]
	}
	for k, w := range words {
		name, val, ok := strings.Cut(w, "=")
		if !ok || !shellName.MatchString(name) {
			if strings.HasPrefix(w, "-") {
				continue // declare -x NAME=…
			}
			return
		}
		if val == "" && k == len(words)-1 && segs[i].cut && i+1 < len(segs) {
			if urls, ok := downloads(segs[i+1].words); ok {
				vars[name] = savedRun{what: segs[i+1].words[0], seg: i + 1, urls: urls, subst: segs[i+1].words, at: i}
			}
			continue
		}
		if urls, body, ok := downloadCommand(substBody(val)); ok {
			vars[name] = savedRun{what: body[0], seg: i, urls: urls, subst: body, at: i}
		}
	}
}

// declareCommands assign the NAME=VALUE words they are given.
var declareCommands = wordSet("export declare local readonly typeset")

// evalVar: the variable a command runs as a script — eval "$s", eval $s, sh -c "$s", bash -c "${s}" — or "".
func evalVar(words []string) string {
	ref := func(x string) string {
		x = strings.TrimSuffix(strings.TrimPrefix(x, "${"), "}")
		x = strings.TrimPrefix(x, "$")
		if shellName.MatchString(x) {
			return x
		}
		return ""
	}
	for i, w := range words {
		if w == "eval" && i+2 == len(words) && strings.HasPrefix(words[i+1], "$") {
			return ref(words[i+1])
		}
	}
	cmd, rest := unwrapped(words)
	if (cmd == "iex" || cmd == "invoke-expression") && len(rest) == 1 && strings.HasPrefix(rest[0], "$") {
		return strings.ToLower(ref(rest[0])) // iex $s (round 4)
	}
	if posixShells[cmd] {
		if script, ok := shellScript(rest, false); ok && strings.HasPrefix(script, "$") && !strings.ContainsAny(script, " \t;|&") {
			return ref(script)
		}
	}
	return ""
}

// psRunsNext: PowerShell's Invoke-Expression with no command of its own, whose argument is the group that follows it
// (iex (gc i.ps1); round 4).
func psRunsNext(words []string) bool {
	cmd, rest := unwrapped(words)
	return (cmd == "iex" || cmd == "invoke-expression") && len(rest) == 0
}
