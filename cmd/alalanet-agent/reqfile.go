package main

// READER-REQFILE-1 (ADR-0159 round 12): a requirements-format file named on an install line (pip install -r FILE, -c
// FILE, uv pip install -r, uv add -r, uv pip sync FILE, --with-requirements) can name an index of its own on an option
// line (--index-url, --extra-index-url, --find-links), which alalanet's server never sees: it reads the line, not the
// user's files; for install_check a named file is a fact, never a hold (ADR-0159 round 13). The hook runs on the
// machine, so it reads them: each file a pip or uv command of the line names
// (installread.CommandRequirementFiles), in the folder that command runs in, and the files those name in turn, as pip
// reads them (installread.ReqFileReasons). A file that moves where packages come from holds the install, as the same
// option on the line does. Nothing of a file is sent.

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/alalanet/alalanet-agent/internal/installread"
)

const (
	// maxReqFile bounds one requirements file; a larger one is not read, and holds. Hashed lock files are the large
	// honest ones: a real 113-package `--generate-hashes` file is 219 KB, 1.9 KB a package on average and 14.6 KB at most
	// (multidict, 171 hashes); 8 MiB is 36 times that file, 560 packages at that most, 4 300 at the average. Round 13's
	// 32 MiB cost 380–791 MiB of allocations for two files at the cap (round 14, P3-C).
	maxReqFile = 8 << 20
	// maxReqFiles bounds the files read for one line, the files they name included; past it, the line holds.
	maxReqFiles = 64
)

// maxReqBytes bounds the bytes read for one line, the nested files included; past it, the line holds (a variable for
// tests).
var maxReqBytes = 16 << 20

// reqScheme: pip's SCHEME_RE — a requirements file it fetches (http, https) or opens as a URL (file).
var reqScheme = regexp.MustCompile(`(?i)^(http|https|file):`)

// reqFileHold says why the requirements files the line names hold it ("" when none does). cwd is the folder the
// runtime says the agent works in (absolute; "" when it does not say: a relative file then cannot be placed and is not
// read); home is the user's home folder, which a leading ~ names ("" when not known: such a name then cannot be placed
// and holds); getenv is the hook's environment, which pip expands ${NAME} from unless the line sets NAME itself (on the
// command, or exported before it): then the line's value is pip's.
//
// It is an allowlist (round 15, after four rounds of cases): it reads only what it is sure of and holds on everything
// else. A command runs in cwd or in a folder the line places: a bare cd (home), cd with one literal path on a line
// whose every other command is one of cdSafe's (round 16) while the hook's environment sets no CDPATH, env -C/--chdir
// and sudo -D with a literal path, uv's
// --directory and UV_WORKING_DIR with a literal path (planReqFiles). Any other change of folder holds — pushd, popd, cd
// -, cd with an option, a cd in ( … ) or on a line with a command substitution, more than 16 changes, a login in
// another user's home (su -, runuser -l, sudo -i, sudo --login), sudo -R or --chroot. A relative file is read in each
// folder the line placed. A file is read only in the encodings pip reads alike everywhere (installread.ReqFileReasons:
// UTF-8, UTF-16 and UTF-32 with their mark); any other holds. A name under /dev/fd, /proc/*/fd or /dev/std* is one of
// pip's own descriptors, which the hook's process does not share: it holds; so does a glob. A reason quotes the names
// as the line and the files write them, never a value from the environment. Paths are joined as the kernel resolves
// them (rawJoin: a link's "..", not filepath.Clean's), but a cd's as bash's logical cd does. A file a line that
// installs sources (source FILE, . FILE) is read in the same folders and bounds, and holds unless it is a known
// virtual environment's activate script (readSourced, round 20).
func reqFileHold(cwd, home, command string, getenv func(string) string) string {
	queue, why := planReqFiles(cwd, home, command, getenv)
	if why != "" {
		return why
	}
	return readReqFiles(queue)
}

// placeName: a folder or file name as the shell gives it to the command — ~ and ~/… from home; "" when it cannot be
// placed (a variable, ~user, ~ with no home).
func placeName(name, home string) string {
	switch {
	case strings.ContainsAny(name, "$`*?["):
		return "" // a variable, a substitution, a glob the shell expands
	case name == "~" || strings.HasPrefix(name, "~/"):
		if !filepath.IsAbs(home) {
			return ""
		}
		if name == "~" {
			return home
		}
		return rawJoin(home, name[2:]) // as the shell expands it: no cleaning (rawJoin)
	case strings.HasPrefix(name, "~"):
		return ""
	}
	return name
}

// reqItem is one requirements file to read: its name as pip opens it, as a reason may show it, the folders a relative
// name is read in, pip's environment for its ${NAME}, and the home folder ~ names ("" when the line may have moved it);
// sourced: a file the line sources instead (round 20), read to match a known activate script or plain data (round 21);
// unwritten: sourced before any command of the line that may write a file (installread.SourcedUnwritten), so missing is
// fine; venv: the bin/activate of a venv a tool of the line creates before it (installread.VenvActivates), missing is
// fine when that folder is not there yet or the tool empties it (clear; round 22, P3-R); pathSet: the line sets PATH,
// which a name with no slash is looked up in (round 22, P2-M); line: the command line, against which a data file's
// assignments are judged. getenv is the hook's environment for a sourced file (its PATH).
type reqItem struct {
	name, show string
	from       []string
	getenv     func(string) string
	home       string
	sourced    bool
	unwritten  bool
	venv       bool
	clear      bool
	pathSet    bool
	line       string
	userHome   string // the user's home: the login files whose PATH folders a name with no slash is looked up in too
}

// planReqFiles reads the line alone — no file — into the files to read (reqFileHold), or why the line holds before any
// is read. The hook runs it, with the reading, under the policy files' deadline (round 15).
func planReqFiles(cwd, home, command string, getenv func(string) string) ([]reqItem, string) {
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	userHome := home // the user's home, for the PATH the login files add (round 23); home may be unplaced below
	place := func(name string) string { return placeName(name, home) }
	cmds := installread.Commands(command)
	names := false
	for _, c := range cmds {
		names = names || len(installread.CommandRequirementFiles(c)) > 0
	}
	// source FILE and . FILE on a line that installs: the file can define the install's command (round 20, P2-I)
	sourced := installread.SourcedFiles(command)
	sources := len(sourced) > 0
	// missing may be fine: the files sourced before any write, the line's own venvs' activate scripts (rounds 21, 22)
	var unwritten []string
	acts := map[string]bool{} // file → its venv tool empties the folder
	if sources {
		unwritten = installread.SourcedUnwritten(command)
		for _, a := range installread.VenvActivates(command) {
			acts[a.File] = acts[a.File] || a.Clear
		}
	}
	pathSet := assignsName(cmds, "PATH") || assignsName(cmds, "path") // zsh's path is PATH
	if !names && !sources {
		return nil, ""
	}
	// pip() { … }; pip install -r r.txt: a line that defines an alias or a function, of any name, may run something
	// else than what alalanet-agent reads, whatever the file says (READER-SHADOW-1, round 19)
	if d := installread.Defines(command); d != "" {
		return nil, "defines an alias or a function (" + clip(d) + "), so what runs may not be what alalanet-agent reads"
	}
	// The folder a command runs in is placed only from an allowlist (rounds 15 and 16): a bare cd (home), cd with one
	// literal path on a line whose every other command is one of cdSafe's (a command that cannot change how cd resolves:
	// no set, shopt, setopt, alias, read, printf, source, function, no CDPATH or cdpath in any spelling) while the hook's
	// environment sets no CDPATH, env -C or --chdir and sudo -D with a literal path, uv's --directory and
	// UV_WORKING_DIR with a literal path. Anything else that changes folder holds the line: pushd, popd, cd -, cd with
	// an option or more than one word, cd inside ( … ) or on a line with a command substitution (the walk takes
	// $(…) apart), more than maxFolderMoves changes, a login in another user's home.
	cdpath := getenv("CDPATH") != ""
	unsafe := ""
	for _, c := range cmds {
		if unsafe = cdUnsafe(c); unsafe != "" {
			break
		}
	}
	// A $ outside single quotes anywhere in the raw line — a word, a redirection, a here-document — can assign while it
	// expands (${CDPATH:=…}, ${HOME=…}, $[CDPATH=1], ${!n:=…}): on such a line no cd is placed and no ~ either (round
	// 17, the coordinator's broad rule); an assignment or export of HOME moves ~ and a bare cd as well.
	dollar := dollarOutsideSingle(command)
	// a[CDPATH=1]=x: an indexed array's subscript is arithmetic, which assigns with no $ and no parenthesis (round 19)
	bracket := bracketAssigns(command)
	if dollar || assignsName(cmds, "HOME") {
		home = "" // place reads home: ~ and a bare cd are no longer placed, nor a nested ~ (reqItem.home)
	}
	subst, substRead, sub := false, false, unquotedParen(command)
	moves := 0
	var dirs []string // cwd, then each folder a cd of the line names, in order
	cur := ""
	if filepath.IsAbs(cwd) {
		cur = filepath.Clean(cwd)
		dirs = append(dirs, cur)
	}
	var queue []reqItem
	exported := map[string]string{} // export NAME=value before the command
	hold := func(c installread.Command, why string) ([]reqItem, string) {
		return nil, "changes folder in a way alalanet-agent does not place (" + clip(strings.Join(c.Words, " ")) + ": " + why +
			"), so it cannot read the requirements files"
	}
	for _, c := range cmds {
		// ${NAME:=word} sets NAME in the line's shell: as an export, for pip's ${NAME} in a file (round 26)
		for _, kv := range installread.CommandExpansionAssigns(c) {
			exported[kv[0]] = kv[1]
		}
		switch c.Prog {
		case "pushd", "popd":
			return hold(c, "pushd and popd")
		case "cd", "chdir":
			if moves++; moves > maxFolderMoves {
				return hold(c, "more folder changes than it follows")
			}
			if !substRead {
				_, _, _, subst = installread.ParseLine(command)
				substRead = true
			}
			args := c.Words[1:]
			switch {
			case subst:
				return hold(c, "a line with a command substitution")
			case sub:
				return hold(c, "a subshell")
			case unsafe != "":
				return hold(c, "the line also runs "+unsafe)
			case dollar:
				return hold(c, "a $ on the line, whose expansion can assign")
			case bracket:
				return hold(c, "a [ … = on the line, an array subscript that can assign")
			case cdpath && len(args) > 0:
				return hold(c, "CDPATH is set")
			case len(args) > 1:
				return hold(c, "more than one word")
			case len(args) == 1 && strings.HasPrefix(args[0], "-"):
				return hold(c, "an option or cd -")
			}
			target := "~" // a bare cd: the home folder
			if len(args) == 1 {
				target = args[0]
			}
			d := place(target)
			switch {
			case d == "":
				return hold(c, "a folder it cannot place")
			case filepath.IsAbs(d):
				cur = filepath.Clean(d)
			case cur != "":
				cur = filepath.Join(cur, d)
			default:
				return hold(c, "no folder to start from")
			}
			if !slices.Contains(dirs, cur) {
				dirs = append(dirs, cur)
			}
			continue
		case "source", ".":
			switch f := installread.CommandSourcedFile(c); {
			case !sources:
			case f == "" && slices.Contains(sourced, installread.SourcedOutput):
				// source <( … ): the output of a command, which alalanet-agent does not run (round 20); a bare source
				// or . loads nothing (bash: "filename argument required")
				return nil, "sources the output of a command (" + clip(strings.Join(c.Words, " ")) + " <( … )), which alalanet-agent does not run, so it may define what the install runs"
			case f != "":
				clear, venv := acts[f]
				queue = append(queue, reqItem{name: f, show: f, from: dirs, home: home, sourced: true, getenv: getenv,
					unwritten: slices.Contains(unwritten, f), venv: venv, clear: clear, pathSet: pathSet, line: command,
					userHome: userHome})
			}
			continue
		case "su", "runuser":
			if loginSwitch(c.Words[1:]) {
				return nil, "runs in another user's login folder (" + c.Prog + " " + clip(strings.Join(c.Words[1:], " ")) +
					"), so alalanet-agent cannot place its requirements files"
			}
			continue
		case "export":
			for _, a := range c.Words[1:] {
				if k, v, ok := strings.Cut(a, "="); ok && !strings.HasPrefix(k, "-") {
					exported[k] = v
				}
			}
			continue
		}
		files := installread.CommandRequirementFiles(c)
		if len(files) == 0 {
			continue
		}
		// pip's environment: the line's assignments on the command, then its exports, then the hook's
		own := map[string]string{}
		for k, v := range exported {
			own[k] = v
		}
		for _, a := range c.Assigns {
			if k, v, ok := strings.Cut(a, "="); ok {
				own[k] = v
			}
		}
		env := func(k string) string {
			if v, ok := own[k]; ok {
				return v
			}
			return getenv(k)
		}
		// the command's own folder: a wrapper's, then uv's (relative to the wrapper's); shown: what a reason may quote
		from := dirs
		wmoves, why := wrapperDir(c.Wrappers)
		if why != "" {
			return nil, why
		}
		shown := slices.Clone(wmoves) // the line's own words
		if d, ok := installread.UvDirectory(c); ok {
			wmoves, shown = append(wmoves, d), append(shown, d)
		} else if v, ok := own["UV_WORKING_DIR"]; ok && (c.Prog == "uv" || c.Prog == "uvx") {
			wmoves, shown = append(wmoves, v), append(shown, "UV_WORKING_DIR") // the variable's name, never its value
		} else if v := getenv("UV_WORKING_DIR"); v != "" && (c.Prog == "uv" || c.Prog == "uvx") {
			wmoves, shown = append(wmoves, v), append(shown, "UV_WORKING_DIR")
		}
		for i, m := range wmoves {
			if moves++; moves > maxFolderMoves {
				return hold(c, "more folder changes than it follows")
			}
			d := place(m)
			if d == "" {
				return nil, "runs " + c.Prog + " in a folder alalanet-agent cannot place (" + clip(shown[i]) + "), so it cannot read the requirements files there"
			}
			var next []string
			for _, f := range from {
				if filepath.IsAbs(d) {
					next = append(next, d)
				} else {
					next = append(next, rawJoin(f, d))
				}
			}
			if filepath.IsAbs(d) && len(next) == 0 {
				next = []string{d}
			}
			from = slices.Compact(next)
		}
		for _, f := range files {
			queue = append(queue, reqItem{name: f, show: f, from: from, getenv: env, home: home})
		}
	}
	return queue, ""
}

// cdSafe: the commands a line may run beside a literal cd for the cd to be placed (round 16): the Python install tools
// (and python -m pip, py), cd itself, and commands that cannot change how cd resolves. Wrappers before them (sudo,
// env, time …) and VAR=value words of other names are no concern of cd's.
var cdSafe = map[string]bool{"cd": true, "chdir": true, "pip": true, "pip3": true, "uv": true, "uvx": true, "pipx": true,
	"py": true, "echo": true, "true": true, "test": true, "[": true, "ls": true, "mkdir": true, "pwd": true} // export: cdUnsafe reads its words

// cdUnsafe: what in command c can change where a literal cd goes ("" when nothing): a command outside cdSafe (set -P,
// shopt -s cdable_vars, setopt, alias cd, read CDPATH, printf -v CDPATH, source, a function definition …), an
// assignment or export of CDPATH or zsh's cdpath in any case or form (CDPATH+=, cdpath=), an export with an option
// (export -f exports a function).
func cdUnsafe(c installread.Command) string {
	cdpathName := func(w string) bool {
		name, _, _ := strings.Cut(w, "=")
		name = strings.TrimSuffix(name, "+")
		return strings.EqualFold(name, "cdpath") || name == "PWD" || name == "OLDPWD" // what cd resolves through
	}
	for _, a := range c.Assigns {
		if cdpathName(a) {
			return "an assignment of CDPATH" // or of cdpath, PWD, OLDPWD
		}
	}
	switch {
	case c.Prog == "":
		return ""
	case c.Prog == "export":
		for _, w := range c.Words[1:] {
			if strings.HasPrefix(w, "-") || cdpathName(w) {
				return clip(strings.Join(c.Words, " "))
			}
		}
		return ""
	case (c.Prog == "test" || c.Prog == "[") && slices.Contains(c.Words[1:], "-v"):
		return c.Prog + " -v" // test -v 'a[CDPATH=1]' evaluates the subscript (bash 5.2, round 19)
	case strings.HasPrefix(c.Prog, "python") && strings.Trim(c.Prog[len("python"):], "0123456789.") == "", cdSafe[c.Prog]:
		return ""
	}
	return c.Prog
}

// dollarOutsideSingle: the raw line has a $ that the shell expands — outside single quotes, not escaped by a backslash.
func dollarOutsideSingle(line string) bool {
	var q byte
	for i := 0; i < len(line); i++ {
		switch c := line[i]; {
		case q == '\'':
			if c == '\'' {
				q = 0
			}
		case c == '\\':
			i++
		case c == '"':
			if q == '"' {
				q = 0
			} else {
				q = c
			}
		case c == '\'' && q == 0:
			q = c
		case c == '$':
			return true
		}
	}
	return false
}

// bracketAssigns: a word of the raw line with a [ and, after it, an = — outside single quotes — the shape of an array
// element's assignment (a[CDPATH=1]=x, export a[CDPATH=1]=x): bash evaluates an indexed array's subscript as an
// arithmetic expression, which can assign with no $ and no parenthesis (round 19, P2-H). A $'…' is no concern: its $
// already holds the line (dollarOutsideSingle).
func bracketAssigns(line string) bool {
	var q byte
	open := false
	for i := 0; i < len(line); i++ {
		switch c := line[i]; {
		case q == '\'':
			if c == '\'' {
				q = 0
			}
		case c == '\\':
			i++
		case c == '"':
			if q == '"' {
				q = 0
			} else {
				q = c
			}
		case c == '\'' && q == 0:
			q = c
		case q == 0 && strings.IndexByte(" \t\r\n;&|()<>", c) >= 0:
			open = false // the word ends
		case c == '[':
			open = true
		case c == '=' && open:
			return true
		}
	}
	return false
}

// readSourced reads a file the line sources (round 20, P2-I; the coordinator's decision): within the requirements
// files' bounds (the folders the line placed, the size, the count, the bytes in all) and silent only when it is byte for
// byte a known virtual environment's activate script for its own folder (activateTemplate, REPO-POL-NPMRC's matcher).
// Any other file holds — it can define the install's command — and so does one that cannot be placed or read. A name
// that is not there is no file the shell runs: nothing is defined.
func readSourced(f reqItem, read, total *int, seen map[string]bool) string {
	name := f.name
	switch {
	case strings.HasPrefix(name, "-"):
		return "sources with an option (" + clip(f.show) + "), which alalanet-agent does not read, so the file may define what the install runs"
	case strings.HasPrefix(name, "~"):
		if name = placeName(name, f.home); name == "" {
			return "sources a file alalanet-agent cannot place (" + clip(f.show) + "), which may define what the install runs"
		}
	case strings.ContainsAny(name, "$`*?["):
		return "sources a file alalanet-agent cannot place (" + clip(f.show) + "), which may define what the install runs"
	}
	var paths []string
	if filepath.IsAbs(name) {
		paths = []string{name}
	} else {
		for _, d := range f.from {
			paths = append(paths, rawJoin(d, name))
		}
	}
	var hits []string // the PATH copies of a name with no slash; a reason names one "from PATH", never PATH's folder
	if !strings.Contains(name, "/") {
		// round 22 (P2-M): bash's source and . (sourcepath, the default) and zsh's . look a name with no slash up in
		// PATH first, then (not in bash's POSIX mode) in the current folder; zsh's source the other way round. The
		// first PATH hit is read, and the current folder's copy too. Round 23 (P3-T): the shell's PATH may hold the
		// folders the login files add, which a hook started from a GUI does not have: their first hit is read too.
		var why string
		if hits, why = pathLookup(f); why != "" {
			return why
		}
		paths = append(slices.Clone(hits), paths...)
	}
	found := false
	for _, p := range paths {
		if seen[p] {
			found = true // read already, for an earlier source of the same file
			continue
		}
		seen[p] = true
		show := f.show
		if slices.Contains(hits, p) {
			show += " from PATH"
		}
		if *read++; *read > maxReqFiles {
			return "names more files than alalanet-agent reads for one line"
		}
		b, err := readFollow(p, maxReqFile)
		switch {
		case errors.Is(err, fs.ErrNotExist), errors.Is(err, syscall.ENOTDIR):
			continue
		case errors.Is(err, errTooBig):
			return clip(show) + " is larger than alalanet-agent reads in a sourced file, so what it defines is not known"
		case err != nil:
			return clip(show) + " could not be read (" + why(err) + "), so what it defines is not known"
		}
		found = true
		if *total += len(b); *total > maxReqBytes {
			return "names files larger in all than alalanet-agent reads for one line"
		}
		if activateTemplate(p, b) != "" {
			continue
		}
		pairs, ok := dotenvPairs(b)
		if !ok {
			return "sources " + clip(show) + ", which is no virtual environment's activate script alalanet-agent knows, so it may define what the install runs"
		}
		if why := dotenvHold(f.line, pairs); why != "" {
			return "sources " + clip(show) + ", which " + why
		}
	}
	// round 21 (P2-J): a file that is not there now may be the line's own work — echo … > new.sh && . ./new.sh — so it
	// holds, unless it is the activate script of a venv the line itself creates first, or no command before it may write
	if !found && f.venv && !f.clear {
		// round 22 (P3-R): a venv tool over a folder that is there keeps what is in it (python -m venv --without-pip
		// and virtualenv leave a bin/pip of the folder's), unless --clear empties it
		for _, d := range f.from {
			if _, err := os.Lstat(rawJoin(d, filepath.Dir(filepath.Dir(name)))); err == nil || filepath.IsAbs(name) && dirThere(name) {
				return clip(f.show) + " is not there when alalanet-agent reads, and the line makes its venv over a folder that is there, which keeps what is in it"
			}
		}
	}
	if !found && !f.venv && !f.unwritten {
		return clip(f.show) + " is not there when alalanet-agent reads, and the line may write it before it sources it, so what it defines is not known"
	}
	return ""
}

// pathLookup: the first file named f.name in the hook's PATH, and the first in the PATH folders the user's login files
// add (startupPATH) — the files bash and zsh may source for a name with no slash — or why it cannot be looked up: the
// line sets PATH, the hook has none, a folder in it that alalanet-agent cannot place or read, or an entry by that name
// that is no regular file and no folder (a FIFO, a socket, a device: bash sources a FIFO, round 23, P3-U). A reason
// never quotes PATH's value.
func pathLookup(f reqItem) (hits []string, reason string) {
	by := "sources " + clip(f.show) + " by name, which the shell looks up in PATH"
	if f.pathSet {
		return nil, by + ", and the line sets PATH"
	}
	pv := ""
	if f.getenv != nil {
		pv = f.getenv("PATH")
	}
	if pv == "" {
		return nil, by + ", and alalanet-agent has no PATH to read"
	}
	first := func(dirs []string) (string, string) {
		for _, d := range dirs {
			if d == "" {
				d = "." // an empty entry is the current folder
			}
			if strings.ContainsAny(d, "$`") || strings.HasPrefix(d, "~") {
				return "", by + ", and a PATH folder is one alalanet-agent cannot place"
			}
			var cands []string
			if filepath.IsAbs(d) {
				cands = []string{rawJoin(d, f.name)}
			} else {
				for _, from := range f.from {
					cands = append(cands, rawJoin(rawJoin(from, d), f.name))
				}
			}
			for _, c := range cands {
				fi, err := os.Stat(c)
				switch {
				case err == nil && fi.Mode().IsRegular():
					return c, ""
				case err == nil && !fi.IsDir():
					return "", by + ", and an entry of PATH by that name is no regular file (a FIFO, a socket or a device the shell may read)"
				case err != nil && !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, syscall.ENOTDIR):
					return "", by + ", and a PATH folder could not be read (" + why(err) + ")"
				}
			}
		}
		return "", ""
	}
	for _, dirs := range [][]string{strings.Split(pv, string(os.PathListSeparator)), startupPATH(f.userHome)} {
		hit, why := first(dirs)
		if why != "" {
			return nil, why
		}
		if hit != "" && !slices.Contains(hits, hit) {
			hits = append(hits, hit)
		}
	}
	return hits, ""
}

// startupNames: the login and interactive files of bash, zsh and sh in the home folder, which may add to PATH.
var startupNames = []string{".zshenv", ".zprofile", ".zshrc", ".zlogin", ".profile", ".bashrc", ".bash_profile", ".bash_login"}

// startupPATHLine: a PATH assignment of a startup file — [export ]PATH=VALUE, or zsh's path=( … ) / path+=( … ).
var startupPATHLine = regexp.MustCompile(`^\s*(?:export\s+)?(?:PATH=(.*)|path\+?=\((.*)\))\s*$`)

// startupPATH: the absolute folders the user's startup files (startupNames) put in PATH by a literal path, with $HOME,
// ${HOME} and a leading ~ as the home folder; $PATH, $path and any other value are left out — what a variable, a
// sourced file or an eval adds (eval "$(brew shellenv)", macOS's path_helper) is not derived (round 23, P3-T).
func startupPATH(home string) []string {
	if !filepath.IsAbs(home) {
		return nil
	}
	var dirs []string
	for _, n := range startupNames {
		b, err := readFollow(filepath.Join(home, n), maxReqFile)
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(b), "\n") {
			m := startupPATHLine.FindStringSubmatch(l)
			if m == nil {
				continue
			}
			var entries []string
			if m[1] != "" {
				v := strings.TrimSpace(m[1])
				if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
					v = v[1 : len(v)-1]
				}
				entries = strings.Split(v, ":")
			} else {
				for _, w := range strings.Fields(m[2]) {
					entries = append(entries, strings.Trim(w, `"'`))
				}
			}
			for _, e := range entries {
				for _, h := range []string{"${HOME}", "$HOME"} {
					if strings.HasPrefix(e, h) {
						e = home + e[len(h):]
					}
				}
				if e == "~" || strings.HasPrefix(e, "~/") {
					e = home + e[1:]
				}
				if filepath.IsAbs(e) && !strings.ContainsAny(e, "$`") && !slices.Contains(dirs, e) {
					dirs = append(dirs, e)
				}
			}
		}
	}
	return dirs
}

// dirThere: the venv folder of an absolute bin/activate name is there.
func dirThere(name string) bool {
	_, err := os.Lstat(filepath.Dir(filepath.Dir(name)))
	return err == nil
}

// dotenvLine: one line of a data file a shell can source — [export ]NAME=VALUE with a literal value: single-quoted,
// double-quoted with no $, backtick or backslash, or plain with no blank, quote, $, backtick, backslash, ( ) ; & | < >.
var dotenvLine = regexp.MustCompile(`^(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)=('[^'\x00]*'|"[^"$` + "`" + `\\\x00]*"|[^\s'"$` + "`" + `\\()\x00;&|<>]*)$`)

// dotenvPairs: the assignments of a sourced file that is only data — every line blank, a comment, or a dotenvLine —
// as (name, value) pairs; ok false for any other file (round 21, P3-P).
func dotenvPairs(b []byte) (pairs [][2]string, ok bool) {
	if !utf8.Valid(b) {
		return nil, false
	}
	for _, l := range strings.Split(string(b), "\n") {
		t := strings.TrimLeft(l, " \t")
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		m := dotenvLine.FindStringSubmatch(t)
		if m == nil {
			return nil, false
		}
		v := m[2]
		if len(v) >= 2 && (v[0] == '\'' || v[0] == '"') {
			v = v[1 : len(v)-1]
		}
		pairs = append(pairs, [2]string{m[1], v})
	}
	return pairs, true
}

// dotenvShell: names a data file must not set — the shell's own (what cd and ~ resolve through, the startup files a
// shell reads, word splitting, prompts and traces): the placing and the reading of the rest of the line assume them.
var dotenvShell = map[string]bool{"HOME": true, "CDPATH": true, "PWD": true, "OLDPWD": true, "ENV": true, "BASH_ENV": true,
	"ZDOTDIR": true, "IFS": true, "PROMPT_COMMAND": true, "PS4": true, "SHELLOPTS": true, "BASHOPTS": true,
	"GLOBIGNORE": true, "BASH_XTRACEFD": true, "BASH_COMPAT": true}

// dotenvHold: why a data file's assignments hold the line, or "": a shell name (dotenvShell), or one the line readers
// judge as they judge the same export on the line (a registry, a config file, code loaded, a search path). The reason
// names the variable, never its value.
func dotenvHold(line string, pairs [][2]string) string {
	for _, kv := range pairs {
		if dotenvShell[kv[0]] {
			return "sets " + kv[0] + ", which changes how the shell runs the rest of the line"
		}
	}
	base := lineReasons(line)
	judge := func(ps [][2]string) bool {
		var b strings.Builder
		b.WriteString("export")
		for _, kv := range ps {
			b.WriteString(" '" + strings.ReplaceAll(kv[0]+"="+kv[1], "'", `'\''`) + "'")
		}
		for _, r := range lineReasons(b.String() + "; " + line) {
			if !slices.Contains(base, r) {
				return true
			}
		}
		return false
	}
	if len(pairs) == 0 || !judge(pairs) {
		return ""
	}
	for _, kv := range pairs {
		if judge([][2]string{kv}) {
			return "sets " + kv[0] + ", which the line readers hold on (where the install comes from, or what it runs)"
		}
	}
	return "sets variables the line readers hold on together"
}

// lineReasons: both line readers' reasons for a line.
func lineReasons(line string) []string {
	tg, un, _, subst := installread.ParseLine(line)
	return append(un, installread.HookExtra(line, tg, un, subst)...)
}

// assignsName: a command of the line assigns or exports name (NAME=…, NAME+=…, export NAME=…, declare/typeset/local
// NAME …).
func assignsName(cmds []installread.Command, name string) bool {
	is := func(w string) bool {
		n, _, _ := strings.Cut(w, "=")
		return strings.TrimSuffix(n, "+") == name
	}
	for _, c := range cmds {
		for _, a := range c.Assigns {
			if is(a) {
				return true
			}
		}
		switch c.Prog {
		case "export", "declare", "typeset", "local", "readonly", "read", "unset":
			for _, w := range c.Words[1:] {
				if is(w) {
					return true
				}
			}
		}
	}
	return false
}

// rawJoin and rawDir join and split a path as pip and the kernel read it — no cleaning: "link/.." is the parent of the
// link's target, which filepath.Clean would make the folder the link is in (round 16).
func rawJoin(dir, name string) string {
	return strings.TrimSuffix(dir, string(filepath.Separator)) + string(filepath.Separator) + name
}

func rawDir(p string) string {
	if i := strings.LastIndexByte(p, filepath.Separator); i > 0 {
		return p[:i]
	}
	return string(filepath.Separator)
}

// maxFolderMoves: the folder changes one line may make before the reader stops following them and holds (round 15:
// the walk was quadratic in cds; 16 is more than any honest line of the corpus makes).
const maxFolderMoves = 16

// unquotedParen: the line opens a ( outside quotes — a subshell, whose cd ends with it, or a substitution: a cd on such a
// line is not placed (round 15).
func unquotedParen(line string) bool {
	var q byte
	for i := 0; i < len(line); i++ {
		switch c := line[i]; {
		case q == '\'':
			if c == '\'' {
				q = 0
			}
		case c == '\\':
			i++
		case q == '"':
			if c == '"' {
				q = 0
			}
		case c == '\'' || c == '"':
			q = c
		case c == '(':
			return true
		}
	}
	return false
}

// readReqFiles reads the files planReqFiles gives, and those they name, as pip reads them: why they hold the line, or "".
func readReqFiles(queue []reqItem) string {
	read, total := 0, 0
	seen := map[string]bool{}
	for len(queue) > 0 {
		f := queue[0]
		queue = queue[1:]
		if f.sourced {
			if why := readSourced(f, &read, &total, seen); why != "" {
				return why
			}
			continue
		}
		name := f.name
		switch {
		case reqScheme.MatchString(name):
			return "names a requirements file at a URL (" + clip(f.show) + "), which alalanet-agent does not fetch"
		case strings.HasPrefix(name, "~"):
			if name = placeName(name, f.home); name == "" {
				return "names a requirements file alalanet-agent cannot place (" + clip(f.show) + ")"
			}
		case strings.ContainsAny(name, "$`"):
			return "names a requirements file by a variable (" + clip(f.show) + "), which alalanet-agent cannot read"
		case pipDescriptor.MatchString(name):
			return "names one of pip's own file descriptors as a requirements file (" + clip(f.show) + "), which alalanet-agent cannot read"
		case strings.ContainsAny(name, "*?["):
			return "names requirements files by a pattern the shell expands (" + clip(f.show) + "), which alalanet-agent does not follow"
		}
		var paths []string
		if filepath.IsAbs(name) {
			paths = []string{name}
		} else {
			for _, d := range f.from {
				paths = append(paths, rawJoin(d, name))
			}
		}
		for _, p := range paths {
			if seen[p] {
				continue
			}
			seen[p] = true
			if read++; read > maxReqFiles {
				return "names more requirements files than alalanet-agent reads for one line"
			}
			b, err := readFollow(p, maxReqFile)
			switch {
			case errors.Is(err, fs.ErrNotExist), errors.Is(err, syscall.ENOTDIR):
				continue // not there: pip reads it in another folder of the line's, or fails
			case errors.Is(err, errTooBig):
				return clip(f.show) + " is larger than alalanet-agent reads in a requirements file, so the index it may name is not known"
			case err != nil:
				return clip(f.show) + " could not be read (" + why(err) + "), so the index it may name is not known"
			}
			if total += len(b); total > maxReqBytes {
				return "names requirements files larger in all than alalanet-agent reads for one line"
			}
			reasons, nested := installread.ReqFileReasons(b, f.getenv)
			if len(reasons) > 0 {
				return clip(f.show) + " " + reasons[0]
			}
			for _, n := range nested {
				// pip reads a nested file from the folder of the one naming it
				queue = append(queue, reqItem{name: n.Name, show: n.Shown, from: []string{rawDir(p)}, getenv: f.getenv, home: f.home})
			}
		}
	}
	return ""
}

// pipDescriptor: a name that is one of pip's own open files (bash and zsh pass /dev/fd/N; Linux's /proc/self/fd/N and
// /proc/PID/fd/N; /dev/stdin and the others), not a file the hook's process can open as pip would.
var pipDescriptor = regexp.MustCompile(`^/(dev/fd(/|$)|dev/std(in|out|err)$|proc/[^/]+/fd(/|$))`)

// loginSwitch: su's or runuser's words start a login shell (-, -l, --login and its prefixes from --lo, -l in a cluster
// before c), which runs in the target user's home folder. getopt reads options on both sides of -c's script.
func loginSwitch(ws []string) bool {
	for i := 0; i < len(ws); i++ {
		switch x := ws[i]; {
		case x == "-" || x == "-l":
			return true
		case strings.HasPrefix(x, "--lo") && strings.HasPrefix("--login", x):
			return true
		case x == "--":
			return false
		case x == "-c" || x == "--command" || x == "-s" || x == "--shell" || x == "-u" || x == "--user" || x == "-g" || x == "-G":
			i++ // the option's value
		case len(x) > 2 && x[0] == '-' && x[1] != '-':
			for _, r := range x[1:] {
				if r == 'l' {
					return true
				}
				if !strings.ContainsRune("mpfP", r) {
					break
				}
			}
		}
	}
	return false
}

// wrapperDir: the folders a command's wrappers change to (env -C DIR, -CDIR, a cluster -iC DIR, --chdir=DIR or a
// prefix of it from --c; sudo -D DIR, --chdir), in order, and why it holds when a wrapper moves the folder in a way
// this reading does not follow (sudo -R or --chroot: another root).
func wrapperDir(ws []string) (dirs []string, why string) {
	prog := ""
	for i := 0; i < len(ws); i++ {
		x := ws[i]
		if !strings.HasPrefix(x, "-") || x == "-" {
			prog = installread.LaunchBase(x)
			continue
		}
		next := func() string {
			if i+1 < len(ws) {
				i++
				return ws[i]
			}
			return ""
		}
		name, val, eq := strings.Cut(x, "=")
		switch {
		case prog == "env" && strings.HasPrefix(name, "--") && len(name) >= 3 && strings.HasPrefix("--chdir", name),
			prog == "sudo" && strings.HasPrefix(name, "--") && len(name) >= 5 && strings.HasPrefix("--chdir", name):
			if !eq {
				val = next()
			}
			dirs = append(dirs, val)
		case prog == "sudo" && strings.HasPrefix(name, "--") && len(name) >= 5 && strings.HasPrefix("--chroot", name):
			return nil, "runs under sudo --chroot, so alalanet-agent cannot place its requirements files"
		case prog == "sudo" && strings.HasPrefix(name, "--lo") && strings.HasPrefix("--login", name):
			return nil, "runs in another user's login folder (sudo --login), so alalanet-agent cannot place its requirements files"
		case (prog == "env" || prog == "sudo") && !strings.HasPrefix(x, "--"):
			// a cluster of short options: the first that takes a value takes the rest of the word, or the next one
			chdir, root, values := "C", "", "uSaP" // env: -C; -u, -S, -a, -P take a value
			if prog == "sudo" {
				chdir, root, values = "D", "R", "ugpUhrtTCc"
			}
			for k := 1; k < len(x); k++ {
				switch l := x[k : k+1]; {
				case l == chdir:
					v := x[k+1:]
					if v == "" {
						v = next()
					}
					dirs = append(dirs, v)
				case l == root:
					return nil, "runs under sudo -R, so alalanet-agent cannot place its requirements files"
				case prog == "sudo" && l == "i":
					return nil, "runs in another user's login folder (sudo -i), so alalanet-agent cannot place its requirements files"
				case strings.Contains(values, l):
					if k+1 == len(x) {
						next()
					}
				default:
					continue
				}
				break
			}
		}
	}
	return dirs, ""
}

// clip keeps a path or a file name short in a reason.
func clip(s string) string {
	if len(s) > 120 {
		return s[:117] + "..."
	}
	return s
}

// reqFileVerdict holds an install for a reason of its requirements files, or adds that reason to alalanet's own hold.
func reqFileVerdict(v verdict, why string) verdict {
	const what = "the line's local files (a requirements file or a sourced script): "
	if v.Decision == "ask" && strings.TrimSpace(v.Reason) != "" {
		v.Reason = strings.TrimSpace(v.Reason) + " Also, " + what + why + "."
		return v
	}
	return verdict{Decision: "ask", Reason: "alalanet install_check: HOLD — " + what + why +
		". Install only if the user confirms.", warn: v.warn}
}
