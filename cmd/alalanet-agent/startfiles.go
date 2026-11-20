package main

// REPO-POL-NPMRC rounds 8 and 9 (ADR-0174 rounds 13 and 14): which shell startup files the hook reads and pins. The
// startup list (startupList) is the files the shells read by name — zsh's, bash's, the login profile, fish's, systemd's
// environment.d, BASH_ENV's and ENV's, Codex's shell snapshots, and with pf.system the /etc ones. Each of these is also
// read for what it names (startupRefs): a ZDOTDIR or BASH_ENV/ENV it sets to a literal path (more startup files), and
// one level deep, the files it sources by a literal path and the program of an eval "$(<program> …)" line (pinned, not
// read further). A path this reader cannot place (a variable it did not see set, a substitution) is the stated
// residual: the reading of its values stays the only check of it.

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// startFile is a file of the startup list: level 0 is a startup file (read for what it names), 1 a file one names;
// prog: a program one evals, pinned by its sum and not read as a shell file.
type startFile struct {
	path  string
	level int
	prog  bool
}

// maxStartRefs bounds what one startup file names; past it, the file counts as moved (a variable for tests).
var maxStartRefs = 256

// startupFiles reads the startup files (startupList, then what they name), judging their values when judge is set,
// and gives them as the pin keeps them (startpin.go): each path's sha256, or pinAbsent. A link is followed (dotfile
// managers link them; readFollow checks the opened file). When a file moves the source (it cannot be read, or with
// judge a value moves it), c.why says why, and the state is not to be pinned: once c.why is set, read gives nothing
// more, so what is left reads as absent.
func (c *regCheck) startupFiles(judge bool) map[string]string {
	c.enumerated, c.autoDirs = map[string]bool{}, map[string]bool{}
	state := map[string]string{}
	var queue []startFile
	queued := map[string]bool{}
	add := func(f startFile) {
		if !filepath.IsAbs(f.path) {
			return
		}
		f.path = filepath.Clean(f.path)
		if !queued[f.path] {
			queued[f.path] = true
			queue = append(queue, f)
		}
	}
	for _, f := range c.startupList() {
		add(startFile{path: f})
	}
	for i := 0; i < len(queue); i++ {
		f := queue[i]
		if f.prog {
			state[f.path] = c.programSum(f.path)
			continue
		}
		delete(c.seen, f.path) // read here even when the line sourced it: the pin is of the file, whoever read it first
		before := c.why
		b := c.readFollow(f.path)
		if b == nil {
			if before == "" && c.why != "" && strings.Contains(c.why, "permission denied") {
				// round 15 (P3): a GUI runtime may not read a file the user's terminal reads (macOS privacy folders)
				c.why = f.path + " is a shell startup file this agent runtime cannot read (permission denied): give the runtime read access to it (on macOS: System Settings, Privacy & Security, Full Disk Access or Files and Folders), or stop the startup files from reading it"
			}
			state[f.path] = pinAbsent
			continue
		}
		if filepath.Base(f.path) == "fish_variables" {
			// round 15 (P3): fish rewrites it whenever any universal variable changes (prompts keep state there), so
			// only what changes the commands is pinned: exported variables, fish_user_paths and fish_function_path
			rel := fishRelevant(b)
			state[f.path] = fileSum(rel)
			if judge {
				c.inStartup = true
				c.fishVariables(f.path, rel)
				c.inStartup = false
			}
			continue
		}
		state[f.path] = fileSum(b)
		if judge {
			c.inStartup = true
			c.assignments(f.path, b, true)
			c.inStartup = false
		}
		if f.level == 0 && !c.autoDirs[filepath.Dir(f.path)] {
			refs := c.startupRefs(f.path, b, judge)
			if len(refs) > maxStartRefs {
				c.moved(f.path, "names more files than this reader pins")
				continue
			}
			for _, r := range refs {
				add(r)
			}
		}
	}
	return state
}

var zshNames = []string{".zshenv", ".zprofile", ".zshrc", ".zlogin"}

// startupList: the startup files by name. A folder of them (conf.d, functions, environment.d, profile.d, paths.d) is
// taken whole; Codex's shell snapshots are pinned on first sight (autoDirs).
func (c *regCheck) startupList() []string {
	var files []string
	fishDirs := []string{}
	if h := c.home; h != "" {
		for _, n := range append(append([]string{}, zshNames...), ".profile", ".bashrc", ".bash_profile", ".bash_login") {
			files = append(files, filepath.Join(h, n))
		}
		fishDirs = append(fishDirs, filepath.Join(h, ".config", "fish"))
		files = append(files, c.listed(filepath.Join(h, ".config", "environment.d"), ".conf")...)
		for _, d := range []string{filepath.Join(h, ".local", "share", "fish", "vendor_conf.d"), filepath.Join(h, ".local", "share", "fish", "vendor_functions.d")} {
			files = append(files, c.listed(d, ".fish")...)
		}
	}
	for _, x := range c.vals("XDG_CONFIG_HOME") {
		if filepath.IsAbs(x) {
			fishDirs = append(fishDirs, filepath.Join(x, "fish")) // fish reads it in place of ~/.config/fish
		}
	}
	for _, x := range c.vals("XDG_DATA_HOME") {
		if filepath.IsAbs(x) {
			files = append(files, c.listed(filepath.Join(x, "fish", "vendor_conf.d"), ".fish")...)
			files = append(files, c.listed(filepath.Join(x, "fish", "vendor_functions.d"), ".fish")...)
		}
	}
	for _, d := range fishDirs {
		files = append(files, filepath.Join(d, "config.fish"), filepath.Join(d, "fish_variables"))
		files = append(files, c.listed(filepath.Join(d, "conf.d"), ".fish")...)
		files = append(files, c.listedMax(filepath.Join(d, "functions"), ".fish", 4*maxListed)...)
	}
	for _, z := range c.vals("ZDOTDIR") {
		for _, n := range zshNames {
			files = append(files, filepath.Join(z, n))
		}
	}
	// BASH_ENV: what a non-interactive bash runs (bash -c in the line, npm's scripts under bash); ENV: sh's
	for _, n := range []string{"BASH_ENV", "ENV"} {
		for _, v := range c.vals(n) {
			if p, ok := c.literal(v); ok {
				files = append(files, p)
			}
		}
	}
	// Codex sources $CODEX_HOME/shell_snapshots/<session>.<nonce>.sh before each command when its shell_snapshot
	// feature is on (stable, on by default: codex-rs/core/src/tools/runtimes/mod.rs, maybe_wrap_shell_lc_with_snapshot)
	var codex []string
	for _, v := range c.vals("CODEX_HOME") {
		if filepath.IsAbs(v) {
			codex = append(codex, v)
		}
	}
	if len(codex) == 0 && c.home != "" {
		codex = []string{filepath.Join(c.home, ".codex")}
	}
	for _, d := range codex {
		snap := filepath.Join(d, "shell_snapshots")
		c.autoDirs[filepath.Clean(snap)] = true
		files = append(files, c.listedMax(snap, ".sh", 4*maxListed)...)
	}
	if c.pf.system {
		files = append(files, "/etc/environment", "/etc/profile", "/etc/bash.bashrc", "/etc/bashrc", "/etc/zshenv",
			"/etc/zprofile", "/etc/zshrc", "/etc/zlogin", "/etc/zsh/zshenv", "/etc/zsh/zprofile", "/etc/zsh/zshrc",
			"/etc/zsh/zlogin", "/etc/fish/config.fish", "/etc/paths")
		files = append(files, c.listed("/etc/profile.d", ".sh")...)
		files = append(files, c.listed("/etc/environment.d", ".conf")...)
		files = append(files, c.listed("/etc/paths.d", "")...) // path_helper's, in /etc/zprofile and /etc/profile
		files = append(files, c.listed("/etc/fish/conf.d", ".fish")...)
		for _, p := range []string{"/opt/homebrew", "/usr/local", "/usr"} { // brew's are the user's on macOS
			files = append(files, c.listed(filepath.Join(p, "share", "fish", "vendor_conf.d"), ".fish")...)
			files = append(files, c.listed(filepath.Join(p, "share", "fish", "vendor_functions.d"), ".fish")...)
		}
	}
	return files
}

var (
	// a source of a file: source or . (\. as nvm writes it), after the start of a command, and its word
	sourceCmd = regexp.MustCompile(`(?:^|[;&|({]|\bthen\b|\bdo\b|\belse\b|\band\b|\bor\b)\s*(?:builtin\s+|command\s+)?(?:source|\\?\.)\s+("[^"]*"|'[^']*'|[^\s;&|)]+)`)
	// eval "$(<program> …)", eval "$(<program>)", eval `<program> …` and fish's eval (<program> …): the program's word
	evalCmd = regexp.MustCompile("\\beval\\s+(?:\"\\$\\(|\\$\\(|`|\"`|\\()\\s*([^\\s)\"'`]+)")
	// source <(<program> …) and . <(…): the program's word (round 15, R9-3)
	procSource = regexp.MustCompile(`(?:^|[;&|({]|\bthen\b|\bdo\b|\belse\b|\band\b|\bor\b)\s*(?:builtin\s+|command\s+)?(?:source|\\?\.)\s+<\(\s*([^\s)"'` + "`" + `]+)`)
	// a here-string's $(<program> …): the program whose output source /dev/stdin reads (round 16)
	hereProg = regexp.MustCompile("<<<\\s*\"?\\$\\(\\s*([^\\s)\"'`]+)")
	// fish's <program> … | source: the program's word
	pipeSource = regexp.MustCompile(`(?:^|[;&(]|\band\b|\bor\b)\s*([^\s|;&()]+)[^|;&]*\|\s*source\b`)
	// ${XDG_CONFIG_HOME:-$HOME/.config} and its ~ form: the usual way to write ZDOTDIR
	xdgDefault = regexp.MustCompile(`\$\{XDG_CONFIG_HOME:-(?:\$HOME|\$\{HOME\}|~)/\.config\}`)
)

// startupRefs: the files a startup file names — the zsh files of a ZDOTDIR it sets (in .zshenv), the files of a
// BASH_ENV or ENV it sets (level 0); the files it sources and the programs it evals, by a path this reader can place
// (level 1). A variable is placed when the file set it to a literal earlier ($ZSH, $NVM_DIR), or it is HOME.
func (c *regCheck) startupRefs(path string, b []byte, judge bool) []startFile {
	var out []startFile
	vars := map[string]string{}
	var names []string // vars' names, the longest first
	place := func(w string) (string, bool) {
		w = strings.TrimSpace(w)
		if xdg := c.vals("XDG_CONFIG_HOME"); len(xdg) > 0 && filepath.IsAbs(xdg[0]) {
			w = xdgDefault.ReplaceAllLiteralString(w, xdg[0])
		} else if c.home != "" {
			w = xdgDefault.ReplaceAllLiteralString(w, filepath.Join(c.home, ".config"))
		}
		for _, n := range names { // $ZZ before $Z, which begins it (READER-REASON-ORDER-1, round 48)
			v := vars[n]
			w = strings.ReplaceAll(strings.ReplaceAll(w, "${"+n+"}", v), "$"+n+"/", v+"/")
			if strings.HasSuffix(w, "$"+n) || strings.HasSuffix(w, "$"+n+`"`) {
				w = strings.Replace(w, "$"+n, v, 1)
			}
		}
		p, ok := c.literal(w)
		if !ok || !filepath.IsAbs(p) {
			return "", false
		}
		return filepath.Clean(p), true
	}
	zshenv := filepath.Base(path) == ".zshenv" || filepath.Base(path) == "zshenv"
	text := strings.ReplaceAll(strings.ReplaceAll(string(b), "\r\n", "\n"), "\\\n", "")
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(codePart(strings.TrimSpace(raw)))
		if line == "" {
			continue
		}
		if m := shAssign.FindStringSubmatch(line); m != nil {
			v := strings.TrimSpace(m[2])
			if p, ok := place(v); ok {
				if i, found := slices.BinarySearchFunc(names, m[1], longestFirst); !found {
					names = slices.Insert(names, i, m[1])
				}
				vars[m[1]] = p
				switch {
				case m[1] == "ZDOTDIR" && zshenv:
					for _, n := range zshNames {
						out = append(out, startFile{path: filepath.Join(p, n)})
					}
				case m[1] == "BASH_ENV" || m[1] == "ENV":
					out = append(out, startFile{path: p})
				}
			}
		}
		progs := append(evalCmd.FindAllStringSubmatch(line, -1), pipeSource.FindAllStringSubmatch(line, -1)...)
		progs = append(progs, hereProg.FindAllStringSubmatch(line, -1)...)
		for _, m := range sourceCmd.FindAllStringSubmatch(line, -1) {
			p, ok := place(m[1])
			if !ok {
				continue
			}
			if !fdPath(p) {
				out = append(out, startFile{path: p, level: 1})
				continue
			}
			// round 16 (R10-2): source /dev/stdin <<<"$(prog …)", prog … | source /dev/stdin: a process's output,
			// as source <(…) — the program is pinned below when the line names it by a path
			placed := false
			for _, pm := range progs {
				if _, ok := place(pm[1]); ok {
					placed = true
				}
			}
			if !placed && judge {
				c.moved(path, "sources the output of a program by "+p+" and names that program by no path this reader can place, so the pin cannot hold it: write the program's full path in that line (or source a file instead)")
			}
		}
		for _, m := range append(progs, procSource.FindAllStringSubmatch(line, -1)...) {
			p, ok := place(m[1])
			if !ok {
				continue
			}
			out = append(out, startFile{path: p, level: 1, prog: true})
			// brew shellenv: bin/brew runs Library/Homebrew/brew.sh, which runs cmd/shellenv.sh
			if filepath.Base(p) == "brew" && filepath.Base(filepath.Dir(p)) == "bin" {
				lib := filepath.Join(filepath.Dir(filepath.Dir(p)), "Library", "Homebrew")
				out = append(out, startFile{path: filepath.Join(lib, "brew.sh"), level: 1, prog: true},
					startFile{path: filepath.Join(lib, "cmd", "shellenv.sh"), level: 1, prog: true})
			}
		}
	}
	return out
}

// longestFirst orders names the longest first, then by their bytes.
func longestFirst(a, b string) int { return cmp.Or(len(b)-len(a), strings.Compare(a, b)) }

// maxProgram bounds a program pinned by its sum (a variable for tests).
var maxProgram int64 = 512 << 20

// programSum is the pin's state of a program a startup file evals: its sha256, read as readFollow reads (a link
// followed, never waiting on a FIFO, the opened file the one Stat saw) but streamed and not counted against the
// reading's budget; pinAbsent when there is none. One that cannot be read counts as moved.
func (c *regCheck) programSum(path string) string {
	seen, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
		return pinAbsent
	}
	if err == nil && !seen.Mode().IsRegular() {
		err = errNotRegular
	}
	var f *os.File
	if err == nil {
		f, err = openFollowNoWait(path)
	}
	if err == nil {
		defer f.Close()
		var fi os.FileInfo
		if fi, err = f.Stat(); err == nil && (!os.SameFile(fi, seen) || !fi.Mode().IsRegular() || fi.Size() != seen.Size()) {
			err = errNotRegular
		}
	}
	if err == nil && seen.Size() > maxProgram {
		err = errTooBig
	}
	if err == nil {
		h := sha256.New()
		if _, err = io.Copy(h, io.LimitReader(f, maxProgram)); err == nil {
			return hex.EncodeToString(h.Sum(nil))
		}
	}
	c.moved(path, "is a program a shell startup file runs and could not be read ("+why(err)+")")
	return pinAbsent
}

// fishRelevant: the lines of fish_variables that change the commands: SETUVAR --export …, fish_user_paths (prepended
// to PATH) and fish_function_path (where functions load from).
func fishRelevant(b []byte) []byte {
	var out []byte
	for _, line := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		rest, ok := strings.CutPrefix(line, "SETUVAR ")
		if !ok {
			continue
		}
		name, _, _ := strings.Cut(strings.TrimPrefix(rest, "--export "), ":")
		if strings.HasPrefix(rest, "--export ") || name == "fish_user_paths" || name == "fish_function_path" {
			out = append(append(out, line...), '\n')
		}
	}
	return out
}

// fishVariables judges fish_variables' exported variables as the environment's (envVar): fish writes a value with
// \xHH escapes and \x1e between a list's items.
func (c *regCheck) fishVariables(path string, rel []byte) {
	for _, line := range strings.Split(string(rel), "\n") {
		rest, ok := strings.CutPrefix(line, "SETUVAR --export ")
		if !ok {
			continue
		}
		name, v, _ := strings.Cut(rest, ":")
		if c.envRelevant(name, true) {
			c.envVar(path, name, strings.ReplaceAll(fishUnescape(v), "\x1e", " "))
		}
	}
}

// fishUnescape decodes fish's \xHH escapes (and \\); anything else is kept as written.
func fishUnescape(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] == '\\' && i+3 < len(v) && v[i+1] == 'x' {
			if n, err := strconv.ParseUint(v[i+2:i+4], 16, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		if v[i] == '\\' && i+1 < len(v) && v[i+1] == '\\' {
			b.WriteByte('\\')
			i++
			continue
		}
		b.WriteByte(v[i])
	}
	return b.String()
}

// fdPath: a path that is a process's input or output, not a file (/dev/stdin, /dev/fd/N, /proc/self/fd/N).
func fdPath(p string) bool {
	return p == "/dev/stdin" || strings.HasPrefix(p, "/dev/fd/") || strings.HasPrefix(p, "/proc/self/fd/")
}
