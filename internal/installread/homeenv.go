package installread

import (
	"path"
	"regexp"
	"slices"
	"strings"
)

// HOME-CONFIG-ENV-1 (eco1-go review P3-4): the variables that move where the package managers read their config —
// npm's ~/.npmrc and $PREFIX/etc/npmrc, pnpm's, Yarn's and bun's rc files under HOME (USERPROFILE on Windows) and
// pnpm's %LOCALAPPDATA%\pnpm\config\rc, pip's $XDG_CONFIG_HOME/pip/pip.conf, %APPDATA%\pip\pip.ini and
// $XDG_CONFIG_DIRS/pip/pip.conf, uv's $XDG_CONFIG_HOME/uv/uv.toml, %APPDATA%\uv\uv.toml and $XDG_CONFIG_DIRS/uv/uv.toml.
// A registry, an index or a script setting in that file is one the line does not show. XDG_CONFIG_DIRS is a list
// (homeConfigLists); the others are one folder each (round 2, P3-3: LOCALAPPDATA, XDG_CONFIG_DIRS and PREFIX).
var (
	homeConfigEnv = map[string]bool{"HOME": true, "USERPROFILE": true, "XDG_CONFIG_HOME": true, "APPDATA": true, "LOCALAPPDATA": true,
		"XDG_CONFIG_DIRS": true, "PREFIX": true}
	homeConfigLists = map[string]bool{"XDG_CONFIG_DIRS": true}
)

// The plain words a reason gives for a folder the readers judge by dirWhy (the go env file's, a module cache's, the
// package managers' config): the reason says why an honest line holds as well (eco1-go round 3).
const (
	whyDirVar      = "a folder the line names through a variable"
	whyDirClimb    = "a path that climbs out with .."
	whyDirTemp     = "a shared temporary folder others can write"
	whyDirRelative = "a folder of the project or the current directory"
	// round 3, P3-1: a UNC path on another host
	whyDirShare = "a share on another host (a UNC path): files that host serves"
	// round 2, P2-1: an MCP entry's value reaches the server as written
	whyDirLiteral = "a value an MCP entry passes as written: no shell expands ~, $NAME or %NAME% there, so it is a folder of that name under the server's working folder"
	// round 6, P2-A: ~name (tildeUser)
	whyDirUser = "a folder named after another user's home, or a literal folder of the project; alalanet cannot see which"
)

// homePrefixes are the spellings of the user's own home folder a shell line's value may start with, in lower case: an
// absolute folder. PowerShell's $home and $env:… are case-blind; a POSIX shell's lower-case $home is unset, which
// leaves an absolute path.
var homePrefixes = []string{"${home}", "$home", "%userprofile%", "${env:userprofile}", "$env:userprofile", "${env:home}", "$env:home"}

// entryHomeForms are the home spellings MCP clients expand in an entry's values, as the clients write them: Claude
// Code's ${HOME}, VS Code's and Cursor's ${env:HOME}, ${env:USERPROFILE} and ${userHome} (round 2, P2-1).
var entryHomeForms = []string{"${HOME}", "${env:HOME}", "${env:USERPROFILE}", "${userHome}"}

// procCwdDir: /proc/<pid>/cwd or root, and a thread's (/proc/<pid>/task/<tid>/cwd), with what follows: the current
// folder under another name.
var procCwdDir = regexp.MustCompile(`^/proc/[^/]+/(task/[^/]+/)?(cwd|root)(/|$)`)

// dirWhy says why one folder may hold a file the repository put there, read as a shell expanded it — a variable other
// than a leading home (homePrefixes), a .. element, the current folder under another name (cwdAlias), a relative
// folder (., ./h, h, .\cfg), a temporary one — or "" for none. An absolute folder elsewhere (/home/u, /workspace,
// C:\Users\me) is not judged by its name: one the line names absolutely is one an attacker would have to control
// already (eco1-go round 4, P3-3/P3-8). The readers' one folder judge (round 2, P3-2): goDirWhy splits GOPATH's list
// and judges each entry here, homeConfigWhy the package managers' config folders.
func dirWhy(d string) string {
	if d == "" {
		return ""
	}
	if strings.HasPrefix(d, "./") || strings.HasPrefix(d, `.\`) {
		return whyDirRelative // ./$X: a folder named so (markTilde), whatever it holds
	}
	if tildeUser(d) {
		return whyDirUser // ~u$X, ~m$ too: the name is looked up first (round 6)
	}
	if strings.ContainsAny(d, "$%`") {
		ld := strings.ToLower(d)
		i := slices.IndexFunc(homePrefixes, func(p string) bool { return strings.HasPrefix(ld, p) })
		if i < 0 {
			return whyDirVar
		}
		rest := d[len(homePrefixes[i]):]
		if strings.ContainsAny(rest, "$%`") || rest != "" && rest[0] != '/' && rest[0] != '\\' {
			return whyDirVar // $HOMEX, $HOME$X, $HOME/$X
		}
		d = "/home" + rest // the user's home: an absolute folder
	}
	if len(d) >= 2 && d[0] == '\\' && d[1] != '\\' {
		return whyDirRelative // \. is an escaped "." in a POSIX shell, \cfg the current drive's root on Windows; \\srv\share is a share
	}
	ld := strings.ToLower(strings.ReplaceAll(d, `\`, "/"))
	switch {
	case slices.Contains(strings.Split(ld, "/"), ".."):
		return whyDirClimb
	case cwdAlias(ld):
		return whyDirRelative
	case !(strings.HasPrefix(ld, "/") || strings.HasPrefix(ld, "~") || len(ld) > 2 && ld[1] == ':' && ld[2] == '/'):
		return whyDirRelative
	case dirTemp(path.Clean(ld)):
		return whyDirTemp
	}
	return ""
}

// cwdAlias: the current (or the previous, or a stacked) folder under another name — ~+, ~-, ~N, ~+N, ~-N (bash and
// zsh expand ~0 to $PWD and ~N from the directory stack), /proc/self/cwd however spelled (//proc/./self/cwd), a
// thread's cwd.
func cwdAlias(ld string) bool {
	if pre, ok := tildePrefixOf(ld); ok && pre != "" && cwdPrefix.MatchString(pre) {
		return true // ~+, ~-, ~0; ~1, ~+x, ~9z are names (rounds 6–7)
	}
	return strings.HasPrefix(ld, "/") && procCwdDir.MatchString(path.Clean(ld))
}

// dirTemp: a temporary folder others can write (ld in lower case, with "/", cleaned).
func dirTemp(ld string) bool {
	return tmpMarker(ld) || strings.Contains(ld, "/temp/") || strings.HasSuffix(ld, "/temp")
}

// entryDirWhy is dirWhy for an MCP entry's value, which no shell expands (round 2, P2-1): the clients' own home forms
// (entryHomeForms) are the user's home; any other ~, $NAME or %NAME% is a folder of that name under the server's
// working folder (whyDirLiteral), a ${NAME} the client expands is a variable's folder; the rest as dirWhy.
func entryDirWhy(v string) string {
	if v == "" {
		return ""
	}
	for _, f := range entryHomeForms {
		if rest, ok := strings.CutPrefix(v, f); ok {
			if strings.ContainsAny(rest, "$%`~") || rest != "" && rest[0] != '/' && rest[0] != '\\' {
				return whyDirVar // ${HOME}x, ${HOME}$X
			}
			return dirWhy("/home" + rest)
		}
	}
	if remoteShare(v) {
		return whyDirShare
	}
	switch {
	case strings.HasPrefix(v, "~") || strings.HasPrefix(v, "%") || strings.HasPrefix(v, "$") && !strings.HasPrefix(v, "${"):
		return whyDirLiteral
	case strings.ContainsAny(v, "$%`"):
		return whyDirVar // ${CLAUDE_PROJECT_DIR}, ${HOME:-/root}
	}
	return dirWhy(v)
}

// homeDirWhy is dirWhy for a shell line's value of k, one of homeConfigEnv.
func homeDirWhy(k, v string) string { return configDirWhy(k, v, dirWhy) }

// configDirWhy judges v, the value of k, folder by folder with judge: XDG_CONFIG_DIRS is a ":" list, the others one
// folder (HOME="/a:b" is one path).
func configDirWhy(k, v string, judge func(string) string) string {
	if !homeConfigLists[strings.ToUpper(k)] {
		return judge(v)
	}
	for _, d := range strings.Split(v, ":") {
		if why := judge(d); why != "" {
			return why
		}
	}
	return ""
}

// homeConfigWhy is the reason for k (one of homeConfigEnv) set to v on a shell line, or "" when the folder is none;
// entryHomeConfigWhy, for an MCP entry's value (entryDirWhy).
func homeConfigWhy(k, v string) string      { return homeReason(k, v, homeDirWhy(k, v)) }
func entryHomeConfigWhy(k, v string) string { return homeReason(k, v, configDirWhy(k, v, entryDirWhy)) }

func homeReason(k, v, why string) string {
	if why == "" {
		return ""
	}
	return "installs with a custom registry or config file alalanet cannot see (" + clip(k, 20) + " moves the package managers' config to " +
		clip(v, 60) + ": " + why + ")"
}

// markTilde writes, in w, an assignment word (NAME=…) of a path variable (pathName), each element whose start the
// shell leaves literal as the folder it is: "./" before it, so every reader judges a folder of that name under the
// current one, and what a target or a reason shows is that folder (HOME-CONFIG-ENV-1 round 4, P3-1: the private-use mark
// of round 3 reached an MCP add's launch target). An element is the value, and for a list (listName) each part after
// an unquoted ":" (bash expands ~ after every ":" of an assignment; round 4, P3-2), and for another variable too (a
// later list may hold it: D='/usr/bin:~'; PATH=$D, round 5, P3-3). Its start is literal when:
//   - it is a ~ whose own character, or any character of its tilde-prefix (up to the first /, \ or :), is quoted or
//     escaped, or has an empty quote next to it, or follows a quoted ":" — bash's rule: HOME=""~, ~"", ~\/x, $'~',
//     "~"/x, ~"/x" (zsh expands ~"", ~”, ""~ and ~\/y to the home: there such a line is honest and holds, a false
//     hold, never a pass);
//   - it is a $ in single quotes or escaped (HOME='$HOME/x', GOPATH=/go:'$X').
//
// segs are the word's quoted parts and escaped characters (splitShell's qsegs: start, end, kind). A quoted name or "="
// makes no assignment. Another variable's literal ~ is written so too (D='~/b'; PATH=$D:… binds the folder ./~/b),
// its literal $ is not (a '$U' that names no folder stays as it is).
func markTilde(w string, segs [][3]int) (word, assigned string) {
	eq := strings.IndexByte(w, '=')
	if eq <= 0 || eq+1 >= len(w) || !shellName.MatchString(w[:eq]) {
		return w, ""
	}
	path := pathName(w[:eq]) // another variable gets its literal ~ written so too: D='~/b'; PATH=$D binds the folder
	// A quoted or escaped character in the name or the "=" makes no assignment-shaped word ("HOME=~/x", 'HOME'=~,
	// HOME"="~): every shell keeps each ~ of it, bash too (round 7, P3-1: home-p6/h/pw/out-quoted.txt). Such a word with
	// a space or an operator in it is a script where a script stands (sh -c "HOME=~ npm i x", eval) and an assignment
	// where one stands (export "PATH=~/a b:/usr/bin", env, sudo, -e): the word stays as written, read again as a line,
	// and assigned is its value as the shell assigns it, which the readers take where an assignment stands (round 8, R2).
	quotedName := false
	for _, s := range segs {
		quotedName = quotedName || s[0] <= eq
	}
	if quotedName && strings.ContainsAny(w, " \t\n;&|<>()`") {
		return w, markTildeStarts(w, segs, eq, path, true)
	}
	return markTildeStarts(w, segs, eq, path, quotedName), ""
}

// markTildeStarts is markTilde's rewrite of w's literal starts (its = at eq; path: a path variable's; quotedName: every
// ~ start is literal).
func markTildeStarts(w string, segs [][3]int, eq int, path, quotedName bool) string {
	starts := []int{eq + 1}
	if listName(w[:eq]) || !path { // another variable may be a later list's part: D='/usr/bin:~'; PATH=$D (round 5, P3-3)
		for i := eq + 1; i < len(w); i++ {
			if w[i] == ':' && i+1 < len(w) && !cmdSubstring.MatchString(w[starts[len(starts)-1]:i]) {
				starts = append(starts, i+1)
			}
		}
	}
	var lit []int
	for _, e := range starts {
		switch w[e] {
		case '$':
			if !path {
				break // a literal $ of another variable names no folder: '$U' stays as it is
			}
			for _, s := range segs {
				if s[2] != 2 && s[0] <= e && s[1] > e {
					lit = append(lit, e)
					break
				}
			}
		case '~':
			end := len(w)
			if i := strings.IndexAny(w[e:], `/\:`); i >= 0 {
				end = e + i
			}
			// a backslash the tokenizer kept (~\/x, ~\x); a quoted ":" before it ends a quoted part at e, which the parts'
			// rule below takes as next to the ~ (X="/etc:"~ is "/etc:~" in bash). An unquoted ~name stays as written:
			// dirWhy holds it (tildeUser, round 6)
			literal := quotedName || end < len(w) && w[end] == '\\'
			for _, s := range segs {
				if s[0] <= end && s[1] >= e {
					literal = true
				}
			}
			if literal {
				lit = append(lit, e)
			}
		}
	}
	for i := len(lit) - 1; i >= 0; i-- {
		w = w[:lit[i]] + "./" + w[lit[i]:]
	}
	return w
}

// goDirNames are the go command's folders and gcc's, which goDirWhy judges.
var goDirNames = wordSet("GOMODCACHE GOPATH GOCACHE GOROOT GOENV GOBIN COMPILER_PATH GCC_EXEC_PREFIX CPATH C_INCLUDE_PATH " +
	"CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH LIBRARY_PATH PKG_CONFIG_PATH PKG_CONFIG_LIBDIR CCACHE_DIR")

// goDirLists are those of them that are ":" lists.
var goDirLists = wordSet("GOPATH COMPILER_PATH CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH LIBRARY_PATH PKG_CONFIG_PATH PKG_CONFIG_LIBDIR")

// pathName: a variable whose value is a folder, a file, a program or a list of folders for a reader — the package
// managers' config folders, the search paths, the go command's folders and the second reader's path levers.
func pathName(n string) bool {
	if goDirNames[strings.ToUpper(n)] {
		return true // the second reader's levers hold the others: homeConfigEnv's are lvHome, searchPathEnv's lvDirs
	}
	switch leverOf(n) {
	case lvDirs, lvPath, lvVenv, lvHome, lvPython, lvInterp, lvProgram, lvConfig:
		return true
	}
	return false
}

// listName: a path variable whose value is a ":" list.
func listName(n string) bool {
	u := strings.ToUpper(n)
	return homeConfigLists[u] || goDirLists[u] || leverOf(n) == lvDirs // searchPathEnv's are lvDirs
}

// remoteShare: a UNC path whose host is not the local machine's device namespace — \\host\share, //host/share,
// \\host@SSL\DavWWWRoot\…, \\?\UNC\host\share — where Windows reads files a host on the network serves; \\?\C:\… and
// \\.\C:\… are local paths (HOME-CONFIG-ENV-1 round 3, P3-1).
func remoteShare(v string) bool {
	if len(v) < 3 || !(v[0] == '\\' || v[0] == '/') || v[1] != v[0] {
		return false
	}
	parts := strings.FieldsFunc(v[2:], func(r rune) bool { return r == '\\' || r == '/' })
	if len(parts) == 0 {
		return false
	}
	if parts[0] == "?" || parts[0] == "." {
		return len(parts) > 2 && strings.EqualFold(parts[1], "UNC") // \\?\UNC\host\share
	}
	return true
}

// tildeUser: a folder that starts with ~name — a tilde-prefix (up to the first /, \ or :, which ends it in an
// assignment) that is neither empty (the home)
// nor the directory stack's (+, -, N, +N, -N: cwdAlias). The shell looks the name up as a user (bash 5.2's manual: "the
// characters in the tilde-prefix following the tilde are treated as a possible login name … If the login name is
// invalid, or the tilde expansion fails, the word is unchanged"): where no user has it, bash and dash leave it as
// written, a folder of that name under the current one (./~xq7/.npmrc); where one does, it is that user's home, whose
// config alalanet does not see (~postgres). Which of the two the reader cannot know, so any name — ~root too, and names
// outside POSIX's portable set (SSSD's user@domain, a machine account's m$) or none can have (~~, ~=x) — is held as
// whyDirUser, the value written as the line wrote it (HOME-CONFIG-ENV-1 round 6, P2-A, the owner's rule).
func tildeUser(d string) bool {
	pre, ok := tildePrefixOf(d)
	return ok && !cwdPrefix.MatchString(pre) // cwdPrefix takes the empty prefix: the home
}

// tildePrefixOf: what follows the ~ that d starts with, up to the first /, \ or :; ok: d starts with ~.
func tildePrefixOf(d string) (string, bool) {
	pre, ok := strings.CutPrefix(d, "~")
	if i := strings.IndexAny(pre, `/\:`); i >= 0 {
		pre = pre[:i]
	}
	return pre, ok
}

// cwdPrefix: a tilde-prefix that names the current or the previous folder — none (the home, which tildeUser and
// cwdAlias leave out), +, -, 0, +0, -0 (bash and zsh: ~+ and ~0 are $PWD, ~- $OLDPWD; ~-0 the stack's last entry, the
// current folder while it has one). Any other — ~1, ~12, ~+1 (bash's stack has one entry, so they go to getpwnam),
// ~+x, ~-lead — is a name a directory service may have (home-p6 review, h/pw/out.txt: an LD_PRELOAD getpwnam that has
// them; round 6 read them as the stack's from /etc/passwd lines, which glibc skips as NIS markers): tildeUser.
var cwdPrefix = regexp.MustCompile(`^[+-]?0?$`)

// cmdSubstring: an element that opens cmd's %NAME:~n,m% (set PATH=%PATH:~0,3%;…), whose ~ after the ":" is no
// tilde: the value is a variable's, which dirWhy judges as one.
var cmdSubstring = regexp.MustCompile(`^%[A-Za-z_][A-Za-z0-9_]*$`)

// What a reason adds when it names the folder ./~ of an assignment-shaped argument word's ~ (rounds 5 and 6, P3-1):
// zsh and dash keep it; bash outside POSIX mode gives ~ and ~/… the home, ~name that user's home where the user exists
// (and keeps it where none does).
const (
	whyArgTildeNote     = "zsh and dash keep a ~ in an argument word; bash, outside POSIX mode, would use your home"
	whyArgTildeUserNote = "zsh and dash keep a ~ in an argument word; bash, outside POSIX mode, would use the named user's home where that user exists"
	whyArgTildeBothNote = "zsh and dash keep a ~ in an argument word; bash, outside POSIX mode, would use your home, and the named user's where that user exists"
)

// argTildeNote: the note for what argTildeValue wrote (tildeHome, tildeOther, both), or "".
func argTildeNote(wrote int) string {
	switch wrote {
	case tildeHome:
		return whyArgTildeNote
	case tildeOther:
		return whyArgTildeUserNote
	case tildeHome | tildeOther:
		return whyArgTildeBothNote
	}
	return ""
}

// withArgTildeNote adds a note inside a reason's closing parenthesis, or after it (once: each reader writes a reason
// once).
func withArgTildeNote(r, note string) string {
	if s, ok := strings.CutSuffix(r, ")"); ok {
		return s + "; " + note + ")"
	}
	return r + " (" + note + ")"
}

// tildeWhy: for a reason that says where a variable points, ": " and whyDirUser when an element of the list v (split
// as untrustedPath splits it) is a tildeUser folder, else whyDirRelative when one is the current folder's ~+, ~-, ~0
// (rounds 6–7); "" otherwise.
func tildeWhy(v string) string {
	ds := strings.Split(v, pathListSep(v))
	why := ""
	for i, d := range ds {
		switch {
		case !listTilde(ds, i):
		case tildeUser(d):
			return ": " + whyDirUser
		default:
			why = ": " + whyDirRelative
		}
	}
	return why
}

// listTilde: the list element ds[i] starts with a ~ and a tilde-prefix, which is not the home: the current folder or
// a name (round 7, P2-1 and P2-2) — not the ~n,m% of cmd's %NAME:~n,m% (cmdSubstring). In a POSIX line's ":" list the
// %P before it is a folder of the project and holds the value (untrustedPathIn, round 8, G).
func listTilde(ds []string, i int) bool {
	pre, ok := tildePrefixOf(ds[i])
	return ok && pre != "" && !(i > 0 && cmdSubstring.MatchString(ds[i-1]))
}

// argTildeValue writes an argument word's value — after env or sudo, an MCP add's -e, cmd's set, PowerShell's — as a
// shell that keeps its ~ reads it: the value and, for a list (listName), each element after sep (":" for a POSIX
// shell's word, ";" for Windows') that starts with a ~ get "./" before it, as markTilde writes a quoted one (rounds
// 3–5, P3-2); the current folder's names (cwdAlias: ~+, ~-, ~N) stay as they are, which every reader judges the same
// way (round 5, P3-4). wrote: tildeHome for a ~ or ~/… it wrote, tildeOther for a ~name, or both; 0 for none.
func argTildeValue(k, v, sep string) (string, int) {
	parts := []string{v}
	if listName(k) {
		parts = strings.Split(v, sep)
	}
	wrote := 0
	for i, s := range parts {
		switch {
		case !strings.HasPrefix(s, "~") || cwdAlias(s):
			continue
		case tildeUser(s):
			wrote |= tildeOther
		default:
			wrote |= tildeHome
		}
		parts[i] = "./" + s
	}
	return strings.Join(parts, sep), wrote
}

// What argTildeValue wrote: a ~ or ~/… (the home in bash), a ~name (another user's).
const (
	tildeHome = 1 << iota
	tildeOther
)
