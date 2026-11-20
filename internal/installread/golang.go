package installread

import (
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// ECO-1, Go: the module a `go install <path>@<version>` or a `go run <path>@<version>` fetches and builds. In
// module-aware mode with a version the go command ignores the current module: it fetches the module that holds the
// package from the module proxy, checks it against the checksum database and builds it (go help install, go help
// run). Those two forms name what they fetch, so the reader names it, as "go:<path>@<version>". Every other go
// command (go build, go install ./cmd, go run main.go, go get) builds the project in the folder, which the line does
// not show: the reader leaves it as a command it does not read, as before.

// goMaxElems: the most path elements of a package path the reader names (the check looks the module up by each
// prefix); a longer path Go would read holds.
const goMaxElems = 10

// goValueFlags are the go build flags of go install and go run that take a value (go help build, Go 1.27); goBoolFlags
// those that take none (a bool flag takes only -flag=value). go run alone has -exec. A flag in neither set is one
// alalanet does not read: it may take the next word.
var (
	goValueFlags = wordSet("C p covermode coverpkg asmflags buildmode compiler gccgoflags gcflags installsuffix ldflags mod modfile overlay pgo pkgdir tags toolexec exec")
	goBoolFlags  = wordSet("a n race msan asan cover v work x linkshared modcacherw trimpath buildvcs json")
)

// goCodeFlags: the flags that make the build run or read code the module does not hold: -toolexec runs a program
// around each tool, go run's -exec runs the built program through another, -overlay replaces source files with local
// ones. -ldflags names an external linker with -extld.
func goCodeFlag(name, value string) bool {
	switch name {
	case "toolexec", "exec", "overlay":
		return true
	case "ldflags":
		return strings.Contains(value, "extld")
	case "gccgoflags": // gccgo's own compiler flags: a plugin or another program (round 2, P3-5)
		return goCFlagsWhy(value) != ""
	}
	return false
}

// goTargets reads go install and go run: their flags up to the first word that is none, then the packages (go
// install: every word; go run: the first, the rest are the program's own arguments).
func (p *hookParse) goTargets(rest []string) (targets []string, recognized, names bool) {
	// go -C dir install …, go -C=dir run …: the go command reads -C before the subcommand (handleChdirFlag; round 3,
	// P2-4). Another option there, before an install or run, is a form alalanet does not read.
	for len(rest) > 0 && strings.HasPrefix(rest[0], "-") && rest[0] != "-" {
		switch name, _, eq := strings.Cut(strings.TrimLeft(rest[0], "-"), "="); {
		case name == "C" && eq:
			rest = rest[1:]
		case name == "C" && len(rest) > 1:
			rest = rest[2:]
		default:
			if slices.ContainsFunc(rest, func(x string) bool { return x == "install" || x == "run" }) {
				p.miss("an install command alalanet could not read (go " + clip(rest[0], 40) + ")")
				return nil, true, true
			}
			return nil, false, false
		}
	}
	if len(rest) == 0 {
		return nil, false, false
	}
	sub := rest[0]
	if unseenWord(sub) { // go $SUB example.com/x@v1: the subcommand is not in the line
		for _, x := range rest[1:] {
			if strings.Contains(x, "@") {
				p.miss(whyVarArgument + " (" + clip(sub, 60) + ")")
				return nil, true, true
			}
		}
		return nil, false, false
	}
	if sub == "env" {
		// go env -w writes what the next go command reads; xargs would append its pairs (names: true)
		return nil, false, p.goEnvCommand(rest[1:])
	}
	if sub != "install" && sub != "run" {
		return nil, false, false
	}
	var reasons []string
	i := 1
	for ; i < len(rest); i++ {
		x := rest[i]
		if x == "--" {
			i++
			break
		}
		if !strings.HasPrefix(x, "-") || x == "-" {
			break
		}
		name, value, eq := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(x, "-"), "-"), "=")
		switch {
		case unseenOption(x):
			reasons = append(reasons, whyVarArgument+" ("+clip(x, 60)+")")
		case goValueFlags[name] && (name != "exec" || sub == "run"):
			if !eq && i+1 < len(rest) {
				i++
				value = rest[i]
			}
			if goCodeFlag(name, value) {
				reasons = append(reasons, "runs go with an option that loads other code (-"+name+")")
			}
		case goBoolFlags[name]:
		default:
			reasons = append(reasons, "an install command alalanet could not read (go "+sub+" "+clip(x, 40)+")")
		}
	}
	words := rest[min(i, len(rest)):]
	if sub == "run" && len(words) > 1 {
		words = words[:1]
	}
	for _, w := range words {
		t, why := goSpec(w)
		switch {
		case why != "":
			reasons = append(reasons, why)
		case t != "":
			targets = append(targets, "go:"+t)
		}
	}
	if len(targets) == 0 && len(reasons) == 0 {
		// a build of the folder's own code: nothing the line names (but words xargs appends would be packages)
		return nil, false, true
	}
	for _, r := range reasons {
		p.miss(r)
	}
	if len(targets) > 0 {
		env, private := p.goEnvReasons(targets)
		for _, r := range env {
			p.miss(r)
		}
		if private {
			// the module does not come from the public proxy: its path is named go-private:, which the server never
			// sends to a registry and only answers from its own block feed (round 2, P3-2; round 3, P3-4)
			for i, t := range targets {
				targets[i] = "go-private:" + strings.TrimPrefix(t, "go:")
			}
		}
	}
	return targets, true, true
}

// goSpec reads one package word: "path@version" as the target it names, a reason for a word alalanet cannot read, or
// neither for a word Go fetches nothing for (a local path, a file, a path Go refuses, a word without a version).
func goSpec(w string) (target, why string) {
	if unseenWord(w) {
		// $PKG@v1, example.com/x@$V: a module fetched by a name or version the line does not show. A word without "@"
		// (go run $GOFILE) fetches no module by name: Go builds it from the folder.
		if strings.Contains(w, "@") {
			return "", whyVarArgument + " (" + clip(w, 60) + ")"
		}
		return "", ""
	}
	pth, ver, ok := strings.Cut(w, "@")
	if !ok || ver == "" || !GoPathOK(pth) {
		return "", ""
	}
	if !GoPathRead(pth) || !GoVersionOK(ver) {
		return "", "an install command alalanet could not read (go " + clip(w, 60) + ")"
	}
	return w, ""
}

// GoPathOK: a package path Go would fetch as a module's — not a local path or the standard library: slash-separated
// elements of letters, digits and - . _ ~ +, none empty, "." or "..", none beginning with a dot, and a first element
// that names a host (lower case, with a dot, not beginning with "-"). A last element "..." is a pattern (go install
// example.com/cmd/...@v1). The rules are module.CheckImportPath's, as far as a line reader needs them.
func GoPathOK(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") {
		return false
	}
	elems := strings.Split(p, "/")
	for i, e := range elems {
		if e == "" || e == "." || e == ".." || (strings.HasPrefix(e, ".") || strings.HasSuffix(e, ".")) && e != "..." || e == "..." && i != len(elems)-1 || e != "..." && strings.Contains(e, "...") {
			return false
		}
		for _, r := range e {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' && i > 0 || strings.ContainsRune("-._~", r) || r == '+' && i > 0) {
				return false
			}
		}
	}
	host := elems[0]
	return strings.Contains(host, ".") && !strings.HasPrefix(host, "-") && host != "..."
}

// GoPathRead: a path within what alalanet reads — at most goMaxElems elements and 300 bytes.
func GoPathRead(p string) bool {
	return len(p) <= 300 && strings.Count(p, "/") < goMaxElems
}

// GoVersionOK: a version the check reads — "latest", a semantic version, a pseudo-version, a commit hash or a plain
// branch or tag name. A query (>=v1.2, <v2) or a name with a slash is not read.
func GoVersionOK(v string) bool {
	if v == "" || len(v) > 128 {
		return false
	}
	for i, r := range v {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || i > 0 && strings.ContainsRune("._+-", r)) {
			return false
		}
	}
	return true
}

// goEnvNames are the variables the Go reader judges at a go install or go run it reads (go help environment, go help
// module-private, go help goauth, go help toolchain, cmd/cgo): where the go command fetches a module from and whether
// it checks it against the checksum database (GOPROXY, GOSUMDB, GONOSUMDB, GOPRIVATE, GONOPROXY, GOINSECURE); what
// runs or is read as code (GOFLAGS, GOAUTH; GOMODCACHE, GOPATH, GOCACHE, GOROOT, GOTOOLCHAIN — round 2, P2-2: the go
// command does not hash an extracted module again; CC, CXX and the cgo flags — P3-5); where its own settings file is
// (GOENV; HOME, XDG_CONFIG_HOME and APPDATA, which move it — P3-4). The reader keeps those the line sets (configEnv,
// go env -w) and judges them at a go install or go run: set for go build, they change nothing it judges.
var goEnvNames = wordSet("GOPROXY GOSUMDB GONOSUMDB GOPRIVATE GONOPROXY GOINSECURE GOFLAGS GOENV GOAUTH GOMODCACHE GOPATH GOCACHE " +
	"GOROOT GOTOOLCHAIN HOME XDG_CONFIG_HOME APPDATA CC CXX GCCGO PKG_CONFIG CGO_CFLAGS CGO_CPPFLAGS CGO_CXXFLAGS CGO_FFLAGS CGO_LDFLAGS " +
	// gcc's own: where it finds its programs, headers and libraries (round 4, P3-4)
	"COMPILER_PATH GCC_EXEC_PREFIX CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH LIBRARY_PATH PKG_CONFIG_PATH PKG_CONFIG_LIBDIR " +
	// ccache's: the command it runs before the compiler, and its object cache (round 5, P3-4)
	"CCACHE_PREFIX CCACHE_DIR")

// GoEnvName: a variable the Go reader judges at a go install or go run line (an MCP entry's env carries them too).
func GoEnvName(k string) bool { return goEnvNames[strings.ToUpper(k)] }

// GoOwnEnvName: one of them that only the go command reads (GO…, CGO_…), which an entry of any command passes on.
func GoOwnEnvName(k string) bool {
	k = strings.ToUpper(k)
	return goEnvNames[k] && (strings.HasPrefix(k, "GO") || strings.HasPrefix(k, "CGO_"))
}

// goCommand: the go command, or a golang.org/dl wrapper of it (go1.22.0, go1.23rc1, gotip), which runs the same
// subcommands and writes the same go env file (round 3, P3-3).
func goCommand(cmd string) bool { return GoCommand(cmd) }

// GoCommand: the go command or a golang.org/dl wrapper of it, by its program name (LaunchBase's).
func GoCommand(cmd string) bool {
	if cmd == "go" || cmd == "gotip" {
		return true
	}
	v, ok := strings.CutPrefix(cmd, "go1")
	return ok && v != "" && strings.Trim(v, "0123456789.rcbeta") == "" || cmd == "go1"
}

// GoEntryAssigns is an MCP server's environment as the VAR=value words (quoted for the line) the Go reader judges with
// its launch: those only the go command reads (GO…, CGO_…) for any command, and HOME, CC and the like for a go
// command, sorted by name. install_check and check_repo_config read an entry so; an MCP add command's -e pairs too.
func GoEntryAssigns(command string, env map[string]string) []string {
	out := goEntryPairs(command, env)
	for i, kv := range out {
		out[i] = shellQuote(kv)
	}
	return out
}

// goEntryPairs is GoEntryAssigns's VAR=value words as they are, for a reading that takes words, not a line.
func goEntryPairs(command string, env map[string]string) []string {
	goCmd := goCommand(launchBase(command))
	var out []string
	for k, v := range env {
		if GoOwnEnvName(k) || goCmd && GoEnvName(k) {
			out = append(out, k+"="+v)
		}
	}
	slices.Sort(out)
	return out
}

// MCPAddGoEnv: the env words (quoted for a line) an MCP add command's -e/--env pairs give the command after them.
func MCPAddGoEnv(opts, command []string) []string { return mcpAddEnvPairs(opts, command, shellQuote) }

func mcpAddEnvPairs(opts, command []string, quote func(string) string) []string {
	return mcpAddEnvFrom(MCPAddEnvWords(opts), command, quote)
}

// mcpAddEnvFrom is mcpAddEnvPairs for env words already read (readMCPAdd).
func mcpAddEnvFrom(words, command []string, quote func(string) string) []string {
	if len(command) == 0 {
		return nil
	}
	env := map[string]string{}
	var unseen []string
	for _, kv := range words {
		k, v, ok := strings.Cut(kv, "=")
		switch {
		case !ok || strings.ContainsAny(k, "$`\\"):
			// "$E", $K=…: a pair the line does not show — any name, GOPRIVATE too (round 4, P2-2); as an assignment
			// whose name has a $, the reader keeps it for the go command (noteGoEnvFrom)
			if !ok {
				kv += "="
			}
			unseen = append(unseen, quote(kv))
		case k != "":
			env[k] = v
		}
	}
	a := goEntryPairs(command[0], env)
	for i := range a {
		a[i] = quote(a[i])
	}
	a = append(a, unseen...) // for every server command: a shell string may run go without saying "go " (round 5, P2-2)
	if len(a) == 0 {
		return nil
	}
	return append([]string{"env"}, a...)
}

// MCPAddEnvWords is the one reading of an MCP add command's server environment, for both readers (extra.go
// mcpAddEnv): the words of -e and --env before "--" — commander's -e is variadic (-e A=1 B=2: every following word with
// "=" that is no option, and a word the line does not show, "$E"), -eK=V attached, yargs's -e=K=V and --env=K=V.
func MCPAddEnvWords(w []string) []string {
	out, _ := mcpAddEnvWords(w)
	return out
}

// mcpAddEnvWords is MCPAddEnvWords with, for each, whether it was glued to its option (--env=K=V, -eK=V, -e=K=V).
func mcpAddEnvWords(w []string) (out []string, glued []bool) {
	for i := 0; i < len(w) && w[i] != "--"; i++ {
		switch x := w[i]; {
		case x == "-e" || x == "--env":
			for i+1 < len(w) && !strings.HasPrefix(w[i+1], "-") && (strings.Contains(w[i+1], "=") || unseenWord(w[i+1])) {
				i++
				out, glued = append(out, w[i]), append(glued, false)
			}
		case strings.HasPrefix(x, "--env="):
			out, glued = append(out, x[len("--env="):]), append(glued, true)
		case strings.HasPrefix(x, "-e") && len(x) > 2 && !strings.HasPrefix(x, "--"):
			out, glued = append(out, strings.TrimPrefix(x[2:], "=")), append(glued, true)
		}
	}
	return out, glued
}

// GoSettings judges Go settings that are not on the line — the user's own environment and go env file, which
// alalanet-agent reads on the machine (ECO-1 Go, round 3, P3-5) — for the go: targets of a line, as the reader judges
// a line's own: the reasons, and whether the module would come from somewhere other than the public proxy (private).
func GoSettings(pairs [][2]string, targets []string) (reasons []string, private bool) {
	p := &hookParse{seen: map[string]bool{}}
	for _, kv := range pairs {
		p.noteGoEnv(kv[0], kv[1])
	}
	return p.goEnvReasons(targets)
}

// goEnvSet is one Go variable the line sets: its name and value, and whether go env -w wrote it (only those go env -u
// removes). An assignment whose name the line does not show ($K=…) is kept with the name "$" (round 3).
type goEnvSet struct {
	k, v    string
	written bool
}

// noteGoEnv keeps a Go variable the line sets, as configEnv reads it, for the go commands after it.
func (p *hookParse) noteGoEnv(k, v string) { p.noteGoEnvFrom(k, v, false) }

func (p *hookParse) noteGoEnvFrom(k, v string, written bool) {
	if strings.Contains(k, "$") {
		p.goEnv = append(p.goEnv, goEnvSet{"$", k, written}) // export $K=…: a name the line does not show
		return
	}
	// cmd.exe's set goproxy=… sets GOPROXY; export GOPRO\XY=… is GOPROXY once the shell removes the backslash
	if k = strings.ToUpper(strings.ReplaceAll(k, `\`, "")); goEnvNames[k] {
		p.goEnv = append(p.goEnv, goEnvSet{k, v, written})
	}
}

// goEnvCommand reads go env: -w NAME=value writes the go env file the next go command reads (as a NAME=value prefix
// is read). -u removes nothing the reader recorded: go refuses the whole -u for one name it does not know or that only
// the environment sets (GOENV), and then changes nothing; keeping the pair is the safe side, at the cost of a hold on
// the rare honest "-w X … -u X" line (round 5, P2-1; rounds 3–4 removed what -w wrote). -w is a bool flag: -w=true and
// -w=1 write too. A pair whose name
// or value the line does not show is a reason, as on an install word (round 3, P2-3). write: the command writes.
func (p *hookParse) goEnvCommand(args []string) (write bool) {
	flag := func(a, name string) bool {
		n, v, eq := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(a, "-"), "-"), "=")
		if !strings.HasPrefix(a, "-") || n != name {
			return false
		}
		b, err := strconv.ParseBool(v)
		return !eq || err == nil && b
	}
	write = slices.ContainsFunc(args, func(a string) bool { return flag(a, "w") })
	if write && p.subst {
		// go env -w $(cat f): the pairs may come from a substitution (substInstall names it): any name, GOPRIVATE too
		p.goEnv = append(p.goEnv, goEnvSet{"$", "go env -w with a substitution", true})
	}
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		k, v, eq := strings.Cut(a, "=")
		switch {
		case write && (!eq || strings.ContainsAny(k, "$\\`") || GoEnvName(k) && strings.ContainsAny(v, "$\\`")):
			// "$V", $K=…, GOPRO\XY=…, GOPROXY=$P: a pair, a name or a judged value the line does not show; a value of
			// a name alalanet does not judge (GOBIN=$HOME/bin) changes nothing it judges
			if !eq && !unseenWord(a) && !strings.Contains(a, "`") {
				continue // go env -w GOPROXY: no value, go refuses it
			}
			p.goEnv = append(p.goEnv, goEnvSet{"$", "go env -w " + a, true}) // judged at the go command: any name, GOPRIVATE too
		case write && eq:
			p.noteGoEnvFrom(k, v, true)
		}
	}
	return write
}

// goSumKey is the checksum database's own key (cmd/go/internal/modfetch: knownGOSUMDB), in two parts here.
const goSumKey = "sum.golang.org+033de0ae+" + "Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8"

// goSumDBOK: GOSUMDB names Go's own checksum database — its name, its official China alias or its exact key — the go
// command then checks the signatures with the known key, so a URL after it only moves where they are read (round 2,
// P2-3). Another key, or anything more, is another database.
func goSumDBOK(v string) bool {
	f := strings.Fields(v)
	switch {
	case len(f) == 0:
		return true
	case len(f) > 2, f[0] != "sum.golang.org" && f[0] != "sum.golang.google.cn" && f[0] != goSumKey:
		return false
	case len(f) == 2:
		u, err := url.Parse(f[1])
		return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
	}
	return true
}

// The plain words a reason gives for a folder or a program the go command would take code from (round 3: the reason
// says why an honest line holds as well): dirWhy's (HOME-CONFIG-ENV-1 round 2, P3-2: one folder judge).
const (
	whyGoVar      = whyDirVar
	whyGoClimb    = whyDirClimb
	whyGoTemp     = whyDirTemp
	whyGoRelative = whyDirRelative
)

// goDirWhy says why a folder list (GOPATH's, or one folder) may hold code the repository put there: dirWhy of each
// entry (a variable other than a leading home, a .. element, the current folder under another name, a temporary or a
// relative folder), the first that holds; "" for none. An absolute folder elsewhere (/cache/mod, /workspace,
// /builds/…, /home/u/proj/.cache) is not judged by its name (round 4, P3-3/P3-8). Since HOME-CONFIG-ENV-1 round 2
// (P3-2) the judge is shared with the package managers' config folders: path.Clean finds /proc/./self/cwd, ~N is the
// directory stack, and the Windows and PowerShell home spellings are the home here too.
func goDirWhy(v string) string {
	sep := ":"
	if strings.Contains(v, ";") || len(v) > 2 && v[1] == ':' && (v[2] == '\\' || v[2] == '/') {
		sep = ";"
	}
	for _, d := range strings.Split(v, sep) {
		if why := dirWhy(d); why != "" {
			return why
		}
	}
	return ""
}

// unseenName: an assignment's name the line does not show — a variable ($K, ${K}) or a substitution.
var unseenName = regexp.MustCompile("^(?:\\$\\{?[A-Za-z_][A-Za-z0-9_]*\\}?|\\$\\(.*\\)|`.*`)$")

// goProgramWhy says why a CC, CXX, GCCGO or PKG_CONFIG value may run a program the repository holds: the go command
// splits it into words and runs them (ccache ./x, gcc -fplugin=./x.so; round 3, P3-2), so every word is judged — a
// variable, a relative, temporary or climbing path, a flag that loads code. "" for none.
func goProgramWhy(v string) string {
	if why := goCFlagsWhy(v); why != "" {
		return why
	}
	for _, f := range strings.Fields(v) {
		switch {
		case strings.HasPrefix(f, "-"):
		case strings.ContainsAny(f, "$%"):
			return whyGoVar
		case strings.ContainsAny(f, `/\`):
			if why := goDirWhy(f); why != "" {
				return why
			}
		}
	}
	return ""
}

// goCFlagsWhy says why C compiler or linker flags (CGO_CFLAGS, CGO_LDFLAGS …, gccgo's -gccgoflags, CC's own words) may
// load code the repository holds: a plugin (-fplugin, -Wl,-plugin, -Xlinker -plugin, -load, -Xclang), another program or
// its folder (-B, -fuse-ld=, --ld-path, -wrapper, -specs), or a header, library or root folder (-include, -imacros, -I,
// -iquote, -isystem, -idirafter, -L, --sysroot) that is relative, temporary or named by a variable. A pattern= prefix
// (all=…) is read past. "" for none.
func goCFlagsWhy(v string) string {
	const plugin = "a compiler or linker flag that loads other code"
	fs := strings.Fields(v)
	for i := 0; i < len(fs); i++ {
		f := fs[i]
		if _, after, ok := strings.Cut(f, "="); ok && !strings.HasPrefix(f, "-") && !strings.HasPrefix(f, "@") {
			f = after
		}
		switch {
		case strings.HasPrefix(f, "@"):
			// a response file: gcc reads more flags from it (round 4, P3-4)
			if why := goDirWhy(f[1:]); why != "" {
				return why
			}
			continue
		case !strings.HasPrefix(f, "-"):
			// a word that is no flag: an object, archive or library the linker takes (./evil.o, libevil.a)
			if strings.ContainsAny(f, `/\`) || goObjectFile(f) {
				if why := goDirWhy(f); why != "" {
					return why
				}
			}
			continue
		}
		next := ""
		if i+1 < len(fs) {
			next = fs[i+1]
		}
		if pass, ok := strings.CutPrefix(f, "-Wl,"); ok && !strings.Contains(f, "plugin") || strings.HasPrefix(f, "-Wp,") || strings.HasPrefix(f, "-Wa,") {
			if !ok {
				pass = f[4:]
			}
			// -Wl,a,b / -Wp,… / -Wa,…: each piece goes to the linker, preprocessor or assembler as its own word
			// (round 5, P3-4: -Wl,@./x, -Wl,./evil.o, -Wl,-T,./x.ld, -Wp,-include,./x.h)
			if why := goCFlagsWhy(strings.ReplaceAll(pass, ",", " ")); why != "" {
				return why
			}
			continue
		}
		switch {
		case strings.HasPrefix(f, "-fplugin"), strings.HasPrefix(f, "-load"), strings.HasPrefix(f, "-Xclang"),
			strings.HasPrefix(f, "-wrapper"), strings.HasPrefix(f, "-specs"), strings.HasPrefix(f, "--ld-path"),
			strings.HasPrefix(f, "-Wl,") && strings.Contains(f, "plugin"),
			f == "-Xlinker" && strings.Contains(next, "plugin"):
			return plugin
		}
		for _, x := range []string{"--include-directory", "--library-directory", "--include", "--imacros", "--specs", "--prefix", "-include",
			"-imacros", "-iquote", "-isystem", "-idirafter", "--sysroot", "--dynamic-linker", "-dynamic-linker", "-fuse-ld", "-I", "-L", "-B", "-T"} {
			val, ok := strings.CutPrefix(f, x)
			if !ok {
				continue
			}
			val = strings.TrimPrefix(val, "=")
			if val == "" {
				val, i = next, i+1
			}
			if x == "-fuse-ld" && !strings.ContainsAny(val, `/\$%`) {
				break // -fuse-ld=lld: a linker by its name, found on PATH
			}
			if why := goDirWhy(val); why != "" {
				return why
			}
			if strings.ContainsAny(val, "$%") {
				return whyGoVar
			}
			break
		}
	}
	return ""
}

// whyUnseenWrite: a line that runs go after writing files the reader cannot name (code unread_env_write).
const whyUnseenWrite = "the line writes files alalanet cannot name before it runs go: the go env file may be among them"

// goWrite is a write of an earlier command of the line, as the Go reader judges it at a go install or go run (round 5,
// P3-2): its destination as written — a file, or the folder a tree goes into — or unknown.
type goWrite struct {
	dest    string
	tree    bool
	unknown bool
}

// noteGoWrites keeps the writes of one simple command: its output redirections, the files writesFiles names, and the
// destinations goWriteDests reads.
func (p *hookParse) noteGoWrites(sg shellSeg) {
	// the command's own moves and links count from the next command on: ln writes its link where the link goes, not
	// through it (round 7)
	defer p.noteGoCwd(sg.words)
	ws := goWriteDests(sg.words)
	for _, o := range sg.outs {
		ws = append(ws, goWrite{dest: o})
	}
	if names, _ := writesFiles(sg.words); len(names) > 0 {
		for _, n := range names {
			ws = append(ws, goWrite{dest: n}) // cp, mv, tee, sed -i, dd, curl -o: resolved like the others
		}
	}
	for _, w := range ws {
		if w.unknown {
			p.goWrites = append(p.goWrites, w)
			continue
		}
		lit, litOK := p.goCwdJoin(w.dest)
		d, ok := p.goResolve(w.dest)
		if !ok {
			p.goWrites = append(p.goWrites, goWrite{unknown: true})
		} else {
			p.goWrites = append(p.goWrites, goWrite{dest: d, tree: w.tree})
		}
		// the write where it lands if a link of the line named a folder that already existed (ln then makes its link
		// inside it, and the path is the folder's own): judged too, so a link cannot move a config write out of sight
		// (round 7)
		if litOK && ok && lit != d {
			p.goWrites = append(p.goWrites, goWrite{dest: lit, tree: w.tree})
		}
	}
}

// noteGoCwd follows the line's own moves of the current folder and its symbolic links, so that a relative write lands
// where the line put it (round 6, P3-1): cd and pushd (a folder the line does not show makes it unknown), cd -,
// popd, and ln -s TARGET LINK. A subshell's cd is followed past its parenthesis: the conservative side.
func (p *hookParse) noteGoCwd(words []string) {
	cmd, rest := unwrapped(words)
	var pos []string
	for _, w := range rest {
		if !strings.HasPrefix(w, "-") || w == "-" {
			pos = append(pos, w)
		}
	}
	move := func(to string) {
		p.goOldCwd = p.goCwd
		// a folder the line names by a variable stays one: a write under "$D/" is judged unknown (goWritesWhy)
		switch d, ok := p.goResolve(to); {
		case to == "":
			p.goCwd = "~"
		case ok:
			p.goCwd = d
		default:
			p.goCwd = "?"
		}
	}
	switch cmd {
	case "cd", "chdir":
		switch {
		case len(pos) == 0:
			move("")
		case pos[0] == "-":
			p.goCwd, p.goOldCwd = p.goOldCwd, p.goCwd
		default:
			move(pos[0])
		}
	case "pushd":
		p.goDirs = append(p.goDirs, p.goCwd)
		if len(pos) > 0 {
			move(pos[0])
		}
	case "popd":
		if n := len(p.goDirs); n > 0 {
			p.goCwd, p.goDirs = p.goDirs[n-1], p.goDirs[:n-1]
		}
	case "ln", "gln", "link", "glink":
		p.noteGoLink(strings.TrimPrefix(cmd, "g"), rest)
	case "cp", "gcp": // cp -s, -l, --symbolic-link, --link: links, not copies (round 7)
		p.noteGoLink("cp", rest)
	}
}

// noteGoLink reads ln (and POSIX link, and cp -s/-l, which make links of what they would copy) as the line's links
// (round 7): -s/--symbolic (cp: -s/--symbolic-link, and -l/--link a hard one), -t DIR/--target-directory (every
// spelling: -t DIR, -tDIR, -st DIR, --target-directory=DIR, an abbreviation), -S/--suffix SUFFIX (a value, not a
// target), -T/--no-target-directory, --, one target (a link of its name here), TARGET LINK, and several targets into
// a folder. TARGET LINK where LINK is a folder that exists makes LINK/<target's name>: both are kept. A hard link
// binds what its target names now; a symbolic one is read when it is used, a relative target from the link's folder.
func (p *hookParse) noteGoLink(cmd string, rest []string) {
	symbolic, hard, noDir, dir := false, false, false, ""
	long := func(w, full string, min int) bool { return len(w) >= min && strings.HasPrefix(full, w) }
	var pos []string
	for i := 0; i < len(rest); i++ {
		w := rest[i]
		switch {
		case w == "--":
			pos = append(pos, rest[i+1:]...)
			i = len(rest)
		case cmd == "link" || w == "-" || !strings.HasPrefix(w, "-"):
			pos = append(pos, w)
		case strings.HasPrefix(w, "--"):
			name, val, has := strings.Cut(w, "=")
			switch {
			case cmd == "ln" && long(name, "--symbolic", 4), cmd == "cp" && long(name, "--symbolic-link", 4):
				symbolic = true
			case cmd == "cp" && long(name, "--link", 3):
				hard = true
			case long(name, "--no-target-directory", 6):
				noDir = true
			case long(name, "--target-directory", 3), long(name, "--suffix", 4):
				if !has && i+1 < len(rest) {
					val, i = rest[i+1], i+1
				}
				if strings.HasPrefix("--target-directory", name) {
					dir = val
				}
			}
		default: // a cluster of short options: t and S take the rest of the word, or the next word
			for j := 1; j < len(w); j++ {
				switch w[j] {
				case 's':
					symbolic = true
				case 'l':
					hard = hard || cmd == "cp"
				case 'T':
					noDir = true
				case 't', 'S':
					val := w[j+1:]
					if val == "" && i+1 < len(rest) {
						val, i = rest[i+1], i+1
					}
					if w[j] == 't' {
						dir = val
					}
					j = len(w)
				}
			}
		}
	}
	if cmd == "cp" && !symbolic && !hard {
		return // a copy: its writes are goWriteDests'
	}
	switch {
	case dir != "":
		for _, t := range pos {
			p.addGoLink(t, path.Join(dir, path.Base(t)), symbolic)
		}
	case len(pos) == 1:
		p.addGoLink(pos[0], path.Base(pos[0]), symbolic)
	case len(pos) == 2:
		p.addGoLink(pos[0], pos[1], symbolic)
		if !noDir {
			p.addGoLink(pos[0], path.Join(pos[1], path.Base(pos[0])), symbolic)
		}
	case len(pos) > 2:
		last := pos[len(pos)-1]
		for _, t := range pos[:len(pos)-1] {
			p.addGoLink(t, path.Join(last, path.Base(t)), symbolic)
		}
	}
}

// goLinkUnknown is a link whose target the reader cannot place (a relative target above a folder it names by ~ or a
// variable): a write through it is unknown.
const goLinkUnknown = "?"

// addGoLink records a link the line makes: its place (its folder through the line's links, its own name not followed)
// and its target.
func (p *hookParse) addGoLink(target, link string, symbolic bool) {
	parent, ok := p.goResolve(path.Dir(link))
	if !ok || target == "" || link == "" {
		return
	}
	place := path.Clean(path.Join(parent, path.Base(link)))
	var t string
	switch {
	case !symbolic: // a hard link is the file its target names now
		if t, ok = p.goResolve(target); !ok {
			t = goLinkUnknown
		}
	case goAbs(target):
		t = target
	default:
		if t, ok = goJoinFrom(parent, target); !ok {
			t = goLinkUnknown
		}
	}
	if p.goLinks == nil {
		p.goLinks = map[string]string{}
	}
	p.goLinks[place] = t
}

// goAbs: a destination that does not depend on the current folder.
func goAbs(x string) bool {
	return strings.HasPrefix(x, "/") || strings.HasPrefix(x, "~") || strings.HasPrefix(x, "$") || strings.HasPrefix(x, "%") ||
		len(x) > 2 && x[1] == ':' || strings.HasPrefix(x, `\\`)
}

// goJoinFrom: rel read from the folder dir, as a symbolic link's relative target is. A dir named by ~, a variable or a
// drive keeps that first word; a rel that climbs above it is not placed (false).
func goJoinFrom(dir, rel string) (string, bool) {
	if !goAbs(dir) || strings.HasPrefix(dir, "/") {
		return path.Join(dir, rel), true
	}
	root, below, _ := strings.Cut(dir, "/")
	depth := 0
	for _, seg := range strings.Split(below, "/") {
		if seg != "" && seg != "." {
			depth++
		}
	}
	for _, seg := range strings.Split(rel, "/") {
		switch seg {
		case "", ".":
		case "..":
			if depth--; depth < 0 {
				return "", false
			}
		default:
			depth++
		}
	}
	return root + path.Join("/", below, rel), true
}

// goLinkPasses bounds the links one destination goes through: past it (a loop of links) the destination is unknown.
const goLinkPasses = 8

// goCwdJoin puts a destination against the folder the line moved to; false when that folder is not known.
func (p *hookParse) goCwdJoin(d string) (string, bool) {
	if !goAbs(d) && p.goCwd != "" {
		if p.goCwd == "?" {
			return "", false
		}
		d = path.Join(p.goCwd, d)
	}
	return d, true
}

// goResolve puts a destination where the line has put it: against the folder the line moved to, then through the
// links it made, the longest one first and again through the next one, as the filesystem follows them (round 7: a
// link made inside another, or before its own target became a link, is followed; a map's order picks nothing); false
// when that folder, or a link's target, is not known, or after goLinkPasses links.
func (p *hookParse) goResolve(d string) (string, bool) {
	d, ok := p.goCwdJoin(d)
	if !ok || len(p.goLinks) == 0 {
		return d, ok
	}
	c := path.Clean(d)
	moved := false
	for range goLinkPasses {
		link := ""
		for l := range p.goLinks {
			if len(l) > len(link) && (c == l || strings.HasPrefix(c, l+"/")) {
				link = l // two links of one length cannot both begin c: the longest is one link
			}
		}
		switch {
		case link == "" && moved:
			return c, true
		case link == "":
			return d, true
		case p.goLinks[link] == goLinkUnknown:
			return "", false
		}
		c, moved = path.Clean(p.goLinks[link]+c[len(link):]), true
	}
	return "", false
}

// goWriteDests: where a command writes (round 5, P3-1/P3-2). A tree writer's folder (tar -C, git clone DIR, git -C,
// unzip -d, rsync and cp -r's last word, 7z -o, ditto, wget -P; the current folder by default), a file a downloader or
// an editor names (curl -so FILE, wget -qO FILE, sponge FILE, sed's w FILE, awk's print > "FILE", vim's :w FILE), or
// unknown: a write whose destination the words do not give, and an interpreter one-liner (python -c, node -e, perl -e,
// ruby -e, php -r, osascript -e) whose text names the go env file or the config folder. Files writesFiles names
// (cp, mv, tee, sed -i, dd, curl -o) are in p.written.
func goWriteDests(words []string) []goWrite {
	cmd, rest := unwrapped(words)
	var pos []string
	for _, w := range rest {
		if !strings.HasPrefix(w, "-") {
			pos = append(pos, w)
		}
	}
	last := func() string {
		if len(pos) == 0 {
			return "."
		}
		return pos[len(pos)-1]
	}
	val := func(names ...string) (string, bool) {
		for i, w := range rest {
			for _, n := range names {
				switch {
				case w == n && i+1 < len(rest):
					return rest[i+1], true
				case strings.HasPrefix(n, "--") && strings.HasPrefix(w, n+"="):
					return w[len(n)+1:], true
				case !strings.HasPrefix(n, "--") && len(w) > len(n) && strings.HasPrefix(w, n):
					return w[len(n):], true
				}
			}
		}
		return "", false
	}
	tree := func(d string) []goWrite { return []goWrite{{dest: d, tree: true}} }
	script := func(flags ...string) []goWrite {
		for i, w := range rest {
			if slices.Contains(flags, w) && i+1 < len(rest) && goEnvText(rest[i+1]) {
				return []goWrite{{unknown: true}}
			}
		}
		return nil
	}
	switch {
	case cmd == "tar" || cmd == "gtar" || cmd == "bsdtar":
		if d, ok := val("-C", "--directory"); ok {
			return tree(d)
		}
		return tree(".")
	case cmd == "git":
		d := "."
		if c, ok := val("-C"); ok {
			d = c
		}
		if i := slices.Index(pos, "clone"); i >= 0 && i+2 < len(pos) {
			d = path.Join(d, pos[i+2])
		}
		return tree(d)
	case cmd == "unzip":
		if d, ok := val("-d"); ok {
			return tree(d)
		}
		return tree(".")
	case cmd == "rsync" || cmd == "ditto":
		return tree(last())
	case cmd == "cp" || cmd == "mv" || cmd == "ln" || cmd == "install":
		if d, ok := val("-t", "--target-directory"); ok {
			return tree(d)
		}
		if slices.ContainsFunc(rest, func(w string) bool {
			return w == "--recursive" || w == "--archive" || len(w) > 1 && w[0] == '-' && w[1] != '-' && strings.ContainsAny(w[1:], "rRa")
		}) {
			return tree(last())
		}
	case cmd == "7z" || cmd == "7za" || cmd == "7zz" || cmd == "7zr":
		for _, w := range rest {
			if d, ok := strings.CutPrefix(w, "-o"); ok {
				return tree(d)
			}
		}
		return tree(".")
	case cmd == "patch":
		return tree(".")
	case cmd == "wget":
		for i, w := range rest {
			if len(w) > 2 && w[0] == '-' && w[1] != '-' && strings.HasSuffix(w, "O") && i+1 < len(rest) && rest[i+1] != "-" {
				return []goWrite{{dest: rest[i+1]}} // wget -qO FILE
			}
		}
		if d, ok := val("-P", "--directory-prefix"); ok {
			return tree(d)
		}
		return tree(".")
	case cmd == "curl":
		var out []goWrite
		for i, w := range rest {
			short := len(w) > 2 && w[0] == '-' && w[1] != '-'
			switch {
			case short && strings.HasSuffix(w, "o") && i+1 < len(rest):
				out = append(out, goWrite{dest: rest[i+1]}) // curl -so FILE
			case short && strings.Contains(w[1:], "o"):
				out = append(out, goWrite{unknown: true})
			case short && strings.Contains(w[1:], "O"), strings.HasPrefix(w, "--remote-name"):
				d, ok := val("--output-dir")
				if !ok {
					d = "."
				}
				out = append(out, goWrite{dest: d, tree: true})
			}
		}
		return out
	case cmd == "sponge":
		if len(pos) > 0 {
			return []goWrite{{dest: pos[0]}}
		}
	case cmd == "sed" || cmd == "gsed":
		var out []goWrite
		for _, w := range rest {
			for _, m := range sedWrite.FindAllStringSubmatch(w, -1) {
				out = append(out, goWrite{dest: m[1]})
			}
		}
		return out
	case cmd == "awk" || cmd == "gawk" || cmd == "mawk" || cmd == "nawk":
		var out []goWrite
		for _, w := range pos {
			ms := awkWrite.FindAllStringSubmatch(w, -1)
			for _, m := range ms {
				out = append(out, goWrite{dest: m[1]})
			}
			if len(ms) == 0 && awkPrintTo.MatchString(w) {
				out = append(out, goWrite{unknown: true}) // print > f: a file the program names by a variable
			}
		}
		return out
	case cmd == "vim" || cmd == "vi" || cmd == "nvim" || cmd == "ex" || cmd == "view":
		var out []goWrite
		writes := false
		for i, w := range rest {
			c := ""
			switch {
			case (w == "-c" || w == "--cmd") && i+1 < len(rest):
				c = rest[i+1]
			case strings.HasPrefix(w, "+"):
				c = w[1:]
			}
			if m := vimWrite.FindStringSubmatch(c); m != nil {
				writes = true
				if m[1] != "" {
					out = append(out, goWrite{dest: m[1]})
				}
			}
		}
		if writes && len(out) == 0 {
			for _, f := range pos {
				out = append(out, goWrite{dest: f}) // :w writes the files it edits
			}
			if len(out) == 0 {
				out = append(out, goWrite{unknown: true})
			}
		}
		return out
	case pythonInterp(cmd):
		return script("-c")
	case cmd == "node" || cmd == "nodejs" || cmd == "deno" || cmd == "bun":
		return script("-e", "--eval", "-p", "--print", "eval")
	case cmd == "perl" || cmd == "ruby":
		return script("-e", "-E")
	case cmd == "php":
		return script("-r")
	case cmd == "osascript":
		return script("-e")
	}
	return nil
}

var (
	sedWrite   = regexp.MustCompile(`(?:^|[;\n}/])\s*w\s+([^\s;'"]+)`)
	awkWrite   = regexp.MustCompile(`>>?\s*"([^"]+)"`)
	awkPrintTo = regexp.MustCompile(`print[^;}]*>`)
	vimWrite   = regexp.MustCompile(`^\s*(?:w|wq|x|write|wall|saveas|sav)!?(?:\s+(\S+))?`)
)

// goEnvText: an interpreter's script that names the go env file, GOENV or the config folders it lives in.
func goEnvText(s string) bool {
	ls := strings.ToLower(strings.ReplaceAll(s, `\\`, "/"))
	ls = strings.ReplaceAll(ls, `\`, "/")
	for _, x := range []string{"go/env", "goenv", ".config/go", "application support/go", "appdata", "user_config", "userconfigdir"} {
		if strings.Contains(ls, x) {
			return true
		}
	}
	return false
}

// goWritesWhy judges the line's writes before a go install or go run, with the line's own assignments put in
// (OUT=build; … > $OUT/a): envFile, a file named go/env (or GOENV's) is written; unseen, a write whose destination is
// not in the line or lies in the Go config folder (~/.config/go, ~/Library/Application Support/go, %AppData%\go,
// $XDG_CONFIG_HOME/go, GOENV's), or a tree written into a folder above it (~, ~/.config). Writes elsewhere — a cloned
// folder, /usr/local, a named file — are not judged (round 5, P3-2: they held 11 of 16 honest lines in round 4).
func (p *hookParse) goWritesWhy() (envFile, unseen bool) {
	ws := slices.Clone(p.goWrites)
	for f := range p.written {
		ws = append(ws, goWrite{dest: f})
	}
	goenv := ""
	for _, e := range p.goEnv {
		if e.k == "GOENV" {
			goenv = goHomeNorm(p.expandAssigned(e.v))
		}
	}
	xdg := ""
	if v, ok := p.assigned["XDG_CONFIG_HOME"]; ok {
		xdg = goHomeNorm(v)
	}
	for _, w := range ws {
		n := goHomeNorm(p.expandAssigned(w.dest))
		if w.unknown || strings.ContainsAny(n, "$`%") {
			unseen = true
			continue
		}
		switch {
		case !w.tree && (strings.HasSuffix(n, "/go/env") || n == "go/env" || goenv != "" && n == goenv):
			envFile = true
		case goConfigDest(n, w.tree, xdg):
			unseen = true
		}
	}
	return envFile, unseen
}

// expandAssigned puts the values the line assigns into $NAME and ${NAME} of a destination.
func (p *hookParse) expandAssigned(d string) string {
	if !strings.Contains(d, "$") {
		return d
	}
	return assignedRef.ReplaceAllStringFunc(d, func(m string) string {
		name := strings.Trim(m, "${}")
		if v, ok := p.assigned[name]; ok && !strings.Contains(v, "$") {
			return v
		}
		return m
	})
}

var assignedRef = regexp.MustCompile(`\$\{?[A-Za-z_][A-Za-z0-9_]*\}?`)

// goHomeNorm: a path with the user's home written as ~ ($HOME, ${HOME}, ~, /root, /home/u, /Users/u), slashes, lower
// case, cleaned.
func goHomeNorm(d string) string {
	d = strings.ToLower(strings.ReplaceAll(d, `\`, "/"))
	for _, h := range []string{"${home}", "$home"} {
		if r, ok := strings.CutPrefix(d, h); ok {
			d = "~" + r
		}
	}
	switch {
	case d == "/root" || strings.HasPrefix(d, "/root/"):
		d = "~" + d[len("/root"):]
	case strings.HasPrefix(d, "/home/") || strings.HasPrefix(d, "/users/"):
		parts := strings.SplitN(d, "/", 4)
		d = "~"
		if len(parts) == 4 {
			d += "/" + parts[3]
		}
	}
	return path.Clean(d)
}

// goConfigDest: a destination in the Go config folder (where go keeps the go env file), or — for a tree — a folder
// above it.
func goConfigDest(n string, tree bool, xdg string) bool {
	cfgs := []string{"~/.config/go", "~/library/application support/go", "~/appdata/roaming/go"}
	if xdg != "" {
		cfgs = append(cfgs, xdg+"/go")
	}
	for _, c := range cfgs {
		if n == c || strings.HasPrefix(n, c+"/") {
			return true
		}
	}
	for _, seg := range []string{"/.config/go", "/application support/go", "/appdata/roaming/go"} {
		if strings.HasSuffix(n, seg) || strings.Contains(n, seg+"/") {
			return true
		}
	}
	if tree {
		above := []string{"~", "/", "~/.config", "~/library", "~/library/application support", "~/appdata", "~/appdata/roaming"}
		if xdg != "" {
			above = append(above, xdg)
		}
		return slices.Contains(above, n)
	}
	return false
}

// goObjectFile: a word the linker reads as an object, archive or shared library.
func goObjectFile(f string) bool {
	return strings.HasSuffix(f, ".o") || strings.HasSuffix(f, ".a") || strings.HasSuffix(f, ".so") || strings.Contains(f, ".so.") ||
		strings.HasSuffix(f, ".dylib") || strings.HasSuffix(f, ".obj") || strings.HasSuffix(f, ".lib")
}

// goEnvReasons judges the Go variables set so far for the targets a go command names. private: the module would not
// come from the public proxy and checksum database alalanet reads — its own repository or the local cache
// (GOPROXY=direct, off), another proxy, another database, or a path the line marks private: its path must not be sent
// to them (round 2, P3-2).
func (p *hookParse) goEnvReasons(targets []string) (out []string, private bool) {
	custom := func(what string) string {
		return "installs from a custom registry or index (" + what + "): alalanet judges packages on the public registries only"
	}
	code := func(what string) string { return "runs with an environment that loads other code (" + what + ")" }
	for _, kv := range p.goEnv {
		k, v := kv.k, kv.v
		switch k {
		case "$":
			// a name the line does not show may be GOPRIVATE or GOPROXY: the path is not sent either (round 3)
			out, private = append(out, whyVarArgument+" ("+clip(v, 60)+")"), true
		case "GOPROXY":
			for i, e := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == '|' }) {
				e = strings.TrimSpace(e)
				switch h := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(e, "https://"), "http://"), "/"); {
				case h == "proxy.golang.org":
				case (h == "direct" || h == "off") && i > 0: // the go command's own fallback after the proxy
				case h == "direct" || h == "off":
					out, private = append(out, custom("GOPROXY="+h+": the module's own repository or the local cache")), true
				default:
					host := e
					if i := strings.Index(host, "://"); i >= 0 {
						host = host[i+3:]
					}
					host, _, _ = strings.Cut(host, "/")
					out, private = append(out, custom(clip(host, 60))), true
				}
			}
		case "GOSUMDB":
			if !goSumDBOK(v) {
				out, private = append(out, "installs with a custom registry or config file alalanet cannot see (GOSUMDB: the Go checksum database is off or another)"), true
			}
		case "GONOSUMDB", "GOPRIVATE", "GONOPROXY", "GOINSECURE":
			for _, t := range targets {
				pth, _, _ := strings.Cut(strings.TrimPrefix(t, "go:"), "@")
				if goPatternMatch(v, pth) {
					out, private = append(out, "installs with a custom registry or config file alalanet cannot see ("+k+")"), true
					break
				}
			}
		case "GOENV":
			if v != "" && v != "off" {
				// what the moved file says is not on the line: GOPRIVATE too (round 6, P3-2)
				out, private = append(out, "installs with a custom registry or config file alalanet cannot see (GOENV)"), true
			}
		case "HOME", "XDG_CONFIG_HOME", "APPDATA":
			if why := goDirWhy(v); why != "" {
				out, private = append(out, "installs with a custom registry or config file alalanet cannot see ("+k+" moves the go env file to "+clip(v, 60)+": "+why+")"), true
			}
		case "GOFLAGS":
			for _, f := range strings.Fields(v) {
				name, value, _ := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(f, "-"), "-"), "=")
				if !strings.HasPrefix(f, "-") || unseenWord(f) || goCodeFlag(name, value) || !goValueFlags[name] && !goBoolFlags[name] {
					out = append(out, code("GOFLAGS "+clip(f, 40)))
					break
				}
			}
		case "GOAUTH":
			if s := strings.TrimSpace(v); s != "" && s != "off" && s != "netrc" {
				out = append(out, code("GOAUTH"))
			}
		case "GOMODCACHE", "GOPATH", "GOCACHE", "GOROOT", "COMPILER_PATH", "GCC_EXEC_PREFIX", "CPATH", "C_INCLUDE_PATH",
			"CPLUS_INCLUDE_PATH", "OBJC_INCLUDE_PATH", "LIBRARY_PATH", "PKG_CONFIG_PATH", "PKG_CONFIG_LIBDIR", "CCACHE_DIR":
			if why := goDirWhy(v); why != "" {
				out = append(out, code(k+" points at "+clip(v, 60)+": "+why))
			}
		case "GOTOOLCHAIN":
			if v == "path" || strings.HasSuffix(v, "+path") {
				out = append(out, code("GOTOOLCHAIN "+clip(v, 40)+": a go toolchain found on PATH"))
			}
		case "CC", "CXX", "GCCGO", "PKG_CONFIG", "CCACHE_PREFIX":
			if why := goProgramWhy(v); why != "" {
				out = append(out, code(k+" "+clip(v, 60)+": "+why))
			}
		default: // CGO_CFLAGS, CGO_LDFLAGS …
			if why := goCFlagsWhy(v); why != "" {
				out = append(out, code(k+" "+clip(v, 40)+": "+why))
			}
		}
	}
	switch envFile, unseen := p.goWritesWhy(); {
	case envFile:
		// what the file now says is a Go setting the line does not show: GOPRIVATE too (round 4, P3-1)
		out, private = append(out, "installs with a custom registry or config file alalanet cannot see (the line writes the go env file)"), true
	case unseen:
		// a write whose destination the line does not give, or in the Go config folder: the go env file may be among
		// them (rounds 4–5, P3-2)
		out, private = append(out, whyUnseenWrite), true
	}
	return out, private
}

// goPatternMatch: a comma-separated list of glob patterns (GOPRIVATE's) that matches a leading run of the path's
// elements, as module.MatchPrefixPatterns reads it.
func goPatternMatch(globs, target string) bool {
	for _, g := range strings.Split(globs, ",") {
		g = strings.TrimSuffix(strings.TrimSpace(g), "/")
		if g == "" {
			continue
		}
		n := strings.Count(g, "/") + 1
		prefix := target
		for i := 0; i < len(target); i++ {
			if target[i] == '/' {
				if n--; n == 0 {
					prefix = target[:i]
					break
				}
			}
		}
		if n > 1 {
			continue // the pattern has more elements than the path
		}
		if ok, _ := path.Match(g, prefix); ok {
			return true
		}
	}
	return false
}
