package installread

import (
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// PIPE-SCRIPT-1: a line that downloads a script and runs it — curl … | sh, wget -qO- … | bash, sh -c "$(curl …)",
// bash <(curl …), irm … | iex, iex (iwr …), Invoke-Expression (Invoke-WebRequest …) — runs code nobody has shown
// alalanet; 268 of 1,710 popular MCP READMEs carry such a line. Each address the line shows is a target,
// script:<address> (scheme and host in lower case, without the user, the query and the fragment), which install_check
// holds as runs_remote_script and judges by its host: a GitHub address is its repository's check. An address the line
// does not show (a variable, a config file, a list of addresses) is the reason without a target. alalanet does not
// fetch the script. A download that is only saved (curl -o f, curl -O, wget URL, iwr -OutFile) or read by a program
// that does not run it (… | tar x, … | jq, … | python3 parse.py) stays as before.

// whyRemoteScript: a script the line downloads and runs whose address it does not show (code runs_remote_script).
const whyRemoteScript = "runs a script it downloads, which alalanet does not read"

// maxScriptURL: the longest address kept whole as a target; a longer one is its scheme and host.
const maxScriptURL = 300

// remoteScript adds what one download that the line runs as a script gives: a target for each address it shows, the
// reason for one it does not. what names the download when it shows no address at all.
func (p *hookParse) remoteScript(urls []string, what string) {
	if len(urls) == 0 {
		p.miss(whyRemoteScript + " (" + clip(what, 60) + ")")
		p.scriptHits++
		return
	}
	for _, u := range urls {
		if t, ok := scriptTarget(u); ok {
			p.add(t)
		} else {
			p.miss(whyRemoteScript + " (" + clip(u, 60) + ")")
		}
		p.scriptHits++
	}
}

// scriptRun: the download a segment runs as a script (its addresses, and its tool's name for the reason).
type scriptRun struct {
	urls []string
	what string
}

// scriptRuns finds, in one line or script the walk reads, the downloads it runs: run, at the segment that runs each
// (a shell fed by a pipe, a command given a <(…) file); ran, every segment that is part of one (the download, the
// filters on its way, the runner), which is then neither "other" nor a definition. A text that is one substitution of
// a download ("$(curl …)", the script of sh -c, eval or an interpreter's -c) and a PowerShell download given to
// Invoke-Expression are added here, before the walk; their segments are all part of them.
//
// wsegs, when not nil, is the line's Windows reading (shellLine.winSegs): the segments are read in it too, and a run or
// a download's part found in either reading counts (READER-ESCAPE-1 round 3, D1: irm URL -OutFile i.ps1; .\i.ps1 runs
// the file in PowerShell, where the POSIX reading names .i.ps1).
func (p *hookParse) scriptRuns(s string, segs, wsegs []shellSeg) (map[int]*scriptRun, map[int]bool) {
	run, ran := map[int]*scriptRun{}, map[int]bool{}
	if p.inlineDownload(s) {
		for i := range segs {
			ran[i] = true
		}
		return run, ran
	}
	if found, names := psRemoteScripts(s); len(found) > 0 {
		for k, urls := range found {
			p.remoteScript(urls, names[k])
		}
		for i, sg := range segs {
			ran[i] = ran[i] || psScriptPart(sg.words) || wsegs != nil && psScriptPart(wsegs[i].words)
		}
		if _, bodies, ok := substSpans(s); ok {
			for _, b := range bodies { // iex "& { $(irm …) }": the substitution is the download it runs
				if _, words, ok := downloadCommand(b); ok {
					p.ranSubst(words)
				}
			}
		}
	}
	p.segRuns(segs, run, ran)
	if wsegs != nil {
		wrun, wran := map[int]*scriptRun{}, map[int]bool{}
		p.segRuns(wsegs, wrun, wran)
		for i := range segs {
			ran[i] = ran[i] || wran[i]
			switch r, w := run[i], wrun[i]; {
			case w == nil:
			case r == nil:
				run[i] = w
			default:
				urls := slices.Clone(r.urls)
				for _, u := range w.urls {
					if !slices.Contains(urls, u) {
						urls = append(urls, u)
					}
				}
				run[i] = &scriptRun{urls, r.what}
			}
		}
	}
	return run, ran
}

// segRuns: scriptRuns' reading of one reading's segments, into run and ran.
func (p *hookParse) segRuns(segs []shellSeg, run map[int]*scriptRun, ran map[int]bool) {
	saved := savedNames{} // the files the line has downloaded to so far, by name (round 2; round 4: by name alone)
	var src *savedRun     // the nearest download upstream in the current pipeline, found in one pass
	// marked: the last segment of the current pipeline a run has marked already (one before its first when none), so
	// that many runners after one download mark each segment once (round 3, re-review P2-1: n runners cost n²/2)
	marked := -1
	vars := map[string]savedRun{} // NAME=$(curl …): a variable that holds a download (round 3)
	// runOf: segment i runs the downloads c gathered, when there are any; their segments are part of the run
	runOf := func(i int, c *runSet) bool {
		if len(c.urls) == 0 && !c.more {
			return false
		}
		run[i] = c.script()
		ran[i] = true
		for _, s := range c.segs {
			ran[s] = true
		}
		return true
	}
	for i, sg := range segs {
		if !sg.piped {
			src = nil
			marked = i - 1
		}
		// each way a command runs a download, the first that finds one (a case that finds none lets the next look)
		if sg.proc && i+1 < len(segs) && runsFile(sg.words) {
			body := cutBody(segs[i+1]) // sh < <(curl …): the tokenizer took curl as the redirection's word
			if urls, ok := downloads(body); ok {
				run[i] = &scriptRun{urls, body[0]}
				ran[i], ran[i+1] = true, true
				p.ranSubst(body)
				// bash <(curl …) --yes: the words after the substitution are the shell's own, cut into a segment
				if i+2 < len(segs) && sg.cut && !segs[i+2].piped && len(segs[i+2].words) > 0 && strings.HasPrefix(segs[i+2].words[0], "-") {
					ran[i+2] = true
				}
			} else if runOf(i, gather(saved.printed(body, nil)...)) { // source <(cat i.sh): a saved download printed (round 4)
				ran[i+1] = true
			}
		}
		if run[i] == nil && sg.cut && i+1 < len(segs) && !segs[i+1].piped && (runsInput(sg.words) || segEval(sg.words)) {
			// eval $(curl …), eval `curl …`, sh <<< $(curl …): the substitution the tokenizer cut out is what runs
			body := cutBody(segs[i+1])
			if urls, ok := downloads(body); ok {
				run[i] = &scriptRun{urls, body[0]}
				ran[i], ran[i+1] = true, true
				p.ranSubst(body)
			} else if runOf(i, gather(saved.printed(body, nil)...)) { // eval $(cat i.sh) (round 4)
				ran[i+1] = true
			}
		}
		if run[i] == nil && i+1 < len(segs) && !segs[i+1].piped && psRunsNext(sg.words) {
			// iex (gc i.ps1 -Raw), iex (Get-Content -Raw i.ps1): the group the tokenizer cut out prints a saved
			// download (round 4)
			if runOf(i, gather(saved.printed(segs[i+1].words, segs[i+1].redirs)...)) {
				ran[i+1] = true
			}
		}
		if w := scriptWord(sg.words); run[i] == nil && w != "" {
			// eval "$(cat i.sh)", bash -c "$(cat i.sh)": the substitution of a saved download is the script (round 4)
			if body := substBody(w); body != "" {
				if sl := splitShell(body); len(sl.segs) == 1 {
					runOf(i, gather(saved.printed(sl.segs[0].words, nil)...))
				}
			}
		}
		if run[i] == nil && len(sg.here) > 0 && runsInput(sg.words) {
			// bash <<< "$(curl …)": the here-string is the download's substitution (review P3-2)
			for _, h := range sg.here {
				if urls, words, ok := downloadCommand(substBody(h)); ok {
					run[i] = &scriptRun{urls, words[0]}
					ran[i] = true
					p.ranSubst(words)
					break
				}
			}
		}
		if run[i] == nil && sg.piped && src != nil && (runsInput(sg.words) || variableProgram(sg.words)) {
			run[i] = &scriptRun{src.urls, src.what}
			if src.subst != nil {
				p.ranSubst(src.subst) // echo "$(curl …)" | sh: the printed substitution is the download it runs
			}
			ran[src.seg] = true // the download, also in an earlier command (cat F | sh); then this pipeline from where it was
			for _, s := range src.segs {
				ran[s] = true
			}
			for j := max(src.seg, marked+1); j <= i; j++ {
				ran[j] = true
			}
			marked = i
		}
		if run[i] == nil && sg.doc && runsInput(sg.words) && i+1 < len(segs) && !segs[i+1].piped {
			// bash <<EOF / $(curl …) / EOF: the here-document's substitution, cut into the next segment (round 3)
			if urls, ok := downloads(segs[i+1].words); ok {
				run[i] = &scriptRun{urls, segs[i+1].words[0]}
				ran[i], ran[i+1] = true, true
				p.ranSubst(segs[i+1].words)
			}
		}
		if name := evalVar(sg.words); run[i] == nil && name != "" {
			// s=$(curl …); eval "$s", bash -c "$s": the variable's download is what runs (round 3)
			if r, ok := vars[name]; ok {
				run[i] = &scriptRun{r.urls, r.what}
				ran[i], ran[r.seg], ran[r.at] = true, true, true
				p.ranSubst(r.subst)
			}
		}
		// a file a download wrote that this command runs (curl -o i.sh URL && sh i.sh, irm URL -OutFile i.ps1; .\i.ps1):
		// every download saved under the name it runs (round 4)
		if run[i] == nil {
			files, computed := runFiles(sg.words)
			if runsInput(sg.words) { // sh < i.sh: the input redirection's file
				for _, f := range sg.redirs {
					if !slices.Contains(sg.outs, f) {
						files = append(files, f)
					}
				}
			}
			var c runSet
			for k, f := range files {
				e := saved.find(f)
				c.add(e)
				computed = computed || e == nil && k > 0 && computedName(f)
			}
			// a script whose name the line computes ($f, bash $(echo i.sh), ls i.sh | xargs sh) may be any download it
			// saved (round 4); a <(…) file is what its body prints, read above
			if computed || i+1 < len(segs) && !segs[i+1].piped && sg.cut && !sg.proc && runsFile(sg.words) {
				c.add(saved[allNames])
			}
			runOf(i, &c)
		}
		for _, f := range savedFiles(sg.words) {
			saved.add(f.file, savedRun{url: f.url, what: sg.words[0], seg: i})
		}
		if urls, ok := downloads(sg.words); ok && len(urls) > 0 {
			for _, f := range sg.outs { // curl URL > i.sh
				saved.add(f, savedRun{url: urls[0], what: sg.words[0], seg: i, urls: urls})
			}
		}
		cmd, rest := unwrapped(sg.words)
		switch {
		case teeCommands[cmd] && sg.piped && src != nil && len(src.urls) > 0:
			for _, f := range rest { // curl URL | tee i.sh > /dev/null; irm URL | Set-Content i.ps1 (round 4)
				if !strings.HasPrefix(f, "-") {
					saved.add(f, savedRun{url: src.urls[0], what: src.what, seg: src.seg, urls: src.urls, segs: src.segs})
				}
			}
		case cmd == "mv" || cmd == "cp" || cmd == "ln" || cmd == "install":
			copyFiles(saved, rest) // mv a.sh b.sh, cp a.sh /tmp/, ln -s a.sh b: the download under its new name
		case catCommands[cmd] && len(sg.outs) > 0: // cat i.sh > j.sh: the download under the new name (round 4)
			e := saved.printed(sg.words, sg.redirs)
			for _, f := range sg.outs {
				for _, x := range e {
					saved.copy(f, x)
				}
			}
		}
		p.noteVars(vars, segs, i)
		// what this command downloads to its output is the next ones' input (curl …, echo "$(curl …)", cat of a file a
		// download wrote)
		if urls, ok := downloads(sg.words); ok {
			src = &savedRun{what: sg.words[0], seg: i, urls: urls}
		} else if urls, body, ok := printedDownload(sg.words); ok {
			src = &savedRun{what: body[0], seg: i, urls: urls, subst: body}
		} else if e := saved.printed(sg.words, sg.redirs); len(e) > 0 {
			// cat F, cat < F, Get-Content F: every download saved under F's name (round 4)
			c := gather(e...)
			r := c.script() // more under one name than kept: the reason without a target, at the runner too
			src = &savedRun{what: r.what, seg: i, urls: r.urls, segs: c.segs}
		}
	}
}

// savedRun: a download's file or output: its address (url, for a file), its tool, the segment that downloaded it,
// its addresses (urls, for its output), the words of the substitution a printed one came from, (a variable's) the
// segment that assigned it, and (a cat of saved files) the segments of the downloads it prints.
type savedRun struct {
	url, what string
	seg       int
	urls      []string
	subst     []string
	at        int
	segs      []int
}

// addrs: the addresses a saved download holds.
func (r savedRun) addrs() []string {
	if len(r.urls) > 0 {
		return r.urls
	}
	return []string{r.url}
}

// segEval: words that are eval alone, through wrappers (eval $(curl …): the substitution is eval's argument).
func segEval(words []string) bool {
	return len(words) > 0 && words[len(words)-1] == "eval"
}

// inlineDownload: a script that is one substitution of a download — what sh -c, eval, python -c, node -e or perl -e
// run when given "$(curl …)" — adds its addresses; true when s is one.
func (p *hookParse) inlineDownload(s string) bool {
	body := substBody(s)
	urls, words, ok := downloadCommand(body)
	if !ok {
		// eval "$(curl … ; echo done)": the download still runs; the walk reads the rest of the body as before
		if sl := splitShell(body); body != "" && len(sl.segs) > 0 {
			if urls, ok := downloads(sl.segs[0].words); ok {
				p.remoteScript(urls, sl.segs[0].words[0])
			}
		}
		// bash -c "$(curl …); echo done": a script that begins with a download's substitution runs it, whatever follows
		// (round 2, review P2-1); the walk reads the rest
		if t := strings.TrimSpace(s); body == "" && strings.HasPrefix(t, "$(") && !strings.HasPrefix(t, "$((") {
			if end, closed := closeParen(t, 2); closed {
				if urls, words, ok := downloadCommand(t[2:end]); ok {
					p.ranSubst(words)
					p.remoteScript(urls, words[0])
				}
			}
		}
		return false
	}
	p.ranSubst(words)
	p.remoteScript(urls, words[0])
	return true
}

// ranSubst notes a substitution the walk read as a download it runs (substsAllRun).
func (p *hookParse) ranSubst(words []string) {
	if p.ranSubsts == nil {
		p.ranSubsts = map[string]bool{}
	}
	p.ranSubsts[substKey(words)] = true
}

// interpInline: the program text python -c, node -e (--eval, -p) or perl -e gives on the line, or "".
func interpInline(cmd string, rest []string) string {
	if !interpreterName.MatchString(cmd) || cmd == "pwsh" || cmd == "powershell" {
		return ""
	}
	for i := 0; i < len(rest); i++ {
		x := rest[i]
		if x == "-" || x == "--" || !strings.HasPrefix(x, "-") {
			return ""
		}
		if v, ok := strings.CutPrefix(x, "--eval="); ok && strings.HasPrefix(cmd, "node") {
			return v
		}
		switch interpOption(cmd, x) {
		case optInline:
			if i+1 < len(rest) {
				return rest[i+1] // python -m "$(curl …)" too: the downloaded text names what runs
			}
			return ""
		case optValue:
			i++
		}
	}
	return ""
}

// scriptTarget: the target of a script address as a download tool reads it — without a scheme, http (curl, wget and
// PowerShell's web cmdlets all read it so). Only http and https with a host the line spells (no variable, quote or
// blank in it); the path as written, also with a variable in it.
func scriptTarget(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" || strings.ContainsAny(s, " \t\r\n\"'`\\") {
		return "", false
	}
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return "", false
	}
	scheme, host := strings.ToLower(u.Scheme), strings.ToLower(u.Host)
	if scheme != "http" && scheme != "https" || strings.ContainsAny(host, "$%{}()<>*?[!") && !ipv6Host(host) ||
		!strings.ContainsAny(host, "abcdefghijklmnopqrstuvwxyz0123456789") || strings.Contains(host, "\u2026") {
		return "", false // a variable, a pattern, a placeholder (https://..., an ellipsis): no host the line shows
	}
	t := scheme + "://" + host
	if whole := t + u.EscapedPath(); len(whole) <= maxScriptURL {
		t = whole
	}
	return "script:" + t, true
}

// ipv6Host: an IPv6 literal in brackets, with a port or without ([2001:db8::7]:8080).
func ipv6Host(h string) bool {
	return strings.HasPrefix(h, "[") && strings.Trim(strings.SplitAfter(h, "]")[0], "[]0123456789abcdef:.") == ""
}

// downloads: the addresses a command downloads and writes to its output, as written, and whether it is such a command
// that writes what it downloads to its output: curl (not to files: -o FILE, -O), wget -O -, fetch -o -, PowerShell's
// Invoke-WebRequest and Invoke-RestMethod (iwr, irm) without -OutFile (or with -PassThru).
func downloads(words []string) ([]string, bool) {
	cmd, rest := unwrapped(words)
	switch cmd {
	case "curl":
		return curlURLs(rest)
	case "wget", "wget2":
		return wgetURLs(rest)
	case "fetch":
		return fetchURLs(rest)
	case "irm", "iwr", "invoke-webrequest", "invoke-restmethod":
		return psWebURLs(rest)
	}
	return nil, false
}

// stdoutFile: an output file that is the output itself.
func stdoutFile(v string) bool {
	return v == "-" || v == "/dev/stdout" || v == "/dev/fd/1" || v == "/proc/self/fd/1"
}

// curlValued: curl's options that take a value (curl 7.88.1's --help all, in the pinned build image, and the ones
// curl 8 added: --ech, --variable, --ip-tos, --vlan-priority, --ipfs-gateway, --trace-config, --ssl-sessions,
// --sigalgs, --knownhosts, --upload-flags, --keepalive-cnt, --haproxy-clientip, --parallel-max-host).
var (
	curlShortValued = wordSet("-E -K -C -b -c -d -D -F -P -H -m -o -x -U -Q -r -e -X -Y -y -t -z -T -u -A -w")
	curlLongValued  = wordSet("abstract-unix-socket alt-svc aws-sigv4 cacert capath cert cert-type ciphers config " +
		"connect-timeout connect-to continue-at cookie cookie-jar create-file-mode crlfile curves data data-ascii " +
		"data-binary data-raw data-urlencode delegation dns-interface dns-ipv4-addr dns-ipv6-addr dns-servers doh-url " +
		"dump-header egd-file engine etag-compare etag-save expect100-timeout form form-string ftp-account " +
		"ftp-alternative-to-user ftp-method ftp-port ftp-ssl-ccc-mode happy-eyeballs-timeout-ms header hostpubmd5 " +
		"hostpubsha256 hsts interface json keepalive-time key key-type krb libcurl limit-rate local-port login-options " +
		"mail-auth mail-from mail-rcpt max-filesize max-redirs max-time netrc-file noproxy oauth2-bearer output " +
		"output-dir parallel-max pass pinnedpubkey preproxy proto proto-default proto-redir proxy proxy-cacert " +
		"proxy-capath proxy-cert proxy-cert-type proxy-ciphers proxy-crlfile proxy-header proxy-key proxy-key-type " +
		"proxy-pass proxy-pinnedpubkey proxy-service-name proxy-tls13-ciphers proxy-tlsauthtype proxy-tlspassword " +
		"proxy-tlsuser proxy-user pubkey quote random-file range rate referer request request-target resolve retry " +
		"retry-delay retry-max-time sasl-authzid service-name socks4 socks4a socks5 socks5-gssapi-service " +
		"socks5-hostname speed-limit speed-time stderr telnet-option tftp-blksize time-cond tls-max tls13-ciphers " +
		"tlsauthtype tlspassword tlsuser trace trace-ascii unix-socket upload-file url url-query user user-agent " +
		"write-out proxy1.0 " +
		"ech variable ip-tos vlan-priority ipfs-gateway trace-config ssl-sessions sigalgs knownhosts upload-flags " +
		"keepalive-cnt haproxy-clientip parallel-max-host")
)

// curlURLs: the addresses curl writes to its output. curl pairs its -o FILE and -O with the addresses in order; the
// addresses past them, and those after -o -, go to the output. --remote-name-all saves every one.
func curlURLs(rest []string) ([]string, bool) {
	var urls []string
	files, all := 0, false
	for i := 0; i < len(rest); i++ {
		x := rest[i]
		switch {
		case strings.HasPrefix(x, "--"):
			name := strings.TrimPrefix(x[2:], "expand-") // curl 8's --expand-NAME takes NAME's value
			switch {
			case name == "remote-name":
				files++
			case name == "remote-name-all":
				all = true
			case curlLongValued[name] && i+1 < len(rest):
				i++
				switch name {
				case "url":
					urls = append(urls, rest[i])
				case "output":
					if !stdoutFile(rest[i]) {
						files++
					}
				}
			}
		case len(x) > 1 && x[0] == '-':
			// a cluster of short options: the first that takes a value takes the rest of the word, or the next word
			for j := 1; j < len(x); j++ {
				c := x[j : j+1]
				if c == "O" {
					files++
					continue
				}
				if curlShortValued["-"+c] {
					v := x[j+1:]
					if v == "" && i+1 < len(rest) {
						i++
						v = rest[i]
					}
					if c == "o" && !stdoutFile(v) {
						files++
					}
					break
				}
			}
		default:
			urls = append(urls, x)
		}
	}
	if all || len(urls) > 0 && files >= len(urls) {
		return nil, false
	}
	return urls[min(files, len(urls)):], true
}

// wgetValued: wget's options that take a value (GNU Wget 1.21.3's --help, in the pinned build image).
var (
	wgetShortValued = wordSet("-e -o -a -i -B -t -O -T -w -Q -P -U -l -A -R -D -I -X")
	wgetLongValued  = wordSet("execute output-file append-output report-speed input-file base config rejected-log tries " +
		"retry-on-http-error output-document start-pos progress timeout dns-timeout connect-timeout read-timeout wait " +
		"waitretry quota bind-address limit-rate restrict-file-names prefer-family user password use-askpass " +
		"local-encoding remote-encoding directory-prefix cut-dirs http-user http-password default-page header " +
		"compression proxy-user proxy-password referer user-agent load-cookies save-cookies post-data post-file method " +
		"body-data body-file secure-protocol certificate certificate-type private-key private-key-type ca-certificate " +
		"ca-directory crl-file pinnedpubkey ciphers ftp-user ftp-password warc-file warc-header warc-max-size " +
		"warc-dedup warc-tempdir level backups accept reject accept-regex reject-regex regex-type domains " +
		"exclude-domains follow-tags ignore-tags include-directories exclude-directories")
)

// wgetURLs: wget writes what it downloads to its output only with -O - (the last -O counts); otherwise to files.
// Addresses from a file (-i) are not on the line.
func wgetURLs(rest []string) ([]string, bool) {
	var urls []string
	out := false
	for i := 0; i < len(rest); i++ {
		x := rest[i]
		switch {
		case strings.HasPrefix(x, "--"):
			name, v, eq := strings.Cut(x[2:], "=")
			if wgetLongValued[name] && !eq && i+1 < len(rest) {
				i++
				v = rest[i]
			}
			if name == "output-document" {
				out = stdoutFile(v)
			}
		case len(x) > 1 && x[0] == '-':
			for j := 1; j < len(x); j++ {
				c := "-" + x[j:j+1]
				if !wgetShortValued[c] {
					continue
				}
				v := x[j+1:]
				if v == "" && i+1 < len(rest) {
					i++
					v = rest[i]
				}
				if c == "-O" {
					out = stdoutFile(v)
				}
				break
			}
		default:
			urls = append(urls, x)
		}
	}
	return urls, out
}

// fetchURLs: FreeBSD's fetch writes to its output with -o - (--output=-); its options with a value: -B -i -N -o -S -T -w.
func fetchURLs(rest []string) ([]string, bool) {
	var urls []string
	out := false
	for i := 0; i < len(rest); i++ {
		x := rest[i]
		switch {
		case strings.HasPrefix(x, "--output="):
			out = stdoutFile(strings.TrimPrefix(x, "--output="))
		case x == "--output" && i+1 < len(rest):
			i++
			out = stdoutFile(rest[i])
		case strings.HasPrefix(x, "--"):
		case len(x) > 1 && x[0] == '-':
			for j := 1; j < len(x); j++ {
				c := x[j : j+1]
				if !strings.Contains("BiNoSTw", c) {
					continue
				}
				v := x[j+1:]
				if v == "" && i+1 < len(rest) {
					i++
					v = rest[i]
				}
				if c == "o" {
					out = stdoutFile(v)
				}
				break
			}
		default:
			urls = append(urls, x)
		}
	}
	return urls, out
}

// PowerShell's web cmdlets' parameters (Invoke-WebRequest and Invoke-RestMethod, PowerShell 7.5 and Windows
// PowerShell 5.1, with the common parameters): those that take a value, and the switches. A parameter is any prefix
// of its name that no other name shares (PowerShell's own rule).
var (
	psWebValued = strings.Fields("uri method headers body contenttype outfile useragent timeoutsec proxy credential " +
		"websession sessionvariable maximumredirection infile transferencoding proxycredential certificatethumbprint " +
		"certificate form authentication token maximumretrycount retryintervalsec sslprotocol httpversion " +
		"connectiontimeoutseconds operationtimeoutseconds responseheadersvariable statuscodevariable custommethod " +
		"erroraction errorvariable outvariable warningaction warningvariable informationaction informationvariable " +
		"progressaction outbuffer pipelinevariable")
	psWebSwitches = strings.Fields("usebasicparsing usedefaultcredentials disablekeepalive passthru skipcertificatecheck " +
		"skipheadervalidation noproxy allowunencryptedauthentication followrellink resume skiphttperrorcheck " +
		"preserveauthorizationonredirect allowinsecureredirect preservehttpmethodonredirect verbose debug")
)

// psParam: the parameter a word names (-Uri, -useb, -Uri:value), whether it takes a value, and the value the word
// carries after ":" (has). "" for a name that is no parameter, or one that more than one name begins with.
func psParam(x string) (name string, valued bool, value string, has bool) {
	n := strings.ToLower(strings.TrimPrefix(x, "-"))
	n, value, has = strings.Cut(n, ":")
	if has {
		value = x[len(x)-len(value):] // as written
	}
	if n == "o" {
		// -o: read as -OutFile (round 3, re-review P3-1). Were it ambiguous to PowerShell (OutFile, OutVariable,
		// OutBuffer), the command would fail and nothing would run, so reading it as the file only reads more.
		return "outfile", true, value, has
	}
	hits := 0
	for k, list := range [2][]string{psWebValued, psWebSwitches} {
		for _, full := range list {
			switch {
			case full == n:
				return full, k == 0, value, has
			case strings.HasPrefix(full, n):
				hits++
				name, valued = full, k == 0
			}
		}
	}
	if hits != 1 {
		return "", false, value, has
	}
	return name, valued, value, has
}

// psWebURLs: the address Invoke-WebRequest or Invoke-RestMethod reads (-Uri, or the first word that is no parameter
// or a parameter's value); it writes to the pipeline unless -OutFile without -PassThru.
func psWebURLs(rest []string) ([]string, bool) {
	var urls []string
	outFile, passThru := false, false
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
			outFile = true
		case "passthru":
			passThru = true
		}
	}
	if outFile && !passThru {
		return nil, false
	}
	if len(urls) > 1 {
		urls = urls[:1] // one address: the rest are positional values PowerShell would refuse
	}
	return urls, true
}

// scriptFilters: commands a downloaded script may pass through on its way to the shell that runs it, changed or not —
// passing it on (tee, cat), unpacking it (gunzip, base64 -d) or editing it (tr, sed). Any other command between the
// download and the shell stops the reading: what reaches the shell is that command's output.
var scriptFilters = wordSet("tee cat gunzip zcat gzip xz unxz xzcat bzip2 bunzip2 bzcat zstd unzstd zstdcat base64 tr sed dos2unix iconv")

// interpreter: python, node and perl (and their versioned names), PowerShell; "" for any other program.
var interpreterName = regexp.MustCompile(`^(?:python[0-9.]*|py|pypy[0-9.]*|node|nodejs|perl[0-9.]*|pwsh|powershell)$`)

// Where an interpreter reads the program it runs.
const (
	srcNone   = iota // not an interpreter alalanet reads here
	srcInput         // no program given, or "-": the input (or a <(…) file in its place)
	srcInline        // -c, -e, -m, -Command …: a program on the line
	srcFile          // a file the line names
)

// interpSource: where python, node, perl or PowerShell read the program they run.
func interpSource(cmd string, rest []string) int {
	if !interpreterName.MatchString(cmd) {
		return srcNone
	}
	for i := 0; i < len(rest); i++ {
		x := rest[i]
		switch {
		case x == "-":
			return srcInput
		case x == "--":
			if i+1 < len(rest) && rest[i+1] != "-" {
				return srcFile
			}
			return srcInput
		case !strings.HasPrefix(x, "-"):
			if cmd == "powershell" {
				return srcInline // Windows PowerShell's first word is its -Command
			}
			return srcFile
		}
		switch interpOption(cmd, x) {
		case optInline:
			return srcInline
		case optValue:
			i++
		}
	}
	return srcInput
}

// What one option word of an interpreter is.
const (
	optSwitch = iota
	optValue  // takes the next word
	optInline // gives the program: -c, -e, -m, -Command, -File, -EncodedCommand
)

var (
	nodeValued = wordSet("-r --require --import --loader --experimental-loader -C --conditions --input-type --title " +
		"--env-file --env-file-if-exists --watch-path --test-name-pattern --inspect-port --stack-trace-limit")
	pwshValued = []string{"executionpolicy", "windowstyle", "workingdirectory", "configurationname", "custompipename",
		"outputformat", "inputformat", "settingsfile", "version", "psconsolefile", "configurationfile"}
)

func interpOption(cmd, x string) int {
	switch {
	case strings.HasPrefix(cmd, "py"):
		if strings.HasPrefix(x, "--") {
			if x == "--check-hash-based-pycs" {
				return optValue
			}
			return optSwitch
		}
		for j := 1; j < len(x); j++ {
			switch x[j] {
			case 'c', 'm':
				return optInline
			case 'W', 'X':
				if j == len(x)-1 {
					return optValue
				}
				return optSwitch // its value is the rest of the word
			}
		}
	case strings.HasPrefix(cmd, "node"):
		if x == "-e" || x == "--eval" || x == "-p" || x == "--print" || x == "-pe" || x == "-ep" ||
			strings.HasPrefix(x, "--eval=") || strings.HasPrefix(x, "--print=") {
			return optInline
		}
		if nodeValued[x] {
			return optValue
		}
	case strings.HasPrefix(cmd, "perl"):
		// perl reads a cluster letter by letter: -I, -M, -m, -i, -x, -C, -d take the rest of the word as their
		// value (-Ilib, -MFoo, -i.bak); -e and -E give the program (-le, -ne)
		for j := 1; j < len(x); j++ {
			switch c := x[j]; {
			case c == 'e' || c == 'E':
				return optInline
			case strings.IndexByte("IMmixCd", c) >= 0:
				return optSwitch
			}
		}
	default: // pwsh, powershell: any prefix of a parameter's name. -Command, -File and -EncodedCommand need no case:
		// their value is read as the first word that is no option — a program on the line, or "-", the input
		n := strings.ToLower(strings.TrimLeft(x, "-/"))
		if n == "ep" || n == "ex" || n == "wd" || n == "of" || n == "if" || n == "w" || n == "o" || n == "v" {
			return optValue
		}
		for _, full := range pwshValued {
			if len(n) > 1 && strings.HasPrefix(full, n) {
				return optValue
			}
		}
	}
	return optSwitch
}

// runsInput: words that run as a script what they read from their input: a shell with no script of its own (sh,
// bash -s, bash /dev/stdin, sudo bash, su, sudo -s), source /dev/stdin, Invoke-Expression with no command, and python,
// node, perl or PowerShell given "-" or no program.
func runsInput(words []string) bool {
	cmd, rest := unwrapped(runnerWords(words)) // pnpm exec sh, npx -y sh, uv run python3 - (round 2)
	switch {
	case posixShells[cmd] || foreignShells[cmd]:
		if script, ok := shellScript(rest, foreignShells[cmd]); ok {
			return scriptReadsInput(script) // bash -c 'cat | sh', sh -c 'sh' (round 2)
		}
		return readsStdin(rest)
	case cmd == "source" || cmd == ".":
		return len(rest) > 0 && stdinFile(rest[0])
	case cmd == "iex" || cmd == "invoke-expression":
		return len(psCommandArgs(rest)) == 0
	case implicitStdinShell(words):
		return true
	}
	return interpSource(cmd, rest) == srcInput
}

// runsFile: words that run as a script the <(…) file the shell gives them in place of a word: a shell, source or an
// interpreter with no script of its own on the line (bash <(curl …), source <(curl …), python3 <(curl …)).
func runsFile(words []string) bool {
	cmd, rest := unwrapped(words) // uv run bash <(curl …): the runner's own reading reads its program
	switch {
	case posixShells[cmd] || foreignShells[cmd]:
		_, ok := shellScript(rest, foreignShells[cmd])
		return !ok
	case cmd == "source" || cmd == ".":
		return len(rest) == 0
	}
	return interpSource(cmd, rest) == srcInput // with a file word of its own the <(…) file is an argument
}

// substBody: the command of a word or script that is one command substitution — "$(curl …)" or a backtick pair —
// followed by nothing but plain words (the arguments sh -c's script is joined with: zsh -c "$(curl …)" "" --unattended),
// or "".
func substBody(s string) string {
	s = strings.TrimSpace(s)
	body, rest := "", ""
	switch {
	case strings.HasPrefix(s, "$(") && !strings.HasPrefix(s, "$(("):
		end, ok := closeParen(s, 2)
		if !ok {
			return ""
		}
		body, rest = s[2:end], s[end+1:]
	case strings.HasPrefix(s, "`"):
		end := strings.IndexByte(s[1:], '`')
		if end < 0 {
			return ""
		}
		body, rest = s[1:end+1], s[end+2:]
	default:
		return ""
	}
	if rest != "" && (rest[0] != ' ' && rest[0] != '\t' || strings.ContainsAny(rest, ";|&<>()`$\n")) {
		return ""
	}
	return body
}

// downloadCommand: a command text that is one download writing to its output, through filters only, and nothing else,
// with the words its key is made of. An address from a substitution of its own ($(curl "$(cat url.txt)")) is one the line does not show.
func downloadCommand(body string) ([]string, []string, bool) {
	if body == "" {
		return nil, nil, false
	}
	sl := splitShell(body)
	if sl.unclosed || len(sl.segs) == 0 {
		return nil, nil, false
	}
	for _, sg := range sl.segs[1:] { // $(curl … | tr -d '\r'): only filters after it, or the output is not the download
		if cmd, _ := unwrapped(sg.words); !sg.piped || !scriptFilters[cmd] {
			return nil, nil, false
		}
	}
	urls, ok := downloads(sl.segs[0].words)
	return urls, sl.segs[0].words, ok
}

// substKey: the key of a substitution the walk read as a download it runs (ranSubsts).
func substKey(words []string) string { return strings.Join(words, "\x00") }

// closeParen: the index of the ")" that closes the "(" before s[from], outside quotes; ok false when none does.
func closeParen(s string, from int) (int, bool) {
	depth := 1
	for i := from; i < len(s); i++ {
		switch c := s[i]; c {
		case '\\':
			i++
		case '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return 0, false
			}
			i += j + 1
		case '"':
			for i++; i < len(s) && s[i] != '"'; i++ {
				if s[i] == '\\' {
					i++
				}
			}
			if i >= len(s) {
				return 0, false
			}
		case '(':
			depth++
		case ')':
			if depth--; depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

// substSpans: the outermost $( … ), <( … ), >( … ) and backtick substitutions of a line outside single quotes, as
// [start, end) spans, with their bodies; ok false when one does not close or there are more than maxSubsts.
func substSpans(s string) (spans [][2]int, bodies []string, ok bool) {
	single, double := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case single:
			single = c != '\''
		case c == '\\':
			i++
		case c == '\'' && !double:
			single = true
		case c == '"':
			double = !double
		case c == '`':
			j := strings.IndexByte(s[i+1:], '`')
			if j < 0 {
				return nil, nil, false
			}
			spans, bodies = append(spans, [2]int{i, i + j + 2}), append(bodies, s[i+1:i+1+j])
			i += j + 1
		case (c == '$' || !double && (c == '<' || c == '>')) && i+1 < len(s) && s[i+1] == '(':
			end, closed := closeParen(s, i+2)
			if !closed {
				return nil, nil, false
			}
			spans, bodies = append(spans, [2]int{i, end + 1}), append(bodies, s[i+2:end])
			i = end
		}
		if len(spans) > maxSubsts {
			return nil, nil, false
		}
	}
	return spans, bodies, true
}

// substsAllRun: whether every substitution in the line is a download the walk read as a script it runs (ran holds
// their keys): then the line shows all it runs, and its substitution flag is cleared. Any other substitution, or one
// the count cannot place, keeps the flag.
func substsAllRun(line string, ran map[string]bool) bool {
	spans, bodies, ok := substSpans(line)
	if !ok || len(spans) == 0 {
		return false
	}
	var b strings.Builder
	last := 0
	for k, sp := range spans {
		_, words, isDL := downloadCommand(bodies[k])
		if !isDL || !ran[substKey(words)] {
			return false
		}
		b.WriteString(line[last:sp[0]])
		b.WriteString("x")
		last = sp[1]
	}
	b.WriteString(line[last:])
	return !splitShell(b.String()).subst
}

// PowerShell: a script a line downloads and gives to Invoke-Expression or [scriptblock]::Create in one statement —
// iex (irm …), iex ((iwr …).Content), (iwr …).Content | iex, iex ((New-Object Net.WebClient).DownloadString('…')),
// iex "& { $(irm …) }", & ([scriptblock]::Create((irm …))). Found in the text with its quoted parts blanked out, so
// a commit message or an echo that quotes such a line is not one.
var (
	psRunner   = regexp.MustCompile(`(?i)(?:^|[;&|({\n]|\bthen\b|\bdo\b)\s*(?:iex|invoke-expression)\b|\[scriptblock\]::create\s*\(`)
	psFetch    = regexp.MustCompile(`(?i)(?:^|[\s(;|&{$])(irm|iwr|invoke-restmethod|invoke-webrequest|curl|wget)(?:\.exe)?\s+([^()|;{}\n]*)`)
	psDownload = regexp.MustCompile(`(?i)\.downloadstring\(\s*([^()]*)\)`)
)

// psRemoteScripts: the downloads a PowerShell text gives to a runner in the same statement: each one's addresses as
// written (nil when it shows none) and a name for it.
func psRemoteScripts(s string) (found [][]string, names []string) {
	masked := blankQuoted(s)
	// each statement once, in one pass: a statement of a thousand runners is read once, not a thousand times
	for from := 0; from <= len(masked); {
		to := len(masked)
		if k := strings.IndexAny(masked[from:], ";\n"); k >= 0 {
			to = from + k
		}
		if psRunner.MatchString(masked[from:to]) {
			f, n := psStatementFetches(s[from:to])
			found, names = append(found, f...), append(names, n...)
		}
		from = to + 1
	}
	return found, names
}

// psStatementFetches: the downloads in one statement that runs what it downloads, with a name for each.
func psStatementFetches(stmt string) (found [][]string, names []string) {
	for _, f := range psFetch.FindAllStringSubmatch(stmt, -1) {
		var urls []string
		ok := false
		words := strings.Fields(strings.NewReplacer(`"`, " ", `'`, " ").Replace(f[2]))
		switch strings.ToLower(f[1]) {
		case "curl":
			urls, ok = curlURLs(words)
		case "wget":
			urls, ok = wgetURLs(words)
		default:
			urls, ok = psWebURLs(words)
		}
		if ok {
			found, names = append(found, urls), append(names, f[1])
		}
	}
	for _, d := range psDownload.FindAllStringSubmatch(stmt, -1) {
		u := strings.Trim(strings.TrimSpace(d[1]), `"'`)
		found, names = append(found, []string{u}), append(names, "DownloadString")
	}
	return found, names
}

// blankQuoted: s with the text inside single and double quotes replaced by blanks, the quotes kept; the same length.
func blankQuoted(s string) string {
	b := []byte(s)
	q := byte(0)
	for i := 0; i < len(b); i++ {
		switch c := b[i]; {
		case q == 0 && (c == '\'' || c == '"'):
			q = c
		case q != 0 && c == q:
			q = 0
		case q != 0:
			b[i] = ' '
		}
	}
	return string(b)
}

// psScriptPart: a segment the POSIX splitting cuts out of a PowerShell download that is run — the runner, the
// download cmdlet, New-Object, a member access (.Content, .DownloadString), a call operator, an address alone.
func psScriptPart(words []string) bool {
	if len(words) == 0 {
		return true
	}
	cmd, _ := unwrapped(words)
	w := strings.ToLower(words[0])
	switch {
	case cmd == "iex" || cmd == "invoke-expression" || cmd == "new-object" || cmd == "&":
		return true
	case cmd == "irm" || cmd == "iwr" || cmd == "invoke-restmethod" || cmd == "invoke-webrequest" || cmd == "curl" || cmd == "wget":
		return true
	case strings.HasPrefix(w, ".") && len(words) == 1, strings.HasPrefix(w, "[scriptblock]::create"):
		return true
	case len(words) == 1 && strings.Contains(w, "://"):
		return true
	case strings.HasPrefix(w, "-"): // a parameter the call operator's group leaves behind: & (…) -Version 1
		return true
	}
	return false
}
