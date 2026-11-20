package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alalanet/alalanet-agent/internal/installread"
)

// Re-review of READER-REQFILE-1 round 15 (reader-rows f728804): proof tests, adopted unchanged in round 16 (ADR-0159). Placeholders only; every file is in
// t.TempDir(). Where bash goes was checked with bash 3.2 and 5 (r3/bash4).

// A: forms that change where a literal cd goes, outside the allowlist's CDPATH check. Each case: the folder bash ends
// in has a requirements file that moves the index; every file the hook's reading reaches is honest.
func TestReview4CdMeaning(t *testing.T) {
	honest := []byte("zz-req-pkg\n")
	for _, c := range []struct {
		line string
		hold bool
	}{
		{"CDPATH+=evil; cd sub && pip install -r r.txt", true},
		{"CDPATH=evil; cd sub && pip install -r r.txt", true},
		{"read CDPATH <<< evil; cd sub && pip install -r r.txt", true},
		{"printf -v CDPATH evil; cd sub && pip install -r r.txt", true},
		{"shopt -s cdable_vars; d=evil; cd d && pip install -r r.txt", true},
		{"set -o physical; cd link && cd .. && pip install -r r.txt", true},
		{"set -P; cd link && cd .. && pip install -r r.txt", true},
		{"shopt -s expand_aliases\nalias cd='builtin cd evil; true'\ncd sub && pip install -r r.txt", true},
		{"function cd { builtin cd evil; }; cd sub && pip install -r r.txt", true},
		{"declare -x CDPATH=evil; cd sub && pip install -r r.txt", true},
		{"typeset CDPATH=evil; cd sub && pip install -r r.txt", true},
		{"{ cd sub; } && CDPATH=evil true && pip install -r r.txt", true},
		{"cdpath=evil; cd sub2 && pip install -r r.txt", true}, // zsh (macOS's default shell): evil/sub2
	} {
		cwd := t.TempDir()
		for n, b := range map[string][]byte{"evil/sub/r.txt": []byte(zzEvil), "evil/r.txt": []byte(zzEvil), "sub/r.txt": honest,
			"r.txt": honest, "phys/r.txt": []byte(zzEvil), "phys/sub/r.txt": honest, "evil/sub2/r.txt": []byte(zzEvil)} {
			zzWrite(t, cwd, n, b)
		}
		if err := os.Symlink(filepath.Join(cwd, "phys", "sub"), filepath.Join(cwd, "link")); err != nil {
			t.Fatal(err)
		}
		why := reqFileHold(cwd, "", c.line, nil)
		t.Logf("%-75q -> %q", c.line, why)
		if (why != "") != c.hold {
			t.Errorf("%q: hold %v, want %v", c.line, why != "", c.hold)
		}
	}
}

// B: encodings, against pip 26.2.2's _decode_req_file.
func TestReview4Encodings(t *testing.T) {
	u16 := func(s string, odd bool) []byte {
		b := []byte{0xff, 0xfe}
		for _, r := range s {
			b = append(b, byte(r), 0)
		}
		if odd {
			b = append(b, 'x')
		}
		return b
	}
	for _, c := range []struct {
		name string
		body []byte
		hold bool
	}{
		{"UTF-8 BOM, a latin-1 coding line (pip: the BOM decides)", []byte("\xef\xbb\xbf# -*- coding: latin-1 -*-\nzz-req-pkg\n"), false},
		{"UTF-8 BOM, a latin-1 coding line, an index", []byte("\xef\xbb\xbf# -*- coding: latin-1 -*-\n" + zzEvil), true},
		{"UTF-16 odd length", u16("zz-req-pkg\n", true), true},
		{"UTF-16 honest", u16("zz-req-pkg\n", false), false},
		{"UTF-16 index", u16(zzEvil, false), true},
		{"honest latin-1 comment (held by the decision)", []byte("# caf\xe9\nzz-req-pkg\n"), true},
		{"U+0085 in UTF-8 (held by the decision)", []byte("# a\u0085b\nzz-req-pkg\n"), true},
		{"coding utf-8 on line 2", []byte("#!x\n# coding: utf-8\nzz-req-pkg\n"), false},
		{"coding cp1252 on line 3 (pip reads 2)", []byte("#a\n#b\n# coding: cp1252\nzz-req-pkg\n"), false},
	} {
		dir := t.TempDir()
		zzWrite(t, dir, "r.txt", c.body)
		why := reqFileHold(dir, "", "pip install -r r.txt", nil)
		t.Logf("%-58s -> %q", c.name, why)
		if (why != "") != c.hold {
			t.Errorf("%s: hold %v, want %v", c.name, why != "", c.hold)
		}
	}
}

// C: what runs outside the deadline (RequirementFiles) and the reading's caps.
func TestReview4Cost(t *testing.T) {
	cwd := t.TempDir()
	for _, c := range []struct{ name, line string }{
		{"8 MiB, no file", strings.Repeat("echo zz ", 1<<20)},
		{"8 MiB of -r", strings.Repeat("pip install -r r.txt; ", (8<<20)/22)},
		{"8 MiB of distinct -r", func() string {
			var b strings.Builder
			for i := 0; b.Len() < 8<<20; i++ {
				b.WriteString("pip install -r r" + strings.Repeat("x", i%50) + ".txt; ")
			}
			return b.String()
		}()},
		{"100k cd then -r", strings.Repeat("cd a;", 100000) + "pip install -r r.txt"},
	} {
		start := time.Now()
		n := len(installread.RequirementFiles(c.line))
		outside := time.Since(start)
		start = time.Now()
		why := reqFileHold(cwd, "", c.line, nil)
		t.Logf("%-22s RequirementFiles %v (%d files); reqFileHold %v %q", c.name, outside, n, time.Since(start), why)
	}
}

// D: the corpus's lines that name a requirements file, through the plan alone (no file exists): which hold.
func TestReview4CorpusPlan(t *testing.T) {
	data, err := os.ReadFile(os.Getenv("ZZ_CORPUS"))
	if err != nil {
		t.Skip()
	}
	cwd, home := t.TempDir(), t.TempDir()
	named, held := 0, 0
	for _, l := range strings.Split(string(data), "\n") {
		var line string
		if json.Unmarshal([]byte(l), &line) != nil || len(installread.RequirementFiles(line)) == 0 {
			continue
		}
		named++
		if why := reqFileHold(cwd, home, line, nil); why != "" {
			held++
			t.Logf("HOLD %q: %s", clip(line), why)
		}
	}
	t.Logf("lines naming a file: %d, held with no file present: %d", named, held)
}
