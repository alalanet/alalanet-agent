package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alalanet/alalanet-agent/internal/installread"
)

// Re-review of READER-REQFILE-1 round 16 (reader-rows 7ec27aa): proof tests, adopted in round 17 (ADR-0159) with one
// change: the self-including file holds (P3-I: the raw paths ./r.txt, ././r.txt … pass the file bound; pip refuses the
// file itself, so the hold costs nothing). Placeholders only; every file is in t.TempDir(). Where the shell goes was checked with bash 3.2 (r3/bash5) and bash 5.2 in the pinned image.

// A: an allowed command whose words assign CDPATH through a parameter expansion (${CDPATH:=…}, ${CDPATH=…}) or an
// arithmetic one ($((CDPATH=1))); an assignment of another name whose value does; declare -n and local (not allowed).
func TestReview5ExpansionAssigns(t *testing.T) {
	honest := []byte("zz-req-pkg\n")
	for _, c := range []struct {
		line string
		hold bool
	}{
		{"echo ${CDPATH:=evil} >/dev/null; cd sub && pip install -r r.txt", true},
		{"true ${CDPATH=evil}; cd sub && pip install -r r.txt", true},
		{"X=${CDPATH:=evil}; cd sub && pip install -r r.txt", true},
		{"mkdir -p ${CDPATH:=evil}; cd sub && pip install -r r.txt", true},
		{`test -n "${CDPATH:=evil}"; cd sub && pip install -r r.txt`, true},
		{"[ ${CDPATH:=evil} ]; cd sub && pip install -r r.txt", true},
		{"pip --version ${CDPATH:=evil}; cd sub && pip install -r r.txt", true},
		{"echo $((CDPATH=1)) >/dev/null; cd sub && pip install -r r.txt", true},
		{"declare -n r=CDPATH; r=evil; cd sub && pip install -r r.txt", true},
		{"echo $[CDPATH=1] >/dev/null; cd sub && pip install -r r.txt", true},
		{"[[ CDPATH=1 -eq 1 ]]; cd sub && pip install -r r.txt", true},
		{"true <<EOF\n${CDPATH:=evil}\nEOF\ncd sub && pip install -r r.txt", true},
		{"echo x > /dev/null${CDPATH:=evil}; cd sub && pip install -r r.txt", true},
		{"n=CDPATH; echo ${!n:=evil} >/dev/null; cd sub && pip install -r r.txt", true}, // bash 5.2; bash 3.2 does not assign
		{"local CDPATH=evil; cd sub && pip install -r r.txt", true},
		{"echo -e 'a\\tb' <<< x; test -o physical; ls -la; mkdir -p sub; pwd -P; cd sub && pip install -r r.txt", false},
	} {
		cwd := t.TempDir()
		for n, b := range map[string][]byte{"evil/sub/r.txt": []byte(zzEvil), "1/sub/r.txt": []byte(zzEvil), "sub/r.txt": honest, "r.txt": honest} {
			zzWrite(t, cwd, n, b)
		}
		why := reqFileHold(cwd, "", c.line, nil)
		t.Logf("%-80q -> %q", c.line, why)
		if (why != "") != c.hold {
			t.Errorf("%q: hold %v, want %v", c.line, why != "", c.hold)
		}
	}
}

// B: the raw join: a link's "..", nested files, ~/link/.., and honest relative paths.
func TestReview5RawJoin(t *testing.T) {
	honest := []byte("zz-req-pkg\n")
	for _, c := range []struct {
		line  string
		files map[string][]byte
		hold  bool
	}{
		{"pip install -r link/../r.txt", map[string][]byte{"phys/r.txt": []byte(zzEvil), "r.txt": honest}, true},
		{"env -C link/.. pip install -r r.txt", map[string][]byte{"phys/r.txt": []byte(zzEvil), "r.txt": honest}, true},
		{"uv --directory link/.. pip install -r r.txt", map[string][]byte{"phys/r.txt": []byte(zzEvil), "r.txt": honest}, true},
		{"pip install -r r.txt", map[string][]byte{"r.txt": []byte("-r link/../x.txt\n"), "phys/x.txt": []byte(zzEvil), "x.txt": honest}, true},
		{"pip install -r link/r.txt", map[string][]byte{"phys/sub/r.txt": []byte("-r ../x.txt\n"), "phys/x.txt": []byte(zzEvil), "x.txt": honest}, true},
		{"pip install -r ~/link/../r.txt", map[string][]byte{"phys/r.txt": []byte(zzEvil), "r.txt": honest}, true},
		{"cd link && pip install -r ../r.txt", map[string][]byte{"phys/r.txt": []byte(zzEvil), "r.txt": honest}, true},
		{"cd link && cd .. && pip install -r r.txt", map[string][]byte{"phys/r.txt": []byte(zzEvil), "r.txt": honest}, false}, // bash -L: cwd
		{"pip install -r ./reqs/../r.txt", map[string][]byte{"reqs/x": honest, "r.txt": honest}, false},
		{"pip install -r reqs/base.txt", map[string][]byte{"reqs/base.txt": []byte("-r ../common.txt\n-c ./c.txt\n"), "common.txt": honest, "reqs/c.txt": honest}, false},
		{"cd reqs && pip install -r ./base.txt", map[string][]byte{"reqs/base.txt": []byte("-r ../common.txt\n"), "common.txt": honest}, false},
		{"pip install -r r.txt", map[string][]byte{"r.txt": []byte("-r ./r.txt\nzz-req-pkg\n")}, true}, // pip refuses it; held (P3-I)
	} {
		cwd := t.TempDir()
		for n, b := range c.files {
			zzWrite(t, cwd, n, b)
		}
		if err := os.MkdirAll(filepath.Join(cwd, "phys", "sub"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(cwd, "phys", "sub"), filepath.Join(cwd, "link")); err != nil {
			t.Fatal(err)
		}
		why := reqFileHold(cwd, cwd, c.line, nil)
		t.Logf("%-50q -> %q", c.line, why)
		if (why != "") != c.hold {
			t.Errorf("%q: hold %v, want %v", c.line, why != "", c.hold)
		}
	}
}

// D: the corpus's lines that name a requirements file, through the plan alone (no file exists): which hold.
func TestReview5CorpusPlan(t *testing.T) {
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
