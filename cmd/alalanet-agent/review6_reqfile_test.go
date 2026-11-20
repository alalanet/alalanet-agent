package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/alalanet/alalanet-agent/internal/installread"
)

// Re-review of READER-REQFILE-1 round 17 (reader-rows 0533aaa), the reviewer's proof adopted in round 19: an array
// subscript is an arithmetic expression in bash, and an assignment inside it needs no $ and no parenthesis (bash 3.2 and
// 5.2: cd sub lands in 1/sub). Changed on adoption: the prefix form holds too (round 19's rule reads raw words).
func TestReview6SubscriptAssigns(t *testing.T) {
	honest := []byte("zz-req-pkg\n")
	for _, c := range []struct {
		line string
		hold bool
	}{
		{"a[CDPATH=1]=x; cd sub && pip install -r r.txt", true},
		// a prefix assignment of an element: bash sets nothing, but the round-19 rule reads raw words and holds (adopted
		// with the expectation changed: the class rule does not tell a prefix from a standalone assignment)
		{"a[CDPATH=1]=x pip --version; cd sub && pip install -r r.txt", true},
		{`test -v "a[CDPATH=1]"; cd sub && pip install -r r.txt`, true}, // bash 5.2
		{`[ -v "a[CDPATH=1]" ]; cd sub && pip install -r r.txt`, true},  // bash 5.2
		{"cd sub && pip install -r r.txt", false},
	} {
		cwd := t.TempDir()
		for n, b := range map[string][]byte{"1/sub/r.txt": []byte(zzEvil), "sub/r.txt": honest, "r.txt": honest} {
			zzWrite(t, cwd, n, b)
		}
		why := reqFileHold(cwd, "", c.line, nil)
		t.Logf("%-60q -> %q", c.line, why)
		if (why != "") != c.hold {
			t.Errorf("%q: hold %v, want %v", c.line, why != "", c.hold)
		}
	}
}

// D: the corpus's lines that name a requirements file, through the plan alone (no file exists): which hold.
func TestReview6CorpusPlan(t *testing.T) {
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
