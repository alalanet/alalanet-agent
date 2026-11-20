//go:build unix

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// PIP-VERSIONED-1 round 4 (re-review P3): pyNames read at most 16 names and dropped the rest without a word, so a line
// that names twelve or more launchers before the one that installs left that one's pip configuration unread. The
// launchers that run pip are read first, and a line that names more than the reader looks up is incomplete.
func TestPipVersionedPyNamesCap(t *testing.T) {
	var parts []string
	for i := 0; i < 17; i++ {
		parts = append(parts, fmt.Sprintf("python3.%d -V", i))
	}
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(bin, "python3.99"), "")
	write(t, filepath.Join(tmp, "pip.conf"), "[global]\nindex-url = https://evil.example/simple\n")
	path := map[string]string{"python3.99": filepath.Join(bin, "python3.99")}
	line := strings.Join(append(parts, "python3.99 -m pip install zz-x"), "; ")
	pf := npmrcFiles(t, t.TempDir(), "", nil, path)
	// the launcher that runs pip is read first: its prefix's pip.conf names the move, not "more than the reader looks up"
	if why := registryMoved(pf, "", line, []string{"pypi:zz-x"}); !strings.Contains(why, filepath.Join(tmp, "pip.conf")) {
		t.Errorf("17 launchers before python3.99 -m pip: %q; want its prefix's pip.conf", why)
	}
	// more launchers that run pip than the reader looks up: incomplete, not silent
	var many []string
	for i := 0; i < 20; i++ {
		many = append(many, fmt.Sprintf("python3.%d -m pip install zz-x", i))
	}
	if why := registryMoved(npmrcFiles(t, t.TempDir(), "", nil, map[string]string{}), "", strings.Join(many, "; "), []string{"pypi:zz-x"}); why == "" {
		t.Errorf("20 launchers that run pip: the reader looks up 16 and says nothing of the rest")
	}
	// a program run by its path past the line's 64th word: its prefix is read
	pre := filepath.Join(tmp, "late")
	if err := os.MkdirAll(filepath.Join(pre, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(pre, "pip.conf"), "[global]\nindex-url = https://evil.example/simple\n")
	long := strings.Repeat("echo a b c d; ", 20) + filepath.Join(pre, "bin", "pip") + " install zz-x"
	if why := registryMoved(npmrcFiles(t, t.TempDir(), "", nil, map[string]string{}), "", long, []string{"pypi:zz-x"}); why == "" {
		t.Errorf("a pip run by its path after 100 words: its prefix's pip.conf is not read")
	}
	// programs from more folders than the reader reads: incomplete
	var dirs []string
	for i := 0; i < 70; i++ {
		dirs = append(dirs, fmt.Sprintf("/opt/p%d/bin/pip install zz-x", i))
	}
	if why := registryMoved(npmrcFiles(t, t.TempDir(), "", nil, map[string]string{}), "", strings.Join(dirs, "; "), []string{"pypi:zz-x"}); why == "" {
		t.Errorf("70 prefixes by path: the reader reads 64 and says nothing of the rest")
	}
}
