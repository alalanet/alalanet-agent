package main

// Review of RT-1 round 5 (0d873d6): a test that runs this test binary as the agent (exec.Command(os.Args[0]) with
// ZZ_REVIEW_RT1_MAIN=1) relies on a TestMain that turns the child into main(). In a copy without that TestMain (the
// public repository's first dry run) the child runs every test again, including the one that started it, and so on:
// a chain of thousands of processes that exhausted the machine's ephemeral ports on 2026-11-15. Every self-exec must
// name the tests the child may run (-test.run=...), so that without the TestMain the child runs nothing and the parent
// test fails instead of forking.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestReviewR5SelfExecNamesItsTests(t *testing.T) {
	files, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	bare := regexp.MustCompile(`exec\.Command(Context)?\((ctx, )?os\.Args\[0\]\)`)
	for _, name := range files {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "//") && bare.MatchString(line) {
				t.Errorf("%s:%d runs the test binary without -test.run: %s", name, i+1, strings.TrimSpace(line))
			}
		}
	}
}
