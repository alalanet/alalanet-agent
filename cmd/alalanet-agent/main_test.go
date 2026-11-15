package main

import (
	"os"
	"testing"
)

// Public repository only (the monorepo's TestMain is in rt1_review_test.go, which needs the server's packages): the
// tests that run this test binary as the agent itself set ZZ_REVIEW_RT1_MAIN, and TestMain is then main().
func TestMain(m *testing.M) {
	if os.Getenv("ZZ_REVIEW_RT1_MAIN") == "1" {
		os.Args = []string{"alalanet-agent", "hook", "codex"}
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}
