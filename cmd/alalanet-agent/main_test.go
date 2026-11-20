package main

import (
	"os"
	"testing"

	"github.com/alalanet/alalanet-agent/internal/safe/safetest"
)

// Public repository only (the monorepo's TestMain is in rt1_review_test.go, which needs the server's packages): the
// tests that run this test binary as the agent itself set ZZ_REVIEW_RT1_MAIN, and TestMain is then main(); otherwise
// a panic recovered in a test fails the run, as in the monorepo (TEST-NIL-1).
func TestMain(m *testing.M) {
	if os.Getenv("ZZ_REVIEW_RT1_MAIN") == "1" {
		os.Args = []string{"alalanet-agent", "hook", "codex"}
		main()
		os.Exit(0)
	}
	os.Exit(safetest.Run(m))
}
