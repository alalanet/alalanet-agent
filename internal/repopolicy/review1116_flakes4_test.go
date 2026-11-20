package repopolicy

// Independent review of flakes-4 (b5c6b958), 2026-11-16: its proof for the surviving Q2 mutant (a quadratic rescan
// of a mapping's keys that allocates nothing), taken into flakes-5 (review-1116/flakes4/review.md, P3-2) on the
// package's threadCPU. The measure is the CPU time of the goroutine's own OS thread: time the thread did not run —
// the machine's load — is not in it, unlike the wall clock, and work that allocates nothing is in it, unlike the
// allocation counters. An operation counter in plainNodes would count only the loop it instruments: a new loop such
// as Q2's is not counted, so it could not catch Q2.

import (
	"fmt"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// mappingOf is a mapping node of n distinct plain keys, as yaml.v3 gives one (the parse itself left out: it is
// linear, and its allocations already have a bound in TestReviewHostileShapesBounded).
func mappingOf(n int) *yaml.Node {
	m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for i := 0; i < n; i++ {
		m.Content = append(m.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: fmt.Sprintf("k%07d", i)},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: "1"})
	}
	return &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{m}}
}

// plainNodesCPU is the least thread CPU time of five rounds of plainNodes over whole and over eighth, one right after
// the other in each, with the collector off (quietCPU; flakes-5: the reviewer's least of three, back to back, gave
// 16 times under the host's load where it gave 5).
func plainNodesCPU(t *testing.T, whole, eighth *yaml.Node) (time.Duration, time.Duration) {
	w, e := time.Duration(-1), time.Duration(-1)
	for i := 0; i < 5; i++ {
		var errE, errW error
		de, okE := quietCPU(1, func() { errE = plainNodes(eighth) })
		dw, okW := quietCPU(1, func() { errW = plainNodes(whole) })
		if errE != nil || errW != nil {
			t.Fatal(errE, errW)
		}
		if !okE || !okW {
			t.Skip(threadCPUWhy)
		}
		if e < 0 || de < e {
			e = de
		}
		if w < 0 || dw < w {
			w = dw
		}
	}
	return w, e
}

// The key check of a mapping grows linearly: 16,000 keys take at most 24 times the thread CPU time of 2,000 (8 times
// for a linear check, 64 for a quadratic one), and 20 ms besides for the clock's grain.
func TestReview1116PlainNodesKeysLinearByThreadCPU(t *testing.T) {
	if threadCPUWhy != "" {
		t.Skip(threadCPUWhy)
	}
	whole, eighth := mappingOf(16000), mappingOf(2000)
	w, e := plainNodesCPU(t, whole, eighth)
	t.Logf("plainNodes: 16,000 keys %v, 2,000 keys %v of thread CPU (%.1f times)", w, e, float64(w)/float64(max(e, 1)))
	if w > 24*e+20*time.Millisecond {
		t.Errorf("plainNodes: 16,000 keys took %v of thread CPU, 2,000 keys %v: not linear", w, e)
	}
}
