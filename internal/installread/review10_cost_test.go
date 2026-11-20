package installread

import (
	"strings"
	"testing"
	"time"
)

// Re-review round 22 (reader-rows 80ac85e): the cost of the substitution walk on lines built to cost.
func TestReview10SubstCost(t *testing.T) {
	for _, n := range []int{500, 1000, 2000, 4000} {
		for name, line := range map[string]string{
			"quoted $( unclosed":   `echo "` + strings.Repeat("$(", n) + `"; pip install zz-pkg`,
			"quoted $( nested":     `echo "` + strings.Repeat("$(", n) + strings.Repeat(")", n) + `"; pip install zz-pkg`,
			"quoted $( flat":       `echo "` + strings.Repeat("$(true) ", n) + `"; pip install zz-pkg`,
			"backticks quoted":     `echo "` + strings.Repeat("`", n) + `"; pip install zz-pkg`,
			"${ with $( unclosed":  `echo ${X:-` + strings.Repeat("$(", n) + `}; pip install zz-pkg`,
			"unquoted $( unclosed": `echo ` + strings.Repeat("$(", n) + `; pip install zz-pkg`,
		} {
			start := time.Now()
			_, un, _, _ := ParseLine(line)
			d1 := time.Since(start)
			start = time.Now()
			s := SourcedFiles(line + "; . ./x.sh")
			d2 := time.Since(start)
			t.Logf("%-22s n=%6d (%4d KiB): ParseLine %v (%d reasons), SourcedFiles %v (%d)", name, n, len(line)>>10, d1, len(un), d2, len(s))
		}
	}
}
