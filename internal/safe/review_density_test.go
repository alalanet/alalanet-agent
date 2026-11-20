package safe

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"unicode"
)

// Review of round 6: a bound that scales with the right-to-left letters of the source. For R, a chunk
// fails when its directional marks in place pass 8 + rtl/R; soft hyphens are left at 8.
func TestReviewRTLDensityBound(t *testing.T) {
	dir := os.Getenv("REVIEW_L10N")
	if dir == "" {
		t.Skip("REVIEW_L10N not set")
	}
	noShy := func(s string) string {
		return strings.Map(func(r rune) rune {
			if r == 0x00AD || r == 0x180E {
				return -1
			}
			return r
		}, s)
	}
	for _, loc := range []string{"he", "ar"} {
		files, _ := filepath.Glob(filepath.Join(dir, "macos-"+loc+"-*.txt"))
		var ratios []float64
		type ch struct{ marks, rtl int }
		var chunks []ch
		for _, f := range files {
			b, _ := os.ReadFile(f)
			s := string(b)
			for len(s) > 0 {
				end := min(len(s), 4096)
				if i := strings.LastIndexByte(s[:end], '\n'); i > 0 && end < len(s) {
					end = i + 1
				}
				c := s[:end]
				s = s[end:]
				if strings.ContainsFunc(c, func(r rune) bool { return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) }) || Unseen(c) >= 2 {
					continue // flagged before this branch anyway
				}
				m, rtl := HonestMarks(noShy(c)), 0
				for _, r := range c {
					if unicode.IsLetter(r) && rightToLeft(r) {
						rtl++
					}
				}
				chunks = append(chunks, ch{m, rtl})
				if m > 0 && rtl > 0 {
					ratios = append(ratios, float64(rtl)/float64(m))
				}
			}
		}
		sort.Float64s(ratios)
		pct := func(p float64) float64 {
			if len(ratios) == 0 {
				return 0
			}
			return ratios[int(p*float64(len(ratios)-1))]
		}
		fmt.Printf("%s: %d clean chunks; RTL letters per mark in place: min %.0f, p1 %.0f, p5 %.0f, median %.0f\n", loc, len(chunks), pct(0), pct(0.01), pct(0.05), pct(0.5))
		for _, R := range []int{5, 10, 20, 40, 80, 1 << 30} {
			fail := 0
			for _, c := range chunks {
				if c.marks > MaxHonestMarks+c.rtl/R {
					fail++
				}
			}
			fmt.Printf("   R=%-10d fail %d of %d\n", R, fail, len(chunks))
		}
	}
}
