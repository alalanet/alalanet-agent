package safe

// Review of ADR-0167 round 6 (scan-p2s): how honest localized text fares under MaxHonestMarks.
// Reads the text sources of REVIEW_L10N (one file per source: an app's or a library's strings of
// one locale) and reports, per locale, how many sources hold more than MaxHonestMarks honest marks
// in place (a flag this branch adds), and how many Unseen already counts two or more units in.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestReviewL10nCorpus(t *testing.T) {
	dir := os.Getenv("REVIEW_L10N")
	if dir == "" {
		t.Skip("REVIEW_L10N not set")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.txt"))
	type agg struct{ sources, over, unseen2, chunks, chunksOver, chunksUnseen2, marks, honest, misplaced, newServer, newRepo, cleanServer, cleanRepo int }
	by := map[string]*agg{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		base := filepath.Base(f)
		parts := strings.SplitN(strings.TrimSuffix(base, ".txt"), "-", 3)
		key := parts[0] + "-" + parts[1]
		a := by[key]
		if a == nil {
			a = &agg{}
			by[key] = a
		}
		s := string(b)
		a.sources++
		h, u := HonestMarks(s), Unseen(s)
		for _, r := range s {
			if honestMark(r) {
				a.marks++
			}
		}
		a.honest += h
		a.misplaced += MisplacedMarks(unseenText(s))
		if h > MaxHonestMarks {
			a.over++
		}
		if u >= 2 {
			a.unseen2++
		}
		// chunks of about 4 KiB at line ends: the size of a small MCP server's texts
		for len(s) > 0 {
			end := min(len(s), 4096)
			if i := strings.LastIndexByte(s[:end], '\n'); i > 0 && end < len(s) {
				end = i + 1
			}
			c := s[:end]
			s = s[end:]
			a.chunks++
			if HonestMarks(c) > MaxHonestMarks {
				a.chunksOver++
			}
			uc, hc := Unseen(c), HonestMarks(c)
			if uc >= 2 {
				a.chunksUnseen2++
			}
			over := max(0, hc-MaxHonestMarks)
			bidi := strings.ContainsFunc(c, func(r rune) bool { return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) })
			if !bidi && uc < 2 && uc+over >= 2 { // the prober flags it now, and did not before
				a.newServer++
			}
			if !bidi && uc < 2 {
				a.cleanServer++
			}
			if !bidi && uc < 3 {
				a.cleanRepo++
			}
			if !bidi && uc < 3 && over > 0 { // check_repo_config holds it now, and did not before
				a.newRepo++
			}
		}
	}
	keys := make([]string, 0, len(by))
	for k := range by {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		a := by[k]
		fmt.Printf("%-10s sources %3d honest>8 %3d unseen>=2 %3d | 4KiB chunks %5d honest>8 %4d unseen>=2 %4d | marks %5d in place %5d misplaced %5d | new server flags %4d of %4d clean, new repo holds %4d of %4d clean\n",
			k, a.sources, a.over, a.unseen2, a.chunks, a.chunksOver, a.chunksUnseen2, a.marks, a.honest, a.misplaced, a.newServer, a.cleanServer, a.newRepo, a.cleanRepo)
	}
}
