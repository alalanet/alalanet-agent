package installread

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/alalanet/alalanet-agent/internal/installread/metamorph"
)

// READER-METAMORPHIC-1: a line respelled into words a shell reads back as the same is read as the line. The full
// sweep runs over the corpora with the oracle's verdicts (make metamorph): METAMORPH_CORPUS names the corpus files
// (":" between them), METAMORPH_DIR the oracle's folder. METAMORPH_STAGE=units writes the oracle's scripts there;
// with the oracle's outputs in it, the sweep compares the readers and writes summary.txt and divergences.jsonl.

const metamorphChunks = 64

func metamorphSweep(t *testing.T) (*metamorph.Sweep, string) {
	corpus, dir := os.Getenv("METAMORPH_CORPUS"), os.Getenv("METAMORPH_DIR")
	if corpus == "" || dir == "" {
		t.Skip("METAMORPH_CORPUS and METAMORPH_DIR name the sweep")
	}
	s, err := metamorph.NewSweep(strings.Split(corpus, ":")...)
	if err != nil {
		t.Fatal(err)
	}
	return s, dir
}

func TestMetamorphUnits(t *testing.T) {
	if os.Getenv("METAMORPH_STAGE") != "units" {
		t.Skip("METAMORPH_STAGE=units writes the oracle's scripts")
	}
	s, dir := metamorphSweep(t)
	if err := s.Units.Oracle(dir, metamorphChunks); err != nil {
		t.Fatal(err)
	}
	t.Logf("lines %d, refused %d, rewrites %d, units %d", len(s.Lines), s.Refused, len(s.Items), len(s.Units.Scripts))
}

// readerAnswer: what both readers answer for a line, as the hook and install_check act on it.
type readerAnswer struct {
	Targets  []string `json:"targets"`
	Unread   []string `json:"unread"`
	Extra    []string `json:"extra"`
	Codes    []string `json:"codes"`
	Other    bool     `json:"other"`
	Subst    bool     `json:"subst"`
	OtherPrg string   `json:"other_program"`
}

func readLine(line string) readerAnswer {
	tg, un, other, subst := ParseLine(line)
	ex := HookExtra(line, tg, un, subst)
	a := readerAnswer{Targets: tg, Unread: un, Extra: ex, Other: other, Subst: subst, OtherPrg: OtherProgram(line)}
	for _, u := range un {
		a.Codes = append(a.Codes, UnreadCode(u))
	}
	for _, x := range ex {
		a.Codes = append(a.Codes, ExtraCode(x))
	}
	return a
}

// differs: what of b is not a's, by the names the sweep counts; "" when the same.
func (a readerAnswer) differs(b readerAnswer) string {
	held := func(x readerAnswer) bool { return len(x.Unread)+len(x.Extra) > 0 }
	switch {
	case !slices.Equal(a.Targets, b.Targets):
		if len(b.Targets) == 0 && !held(b) {
			return "targets-lost-silent" // the respelled line installs nothing to the readers and holds nothing
		}
		return "targets"
	case held(a) != held(b):
		if held(a) {
			return "hold-lost"
		}
		return "hold-new"
	case !slices.Equal(a.Codes, b.Codes):
		return "codes"
	case a.Other != b.Other:
		return "other"
	case a.Subst != b.Subst:
		return "subst"
	case a.OtherPrg != b.OtherPrg && (held(a) || len(a.Targets) > 0):
		// OtherProgram is ECO-1's program name for a line install_check could not read and so counts; where the line
		// neither installs nor holds, it is not counted and the exact string is no signal (a prose %s%\\s%s)
		return "other-program"
	case !slices.Equal(a.Unread, b.Unread) || !slices.Equal(a.Extra, b.Extra):
		return "text"
	}
	return ""
}

func TestMetamorphSweep(t *testing.T) {
	if os.Getenv("METAMORPH_STAGE") != "sweep" {
		t.Skip("METAMORPH_STAGE=sweep compares the readers on the oracle's verdicts")
	}
	s, dir := metamorphSweep(t)
	judged, err := s.Judge(dir, metamorphChunks)
	if err != nil {
		t.Fatal(err)
	}
	tag := os.Getenv("METAMORPH_TAG")
	if tag == "" {
		tag = "sweep"
	}
	outDir := filepath.Join(dir, tag)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	div, err := os.Create(filepath.Join(outDir, "divergences.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer div.Close()
	type key struct{ what, kind, role string }
	count := map[key]int{}
	perKind := map[string]*[5]int{} // generated, original dumpable, kept (all three), kept bash+zsh only, unlike the generator
	orig := map[int]readerAnswer{}
	unlike := 0
	for _, j := range judged {
		r := j.Rewrite
		k := perKind[r.Kind]
		if k == nil {
			k = &[5]int{}
			perKind[r.Kind] = k
		}
		k[0]++
		if !j.OrigOK {
			continue
		}
		k[1]++
		if j.Unlike {
			k[4]++
			if unlike++; unlike <= 50 {
				t.Errorf("the shells disagree with the generator (%s, %s, expected %s; same %v, bash+zsh %v): %q", r.Kind, r.Role, r.Shells, j.Same, j.BashZsh, r.Line)
			}
		}
		class := ""
		switch {
		case j.Same:
			k[2]++
		case j.BashZsh:
			k[3]++
			class = "bash,zsh:"
		default:
			continue
		}
		a, ok := orig[j.Line]
		if !ok {
			a = readLine(s.Lines[j.Line])
			orig[j.Line] = a
		}
		b := readLine(r.Line)
		what := a.differs(b)
		if what == "" {
			continue
		}
		count[key{class + what, r.Kind, r.Role}]++
		rec, _ := json.Marshal(map[string]any{"what": class + what, "kind": r.Kind, "role": r.Role, "line": s.Lines[j.Line], "rewrite": r.Line, "orig": a, "new": b})
		fmt.Fprintln(div, string(rec))
	}
	var sum strings.Builder
	fmt.Fprintf(&sum, "corpus %s\nlines %d, refused by the lexer %d, rewrites %d, units %d\n\n", os.Getenv("METAMORPH_CORPUS"), len(s.Lines), s.Refused, len(s.Items), len(s.Units.Scripts))
	fmt.Fprintf(&sum, "%-12s %9s %9s %9s %9s %7s\n", "kind", "generated", "orig-ok", "kept", "bash+zsh", "unlike")
	tot := [5]int{}
	for _, kind := range metamorph.Kinds {
		k := perKind[kind]
		if k == nil {
			continue
		}
		fmt.Fprintf(&sum, "%-12s %9d %9d %9d %9d %7d\n", kind, k[0], k[1], k[2], k[3], k[4])
		for i := range tot {
			tot[i] += k[i]
		}
	}
	fmt.Fprintf(&sum, "%-12s %9d %9d %9d %9d %7d\n\n", "total", tot[0], tot[1], tot[2], tot[3], tot[4])
	keys := make([]key, 0, len(count))
	byWhat := map[string]int{}
	n := 0
	for k, c := range count {
		keys = append(keys, k)
		byWhat[k.what] += c
		n += c
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].what != keys[j].what {
			return keys[i].what < keys[j].what
		}
		if count[keys[i]] != count[keys[j]] {
			return count[keys[i]] > count[keys[j]]
		}
		return keys[i].kind+keys[i].role < keys[j].kind+keys[j].role
	})
	fmt.Fprintf(&sum, "divergences %d\n", n)
	whats := make([]string, 0, len(byWhat))
	for w := range byWhat {
		whats = append(whats, w)
	}
	sort.Strings(whats)
	for _, w := range whats {
		fmt.Fprintf(&sum, "  %-28s %8d\n", w, byWhat[w])
	}
	sum.WriteString("\nby what, kind, role\n")
	for _, k := range keys {
		fmt.Fprintf(&sum, "  %-28s %-12s %-14s %8d\n", k.what, k.kind, k.role, count[k])
	}
	if err := os.WriteFile(filepath.Join(outDir, "summary.txt"), []byte(sum.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("%s", sum.String())
	if want := os.Getenv("METAMORPH_WANT_ZERO"); want != "" && n > 0 {
		t.Errorf("%d divergences", n)
	}
}
