package installread

import (
	"bufio"
	"encoding/json"
	"os"
	"slices"
	"testing"
)

// READER-METAMORPHIC-1, in the normal test run: a bounded sample of respellings with the oracle's verdicts stored in
// testdata (no environment, no container). testdata/metamorph/sample.jsonl: 2,911 rewrites of the review generator
// (backslashes, quotes, $'…', line continuations, empty-by-default expansions, the same inside sh -c, bash -c and eval
// scripts, assignment values, and their combinations), each one whose words bash and zsh — and dash, where it reads
// the spelling — printed exactly as its seed's (shells names them). testdata/metamorph/windows-pwsh.jsonl: Windows
// lines with the words PowerShell's own parser (pwsh 7.4.7, Parser.ParseInput, nothing run) gives each command.
// The rows are the review generator's (READER-ESCAPE-1 round 2, ten per kind, sixty of the combinations) with the
// verdicts of its oracle run (bash 5.2.15, dash 0.5.12, zsh 5.9). The last 336 are bash's $"…" (round 3, N1: $"npm",
// $""npm, n$"pm", $"np"m in a word of each seed): bash prints the seed's words, dash and zsh a literal $ (shells "bash").
// make metamorph runs the full sweep of this package's own generator with the oracle (internal/installread/metamorph/oracle).

type sampleRow struct {
	Seed, Line, Kind, Shells string
}

func readJSONL[T any](t *testing.T, path string) []T {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []T
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<16), 1<<20)
	for sc.Scan() {
		var x T
		if err := json.Unmarshal(sc.Bytes(), &x); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		out = append(out, x)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// weaker: what b (the respelling) lost of a (its seed): a target, or a hold where b neither holds nor installs.
func weaker(a, b readerAnswer) string {
	held := func(x readerAnswer) bool { return len(x.Unread)+len(x.Extra) > 0 }
	for _, tg := range a.Targets {
		if !slices.Contains(b.Targets, tg) {
			return "target " + tg + " lost"
		}
	}
	if held(a) && !held(b) {
		return "hold lost"
	}
	return ""
}

// A respelling the shells read as its seed is never read less strictly than the seed; the stricter ones are counted.
func TestMetamorphSample(t *testing.T) {
	rows := readJSONL[sampleRow](t, "testdata/metamorph/sample.jsonl")
	if len(rows) < 2500 {
		t.Fatalf("the sample has %d rows", len(rows))
	}
	seeds := map[string]readerAnswer{}
	same, stricter := 0, map[string]int{}
	for _, r := range rows {
		a, ok := seeds[r.Seed]
		if !ok {
			a = readLine(r.Seed)
			seeds[r.Seed] = a
		}
		b := readLine(r.Line)
		if w := weaker(a, b); w != "" {
			t.Errorf("%s (%s): %q reads weaker than its seed %q: %s\n  seed %+v\n  this %+v", r.Kind, r.Shells, r.Line, r.Seed, w, a, b)
			continue
		}
		if d := a.differs(b); d == "" {
			same++
		} else {
			stricter[d]++
		}
	}
	t.Logf("%d rewrites of %d seeds: %d read as the seed, none weaker; stricter %v", len(rows), len(seeds), same, stricter)
}

// The reader's Windows reading of a line is PowerShell's: each command's words, spelled the Windows way where a word
// has a second spelling, are the elements PowerShell's parser gives (an & call operator is a word of its own here).
func TestMetamorphWindowsPowerShell(t *testing.T) {
	type psRow struct {
		Line string
		Pwsh [][]string
	}
	rows := readJSONL[psRow](t, "testdata/metamorph/windows-pwsh.jsonl")
	if len(rows) < 50 {
		t.Fatalf("%d rows", len(rows))
	}
	for _, r := range rows {
		var ours [][]string
		for _, sg := range splitShell(r.Line).segs {
			w := sg.winWords()
			if w == nil {
				w = sg.words
			}
			if len(w) == 1 && w[0] == "&" {
				continue
			}
			ours = append(ours, w)
		}
		if !slices.EqualFunc(ours, r.Pwsh, slices.Equal[[]string]) {
			t.Errorf("%q: the reader's Windows reading %q, PowerShell's %q", r.Line, ours, r.Pwsh)
		}
	}
}
