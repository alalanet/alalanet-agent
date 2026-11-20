package tooldigest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The fixtures and golden answers that internal/prober's TestDigestGolden wrote at develop b2d61e9, before the digest
// code moved here (VERIFY-AUTO-1).
type fixture struct {
	Name         string `json:"name"`
	Instructions string `json:"instructions,omitempty"`
	Result       string `json:"result"`
}

type golden struct {
	Name       string    `json:"name"`
	OK         bool      `json:"ok"`
	Hash       string    `json:"hash"`
	Sigs       []ToolSig `json:"sigs"`
	Flags      []string  `json:"flags"`
	Ambiguous  bool      `json:"ambiguous"`
	InstrFlags string    `json:"instructions_flags"`
	InstrHash  string    `json:"instructions_hash"`
	Folded     string    `json:"folded_hash"` // the prober's own (foldedHash); not read here
}

func loadGolden(t *testing.T) ([]fixture, []golden) {
	t.Helper()
	var fx []fixture
	var gold []golden
	for name, v := range map[string]any{"digest_fixtures.json": &fx, "digest_golden.json": &gold} {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, v); err != nil {
			t.Fatal(err)
		}
	}
	if len(fx) != len(gold) || len(fx) < 50 {
		t.Fatalf("%d fixtures, %d golden answers", len(fx), len(gold))
	}
	return fx, gold
}

// TestToolDigestSameAsProber: every set hash, signature (name, digest, description preview, hints, version), flag,
// ambiguity and instruction flag is the one the prober gave before the move, so no stored digest changes and FN-2's
// ChangeHolds sees no change on any listing.
func TestToolDigestSameAsProber(t *testing.T) {
	fx, gold := loadGolden(t)
	for i, f := range fx {
		want := gold[i]
		got := golden{Name: f.Name, Folded: want.Folded}
		var st *ServerText
		if f.Instructions != "" {
			st = &ServerText{}
			got.InstrFlags = strings.Join(InstructionFlags(f.Instructions, st), ",")
			sum := sha256.Sum256([]byte(f.Instructions))
			got.InstrHash = hex.EncodeToString(sum[:])
		}
		got.Hash, got.Sigs, got.Flags, got.OK = ParseToolsWith(json.RawMessage(f.Result), st)
		if tools, _, _, err := ReadList([]byte(f.Result)); err == nil {
			_, _, _, got.Ambiguous, _ = DigestTools(tools, nil)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: digest changed\n got %+v\nwant %+v", f.Name, got, want)
		}
		if f.Instructions == "" {
			h, s, fl, ok := ParseTools(json.RawMessage(f.Result))
			if h != want.Hash || !reflect.DeepEqual(s, want.Sigs) || !reflect.DeepEqual(fl, want.Flags) || ok != want.OK {
				t.Errorf("%s: ParseTools differs from the golden answer", f.Name)
			}
		}
	}
}
