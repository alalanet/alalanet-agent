package tooldigest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/alalanet/alalanet-agent/internal/safe"
)

// ToolSig is what we keep per MCP tool: its name, a digest of its full definition (description and
// input schema) and the start of its description for readable diffs.
type ToolSig struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
	Desc   string `json:"desc,omitempty"`
	// Hints: the behaviour the server declares (MCP annotations): ro (readOnlyHint), destructive,
	// idempotent, open_world. A tool that stops being read-only or becomes destructive gains authority
	// without changing its name.
	Hints string `json:"hints,omitempty"`
	V     int    `json:"v,omitempty"` // 2: digest also covers annotations and outputSchema; 3: and the titles
}

// SigVersion is the current ToolSig format. Snapshots in an older format are re-recorded silently
// on the next probe instead of being reported as a tool change.
const SigVersion = 3

const (
	// MaxTools: the tools of a list that are digested; a longer list is not the whole list (FN-2).
	MaxTools    = 300
	descPreview = 300
)

// ParseTools digests a tools/list result: a stable hash of the whole set, per-tool signatures
// (sorted by name) and flags for suspicious descriptions. The result is read as the MCP clients read it
// (ReadList, ReadTool: members by their exact names, the last of a repeated name whole), so the digest
// is that of the tools a client receives (FN-10).
func ParseTools(result json.RawMessage) (hash string, sigs []ToolSig, flags []string, ok bool) {
	return ParseToolsWith(result, nil)
}

// ParseToolsWith is ParseTools for a server whose instructions st has judged (nil: none).
func ParseToolsWith(result json.RawMessage, st *ServerText) (hash string, sigs []ToolSig, flags []string, ok bool) {
	tools, _, _, err := ReadList(result)
	if err != nil {
		return "", nil, nil, false
	}
	hash, sigs, flags, _, ok = DigestTools(tools, st)
	return hash, sigs, flags, ok
}

// DigestTools digests the tools of a tools/list result (ParseTools) for a server whose other texts st has judged (nil:
// none), and reports whether one of them reads differently to different clients (ReadTool). Every tool is read and
// the first MaxTools are digested: a tool that is not of its type fails the whole list, as encoding/json failed it.
func DigestTools(tools []json.RawMessage, st *ServerText) (hash string, sigs []ToolSig, flags []string, ambiguous, ok bool) {
	defs := make([]ToolDef, 0, min(len(tools), MaxTools))
	for i, raw := range tools {
		t, amb, err := ReadTool(raw)
		if err != nil {
			return "", nil, nil, false, false
		}
		ambiguous = ambiguous || amb
		if i < MaxTools {
			defs = append(defs, t)
		}
	}
	hash, sigs, flags = DigestDefs(defs, st)
	return hash, sigs, flags, ambiguous, true
}

// DigestDefs digests tools read from a tools/list result: the hash of the set, per-tool signatures
// (sorted by name) and the description flags.
func DigestDefs(defs []ToolDef, st *ServerText) (hash string, sigs []ToolSig, flags []string) {
	if st == nil {
		st = &ServerText{}
	}
	seen, units, reorders := map[string]bool{}, 0, false
	for _, t := range defs {
		schema := Canonical(t.InputSchema)
		var hints []string
		for _, h := range []struct {
			name string
			v    *bool
		}{{"ro", t.ReadOnly}, {"destructive", t.Destructive}, {"idempotent", t.Idempotent}, {"open_world", t.OpenWorld}} {
			if h.v != nil && *h.v {
				hints = append(hints, h.name)
			}
		}
		hint := strings.Join(hints, ",")
		sum := sha256.Sum256([]byte(t.Name + "\x00" + t.Title + "\x01" + t.AnnotationsTitle + "\x00" + t.Description + "\x00" + schema + "\x00" + Canonical(t.OutputSchema) + "\x00" + hint))
		sigs = append(sigs, ToolSig{Name: trunc(t.Name, 128), Digest: hex.EncodeToString(sum[:16]), Desc: Preview(t.Description), Hints: hint, V: SigVersion})
		// The name too (round 7, PRE-2): clients that do not enforce the name's pattern pass it on.
		text := t.Name + "\n" + t.Title + "\n" + t.AnnotationsTitle + "\n" + t.Description + "\n" + DecodedJSON(t.InputSchema) + "\n" + DecodedJSON(t.OutputSchema)
		for _, f := range ScanPatterns(text) {
			seen[f] = true
		}
		u, _, b := st.Judge(text)
		units, reorders = units+u, reorders || b
		// Every string of a repeated member, one of which some client receives (FN10-TOOLDESC-NULL), each
		// judged alone (ScanText): not digested, not counted with the server's texts.
		for _, o := range t.Others {
			for _, f := range ScanText(o) {
				seen[f] = true
			}
		}
	}
	switch {
	case reorders || units > 0 && st.units >= MinHiddenUnits && st.units > st.marks:
		seen["hidden_unicode"] = true
	case units > 0 && st.units >= MinHiddenUnits:
		seen[InvisibleMarks] = true
	}
	sort.Slice(sigs, func(i, j int) bool { return sigs[i].Name < sigs[j].Name })
	h := sha256.New()
	for _, s := range sigs {
		h.Write([]byte(s.Name + ":" + s.Digest + "\n"))
	}
	for f := range seen {
		flags = append(flags, f)
	}
	sort.Strings(flags)
	return hex.EncodeToString(h.Sum(nil)), sigs, flags
}

// canonical re-encodes JSON with sorted object keys, so key order does not count as a change.
func Canonical(raw json.RawMessage) string {
	var v any
	if len(raw) == 0 || json.Unmarshal(raw, &v) != nil {
		return string(raw)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// DecodedJSON is a schema as the scanner reads it: canonical's re-encoding with its strings
// unescaped, through a decoder that keeps numbers as written (UseNumber), so that a number beyond
// float64 (1e999) no longer leaves the whole schema raw, its \u escapes ASCII (round 3, PE-5). The
// digest keeps canonical: no tool shows as changed.
func DecodedJSON(raw json.RawMessage) string {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if len(raw) == 0 || dec.Decode(&v) != nil {
		return string(raw)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return string(raw)
	}
	return string(b)
}

func Preview(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= descPreview {
		return s
	}
	cut := descPreview
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// Patterns of tool poisoning: instructions to the model hidden in tool descriptions or schemas.
var suspicious = []struct {
	flag string
	re   *regexp.Regexp
}{
	{"injection_phrase", regexp.MustCompile(`(?i)ignore (all |any )?(the )?(previous|prior|above|earlier) (instructions|prompts?|rules)`)},
	{"hidden_directive_tag", regexp.MustCompile(`(?i)<\s*(important|system|secret|hidden)\s*>|\[\s*system\s*\]`)},
	{"conceal_from_user", regexp.MustCompile(`(?i)(do not|don't|never) (tell|inform|mention|reveal|show)( this)? (to )?(the )?user|without (telling|informing|asking) the user`)},
	{"secret_access", regexp.MustCompile(`(?i)(~/\.ssh|id_rsa|id_ed25519|\.aws/credentials|seed phrase|mnemonic phrase|private key file|wallet\.dat)`)},
	{"cross_tool_instruction", regexp.MustCompile(`(?i)(before|instead of) (using|calling) (any|this|the|another|other) (other )?tools?,? (you must|always|first)`)},
}

// ScanText is ScanPatterns for one text alone, with hidden_unicode for what no one sees in it: a
// directional override, embedding or isolate out of a balanced pair, or two hidden units
// (ServerText); InvisibleMarks when the units are all honest marks past the bound.
func ScanText(s string) []string {
	out := ScanPatterns(s)
	var st ServerText
	if f := HiddenFlag(st.Judge(s)); f != "" {
		out = append(out, f)
	}
	return out
}

// HiddenFlag is the flag for one text's units (ServerText.judge): hidden_unicode for two units of
// which one at least is no honest mark, or a reordering control; InvisibleMarks for two units all of
// honest marks past the bound; none for less.
func HiddenFlag(units, marks int, reorders bool) string {
	switch {
	case reorders || units >= MinHiddenUnits && units > marks:
		return "hidden_unicode"
	case units >= MinHiddenUnits:
		return InvisibleMarks
	}
	return ""
}

// InvisibleMarks is the weak flag for a server whose only hidden units are honest marks in place past
// its bound (safe.Selectors.Judge; ADR-0167 round 7, R6-FP-2): soft hyphens and directional marks
// that honest German, Dutch or right-to-left text carries in number (a sentence copied from a
// hyphenating web page holds sixteen). It asks for a review and costs nothing, as the other weak
// flags (tool_descriptions_need_review); app.Advice gives it no caution.
const InvisibleMarks = "invisible_marks"

// ServerText judges the texts of one MCP server together: its instructions, then its tools of one
// read. A hidden unit is a stray variation selector (the server's ideographic bound, round 2 P3-1),
// another character no one sees beyond honest text (safe.Unseen: round 3, PE-6) or an honest mark in
// place past the server's bound (safe.Selectors.Judge: rounds 6 and 7, SCAN-INVIS-1). hidden_unicode
// takes two units (MinHiddenUnits): in the instructions alone, or in the server's texts with one in
// its tools at least (round 3, R2-P3-2: the instructions' units were counted apart); or a directional
// override, embedding or isolate out of a balanced pair (safe.Reorders), which changes what a person
// sees of the text around it. When all of a server's units are honest marks past its bound the flag
// is the weak InvisibleMarks instead (round 7, R6-FP-2).
type ServerText struct {
	sel   safe.Selectors
	units int // the hidden units of the server's texts so far
	marks int // those of them that are honest marks past the server's bound
	later int // the code points of the server's texts Unseen takes for emoji (safe.LaterEmoji)
}

// Judge adds text to the server's: its hidden units, those of them that are honest marks past the
// bound, and whether it holds a control that reorders (safe.Reorders).
func (st *ServerText) Judge(text string) (units, marks int, reorders bool) {
	n, _ := st.sel.Stray(text)
	over := max(0, st.later-safe.MaxLaterEmoji) // the later emoji past the server's bound so far
	st.later += safe.LaterEmoji(text)
	unseen, marks := st.sel.Judge(text)
	units = n + unseen + marks + max(0, st.later-safe.MaxLaterEmoji) - over
	st.units += units
	st.marks += marks
	return units, marks, safe.Reorders(text)
}

// MinHiddenUnits is how many hidden units make hidden_unicode in an MCP server's text (A1-VS-1 round
// 2, P2-1; round 3 for every invisible character): one spells a byte at most, and honest text leaves
// one behind (an emoji deleted and its VS16 kept, "Open Collective" + U+FE0F in ajv's README; a VS16
// doubled by two converters, U+1F6E0 U+FE0F U+FE0F in ts-api-utils' README; a zero-width space pasted
// from a web page), while hidden_unicode costs the server 20 points and a public "strong signs of
// hidden instructions". A repository's instruction files hold on one stray selector (repoconfig.go):
// a hold asks to read a named line, it scores and publishes nothing.
const MinHiddenUnits = 2

// ScanPatterns lists the patterns of suspicious that s matches.
func ScanPatterns(s string) []string {
	var out []string
	for _, p := range suspicious {
		if p.re.MatchString(s) {
			out = append(out, p.flag)
		}
	}
	return out
}

// DiffTools summarises what changed between two signature sets. Digests of different signature
// versions cannot be compared, so across versions a tool counts as changed when its description
// preview or (when both carry them, since v2) its hints differ.
func DiffTools(prev, cur []ToolSig) (added, removed, changed []string) {
	p := map[string]ToolSig{}
	for _, s := range prev {
		p[s.Name] = s
	}
	c := map[string]bool{}
	for _, s := range cur {
		c[s.Name] = true
		o, ok := p[s.Name]
		switch {
		case !ok:
			added = append(added, s.Name)
		case o.V == s.V && o.Digest != s.Digest:
			changed = append(changed, s.Name)
		case o.V != s.V && (o.Desc != s.Desc || (min(o.V, s.V) >= 2 && o.Hints != s.Hints)):
			changed = append(changed, s.Name)
		}
	}
	for _, s := range prev {
		if !c[s.Name] {
			removed = append(removed, s.Name)
		}
	}
	return
}

// Escalations lists tools that kept their name but gained authority: no longer read-only, newly
// destructive, or newly reaching the open world. Only compares tools both snapshots carry hints for.
func Escalations(prev, cur []ToolSig) []string {
	p := map[string]ToolSig{}
	for _, s := range prev {
		p[s.Name] = s
	}
	has := func(h, x string) bool {
		for _, v := range strings.Split(h, ",") {
			if v == x {
				return true
			}
		}
		return false
	}
	var out []string
	for _, c := range cur {
		o, ok := p[c.Name]
		if !ok || o.V < SigVersion {
			continue
		}
		var what []string
		if has(o.Hints, "ro") && !has(c.Hints, "ro") {
			what = append(what, "no longer read-only")
		}
		if !has(o.Hints, "destructive") && has(c.Hints, "destructive") {
			what = append(what, "now destructive")
		}
		if !has(o.Hints, "open_world") && has(c.Hints, "open_world") {
			what = append(what, "now open-world")
		}
		if len(what) > 0 {
			out = append(out, c.Name+" ("+strings.Join(what, ", ")+")")
		}
	}
	return out
}

// InstructionFlags are the flags of an MCP server's instructions (the initialize result's), judged with the tools of the
// same read that st judges next: every pattern but cross_tool_instruction (instructions are meant to tell the model what
// to call first), and hidden_unicode or invisible_marks for the units hidden in them (prober.SetInstructions).
func InstructionFlags(text string, st *ServerText) []string {
	if st == nil {
		st = &ServerText{}
	}
	var flags []string
	for _, f := range ScanPatterns(text) {
		if f != "cross_tool_instruction" {
			flags = append(flags, f)
		}
	}
	if f := HiddenFlag(st.Judge(text)); f != "" {
		flags = append(flags, f)
	}
	return flags
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
