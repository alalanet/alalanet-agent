package repopolicy

// Independent review of 2950215 (REPO-POL-1), 2026-11-15: proof tests. Each test states what it shows; a test that
// fails on 2950215 is a finding, a test that passes pins a property the review checked.

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
)

// R1: a YAML merge key with an inline mapping (no anchor, no alias) passes plainNodes, so a key can be given twice
// after all — the reader of the file sees "packages: deny", the parser may read something else.
func TestReviewMergeKeyWithoutAlias(t *testing.T) {
	for name, body := range map[string]string{
		"merge mapping":  "version: 1\non_hold:\n  packages: deny\n  <<: {packages: ask}\n",
		"merge sequence": "version: 1\non_hold:\n  <<: [{packages: ask}]\n  packages: deny\n",
		"merge at top":   "version: 1\n<<: {version: 2}\n",
	} {
		p, err := Parse([]byte(body))
		if err == nil {
			t.Errorf("%s: parsed (on_hold.packages=%q, version=%d): a merge key is a second spelling of a key", name, p.OnHold.Packages, p.Version)
		}
	}
}

// R2: the duplicate-key error quotes the key unredacted — a plan token used as a key reaches the error text, which
// check_repo_config shows as the unparsable finding's detail.
func TestReviewDuplicateKeyErrorHidesToken(t *testing.T) {
	tok := "aln_" + strings.Repeat("abcdefghijklmnopqrstuvwxyz234567", 1) + "abcdefghijklmnopqrst"
	_, err := Parse([]byte("version: 1\n" + tok + ": 1\n" + tok + ": 2\n"))
	if err == nil {
		t.Fatal("parsed")
	}
	if strings.Contains(err.Error(), tok[:24]) {
		t.Errorf("the token is in the error: %q", err.Error())
	}
}

// R3: a Layer whose Source is left at its zero value has its exceptions applied as if it were the organisation's.
// The safe default is the untrusted one: only Managed and User (or an explicit trust) apply exceptions.
func TestReviewZeroSourceIsNotTrusted(t *testing.T) {
	p, err := Parse([]byte("version: 1\nexceptions:\n  - {package: npm:evil, reason: ours, expires: 2027-06-01}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := Decide([]Layer{{Policy: p}}, "hold", Hold{Kind: Package, Targets: []string{"npm:evil@1"}, Reasons: []string{"new_package"}}, now); got == Allow {
		t.Errorf("a layer of no source applies its exceptions: %s", got)
	}
}

// R4: whether a hold has reasons beyond its targets was the caller's flag, and its zero value said "none": an adapter
// that forgot it let an organisation's exception cover a hold that is about the registry a hostile repository's .npmrc
// points at (no trust in the repository needed). Since the F-round (ADR-0174 round 2) a hold carries its reason codes
// (Hold.Reasons), and only the codes an exception may cover are covered: no reasons is not covered.
func TestReviewUnreadZeroValueCovers(t *testing.T) {
	org, err := Parse([]byte("version: 1\nexceptions:\n  - {package: npm:@acme/cli, reason: ours, expires: 2027-06-01}\n"))
	if err != nil {
		t.Fatal(err)
	}
	// The server held @acme/cli because the repository's .npmrc moved the registry; the adapter passed only targets.
	got := Decide([]Layer{{Source: Managed, Policy: org}}, "hold", Hold{Kind: Package, Targets: []string{"npm:@acme/cli@1.0.0"}}, now)
	if got != Ask {
		t.Fatalf("a hold of no known reasons is covered: %s", got)
	}
	// The registry moved: a code no exception covers, beside one it does.
	got = Decide([]Layer{{Source: Managed, Policy: org}}, "hold", Hold{Kind: Package, Targets: []string{"npm:@acme/cli@1.0.0"},
		Reasons: []string{"new_package", "unread:registry_override"}}, now)
	if got != Ask {
		t.Fatalf("a moved registry is covered: %s", got)
	}
	if got := Decide([]Layer{{Source: Managed, Policy: org}}, "hold", Hold{Kind: Package, Targets: []string{"npm:@acme/cli@1.0.0"},
		Reasons: []string{"new_package"}}, now); got != Allow {
		t.Fatalf("a new package of ours: %s", got)
	}
}

// R5: reason text: what the reader accepts as visible. U+2028/U+2029 (line and paragraph separators), U+3164 (Hangul
// filler), U+115F, a variation selector and a combining mark pass reasonOK.
func TestReviewReasonInvisibles(t *testing.T) {
	for name, r := range map[string]string{
		"line separator":       "ours\u2028approved by security",
		"paragraph separator":  "ours\u2029x",
		"hangul filler":        "ours\u3164",
		"hangul choseong fill": "ours\u115f",
		"variation selector":   "ours\ufe0f",
		"combining only":       "\u0301\u0301\u0301",
	} {
		if err := reasonOK(r); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// R6: names. Checks that what the review expected to fail closed does: no lookalike, case or source trick covers
// a target an exception does not name.
func TestReviewNamesFailClosed(t *testing.T) {
	p, err := Parse([]byte(`version: 1
exceptions:
  - {package: "npm:@acme/cli", reason: ours, expires: 2027-06-01}
  - {package: "npm:acme", reason: ours, expires: 2027-06-01}
  - {package: "pypi:acme-tools", reason: ours, expires: 2027-06-01}
  - {mcp_server: "https://mcp.acme.dev/mcp", reason: ours, expires: 2027-06-01}
`))
	if err != nil {
		t.Fatal(err)
	}
	l := []Layer{{Source: Managed, Policy: p}}
	for _, tg := range []string{
		"npm:@acme/cli@npm:evil@1", "npm:@acme/cli@github:evil/cli", "npm:@acme/cli@evil/cli", "npm:@acme/cli@file:../x",
		"npm:@acme/cli@https://evil.example/x.tgz", "npm:acme@git+ssh://git@evil/x", "npm:acme@1 || 2", "npm:\u0430cme@1",
		"npm:ACME@1", "npm:acme @1", "npm:@acme/cli/../evil@1", "npm:acme@1.0.0@evil", "npm:acme@1\x00",
		"pypi:acme-tools @ https://evil.example/a.whl", "pypi:acme-tools@https://evil", "pypi:acme_tools==1; --index-url=https://evil",
		"pypi:acme-tools==1 --extra-index-url https://evil", "pypi:\u0430cme-tools", "pypi:./acme-tools", "pypi:acme-tools.tar.gz",
		"pypi:acme-tools@https://evil.example/a.whl", "pypi:acme-tools@1.0 --find-links x", "pypi:acme-tools@", "pypi:acme-tools@v1",
	} {
		if got := Decide(l, "hold", Hold{Kind: Package, Targets: []string{tg}, Reasons: []string{"new_package"}}, now); got == Allow {
			t.Errorf("package %q is covered", tg)
		}
	}
	for _, tg := range []string{
		"https://mcp.acme.dev@evil.example/mcp", "https://mcp.acme.dev.evil.example/mcp", "https://mcp.acme.dev:8443/mcp",
		"https://mcp.acme.dev/mcp/../evil", "https://mcp.acme.dev/MCP", "https://mcp.acme.dev./mcp", "http://mcp.acme.dev/mcp",
		"https://xn--mcp-acme.dev/mcp", "https://mcp.\u0430cme.dev/mcp", "remote-mcp:https://mcp.acme.dev/other", "remote-mcp:http://mcp.acme.dev/mcp",
		"https://mcp.acme.dev/mcp%2f..%2fevil", "//mcp.acme.dev/mcp", "https:mcp.acme.dev/mcp",
	} {
		if got := Decide(l, "hold", Hold{Kind: MCPServer, Targets: []string{tg}, Reasons: []string{"unverified_yet"}}, now); got == Allow {
			t.Errorf("server %q is covered", tg)
		}
	}
	// What must still be covered (equivalent spellings).
	// Round 2 (F7): install_check's own forms, which the hook's answer names, are covered — pypi:name@version and a
	// remote server as remote-mcp:<URL>.
	if got := Decide(l, "hold", Hold{Kind: MCPServer, Targets: []string{"remote-mcp:https://mcp.acme.dev/mcp"}, Reasons: []string{"unverified_yet"}}, now); got != Allow {
		t.Errorf("remote-mcp: form not covered: %s", got)
	}
	for _, tg := range []string{"npm:acme@1.2.3", "npm:acme@^1", "npm:acme@latest", "pypi:Acme.Tools[x]>=1", "pypi:acme__tools==1", "pypi:acme-tools@1.0", "pypi:acme-tools@2.0.1rc1+local"} {
		if got := Decide(l, "hold", Hold{Kind: Package, Targets: []string{tg}, Reasons: []string{"new_package"}}, now); got != Allow {
			t.Errorf("package %q not covered: %s", tg, got)
		}
	}
}

// R7: expiry is the end of the named day in UTC; since round 2 (F7) one more than a year ahead is not in force; the order
// of layers never changes the answer.
func TestReviewExpiryAndOrder(t *testing.T) {
	p, err := Parse([]byte("version: 1\nexceptions:\n  - {package: npm:a, reason: r, expires: 2026-11-15}\n  - {package: npm:b, reason: r, expires: 2027-06-01}\n  - {package: npm:c, reason: r, expires: 9999-12-31}\n"))
	if err != nil {
		t.Fatal(err)
	}
	end := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	if len(p.Live(end.Add(-time.Nanosecond))) != 2 || len(p.Live(end)) != 1 {
		t.Error("the expiry day's end in UTC")
	}
	// UTC+14: the local 2026-11-16 10:00 is still 11-15 in UTC... and in the other direction, Kiribati's 11-16 00:00
	// is 11-15 10:00 UTC: the exception lasts 14 hours past the local day there, 12 hours short of it at UTC-12.
	kiritimati := time.FixedZone("UTC+14", 14*3600)
	if len(p.Live(time.Date(2026, 11, 16, 13, 0, 0, 0, kiritimati))) != 2 {
		t.Error("an instant in another zone is compared as an instant")
	}
	for _, e := range p.Live(now) {
		if e.Expires.Sub(now) > MaxAhead {
			t.Errorf("an expiry past the cap is in force: %s", e.Expires.Format(time.DateOnly))
		}
	}
	if far := p.TooFar(now); len(far) != 1 || far[0].Package != "npm:c" {
		t.Errorf("too far: %+v", far)
	}
	// The cap moves with now: a year before 9999-12-31 the exception is in force.
	if len(p.Live(time.Date(9999, 6, 1, 0, 0, 0, 0, time.UTC))) != 1 {
		t.Error("the cap is a span from now, not a fixed date")
	}
	// Order: every permutation of three layers gives one answer.
	deny := mustParse(t, "version: 1\non_hold:\n  packages: deny\n")
	ask := mustParse(t, "version: 1\non_hold:\n  packages: ask\n")
	exc := mustParse(t, "version: 1\nexceptions:\n  - {package: npm:a, reason: r, expires: 2027-06-01}\n")
	sets := [][]Layer{
		{{Source: Managed, Policy: exc}, {Source: User, Policy: ask}, {Source: Repo, Policy: deny}},
		{{Source: Managed, Policy: exc}, {Source: User, Policy: exc}, {Source: Repo, Policy: exc, TrustExceptions: true}},
		{{Source: Managed, Policy: exc}, {Source: User, Policy: ask}, {Source: Repo, Policy: exc}},
	}
	h := Hold{Kind: Package, Targets: []string{"npm:a@1"}, Reasons: []string{"new_package"}}
	for i, s := range sets {
		want := Decide(s, "hold", h, now)
		perms := [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
		for _, pm := range perms {
			if got := Decide([]Layer{s[pm[0]], s[pm[1]], s[pm[2]]}, "hold", h, now); got != want {
				t.Errorf("set %d order %v: %s, want %s", i, pm, got, want)
			}
		}
	}
}

// R8: hostile shapes stay cheap: deep nesting, many keys, a wide flow mapping — each under MaxBytes, each refused or
// read in well under a second.
//
// Linear growth is judged by work counted, not by the clock (flakes-4): the allocations of a parse and their bytes,
// which are the same on every run whatever the machine's load, and the parse's own thread CPU time (flakes-5) as a
// guard against a blow-up (linearWork; TestReview1116PlainNodesKeysLinearByThreadCPU holds the key check alone to it). Wall-clock ratios flaked three times under make ci
// (ci-flakes-3 loosened one; develop 8c0c02ae under load 19-26: "many keys" 3.15 s for the whole, 86 ms for an
// eighth): an allocation-heavy parse slows down far more than 8 times when the machine is busy. Times are logged.
// A shape built from n repeated parts may take at most 12 times the allocations and bytes of an eighth of it, plus
// a little: a linear parse takes about 8 times, a quadratic one 64 (a set copied for every key, a list re-sliced
// for every item). Every shape but the BOM is built so.
func TestReviewHostileShapesBounded(t *testing.T) {
	// fastest is the quickest of three parses: one sample on a loaded machine measures the load.
	fastest := func(body string) (time.Duration, error) {
		var err error
		best := time.Duration(1<<63 - 1)
		for i := 0; i < 3; i++ {
			start := time.Now()
			_, err = Parse([]byte(body))
			best = min(best, time.Since(start))
		}
		return best, err
	}
	scaled := map[string]func(n int) string{
		"deep flow seq":   func(n int) string { return "version: 1\nx: " + strings.Repeat("[", n) },
		"deep flow map":   func(n int) string { return "version: 1\nx: " + strings.Repeat("{a: ", n) },
		"deep block":      func(n int) string { return "version: 1\n" + deepBlock(n) },
		"many keys":       func(n int) string { return "version: 1\non_hold:\n" + manyKeys(n) },
		"many list items": func(n int) string { return "version: 1\nexceptions:\n" + strings.Repeat("- 1\n", n) },
		"long scalar": func(n int) string {
			return "version: 1\nexceptions:\n  - {package: npm:a, reason: \"" + strings.Repeat("a", n) + "\", expires: 2027-06-01}\n"
		},
	}
	sizes := map[string]int{"deep flow seq": MaxBytes - 20, "deep flow map": (MaxBytes - 20) / 4, "deep block": 3000,
		"many keys": 6000, "many list items": (MaxBytes - 30) / 4, "long scalar": MaxBytes - 100}
	for name, n := range sizes {
		wholeBody, eighthBody := build_(scaled[name], n), build_(scaled[name], n/8)
		whole, eighth := parseWork(wholeBody), parseWork(eighthBody)
		parseCPU(&whole, &eighth, wholeBody, eighthBody)
		t.Logf("%s: %d and %d bytes: %s for the whole, %s for an eighth", name, len(wholeBody), len(eighthBody), whole, eighth)
		if !linearWork(whole, eighth) {
			t.Errorf("%s: %s for the whole, %s for an eighth: not linear", name, whole, eighth)
		}
	}
	for name, body := range map[string]string{
		"deep flow seq":     "version: 1\nx: " + strings.Repeat("[", MaxBytes-20),
		"deep flow map":     "version: 1\nx: " + strings.Repeat("{a: ", (MaxBytes-20)/4),
		"deep block":        "version: 1\n" + deepBlock(3000),
		"many keys":         "version: 1\non_hold:\n" + manyKeys(6000),
		"many list items":   "version: 1\nexceptions:\n" + strings.Repeat("- 1\n", (MaxBytes-30)/4),
		"long scalar":       "version: 1\nexceptions:\n  - {package: npm:a, reason: \"" + strings.Repeat("a", MaxBytes-100) + "\", expires: 2027-06-01}\n",
		"bom then document": "\ufeffversion: 1\n",
	} {
		if len(body) > MaxBytes {
			body = body[:MaxBytes]
		}
		best, err := fastest(body)
		if best > 10*time.Second {
			t.Errorf("%s: %v (the fastest of three)", name, best)
		}
		t.Logf("%s: %d bytes, err=%v", name, len(body), err != nil)
	}
}

// work is what one parse did: its allocations and their bytes (the same on every run), and its time (logged only).
type work struct {
	allocs, bytes uint64
	cpu           time.Duration // the parse's thread CPU time (threadCPU); cpuOK false where it cannot be measured
	cpuOK         bool
	took          time.Duration
}

func (w work) String() string {
	return fmt.Sprintf("%d allocations, %d bytes, %v of thread CPU (%v)", w.allocs, w.bytes, w.cpu.Round(time.Millisecond), w.took.Round(time.Millisecond))
}

// parseWork parses body once to warm up, then once counted: the allocations and bytes from the runtime's own
// counters, which a parse on one goroutine moves by exactly its own work (the test runs nothing beside it).
func parseWork(body string) work {
	_, _ = Parse([]byte(body))
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	_, _ = Parse([]byte(body))
	took := time.Since(start)
	runtime.ReadMemStats(&after)
	return work{allocs: after.Mallocs - before.Mallocs, bytes: after.TotalAlloc - before.TotalAlloc, took: took}
}

// parseCPU sets the thread CPU time of parsing the whole and the eighth: the least of five rounds, the two parsed
// one right after the other in each, with the collector off (quietCPU), so that a busy host takes as much from both.
func parseCPU(whole, eighth *work, wholeBody, eighthBody string) {
	w, e := time.Duration(-1), time.Duration(-1)
	ok := true
	for i := 0; i < 5; i++ {
		de, okE := quietCPU(1, func() { _, _ = Parse([]byte(eighthBody)) })
		dw, okW := quietCPU(1, func() { _, _ = Parse([]byte(wholeBody)) })
		ok = ok && okE && okW
		if e < 0 || de < e {
			e = de
		}
		if w < 0 || dw < w {
			w = dw
		}
	}
	whole.cpu, eighth.cpu, whole.cpuOK, eighth.cpuOK = w, e, ok, ok
}

// linearWork: the whole took at most 12 times the eighth's allocations and bytes, plus 2,000 allocations and
// 256 KiB (the parse's fixed part: the decoders, the policy), and at most 48 times its thread CPU time and 100 ms,
// where measured. The thread CPU bound guards against a blow-up, not a measure of linearity: yaml.v3's parse of
// "many keys" took 14 to 22 times the eighth's thread CPU under -race on correct code (flakes-5, the collector off,
// the least of five rounds), where its allocations grow 6.8 times; the key check alone, plainNodes, is held to 24
// times by TestReview1116PlainNodesKeysLinearByThreadCPU.
func linearWork(whole, eighth work) bool {
	if whole.allocs > 12*eighth.allocs+2000 || whole.bytes > 12*eighth.bytes+256<<10 {
		return false
	}
	return !whole.cpuOK || !eighth.cpuOK || whole.cpu <= 48*eighth.cpu+100*time.Millisecond
}

// build_ cuts a built body to MaxBytes, as the shapes above are cut.
func build_(f func(int) string, n int) string {
	b := f(n)
	if len(b) > MaxBytes {
		b = b[:MaxBytes]
	}
	return b
}

func deepBlock(n int) string {
	var b strings.Builder
	for i := 0; i < n && b.Len() < MaxBytes-100; i++ {
		b.WriteString(strings.Repeat(" ", i%40))
		b.WriteString("a:\n")
	}
	return b.String()
}

func manyKeys(n int) string {
	var b strings.Builder
	for i := 0; i < n && b.Len() < MaxBytes-100; i++ {
		b.WriteString("  k")
		b.WriteString(strings.Repeat("x", i%5))
		b.WriteString(itoa(i))
		b.WriteString(": 1\n")
	}
	return b.String()
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var d []byte
	for ; i > 0; i /= 10 {
		d = append([]byte{byte('0' + i%10)}, d...)
	}
	return string(d)
}

// R9: YAML spellings that change a value's meaning without a duplicate key.
func TestReviewYAMLSpellings(t *testing.T) {
	for name, body := range map[string]string{
		"hex version":       "version: 0x1\n",
		"octal-ish version": "version: 0o1\n",
		"plus version":      "version: +1\n",
		"binary reason":     "version: 1\nexceptions:\n  - {package: npm:a, reason: !!binary b3Vycw==, expires: 2027-06-01}\n",
		"custom tag":        "version: 1\non_hold:\n  packages: !allow deny\n",
		"null on_hold":      "version: 1\non_hold:\n  packages: ~\n",
		"date as timestamp": "version: 1\nexceptions:\n  - {package: npm:a, reason: r, expires: !!timestamp 2027-06-01}\n",
		"date with time":    "version: 1\nexceptions:\n  - {package: npm:a, reason: r, expires: 2027-06-01T00:00:00Z}\n",
	} {
		p, err := Parse([]byte(body))
		// round 2 (F4): a spelling that changes a value's meaning is refused; null is no opinion
		if (err == nil) != (name == "null on_hold") || err == nil && p.OnHold.Packages != "" {
			t.Errorf("%s: err=%v onhold=%+v exc=%d", name, err, p.OnHold, len(p.Exceptions))
		}
	}
}

// R12: property — adding an untrusted repository layer never makes an answer less strict, for installs, servers and
// payments, whatever the file says (the fuzzer writes the repository's file).
func FuzzReviewRepoNeverRelaxes(f *testing.F) {
	f.Add([]byte(full), "npm:@acme/cli@1", "hold", int64(1), "0x00000000000000000000000000000000000000ab", "api.example.com")
	f.Add([]byte("version: 1\nexceptions:\n  - {package: npm:a, reason: r, expires: 2027-06-01}\n"), "npm:a@1", "hold", int64(5), "", "x.example")
	org := mustParseF(f, "version: 1\nexceptions:\n  - {package: npm:b, reason: r, expires: 2027-06-01}\n  - {mcp_server: \"https://mcp.acme.dev/mcp\", reason: r, expires: 2027-06-01}\n")
	f.Fuzz(func(t *testing.T, b []byte, target, verdict string, amount int64, payTo, host string) {
		repo, err := Parse(b)
		if err != nil {
			return
		}
		for _, base := range [][]Layer{nil, {{Source: Managed, Policy: org}}} {
			with := append(append([]Layer{}, base...), Layer{Source: Repo, Policy: repo})
			for _, k := range []Kind{Package, MCPServer} {
				h := Hold{Kind: k, Targets: []string{target}, Reasons: []string{"new_package", "unverified_yet"}} // codes exceptions cover (round 2)
				if a, b := Decide(base, verdict, h, now), Decide(with, verdict, h, now); rank(b) < rank(a) {
					t.Fatalf("the repository relaxed %s to %s (kind %d, %q)", a, b, k, target)
				}
			}
			p := Payment{PayTo: payTo, Host: host, MicroUSD: amount, AmountKnown: amount >= 0}
			if a, b := DecidePayment(base, verdict, p), DecidePayment(with, verdict, p); rank(b) < rank(a) {
				t.Fatalf("the repository relaxed a payment %s to %s", a, b)
			}
		}
	})
}

func mustParseF(f *testing.F, body string) Policy {
	p, err := Parse([]byte(body))
	if err != nil {
		f.Fatal(err)
	}
	return p
}

// R13: the review's mutants that the commit's tests let live (each line kills one): an empty receivers list is nobody,
// a negative amount under a ceiling is unknown, an invisible format character in a reason is refused, a PEP 508 direct
// reference is not covered, a ceiling of exactly a million dollars is read, a base58 receiver is taken, at most
// MaxReceivers.
func TestReviewMutantKills(t *testing.T) {
	nobody := mustParse(t, "version: 1\npayments:\n  receivers: []\n")
	if got := DecidePayment([]Layer{{Source: Repo, Policy: nobody}}, "allow", Payment{Host: "api.example.com", MicroUSD: 1, AmountKnown: true}); got != Deny {
		t.Errorf("receivers: [] lets a payment through: %s", got)
	}
	ceiling := mustParse(t, "version: 1\npayments:\n  max_per_call_usd: \"0.10\"\n")
	if got := DecidePayment([]Layer{{Source: Repo, Policy: ceiling}}, "allow", Payment{Host: "a.example", MicroUSD: -1, AmountKnown: true}); got != Deny {
		t.Errorf("a negative amount under a ceiling: %s", got)
	}
	for _, r := range []string{"ours\u202e", "ours\u200b", "ours\U000e0041"} {
		if reasonOK(r) == nil {
			t.Errorf("reason %q accepted", r)
		}
	}
	org := mustParse(t, "version: 1\nexceptions:\n  - {package: pypi:acme-tools, reason: r, expires: 2027-06-01}\n")
	if got := Decide([]Layer{{Source: Managed, Policy: org}}, "hold", Hold{Kind: Package, Targets: []string{"pypi:acme-tools @ https://evil.example/a.whl"}, Reasons: []string{"new_package"}}, now); got == Allow {
		t.Errorf("a PEP 508 direct reference is covered")
	}
	if p, err := Parse([]byte("version: 1\npayments:\n  max_per_call_usd: \"1000000\"\n")); err != nil || p.Payments.MaxPerCallMicroUSD != 1_000_000_000_000 {
		t.Errorf("a ceiling of a million: %v %d", err, p.Payments.MaxPerCallMicroUSD)
	}
	sol := mustParse(t, "version: 1\npayments:\n  receivers:\n    - pay_to: 9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin\n")
	if got := DecidePayment([]Layer{{Source: Repo, Policy: sol}}, "allow", Payment{PayTo: "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin", MicroUSD: 1, AmountKnown: true}); got != Allow {
		t.Errorf("a listed base58 receiver: %s", got)
	}
	if _, err := Parse([]byte("version: 1\npayments:\n  receivers:\n" + strings.Repeat("    - host: a.example\n", MaxReceivers+1))); err == nil {
		t.Error("over MaxReceivers: parsed")
	}
}
