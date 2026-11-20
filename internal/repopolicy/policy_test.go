package repopolicy

import (
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

const full = `version: 1
on_hold:
  packages: ask
  mcp_servers: deny
  payments: deny
exceptions:
  - package: npm:@acme/cli
    reason: ours, published by our CI
    expires: 2027-01-31
  - package: pypi:Acme_Tools
    reason: ours
    expires: "2026-11-15"
  - mcp_server: https://MCP.acme.dev/mcp/
    reason: approved by security
    expires: 2026-12-01
  - package: npm:old-thing
    reason: was ours
    expires: 2026-11-14
payments:
  max_per_call_usd: "0.50"
  receivers:
    - pay_to: "0x00000000000000000000000000000000000000Ab"
    - host: api.example.com
`

func TestParseFull(t *testing.T) {
	p, err := Parse([]byte(full))
	if err != nil {
		t.Fatal(err)
	}
	if p.Version != 1 || p.OnHold.Packages != Ask || p.OnHold.MCPServers != Deny || p.OnHold.Payments != Deny {
		t.Errorf("on_hold: %+v", p.OnHold)
	}
	if len(p.Exceptions) != 4 || p.Exceptions[0].Package != "npm:@acme/cli" || p.Exceptions[2].MCPServer != "https://MCP.acme.dev/mcp/" {
		t.Errorf("exceptions: %+v", p.Exceptions)
	}
	if !p.Payments.HasMax || p.Payments.MaxPerCallMicroUSD != 500_000 || len(p.Payments.Receivers) != 2 || !p.Payments.HasReceivers {
		t.Errorf("payments: %+v", p.Payments)
	}
	if live := p.Live(now); len(live) != 3 {
		t.Errorf("live exceptions on 2026-11-15: %d, want 3 (one expired on 11-14; 11-15 lasts the whole day)", len(live))
	}
	if ex := p.Expired(now); len(ex) != 1 || ex[0].Package != "npm:old-thing" {
		t.Errorf("expired: %+v", ex)
	}
	if ex := p.Expired(time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)); len(ex) != 2 {
		t.Errorf("expired at the start of 11-16: %d, want 2", len(ex))
	}
}

func TestParseUnquotedNumbersAndDates(t *testing.T) {
	p, err := Parse([]byte("version: 1\npayments:\n  max_per_call_usd: 2\n"))
	if err != nil || p.Payments.MaxPerCallMicroUSD != 2_000_000 {
		t.Errorf("unquoted ceiling: %+v %v", p.Payments, err)
	}
	p, err = Parse([]byte("version: 1\npayments:\n  max_per_call_usd: 0.000001\n"))
	if err != nil || p.Payments.MaxPerCallMicroUSD != 1 {
		t.Errorf("one micro-dollar: %+v %v", p.Payments, err)
	}
}

func TestParseRefuses(t *testing.T) {
	for name, body := range map[string]string{
		"empty":                       "",
		"no version":                  "on_hold:\n  packages: deny\n",
		"version 2":                   "version: 2\n",
		"unknown key":                 "version: 1\nallow_everything: true\n",
		"unknown nested key":          "version: 1\non_hold:\n  packages: deny\n  skills: deny\n",
		"allow is not an answer":      "version: 1\non_hold:\n  packages: allow\n",
		"unknown answer":              "version: 1\non_hold:\n  packages: maybe\n",
		"two documents":               "version: 1\n---\nversion: 1\n",
		"an alias":                    "version: 1\nexceptions:\n  - &e {package: npm:a, reason: r, expires: 2027-01-01}\n  - *e\n",
		"duplicate key":               "version: 1\nversion: 1\n",
		"exception without reason":    "version: 1\nexceptions:\n  - package: npm:a\n    expires: 2027-01-01\n",
		"exception without expiry":    "version: 1\nexceptions:\n  - package: npm:a\n    reason: ours\n",
		"exception bad date":          "version: 1\nexceptions:\n  - package: npm:a\n    reason: ours\n    expires: 31.01.2027\n",
		"exception with both":         "version: 1\nexceptions:\n  - package: npm:a\n    mcp_server: https://a.example/\n    reason: ours\n    expires: 2027-01-01\n",
		"exception with neither":      "version: 1\nexceptions:\n  - reason: ours\n    expires: 2027-01-01\n",
		"package without ecosystem":   "version: 1\nexceptions:\n  - package: lodash\n    reason: ours\n    expires: 2027-01-01\n",
		"unknown ecosystem":           "version: 1\nexceptions:\n  - package: cargo:ripgrep\n    reason: ours\n    expires: 2027-01-01\n",
		"package with a version":      "version: 1\nexceptions:\n  - package: npm:a@1.0.0\n    reason: ours\n    expires: 2027-01-01\n",
		"package as a URL":            "version: 1\nexceptions:\n  - package: npm:https://x.example/a.tgz\n    reason: ours\n    expires: 2027-01-01\n",
		"pypi with a specifier":       "version: 1\nexceptions:\n  - package: pypi:a==1\n    reason: ours\n    expires: 2027-01-01\n",
		"server over http":            "version: 1\nexceptions:\n  - mcp_server: http://a.example/mcp\n    reason: ours\n    expires: 2027-01-01\n",
		"server with a query":         "version: 1\nexceptions:\n  - mcp_server: https://a.example/mcp?key=x\n    reason: ours\n    expires: 2027-01-01\n",
		"server with user info":       "version: 1\nexceptions:\n  - mcp_server: https://u:p@a.example/mcp\n    reason: ours\n    expires: 2027-01-01\n",
		"reason with a control":       "version: 1\nexceptions:\n  - package: npm:a\n    reason: \"ours\\u0007\"\n    expires: 2027-01-01\n",
		"reason over 300":             "version: 1\nexceptions:\n  - package: npm:a\n    reason: " + strings.Repeat("r", 301) + "\n    expires: 2027-01-01\n",
		"negative ceiling":            "version: 1\npayments:\n  max_per_call_usd: \"-1\"\n",
		"ceiling with 7 places":       "version: 1\npayments:\n  max_per_call_usd: \"0.0000001\"\n",
		"ceiling as words":            "version: 1\npayments:\n  max_per_call_usd: ten\n",
		"ceiling over a million":      "version: 1\npayments:\n  max_per_call_usd: \"1000001\"\n",
		"receiver with both":          "version: 1\npayments:\n  receivers:\n    - pay_to: \"0x00000000000000000000000000000000000000Ab\"\n      host: a.example\n",
		"receiver with neither":       "version: 1\npayments:\n  receivers:\n    - {}\n",
		"receiver host with a scheme": "version: 1\npayments:\n  receivers:\n    - host: https://a.example\n",
		"receiver address too short":  "version: 1\npayments:\n  receivers:\n    - pay_to: \"0xAb\"\n",
		"a list at the top":           "- version: 1\n",
	} {
		if _, err := Parse([]byte(body)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	if _, err := Parse([]byte("version: 1\n# " + strings.Repeat("x", MaxBytes) + "\n")); err == nil {
		t.Error("over MaxBytes: parsed")
	}
	many := "version: 1\nexceptions:\n" + strings.Repeat("  - {package: npm:a, reason: r, expires: 2027-01-01}\n", MaxExceptions+1)
	if _, err := Parse([]byte(many)); err == nil {
		t.Error("over MaxExceptions: parsed")
	}
}

func TestParseKeepsNoToken(t *testing.T) {
	// The file has no member a token could go in: the only free text is a reason, and a token there is refused.
	body := "version: 1\nexceptions:\n  - package: npm:a\n    reason: aln_abcdefghijklmnopqrstuvwxyz234567\n    expires: 2027-01-01\n"
	if _, err := Parse([]byte(body)); err == nil || strings.Contains(err.Error(), "aln_abc") {
		t.Errorf("a token in a reason: %v", err)
	}
}

func mustParse(t *testing.T, body string) Policy {
	t.Helper()
	p, err := Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDecideHold(t *testing.T) {
	repo := mustParse(t, full)
	acmeScope, err := ParseManaged([]byte("version: 1\nrepository_exception_scopes:\n  - npm:@acme/*\n"))
	if err != nil {
		t.Fatal(err)
	}
	exceptNPM := mustParse(t, "version: 1\nexceptions:\n  - {package: npm:@acme/cli, reason: ours, expires: 2027-01-01}\n")
	denyPkgs := mustParse(t, "version: 1\non_hold:\n  packages: deny\n")
	askPkgs := mustParse(t, "version: 1\non_hold:\n  packages: ask\n")
	payDeny := mustParse(t, "version: 1\non_hold:\n  payments: deny\n")
	pkg := func(targets ...string) Hold {
		return Hold{Kind: Package, Targets: targets, Reasons: []string{"new_package"}}
	}
	for _, c := range []struct {
		name    string
		layers  []Layer
		verdict string
		hold    Hold
		want    Action
	}{
		{"no policy: a hold asks", nil, "hold", pkg("npm:x"), Ask},
		{"no policy: allow", nil, "allow", pkg("npm:x"), Allow},
		{"no policy: block", nil, "block", pkg("npm:x"), Deny},
		{"unknown verdict asks", nil, "", pkg("npm:x"), Ask},
		{"a block stays a block under an exception", []Layer{{Source: Managed, Policy: exceptNPM}}, "block", pkg("npm:@acme/cli@1.2.0"), Deny},
		{"managed exception allows a held package", []Layer{{Source: Managed, Policy: exceptNPM}}, "hold", pkg("npm:@acme/cli@1.2.0"), Allow},
		{"user exception allows", []Layer{{Source: User, Policy: exceptNPM}}, "hold", pkg("npm:@acme/cli"), Allow},
		{"untrusted repo exception does not", []Layer{{Source: Repo, Policy: exceptNPM}}, "hold", pkg("npm:@acme/cli@1.2.0"), Ask},
		{"trusted repo exception, no organisation's scopes (round 4)", []Layer{{Source: Repo, Policy: exceptNPM, TrustExceptions: true}}, "hold", pkg("npm:@acme/cli@1.2.0"), Ask},
		{"trusted repo exception inside the organisation's scope", []Layer{{Source: Managed, Policy: acmeScope}, {Source: Repo, Policy: exceptNPM, TrustExceptions: true}}, "hold", pkg("npm:@acme/cli@1.2.0"), Allow},
		{"untrusted repo deny applies at once", []Layer{{Source: Repo, Policy: denyPkgs}}, "hold", pkg("npm:x"), Deny},
		{"a deny never touches an allow", []Layer{{Source: Repo, Policy: denyPkgs}}, "allow", pkg("npm:x"), Allow},
		{"stricter wins: managed deny over a trusted repo exception", []Layer{{Source: Managed, Policy: denyPkgs}, {Source: Repo, Policy: exceptNPM, TrustExceptions: true}}, "hold", pkg("npm:@acme/cli"), Deny},
		{"stricter wins: managed ask over a trusted repo exception", []Layer{{Source: Managed, Policy: askPkgs}, {Source: Repo, Policy: exceptNPM, TrustExceptions: true}}, "hold", pkg("npm:@acme/cli"), Ask},
		{"a layer with no word on packages leaves the exception", []Layer{{Source: Managed, Policy: payDeny}, {Source: User, Policy: exceptNPM}}, "hold", pkg("npm:@acme/cli"), Allow},
		{"an exception in the same layer beats its own on_hold", []Layer{{Source: Managed, Policy: repo}}, "hold", pkg("npm:@acme/cli@2"), Allow},
		{"every target must be excepted", []Layer{{Source: Managed, Policy: exceptNPM}}, "hold", pkg("npm:@acme/cli", "npm:evil"), Ask},
		{"no target, no exception", []Layer{{Source: Managed, Policy: exceptNPM}}, "hold", pkg(), Ask},
		{"a hold with unread reasons is not covered", []Layer{{Source: Managed, Policy: exceptNPM}}, "hold", Hold{Kind: Package, Targets: []string{"npm:@acme/cli"}, Reasons: []string{"new_package", "check_incomplete:registry_unreachable"}}, Ask},
		{"the other ecosystem is not covered", []Layer{{Source: Managed, Policy: exceptNPM}}, "hold", pkg("pypi:@acme/cli"), Ask},
		{"a lookalike scope is not covered", []Layer{{Source: Managed, Policy: exceptNPM}}, "hold", pkg("npm:@acme/cli-x"), Ask},
		{"npm names are exact", []Layer{{Source: Managed, Policy: exceptNPM}}, "hold", pkg("npm:@ACME/cli"), Ask},
		{"a git source under the name is not covered", []Layer{{Source: Managed, Policy: exceptNPM}}, "hold", pkg("npm:@acme/cli@git+https://x.example/a.git"), Ask},
		{"pypi names normalise", []Layer{{Source: Managed, Policy: repo}}, "hold", pkg("pypi:acme.tools==1.0"), Allow},
		{"pypi extras and specifiers", []Layer{{Source: Managed, Policy: repo}}, "hold", pkg("pypi:ACME-tools[cli]>=2"), Allow},
		{"an expired exception is gone", []Layer{{Source: Managed, Policy: repo}}, "hold", pkg("npm:old-thing"), Ask},
		{"server exception by URL", []Layer{{Source: Managed, Policy: repo}}, "hold", Hold{Kind: MCPServer, Reasons: []string{"unverified_yet"}, Targets: []string{"https://mcp.acme.dev/mcp"}}, Allow},
		{"server: another path is not covered", []Layer{{Source: Managed, Policy: repo}}, "hold", Hold{Kind: MCPServer, Reasons: []string{"unverified_yet"}, Targets: []string{"https://mcp.acme.dev/other"}}, Deny},
		{"server: http is not covered", []Layer{{Source: Managed, Policy: repo}}, "hold", Hold{Kind: MCPServer, Reasons: []string{"unverified_yet"}, Targets: []string{"http://mcp.acme.dev/mcp"}}, Deny},
		{"server: another port is not covered", []Layer{{Source: Managed, Policy: repo}}, "hold", Hold{Kind: MCPServer, Reasons: []string{"unverified_yet"}, Targets: []string{"https://mcp.acme.dev:8443/mcp"}}, Deny},
		{"server: a package exception does not cover a server", []Layer{{Source: Managed, Policy: exceptNPM}}, "hold", Hold{Kind: MCPServer, Reasons: []string{"unverified_yet"}, Targets: []string{"npm:@acme/cli"}}, Ask},
		{"package: a server exception does not cover a package", []Layer{{Source: Managed, Policy: repo}}, "hold", pkg("https://mcp.acme.dev/mcp"), Ask},
	} {
		if got := Decide(c.layers, c.verdict, c.hold, now); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestDecidePayment(t *testing.T) {
	repo := mustParse(t, full)
	ceiling := mustParse(t, "version: 1\npayments:\n  max_per_call_usd: \"0.10\"\n")
	onlyHost := mustParse(t, "version: 1\npayments:\n  receivers:\n    - host: api.example.com\n")
	addr := "0x00000000000000000000000000000000000000ab"
	for _, c := range []struct {
		name    string
		layers  []Layer
		verdict string
		pay     Payment
		want    Action
	}{
		{"no policy: allow", nil, "allow", Payment{PayTo: addr, MicroUSD: 1, AmountKnown: true}, Allow},
		{"no policy: a hold asks", nil, "hold", Payment{PayTo: addr, MicroUSD: 1, AmountKnown: true}, Ask},
		{"no policy: block", nil, "block", Payment{PayTo: addr}, Deny},
		{"listed address (any case), under the ceiling", []Layer{{Source: Repo, Policy: repo}}, "allow", Payment{PayTo: addr, MicroUSD: 500_000, AmountKnown: true}, Allow},
		{"over the ceiling", []Layer{{Source: Repo, Policy: repo}}, "allow", Payment{PayTo: addr, MicroUSD: 500_001, AmountKnown: true}, Deny},
		{"an unknown amount under a ceiling", []Layer{{Source: Repo, Policy: repo}}, "allow", Payment{PayTo: addr}, Deny},
		{"listed host", []Layer{{Source: Repo, Policy: repo}}, "allow", Payment{Host: "API.example.com.", MicroUSD: 1, AmountKnown: true}, Allow},
		{"a subdomain is another host", []Layer{{Source: Repo, Policy: repo}}, "allow", Payment{Host: "x.api.example.com", MicroUSD: 1, AmountKnown: true}, Deny},
		{"an unlisted receiver", []Layer{{Source: Repo, Policy: repo}}, "allow", Payment{PayTo: "0x1111111111111111111111111111111111111111", MicroUSD: 1, AmountKnown: true}, Deny},
		{"a hold with on_hold deny", []Layer{{Source: Repo, Policy: repo}}, "hold", Payment{PayTo: addr, MicroUSD: 1, AmountKnown: true}, Deny},
		{"a listed receiver does not relax a hold", []Layer{{Source: Repo, Policy: onlyHost}}, "hold", Payment{Host: "api.example.com", MicroUSD: 1, AmountKnown: true}, Ask},
		{"the lower ceiling of two layers", []Layer{{Source: Managed, Policy: ceiling}, {Source: Repo, Policy: repo}}, "allow", Payment{PayTo: addr, MicroUSD: 200_000, AmountKnown: true}, Deny},
		{"receivers of both layers must agree", []Layer{{Source: Managed, Policy: onlyHost}, {Source: Repo, Policy: repo}}, "allow", Payment{PayTo: addr, MicroUSD: 1, AmountKnown: true}, Deny},
		{"both agree", []Layer{{Source: Managed, Policy: onlyHost}, {Source: Repo, Policy: repo}}, "allow", Payment{Host: "api.example.com", MicroUSD: 1, AmountKnown: true}, Allow},
	} {
		if got := DecidePayment(c.layers, c.verdict, c.pay); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(full))
	f.Add([]byte("version: 1\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := Parse(b)
		if err != nil {
			return
		}
		if p.Version != Version {
			t.Fatalf("parsed version %d", p.Version)
		}
		for _, e := range p.Exceptions {
			if (e.Package == "") == (e.MCPServer == "") || e.Reason == "" || e.Expires.IsZero() {
				t.Fatalf("an exception without one target, a reason and an expiry: %+v", e)
			}
		}
	})
}

// The mutation run's survivors (ADR-0174): the order of layers, a verdict this package does not know, a policy built by
// hand, the default https port.
func TestDecideEdges(t *testing.T) {
	exceptNPM := mustParse(t, "version: 1\nexceptions:\n  - {package: npm:@acme/cli, reason: ours, expires: 2027-01-01}\n")
	askPkgs := mustParse(t, "version: 1\non_hold:\n  packages: ask\n")
	denyPkgs := mustParse(t, "version: 1\non_hold:\n  packages: deny\n")
	server := mustParse(t, "version: 1\nexceptions:\n  - {mcp_server: \"https://mcp.acme.dev:443/mcp\", reason: ours, expires: 2027-01-01}\n")
	ours := Hold{Kind: Package, Reasons: []string{"new_package"}, Targets: []string{"npm:@acme/cli@1"}}
	soon := now.Add(24 * time.Hour)
	for _, c := range []struct {
		name    string
		layers  []Layer
		verdict string
		hold    Hold
		want    Action
	}{
		{"ask after an allow still wins", []Layer{{Source: Repo, Policy: exceptNPM, TrustExceptions: true}, {Source: Managed, Policy: askPkgs}}, "hold", ours, Ask},
		{"an unknown verdict: no exception covers it", []Layer{{Source: Managed, Policy: exceptNPM}}, "maybe", ours, Ask},
		{"an unknown verdict: on_hold applies", []Layer{{Source: Managed, Policy: denyPkgs}}, "maybe", ours, Deny},
		{"a hand-built exception Parse would refuse names nothing", []Layer{{Source: Managed, Policy: Policy{Version: 1,
			Exceptions: []Exception{{Package: "npm:https://x.example/a.tgz", Reason: "r", Expires: soon}}}}}, "hold",
			Hold{Kind: Package, Reasons: []string{"new_package"}, Targets: []string{"npm:@acme/cli@git+https://x.example/a.git"}}, Ask},
		{"a hand-built exception Parse would take", []Layer{{Source: Managed, Policy: Policy{Version: 1,
			Exceptions: []Exception{{Package: "npm:@acme/cli", Reason: "r", Expires: soon}}}}}, "hold", ours, Allow},
		{"a server exception names no package", []Layer{{Source: Managed, Policy: Policy{Version: 1,
			Exceptions: []Exception{{MCPServer: "https://mcp.acme.dev/mcp", Reason: "r", Expires: soon}}}}}, "hold", ours, Ask},
		{"the default port is the same server", []Layer{{Source: Managed, Policy: server}}, "hold", Hold{Kind: MCPServer, Reasons: []string{"unverified_yet"}, Targets: []string{"https://MCP.acme.dev/mcp"}}, Allow},
		{"its query is not who the server is", []Layer{{Source: Managed, Policy: server}}, "hold", Hold{Kind: MCPServer, Reasons: []string{"unverified_yet"}, Targets: []string{"https://mcp.acme.dev/mcp?x=1"}}, Allow},
	} {
		if got := Decide(c.layers, c.verdict, c.hold, now); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}
