package repopolicy

import (
	"strings"
	"testing"
)

// The F-round of the review of 2950215 (ADR-0174 round 2): the zero values are the safe ones, a hold is covered only
// by the reason codes an exception may cover, a token is refused in every field.
func TestFRoundZeroValuesAndCodes(t *testing.T) {
	org := mustParse(t, "version: 1\nexceptions:\n  - {package: npm:@acme/cli, reason: ours, expires: 2027-06-01}\n  - {mcp_server: \"https://mcp.acme.dev/mcp\", reason: ours, expires: 2027-06-01}\n")
	pkg := func(codes ...string) Hold {
		return Hold{Kind: Package, Targets: []string{"npm:@acme/cli@1"}, Reasons: codes}
	}
	srv := func(codes ...string) Hold {
		return Hold{Kind: MCPServer, Targets: []string{"https://mcp.acme.dev/mcp"}, Reasons: codes}
	}
	for _, c := range []struct {
		name  string
		layer Layer
		hold  Hold
		want  Action
	}{
		{"a layer of no source is not trusted", Layer{Policy: org}, pkg("new_package"), Ask},
		{"a layer of an unknown source is not trusted", Layer{Source: Source(9), Policy: org}, pkg("new_package"), Ask},
		{"no source, trusted explicitly: bound like a repository's, and no organisation's scopes (round 4)", Layer{Policy: org, TrustExceptions: true}, pkg("new_package"), Ask},
		{"the developer's own layer", Layer{Source: User, Policy: org}, pkg("new_package"), Allow},
		{"an install script of ours", Layer{Source: Managed, Policy: org}, pkg("runs_install_script"), Allow},
		{"a name like an official one, ours", Layer{Source: Managed, Policy: org}, pkg("name_like_official:@anthropic-ai/cli"), Allow},
		{"the prefix's bare word is another code", Layer{Source: Managed, Policy: org}, pkg("name_like_official"), Ask},
		{"the prefix with no detail", Layer{Source: Managed, Policy: org}, pkg("name_like_official:"), Ask},
		{"maintainers changed: never covered", Layer{Source: Managed, Policy: org}, pkg("new_package", "maintainers_changed"), Ask},
		{"provenance dropped: never covered", Layer{Source: Managed, Policy: org}, pkg("provenance_dropped"), Ask},
		{"not checked: never covered", Layer{Source: Managed, Policy: org}, pkg("check_incomplete:registry_unreachable"), Ask},
		{"a code of tomorrow: not covered", Layer{Source: Managed, Policy: org}, pkg("some_new_code"), Ask},
		{"a code that begins like a coverable one", Layer{Source: Managed, Policy: org}, pkg("new_package_owner_changed"), Ask},
		{"an empty code", Layer{Source: Managed, Policy: org}, pkg(""), Ask},
		{"a server's code on a package", Layer{Source: Managed, Policy: org}, pkg("unverified_yet"), Ask},
		{"a server not verified yet", Layer{Source: Managed, Policy: org}, srv("unverified_yet"), Allow},
		{"a server's caution: never covered", Layer{Source: Managed, Policy: org}, srv("caution_tools_changed"), Ask},
		{"a package's code on a server", Layer{Source: Managed, Policy: org}, srv("new_package"), Ask},
		{"a server of no reasons", Layer{Source: Managed, Policy: org}, srv(), Ask},
	} {
		if got := Decide([]Layer{c.layer}, "hold", c.hold, now); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestFRoundTokenInEveryField(t *testing.T) {
	tok := "aln_abcdefghijklmnopqrstuvwxyz234567"
	gh := "ghp_" + strings.Repeat("A1b2", 9)
	for name, body := range map[string]string{
		"package":      "version: 1\nexceptions:\n  - {package: \"npm:" + tok + "\", reason: r, expires: 2027-06-01}\n",
		"server path":  "version: 1\nexceptions:\n  - {mcp_server: \"https://a.example/" + tok + "\", reason: r, expires: 2027-06-01}\n",
		"server query": "version: 1\nexceptions:\n  - {mcp_server: \"https://a.example/x?k=" + tok + "\", reason: r, expires: 2027-06-01}\n",
		"host":         "version: 1\npayments:\n  receivers:\n    - host: " + tok + ".example.com\n",
		"a key":        "version: 1\n" + tok + ": 1\n",
		"another kind": "version: 1\nexceptions:\n  - {package: npm:a, reason: \"" + gh + "\", expires: 2027-06-01}\n",
		"in on_hold":   "version: 1\non_hold:\n  packages: " + tok + "\n",
	} {
		_, err := Parse([]byte(body))
		if err == nil {
			t.Errorf("%s: parsed", name)
			continue
		}
		if strings.Contains(err.Error(), tok[:12]) || strings.Contains(err.Error(), gh[:12]) {
			t.Errorf("%s: the error shows the token: %q", name, err)
		}
	}
}

// F5: what follows a name is a registry version or range (npm) or extras and a PEP 440 specifier list (PyPI); anything
// else matches nothing.
func TestFRoundTargetGrammar(t *testing.T) {
	for tg, want := range map[string]string{
		"npm:acme":                     "npm:acme",
		"npm:acme@1.2.3":               "npm:acme",
		"npm:acme@^1.2":                "npm:acme",
		"npm:acme@>=1.0.0<2":           "npm:acme",
		"npm:acme@1.x||2.x":            "npm:acme",
		"npm:acme@next":                "npm:acme",
		"npm:acme@1.0.0-rc.1+b":        "npm:acme",
		"npm:@acme/cli@*":              "npm:@acme/cli",
		"npm:acme@":                    "",
		"npm:acme@1.0.0@evil":          "",
		"npm:acme@1 2":                 "",
		"npm:acme@1;x":                 "",
		"npm:acme@npm:x":               "",
		"npm:acme@a/b":                 "",
		"pypi:acme":                    "pypi:acme",
		"pypi:acme==1.0":               "pypi:acme",
		"pypi:acme[x,y]>=1,<2":         "pypi:acme",
		"pypi:acme~=1.4.2":             "pypi:acme",
		"pypi:acme===1.0":              "pypi:acme",
		"pypi:acme!=1.*":               "pypi:acme",
		"pypi:acme[x]":                 "pypi:acme",
		"pypi:acme[]":                  "",
		"pypi:acme==":                  "",
		"pypi:acme 1":                  "",
		"pypi:acme;python_version<'3'": "",
		"pypi:acme==1 -f x":            "",
		"pypi:acme@1.0":                "pypi:acme", // install_check's own form (round 2, F7)
		"pypi:acme@https://x":          "",
		"pypi:acme[x]@1.0":             "pypi:acme",
		"pypi:acme@1.0,>=2":            "",
		"pypi:acme=1":                  "",
		"pypi:acme==1,":                "",
	} {
		if got := packageTarget(tg); got != want {
			t.Errorf("%q: %q, want %q", tg, got, want)
		}
	}
}

// F6: a reason is refused for what the repository's instruction files are held for: a character safe.Text drops, and a
// joiner it keeps but safe.Unseen counts (a ZWNJ after f before a Latin letter carries a bit in plain English).
func TestFRoundReasonUnseen(t *testing.T) {
	for _, r := range []string{"of\u200ctaste", "ours\u2028", "ours\u00ad", "ours\u200b", "\u0301ours", "ours\tx", "ours\u0007"} {
		if reasonOK(r) == nil {
			t.Errorf("%+q accepted", r)
		}
	}
	for _, r := range []string{"ours, published by our CI", "наш пакет", "社内ツール", "café", "ours 👍"} {
		if err := reasonOK(r); err != nil {
			t.Errorf("%q refused: %v", r, err)
		}
	}
}
