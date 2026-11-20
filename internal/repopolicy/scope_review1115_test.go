package repopolicy

import (
	"testing"
	"time"
)

// Re-review of 711497f (round 4, S2), 2026-11-15: scope matching cannot be widened by case, Unicode, a lookalike
// scope or a domain that only ends in the organisation's name.
func TestReviewScopesHoldTheirEdges(t *testing.T) {
	org, err := ParseManaged([]byte("version: 1\ntrusted_repositories:\n  - github.com/acme/*\nrepository_exception_scopes:\n  - npm:@acme/*\n  - npm:@tools/cli\n  - mcp:*.acme.dev\n  - mcp:mcp.partner.example\n"))
	if err != nil {
		t.Fatal(err)
	}
	soon := now.Add(30 * 24 * time.Hour).Format(time.DateOnly)
	try := func(spec string, kind Kind, target, code string) Action {
		field := "package"
		if kind == MCPServer {
			field = "mcp_server"
		}
		repo, err := Parse([]byte("version: 1\nexceptions:\n  - {" + field + ": \"" + spec + "\", reason: r, expires: " + soon + "}\n"))
		if err != nil {
			return "refused"
		}
		return Decide([]Layer{{Source: Managed, Policy: org}, {Source: Repo, Policy: repo, TrustExceptions: true}}, "hold",
			Hold{Kind: kind, Targets: []string{target}, Reasons: []string{code}}, now)
	}
	for _, c := range []struct {
		spec   string
		kind   Kind
		target string
		want   bool // allowed
	}{
		{"npm:@acme/cli", Package, "npm:@acme/cli@1", true},
		{"npm:@ACME/cli", Package, "npm:@ACME/cli@1", false},
		{"npm:@acme-evil/cli", Package, "npm:@acme-evil/cli@1", false},
		{"npm:@acmecorp/cli", Package, "npm:@acmecorp/cli@1", false},
		{"npm:acme-cli", Package, "npm:acme-cli@1", false},
		{"npm:@tools/cli", Package, "npm:@tools/cli@1", true},
		{"npm:@tools/cli-x", Package, "npm:@tools/cli-x@1", false},
		{"pypi:acme-tools", Package, "pypi:acme-tools==1", false},
		{"https://mcp.acme.dev/mcp", MCPServer, "remote-mcp:https://mcp.acme.dev/mcp", true},
		{"https://MCP.ACME.DEV/mcp", MCPServer, "remote-mcp:https://mcp.acme.dev/mcp", true},
		{"https://acme.dev/mcp", MCPServer, "remote-mcp:https://acme.dev/mcp", false}, // the apex is not *.acme.dev
		{"https://xacme.dev/mcp", MCPServer, "remote-mcp:https://xacme.dev/mcp", false},
		{"https://mcp.acme.dev.evil.example/mcp", MCPServer, "remote-mcp:https://mcp.acme.dev.evil.example/mcp", false},
		{"https://evil.example/.acme.dev", MCPServer, "remote-mcp:https://evil.example/.acme.dev", false},
		{"https://evil．acme.dev/mcp", MCPServer, "remote-mcp:https://evil．acme.dev/mcp", false},
		{"https://mcp.acme.dev:8443/mcp", MCPServer, "remote-mcp:https://mcp.acme.dev:8443/mcp", true},
		{"https://mcp.partner.example/mcp", MCPServer, "remote-mcp:https://mcp.partner.example/mcp", true},
		{"https://x.mcp.partner.example/mcp", MCPServer, "remote-mcp:https://x.mcp.partner.example/mcp", false},
		{"https://mcp.partner.example.evil/mcp", MCPServer, "remote-mcp:https://mcp.partner.example.evil/mcp", false},
	} {
		code := "new_package"
		if c.kind == MCPServer {
			code = "unverified_yet"
		}
		got := try(c.spec, c.kind, c.target, code)
		if (got == Allow) != c.want {
			t.Errorf("%s -> %s: %s, want allowed=%v", c.spec, c.target, got, c.want)
		}
	}
	// A scope the organisation could mistype into a public suffix.
	// Round 5: a public suffix (or a host anyone can rent a name under) is refused as a scope.
	for _, sc := range []string{"mcp:*.co.uk", "mcp:*.com.au", "mcp:*.ac.jp", "mcp:*.github.io", "mcp:*.vercel.app", "mcp:*.workers.dev", "mcp:*.amazonaws.com",
		"mcp:*.s3.amazonaws.com", "mcp:*.lambda-url.us-east-1.on.aws", "mcp:*.on.aws"} {
		if _, err := ParseManaged([]byte("version: 1\nrepository_exception_scopes:\n  - " + sc + "\n")); err == nil {
			t.Errorf("%s is accepted (every host under it is anyone's)", sc)
		}
	}
	// A domain someone holds is a scope, whatever its labels look like (co.dev is a .dev name, not a country's level).
	for _, sc := range []string{"mcp:*.acme.co.uk", "mcp:*.acme.github.io", "mcp:*.acme.dev", "mcp:acme.github.io", "mcp:*.co.dev", "mcp:*.acme.com", "mcp:*.co.uk.acme.dev"} {
		if _, err := ParseManaged([]byte("version: 1\nrepository_exception_scopes:\n  - " + sc + "\n")); err != nil {
			t.Errorf("%s is refused: %v", sc, err)
		}
	}
	if _, err := ParseManaged([]byte("version: 1\nrepository_exception_scopes:\n  - npm:@*/*\n")); err == nil {
		t.Error("npm:@*/* is accepted")
	}
}
