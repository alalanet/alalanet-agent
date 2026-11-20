package repopolicy

import "testing"

// Round 2 (ADR-0174): only the organisation's policy trusts a repository's exceptions, by the repository's address.
func TestTrustedRepositoriesOnlyInTheOrganisationsPolicy(t *testing.T) {
	body := "version: 1\ntrusted_repositories:\n  - github.com/Acme/*\n  - gitlab.example.com/team/app\n"
	p, err := ParseManaged([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.TrustedRepositories) != 2 || p.TrustedRepositories[0] != "github.com/acme/*" {
		t.Errorf("trusted: %q", p.TrustedRepositories)
	}
	if _, err := Parse([]byte(body)); err == nil {
		t.Error("a repository's file trusts repositories")
	}
	if _, err := Parse([]byte("version: 1\ntrusted_repositories: []\n")); err == nil {
		t.Error("a repository's file names the key, even empty")
	}
	for _, bad := range []string{"https://github.com/acme/app", "github.com", "github.com/*", "*", "github.com/acme/*/x", "github.com/acme/../x",
		"github.com//x", "github.com:22/acme/app", "github.com/acme/app.git", "git@github.com:acme/app", "github.com/acme/app/"} {
		if _, err := ParseManaged([]byte("version: 1\ntrusted_repositories:\n  - \"" + bad + "\"\n")); err == nil {
			t.Errorf("%q: parsed", bad)
		}
	}
	// ParseManaged reads everything Parse reads, with the same refusals.
	if _, err := ParseManaged([]byte("version: 1\nhooks: []\n")); err == nil {
		t.Error("an unknown key in the organisation's policy")
	}
	if q, err := ParseManaged([]byte(full)); err != nil || len(q.Exceptions) != 4 {
		t.Errorf("the full file as the organisation's: %v", err)
	}
}

func TestTrustsRepository(t *testing.T) {
	p, err := ParseManaged([]byte("version: 1\ntrusted_repositories:\n  - github.com/acme/*\n  - gitlab.example.com/team/app\n"))
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]bool{
		"github.com/acme/app":           true,
		"github.com/acme/group/app":     true,
		"github.com/acme":               false,
		"github.com/acme-evil/app":      false,
		"github.com/acmex/app":          false,
		"gitlab.example.com/team/app":   true,
		"gitlab.example.com/team/ap":    false,
		"gitlab.example.com/team/app/x": false,
		"":                              false,
	} {
		if got := p.TrustsRepository(id); got != want {
			t.Errorf("%q: %v, want %v", id, got, want)
		}
	}
	if (Policy{}).TrustsRepository("github.com/acme/app") {
		t.Error("an empty policy trusts")
	}
	// The prefix itself, and an empty id under a policy built by hand that ParseManaged would refuse.
	if p.TrustsRepository("github.com/acme/") || (Policy{TrustedRepositories: []string{"*"}}).TrustsRepository("") ||
		(Policy{TrustedRepositories: []string{""}}).TrustsRepository("") {
		t.Error("trusted without a repository")
	}
}

func TestRepositoryID(t *testing.T) {
	for u, want := range map[string]string{
		"https://github.com/Acme/App.git":                       "github.com/acme/app",
		"https://github.com/acme/app":                           "github.com/acme/app",
		"https://github.com/acme/app/":                          "github.com/acme/app",
		"https://x-access-token:SECRET@github.com/acme/app.git": "github.com/acme/app",
		"http://git.example.com:8080/team/app.git":              "git.example.com/team/app",
		"ssh://git@github.com:22/acme/app.git":                  "github.com/acme/app",
		"git+ssh://git@github.com/acme/app.git":                 "github.com/acme/app",
		"git://github.com/acme/app.git":                         "github.com/acme/app",
		"git@github.com:acme/app.git":                           "github.com/acme/app",
		"github.com:acme/app":                                   "github.com/acme/app",
		"  git@GitHub.com:acme/group/app.git  ":                 "github.com/acme/group/app",
		"file:///srv/git/app.git":                               "",
		"/srv/git/app.git":                                      "",
		"../app":                                                "",
		"./dir:x/app":                                           "",
		"/srv/git:acme/app":                                     "",
		"C:/repos/app":                                          "",
		`C:\repos\app`:                                          "",
		"https://github.com/acme/../evil":                       "",
		"https://github.com/":                                   "",
		"git@github.com:":                                       "",
		"ftp://github.com/acme/app":                             "",
		"":                                                      "",
	} {
		if got := RepositoryID(u); got != want {
			t.Errorf("%q: %q, want %q", u, got, want)
		}
	}
}

// F7: an expiry more than MaxAhead after now is not in force — at the boundary.
func TestExpiryCapBoundary(t *testing.T) {
	p := mustParse(t, "version: 1\nexceptions:\n  - {package: npm:a, reason: r, expires: 2027-11-15}\n  - {package: npm:b, reason: r, expires: 2027-11-16}\n")
	live, far := p.Live(now), p.TooFar(now)
	if len(live) != 1 || live[0].Package != "npm:a" || len(far) != 1 || far[0].Package != "npm:b" {
		t.Errorf("live %+v, too far %+v (now %s, cap %s)", live, far, now, MaxAhead)
	}
}

// F7: the organisation can say in plain words that no repository's exceptions apply, whoever trusts them.
func TestRepositoryExceptionsNever(t *testing.T) {
	never, err := ParseManaged([]byte("version: 1\nrepository_exceptions: never\ntrusted_repositories:\n  - github.com/acme/*\nexceptions:\n  - {package: npm:org-own, reason: ours, expires: 2027-06-01}\n"))
	if err != nil || !never.RepositoryExceptionsNever {
		t.Fatalf("%v %+v", err, never)
	}
	for _, bad := range []string{"always", "yes", "", "Never "} {
		if _, err := ParseManaged([]byte("version: 1\nrepository_exceptions: \"" + bad + "\"\n")); err == nil {
			t.Errorf("%q: parsed", bad)
		}
	}
	if _, err := Parse([]byte("version: 1\nrepository_exceptions: never\n")); err == nil {
		t.Error("a repository's file says it")
	}
	repo := mustParse(t, "version: 1\nexceptions:\n  - {package: npm:@acme/cli, reason: ours, expires: 2027-06-01}\n")
	held := func(name string) Hold {
		return Hold{Kind: Package, Targets: []string{name}, Reasons: []string{"new_package"}}
	}
	layers := []Layer{{Source: Managed, Policy: never}, {Source: Repo, Policy: repo, TrustExceptions: true}}
	if got := Decide(layers, "hold", held("npm:@acme/cli@1"), now); got != Ask {
		t.Errorf("a trusted repository's exception under never: %s", got)
	}
	if got := Decide(layers, "hold", held("npm:org-own@1"), now); got != Allow {
		t.Errorf("the organisation's own exception under never: %s", got)
	}
	// The organisation's never binds whatever the order, and only the organisation says it.
	if got := Decide([]Layer{layers[1], layers[0]}, "hold", held("npm:@acme/cli@1"), now); got != Ask {
		t.Errorf("never after the repository's layer: %s", got)
	}
	scoped, err := ParseManaged([]byte("version: 1\nrepository_exception_scopes:\n  - npm:@acme/*\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := Decide([]Layer{{Source: User, Policy: never}, {Source: Managed, Policy: scoped}, {Source: Repo, Policy: repo, TrustExceptions: true}}, "hold", held("npm:@acme/cli@1"), now); got != Allow {
		t.Errorf("never from a layer that is not the organisation's: %s", got)
	}
	if got := Decide([]Layer{{Source: Managed, Policy: never}, {Source: Managed, Policy: scoped}, {Policy: repo, TrustExceptions: true}}, "hold", held("npm:@acme/cli@1"), now); got != Ask {
		t.Errorf("never binds a layer of no source too: %s", got)
	}
}

// Round 4 (S2): the organisation bounds what a trusted repository's exceptions may name — npm scopes and domains it
// owns; PyPI has no namespaces, so its exceptions stay in the organisation's own file.
func TestRepositoryExceptionScopes(t *testing.T) {
	org, err := ParseManaged([]byte("version: 1\nrepository_exception_scopes:\n  - npm:@Acme/*\n  - npm:@tools/one\n  - mcp:*.acme.dev\n  - mcp:mcp.example.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(org.RepositoryExceptionScopes) != 4 || org.RepositoryExceptionScopes[0] != "npm:@acme/*" {
		t.Errorf("scopes: %q", org.RepositoryExceptionScopes)
	}
	for _, bad := range []string{"npm:acme-helpers", "npm:*", "npm:@acme", "npm:@acme/x*", "pypi:acme-tools", "pypi:*", "mcp:*", "mcp:*.dev", "mcp:*.*.acme.dev",
		"mcp:https://acme.dev", "mcp:acme.dev:8443", "mcp:acme.dev/path", "github:acme/*", ""} {
		if _, err := ParseManaged([]byte("version: 1\nrepository_exception_scopes:\n  - \"" + bad + "\"\n")); err == nil {
			t.Errorf("%q: parsed", bad)
		}
	}
	if _, err := Parse([]byte("version: 1\nrepository_exception_scopes:\n  - npm:@acme/*\n")); err == nil {
		t.Error("a repository's file names scopes")
	}
	repo := mustParse(t, `version: 1
exceptions:
  - {package: "npm:@acme/cli", reason: ours, expires: 2027-06-01}
  - {package: "npm:@acmex/cli", reason: ours, expires: 2027-06-01}
  - {package: "npm:@tools/one", reason: ours, expires: 2027-06-01}
  - {package: "npm:@tools/two", reason: ours, expires: 2027-06-01}
  - {package: "npm:acme-helpers", reason: ours, expires: 2027-06-01}
  - {package: "pypi:acme-tools", reason: ours, expires: 2027-06-01}
  - {mcp_server: "https://api.acme.dev/mcp", reason: ours, expires: 2027-06-01}
  - {mcp_server: "https://acme.dev/mcp", reason: ours, expires: 2027-06-01}
  - {mcp_server: "https://evilacme.dev/mcp", reason: ours, expires: 2027-06-01}
  - {mcp_server: "https://mcp.example.com:8443/mcp", reason: ours, expires: 2027-06-01}
  - {mcp_server: "https://evilmcp.example.com/mcp", reason: ours, expires: 2027-06-01}
  - {package: "npm:@tools/onex", reason: ours, expires: 2027-06-01}
`)
	pkg := func(name string) Hold {
		return Hold{Kind: Package, Targets: []string{name}, Reasons: []string{"new_package"}}
	}
	srv := func(u string) Hold {
		return Hold{Kind: MCPServer, Targets: []string{u}, Reasons: []string{"unverified_yet"}}
	}
	for _, c := range []struct {
		name   string
		layers []Layer
		hold   Hold
		want   Action
	}{
		{"in an npm scope", []Layer{{Source: Managed, Policy: org}, {Source: Repo, Policy: repo, TrustExceptions: true}}, pkg("npm:@acme/cli@1"), Allow},
		{"a lookalike scope", []Layer{{Source: Managed, Policy: org}, {Source: Repo, Policy: repo, TrustExceptions: true}}, pkg("npm:@acmex/cli@1"), Ask},
		{"an exact scoped name", []Layer{{Source: Managed, Policy: org}, {Source: Repo, Policy: repo, TrustExceptions: true}}, pkg("npm:@tools/one@1"), Allow},
		{"another name in that scope", []Layer{{Source: Managed, Policy: org}, {Source: Repo, Policy: repo, TrustExceptions: true}}, pkg("npm:@tools/two@1"), Ask},
		{"an unscoped name", []Layer{{Source: Managed, Policy: org}, {Source: Repo, Policy: repo, TrustExceptions: true}}, pkg("npm:acme-helpers@1"), Ask},
		{"PyPI", []Layer{{Source: Managed, Policy: org}, {Source: Repo, Policy: repo, TrustExceptions: true}}, pkg("pypi:acme-tools@1"), Ask},
		{"a subdomain", []Layer{{Source: Managed, Policy: org}, {Source: Repo, Policy: repo, TrustExceptions: true}}, srv("https://api.acme.dev/mcp"), Allow},
		{"the apex is not *.", []Layer{{Source: Managed, Policy: org}, {Source: Repo, Policy: repo, TrustExceptions: true}}, srv("https://acme.dev/mcp"), Ask},
		{"a lookalike domain", []Layer{{Source: Managed, Policy: org}, {Source: Repo, Policy: repo, TrustExceptions: true}}, srv("https://evilacme.dev/mcp"), Ask},
		{"an exact host, any port", []Layer{{Source: Managed, Policy: org}, {Source: Repo, Policy: repo, TrustExceptions: true}}, srv("https://mcp.example.com:8443/mcp"), Allow},
		{"a host that ends like the exact one", []Layer{{Source: Managed, Policy: org}, {Source: Repo, Policy: repo, TrustExceptions: true}}, srv("https://evilmcp.example.com/mcp"), Ask},
		{"a name that begins like the exact one", []Layer{{Source: Managed, Policy: org}, {Source: Repo, Policy: repo, TrustExceptions: true}}, pkg("npm:@tools/onex@1"), Ask},
		{"no scopes: nothing from the repository", []Layer{{Source: Managed, Policy: Policy{Version: 1}}, {Source: Repo, Policy: repo, TrustExceptions: true}}, pkg("npm:@acme/cli@1"), Ask},
		{"no organisation: nothing from the repository", []Layer{{Source: Repo, Policy: repo, TrustExceptions: true}}, pkg("npm:@acme/cli@1"), Ask},
		{"a layer of no source is bound like a repository", []Layer{{Source: Managed, Policy: org}, {Policy: repo, TrustExceptions: true}}, pkg("npm:acme-helpers@1"), Ask},
		{"the developer's own layer is not bound", []Layer{{Source: User, Policy: repo}}, pkg("pypi:acme-tools@1"), Allow},
		{"the organisation's own exceptions are not bound", []Layer{{Source: Managed, Policy: repo}}, pkg("npm:acme-helpers@1"), Allow},
		{"scopes from a layer that is not the organisation's", []Layer{{Source: User, Policy: org}, {Source: Repo, Policy: repo, TrustExceptions: true}}, pkg("npm:@acme/cli@1"), Ask},
	} {
		if got := Decide(c.layers, "hold", c.hold, now); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}
