// Package repopolicy reads a repository's alalanet policy file (.alalanet.yml) and an organisation's or a developer's
// policy in the same form, and applies them to a verdict alalanet already gave (REPO-POL-1, ADR-0174).
//
// The file says only what no runtime or package manager says natively (docs/audits/2026-11-12-research/REPO-POL-1.md,
// question 1): what to do with alalanet's hold per kind (ask, the default, or deny); exceptions to a hold, each with a
// reason and an expiry; and the payment receivers an agent may pay, with a ceiling per call. Cooldowns, denied MCP
// servers, allowed extensions and denied shell commands stay in their native knobs.
//
// The file is data: it runs nothing, sends nothing and holds no token. The installed hook reads it locally, so its
// contents never reach alalanet's server. When layers disagree the stricter answer wins: a block is never relaxed, a
// deny from any layer stands, and a repository's tightening applies at once while its exceptions apply only where the
// developer or the organisation trusts them (as Claude Code applies a project's deny and ask rules at once and its allow
// rules after workspace trust).
//
// No state, no store, no network.
//
// The F-round of the review of 2950215 (ADR-0174 round 2): every zero value is the safe one. A layer of no known source
// applies no exceptions; a hold carries its reason codes, and an exception covers only the codes in coverable, so a hold
// of no codes, or of a code added later, is not covered.
package repopolicy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/alalanet/alalanet-agent/internal/safe"
)

const (
	// FileName is the policy file at a repository's root.
	FileName = ".alalanet.yml"
	// Version is the only version this reader knows; any other is refused, never guessed.
	Version       = 1
	MaxBytes      = 64 << 10
	MaxExceptions = 200
	MaxReceivers  = 100
	maxReason     = 300
	maxMicroUSD   = 1_000_000 * 1_000_000 // a million dollars a call: anything above is a typo
)

// Action is a policy's answer, in the hooks' words.
type Action string

const (
	Allow Action = "allow"
	Ask   Action = "ask"
	Deny  Action = "deny"
)

func rank(a Action) int {
	switch a {
	case Allow:
		return 0
	case Ask:
		return 1
	}
	return 2
}

// Kind is what a hold is about.
type Kind int

const (
	Package   Kind = iota + 1 // install targets as alalanet's reader names them: npm:name@version, pypi:name==version
	MCPServer                 // remote MCP servers by URL
)

// Source is where a policy comes from. Exceptions apply from a Managed or User layer (the organisation's or the
// developer's own word), or from any layer marked TrustExceptions; never from a Repo layer that is not, nor from a layer
// whose Source is left unset.
type Source int

const (
	Managed Source = iota + 1
	User
	Repo
)

// OnHold is what to do with alalanet's hold, per kind: Ask, Deny, or "" (this policy says nothing). Writing the default
// is not saying nothing: a layer that states ask outranks another layer's exception (Ask is stricter than Allow), so a
// developer's file with "packages: ask" cancels the organisation's exceptions for packages; leave the key out to keep
// them (review of 2950215, F7).
type OnHold struct {
	Packages, MCPServers, Payments Action
}

func (o OnHold) of(k Kind) Action {
	if k == MCPServer {
		return o.MCPServers
	}
	return o.Packages
}

// Exception turns a hold into an allow for one package (any version) or one remote MCP server, until its expiry. It
// never touches a block.
type Exception struct {
	Package   string    // npm:<name> or pypi:<name>, as written
	MCPServer string    // https://host/path, as written
	Reason    string    // why, in the team's words
	Expires   time.Time // the end of the expiry day (UTC): live while now is before it
}

// Receiver is one an agent may pay: an x402 payTo address or the host that asks for the payment.
type Receiver struct {
	PayTo, Host string
}

// Payments: a ceiling per call (micro-dollars) and the receivers an agent may pay; each applies only when set.
type Payments struct {
	HasMax             bool
	MaxPerCallMicroUSD int64
	HasReceivers       bool // receivers: [] means nobody
	Receivers          []Receiver
}

// Policy is one parsed file.
type Policy struct {
	Version    int
	OnHold     OnHold
	Exceptions []Exception
	Payments   Payments
	// TrustedRepositories: in the organisation's policy only (ParseManaged), the repositories whose own exceptions
	// apply, as host/owner/name or host/prefix/* in lower case (round 2).
	TrustedRepositories []string
	// RepositoryExceptionsNever: in the organisation's policy only, "repository_exceptions: never" — no repository's
	// exceptions apply, whoever trusts them (Decide; trusted_repositories is then without effect).
	RepositoryExceptionsNever bool
	// RepositoryExceptionScopes: in the organisation's policy only, what a trusted repository's exceptions may name
	// (round 4, S2): npm:@scope/* or npm:@scope/name (a scope only its owner publishes in), mcp:host or mcp:*.domain (a
	// domain the organisation holds). A repository's exception outside them never applies; with none, none does. PyPI
	// has no namespaces: its exceptions stay in the organisation's own file. Trusting a repository trusts every branch
	// checked out of it and every edit of its working tree, so a trusted exception can name only what the organisation
	// owns.
	RepositoryExceptionScopes []string
}

// MaxAhead caps an exception's expiry: one that ends more than a year (366 days) after now is not in force, as if it
// had none (review of 2950215, F7: 9999-12-31 is no expiry).
const MaxAhead = 366 * 24 * time.Hour

// Live is the exceptions in force at now: not past their expiry, and not expiring more than MaxAhead after now.
func (p Policy) Live(now time.Time) []Exception {
	var out []Exception
	for _, e := range p.Exceptions {
		if now.Before(e.Expires) && e.Expires.Sub(now) <= MaxAhead {
			out = append(out, e)
		}
	}
	return out
}

// TooFar is the exceptions whose expiry is more than MaxAhead after now: not applied.
func (p Policy) TooFar(now time.Time) []Exception {
	var out []Exception
	for _, e := range p.Exceptions {
		if e.Expires.Sub(now) > MaxAhead {
			out = append(out, e)
		}
	}
	return out
}

// Expired is the exceptions past their expiry at now.
func (p Policy) Expired(now time.Time) []Exception {
	var out []Exception
	for _, e := range p.Exceptions {
		if !now.Before(e.Expires) {
			out = append(out, e)
		}
	}
	return out
}

type rawPolicy struct {
	Version *int `yaml:"version"`
	OnHold  struct {
		Packages   string `yaml:"packages"`
		MCPServers string `yaml:"mcp_servers"`
		Payments   string `yaml:"payments"`
	} `yaml:"on_hold"`
	Exceptions []struct {
		Package   string `yaml:"package"`
		MCPServer string `yaml:"mcp_server"`
		Reason    string `yaml:"reason"`
		Expires   string `yaml:"expires"`
	} `yaml:"exceptions"`
	Payments struct {
		Max       *string `yaml:"max_per_call_usd"`
		Receivers *[]struct {
			PayTo string `yaml:"pay_to"`
			Host  string `yaml:"host"`
		} `yaml:"receivers"`
	} `yaml:"payments"`
	TrustedRepositories  *[]string `yaml:"trusted_repositories"`
	RepositoryExceptions *string   `yaml:"repository_exceptions"`
	ExceptionScopes      *[]string `yaml:"repository_exception_scopes"`
}

var (
	npmName   = regexp.MustCompile(`^(@[A-Za-z0-9][A-Za-z0-9._~-]*/)?[A-Za-z0-9][A-Za-z0-9._~-]*$`)
	pypiName  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$`)
	pypiSep   = regexp.MustCompile(`[-_.]+`)
	evmAddr   = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
	solAddr   = regexp.MustCompile(`^[1-9A-HJ-NP-Za-km-z]{32,44}$`)
	hostName  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	usdAmount = regexp.MustCompile(`^[0-9]{1,7}(\.[0-9]{1,6})?$`)
	// npmScope: npm:@scope/* or npm:@scope/name, in lower case (the registry's scoped names are).
	npmScope = regexp.MustCompile(`^npm:@[a-z0-9][a-z0-9._~-]*/(\*|[a-z0-9][a-z0-9._~-]*)$`)
	// npmVersion: a semver version, range or dist-tag, without spaces (npm's own range syntax joins with spaces, which
	// alalanet's reader never puts in one target).
	npmVersion = regexp.MustCompile(`^[A-Za-z0-9.^~<>=*|x+-]+$`)
	// pypiRest: [extras] then a PEP 440 specifier list (~= == != <= >= < > ===, versions with * and local parts), or
	// "@" and a version as install_check names a target (pypi:name@1.0; F7) — never "@" and a URL.
	pypiRest = regexp.MustCompile(`^(\[[A-Za-z0-9._-]+(,[A-Za-z0-9._-]+)*\])?((~=|===|==|!=|<=|>=|<|>)[A-Za-z0-9.*+!_-]+(,(~=|===|==|!=|<=|>=|<|>)[A-Za-z0-9.*+!_-]+)*|@[0-9][A-Za-z0-9.+!_-]*)?$`)
	// repoPattern: host/owner/name… or host/owner…/* (at least one path segment before the *).
	repoPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(/[a-z0-9._~-]+)+(/\*)?$`)
	singleLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
	// TokenLike is an alalanet plan token (billing.TokenPrefix, then base32): never in this file.
	TokenLike = regexp.MustCompile(`aln_[a-z2-7]{16,}`)
)

// Parse reads a repository's policy file strictly: one YAML document, a mapping at the top, no anchors or aliases, no
// duplicate or unknown keys, version 1, every value checked. An error names what is wrong, never a token. A repository
// never trusts itself: trusted_repositories is refused here.
func Parse(b []byte) (Policy, error) { return parse(b, false) }

// ParseManaged reads the organisation's policy: what Parse reads, and trusted_repositories.
func ParseManaged(b []byte) (Policy, error) { return parse(b, true) }

func parse(b []byte, managed bool) (Policy, error) {
	if len(b) > MaxBytes {
		return Policy{}, fmt.Errorf("the file is over %d bytes", MaxBytes)
	}
	var doc yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return Policy{}, errors.New("the file is empty")
		}
		return Policy{}, errors.New("not YAML: " + clean(err.Error()))
	}
	var more yaml.Node
	if err := dec.Decode(&more); !errors.Is(err, io.EOF) {
		return Policy{}, errors.New("one YAML document only")
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return Policy{}, errors.New("the top of the file is a mapping (version: 1, …)")
	}
	if err := plainNodes(doc.Content[0]); err != nil {
		return Policy{}, err
	}
	var raw rawPolicy
	strict := yaml.NewDecoder(bytes.NewReader(b))
	strict.KnownFields(true)
	if err := strict.Decode(&raw); err != nil {
		return Policy{}, errors.New(clean(err.Error()))
	}
	if raw.Version == nil || *raw.Version != Version {
		return Policy{}, fmt.Errorf("version: %d is the only version this reader knows", Version)
	}
	p := Policy{Version: Version}
	var err error
	if p.OnHold.Packages, err = onHold("packages", raw.OnHold.Packages); err != nil {
		return Policy{}, err
	}
	if p.OnHold.MCPServers, err = onHold("mcp_servers", raw.OnHold.MCPServers); err != nil {
		return Policy{}, err
	}
	if p.OnHold.Payments, err = onHold("payments", raw.OnHold.Payments); err != nil {
		return Policy{}, err
	}
	if len(raw.Exceptions) > MaxExceptions {
		return Policy{}, fmt.Errorf("exceptions: at most %d", MaxExceptions)
	}
	for i, r := range raw.Exceptions {
		e := Exception{Package: strings.TrimSpace(r.Package), MCPServer: strings.TrimSpace(r.MCPServer), Reason: strings.TrimSpace(r.Reason)}
		at := fmt.Sprintf("exceptions[%d]", i)
		switch {
		case (e.Package == "") == (e.MCPServer == ""):
			return Policy{}, errors.New(at + ": exactly one of package or mcp_server")
		case e.Package != "":
			if packageSpec(e.Package) == "" {
				return Policy{}, errors.New(at + ": package is npm:<name> or pypi:<name>, without a version")
			}
		default:
			if serverSpec(e.MCPServer) == "" {
				return Policy{}, errors.New(at + ": mcp_server is an https URL without user, query or fragment")
			}
		}
		if err := reasonOK(e.Reason); err != nil {
			return Policy{}, errors.New(at + ": reason " + err.Error())
		}
		day, err := time.Parse(time.DateOnly, strings.TrimSpace(r.Expires))
		if err != nil {
			return Policy{}, errors.New(at + ": expires is a date, YYYY-MM-DD")
		}
		e.Expires = day.Add(24 * time.Hour)
		p.Exceptions = append(p.Exceptions, e)
	}
	if m := raw.Payments.Max; m != nil {
		v, ok := microUSD(strings.TrimSpace(*m))
		if !ok {
			return Policy{}, errors.New("payments.max_per_call_usd: dollars with at most six decimals, up to 1000000")
		}
		p.Payments.HasMax, p.Payments.MaxPerCallMicroUSD = true, v
	}
	if rs := raw.Payments.Receivers; rs != nil {
		if len(*rs) > MaxReceivers {
			return Policy{}, fmt.Errorf("payments.receivers: at most %d", MaxReceivers)
		}
		p.Payments.HasReceivers = true
		for i, r := range *rs {
			at := fmt.Sprintf("payments.receivers[%d]", i)
			rc := Receiver{PayTo: strings.TrimSpace(r.PayTo), Host: strings.ToLower(strings.TrimSpace(r.Host))}
			switch {
			case (rc.PayTo == "") == (rc.Host == ""):
				return Policy{}, errors.New(at + ": exactly one of pay_to or host")
			case rc.PayTo != "" && !evmAddr.MatchString(rc.PayTo) && !solAddr.MatchString(rc.PayTo):
				return Policy{}, errors.New(at + ": pay_to is a 0x address or a base58 one")
			case rc.Host != "" && (len(rc.Host) > 253 || !hostName.MatchString(rc.Host)):
				return Policy{}, errors.New(at + ": host is a host name, without scheme, port or path")
			}
			p.Payments.Receivers = append(p.Payments.Receivers, rc)
		}
	}
	if tr := raw.TrustedRepositories; tr != nil {
		if !managed {
			return Policy{}, errors.New("trusted_repositories: only the organisation's policy trusts repositories, never a repository's own file")
		}
		if len(*tr) > MaxReceivers {
			return Policy{}, fmt.Errorf("trusted_repositories: at most %d", MaxReceivers)
		}
		for i, r := range *tr {
			r = strings.ToLower(strings.TrimSpace(r))
			if !repoPattern.MatchString(r) || strings.Contains("/"+r+"/", "/../") || strings.Contains("/"+r+"/", "/./") || strings.HasSuffix(r, ".git") {
				return Policy{}, fmt.Errorf("trusted_repositories[%d]: host/owner/name or host/owner/*, without scheme, user, port or .git", i)
			}
			p.TrustedRepositories = append(p.TrustedRepositories, r)
		}
	}
	if re := raw.RepositoryExceptions; re != nil {
		switch {
		case !managed:
			return Policy{}, errors.New("repository_exceptions: only the organisation's policy says whether repositories' exceptions apply")
		case strings.TrimSpace(*re) != "never":
			return Policy{}, errors.New("repository_exceptions: never is its only value (leave it out to apply the exceptions of trusted_repositories)")
		}
		p.RepositoryExceptionsNever = true
	}
	if sc := raw.ExceptionScopes; sc != nil {
		if !managed {
			return Policy{}, errors.New("repository_exception_scopes: only the organisation's policy bounds repositories' exceptions")
		}
		if len(*sc) > MaxReceivers {
			return Policy{}, fmt.Errorf("repository_exception_scopes: at most %d", MaxReceivers)
		}
		for i, s := range *sc {
			s = strings.ToLower(strings.TrimSpace(s))
			host, mcp := strings.CutPrefix(s, "mcp:")
			if mcp {
				host = strings.TrimPrefix(host, "*.")
			}
			if mcp && strings.HasPrefix(s, "mcp:*.") && publicSuffix(host) {
				return Policy{}, fmt.Errorf("repository_exception_scopes[%d]: %s is a public suffix or a host anyone can rent a name under: name the organisation's own domain", i, s)
			}
			if !npmScope.MatchString(s) && !(mcp && len(host) <= 253 && hostName.MatchString(host)) {
				return Policy{}, fmt.Errorf("repository_exception_scopes[%d]: npm:@scope/* or npm:@scope/name, mcp:host or mcp:*.domain (PyPI has no scopes; its exceptions stay in this file)", i)
			}
			p.RepositoryExceptionScopes = append(p.RepositoryExceptionScopes, s)
		}
	}
	return p, nil
}

// publicSuffix: a domain under which anyone can hold a name — a country's generic second level (co.uk, com.au, ac.jp:
// a generic label under a two-letter top level) or a host platform's shared suffix (rentable). A heuristic, not the
// Public Suffix List, which the agent does not carry (round 5): it refuses the scopes a mistype would make wide open.
func publicSuffix(domain string) bool {
	labels := strings.Split(domain, ".")
	if len(labels) == 2 && len(labels[1]) == 2 && genericSLD[labels[0]] {
		return true
	}
	for _, r := range rentable {
		// below amazonaws.com and on.aws a region or a service label comes first (s3.amazonaws.com, lambda-url.<region>.on.aws)
		if domain == r || strings.HasSuffix(domain, "."+r) && (r == "amazonaws.com" || r == "on.aws") {
			return true
		}
	}
	return false
}

var genericSLD = map[string]bool{"co": true, "com": true, "net": true, "org": true, "gov": true, "govt": true, "edu": true, "ac": true,
	"ne": true, "or": true, "go": true, "gob": true, "mil": true, "nom": true, "sch": true, "ltd": true, "plc": true, "gen": true,
	"biz": true, "info": true, "me": true, "nic": true, "web": true, "firm": true, "ind": true, "int": true, "ed": true, "gr": true,
	"gv": true, "priv": true, "res": true, "lg": true, "nhs": true, "police": true, "mod": true}

// rentable: shared suffixes of host platforms, where a name below is anyone's for the asking (Public Suffix List,
// private section, the most common).
var rentable = []string{"github.io", "gitlab.io", "vercel.app", "netlify.app", "pages.dev", "workers.dev", "herokuapp.com",
	"onrender.com", "fly.dev", "web.app", "firebaseapp.com", "appspot.com", "azurewebsites.net", "azurestaticapps.net",
	"cloudfront.net", "amazonaws.com", "ngrok.io", "ngrok.app", "ngrok-free.app", "trycloudflare.com", "glitch.me", "repl.co",
	"replit.app", "replit.dev", "deno.dev", "supabase.co", "railway.app", "up.railway.app", "modal.run", "hf.space",
	"blogspot.com", "wordpress.com", "surge.sh", "now.sh", "run.app", "cloudfunctions.net", "azure-api.net", "on.aws"}

// inScopes: the exception names a package or a server inside one of the organisation's scopes.
func inScopes(scopes []string, e Exception) bool {
	key, host := packageSpec(e.Package), ""
	if e.Package == "" {
		key = ""
		if u, err := url.Parse(serverSpec(e.MCPServer)); err == nil && serverSpec(e.MCPServer) != "" {
			host = u.Hostname()
		}
	}
	for _, s := range scopes {
		switch {
		case key != "" && strings.HasSuffix(s, "/*"):
			if strings.HasPrefix(key, strings.TrimSuffix(s, "*")) {
				return true
			}
		case key != "" && strings.HasPrefix(s, "npm:"):
			if key == s {
				return true
			}
		case host != "" && strings.HasPrefix(s, "mcp:*."):
			if strings.HasSuffix(host, "."+strings.TrimPrefix(s, "mcp:*.")) {
				return true
			}
		case host != "" && strings.HasPrefix(s, "mcp:"):
			if host == strings.TrimPrefix(s, "mcp:") {
				return true
			}
		}
	}
	return false
}

// TrustsRepository: the policy's trusted_repositories name the repository id (RepositoryID): exactly, or under a
// host/prefix/* entry (anything deeper than the prefix). An empty id is never trusted.
func (p Policy) TrustsRepository(id string) bool {
	if id == "" {
		return false
	}
	for _, r := range p.TrustedRepositories {
		if prefix, ok := strings.CutSuffix(r, "*"); ok {
			if strings.HasPrefix(id, prefix) && len(id) > len(prefix) {
				return true
			}
		} else if id == r {
			return true
		}
	}
	return false
}

// RepositoryID is a git remote's address as host/path in lower case, without scheme, user, password, port, trailing
// slash or .git: https://github.com/Acme/App.git and git@github.com:acme/app both are github.com/acme/app. A local path
// or file:// address, or one with a "." or ".." segment, has no id ("").
func RepositoryID(remote string) string {
	s := strings.TrimSpace(remote)
	var host, path string
	if scheme, rest, ok := strings.Cut(s, "://"); ok {
		switch strings.ToLower(scheme) {
		case "https", "http", "ssh", "git", "git+ssh", "ssh+git":
		default:
			return ""
		}
		u, err := url.Parse("x://" + rest)
		if err != nil {
			return ""
		}
		host, path = u.Hostname(), u.Path
	} else {
		// scp-like: [user@]host:path, where no slash comes before the colon (git's own rule); a drive letter is a path.
		before, after, ok := strings.Cut(s, ":")
		if !ok {
			return "" // a path; a host with a slash or a drive letter fails the host check below
		}
		if i := strings.LastIndexByte(before, '@'); i >= 0 {
			before = before[i+1:]
		}
		if len(before) < 2 {
			return ""
		}
		host, path = before, after
	}
	host = strings.ToLower(host)
	path = strings.TrimSuffix(strings.Trim(strings.ToLower(path), "/"), ".git")
	id := host + "/" + path
	if host == "" || path == "" || !hostName.MatchString(host) && !singleLabel.MatchString(host) || strings.ContainsAny(path, `\ `) {
		return ""
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return ""
		}
	}
	return id
}

// plainNodes refuses, anywhere in the document: anchors and aliases, merge keys (<<, a second spelling of a key), any
// explicit tag (!!binary, !!timestamp, a custom one: what the file shows would not be its value), duplicate keys, and a
// value that looks like a token (tokenLike). version is the plain number 1, not 0x1 or +1.
func plainNodes(n *yaml.Node) error {
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return errors.New("anchors and aliases are not read here")
	}
	if n.Style&yaml.TaggedStyle != 0 {
		return fmt.Errorf("line %d: an explicit tag (%s) is not read here", n.Line, clean(n.Tag))
	}
	if n.Kind == yaml.ScalarNode && tokenLike(n.Value) {
		return fmt.Errorf("line %d: a value holds a token; tokens never go in this file (rotate it)", n.Line)
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			key := n.Content[i]
			if key.Tag == "!!merge" || key.Value == "<<" {
				return fmt.Errorf("line %d: a merge key (<<) is not read here", key.Line)
			}
			if seen[key.Value] {
				return fmt.Errorf("line %d: the key %q twice", key.Line, clean(key.Value))
			}
			seen[key.Value] = true
			if key.Value == "version" && n.Content[i+1].Kind == yaml.ScalarNode && n.Content[i+1].Value != "1" {
				return fmt.Errorf("version: %d is the only version this reader knows", Version)
			}
		}
	}
	for _, c := range n.Content {
		if err := plainNodes(c); err != nil {
			return err
		}
	}
	return nil
}

func onHold(name, v string) (Action, error) {
	switch a := Action(strings.TrimSpace(v)); a {
	case "", Ask, Deny:
		return a, nil
	}
	return "", errors.New("on_hold." + name + ": ask or deny (a hold is never turned into an allow here; use an exception)")
}

func reasonOK(r string) error {
	switch {
	case r == "":
		return errors.New("is required")
	case !utf8.ValidString(r) || utf8.RuneCountInString(r) > maxReason:
		return fmt.Errorf("is text of at most %d characters", maxReason)
	case tokenLike(r):
		return errors.New("holds an alalanet plan token: tokens never go in this file (rotate it)")
	}
	// What the repository's instruction files are held for (safe.Text, safe.Unseen): no character that is not seen, no
	// line break of any kind, no combining mark without a letter before it.
	if cleaned, _ := safe.Text(r); cleaned != r || safe.Unseen(r) > 0 {
		return errors.New("has a control or invisible character")
	}
	for i, c := range r {
		if unicode.IsControl(c) || unicode.In(c, unicode.Zl, unicode.Zp) || i == 0 && unicode.Is(unicode.M, c) {
			return errors.New("has a control or invisible character")
		}
	}
	return nil
}

// tokenLike: an alalanet plan token (TokenLike), or a token of a shape safe.RedactTokens knows (GitHub, cloud keys …).
func tokenLike(s string) bool { return TokenLike.MatchString(s) || safe.RedactTokens(s) != s }

// microUSD reads dollars with at most six decimals as micro-dollars.
func microUSD(s string) (int64, bool) {
	if !usdAmount.MatchString(s) {
		return 0, false
	}
	whole, frac, _ := strings.Cut(s, ".")
	w, _ := strconv.ParseInt(whole, 10, 64)
	f, _ := strconv.ParseInt((frac + "000000")[:6], 10, 64)
	v := w*1_000_000 + f
	return v, v <= maxMicroUSD
}

// packageSpec is the key of an exception's package: "npm:<name>" exactly, or "pypi:<normalised name>"; "" when it is
// not a bare registry name of an ecosystem this file knows.
func packageSpec(s string) string {
	eco, name, _ := strings.Cut(s, ":")
	switch {
	case eco == "npm" && npmName.MatchString(name):
		return "npm:" + name
	case eco == "pypi" && pypiName.MatchString(name):
		return "pypi:" + pypiNorm(name)
	}
	return ""
}

// pypiNorm is PEP 503's normalised name.
func pypiNorm(n string) string { return pypiSep.ReplaceAllString(strings.ToLower(n), "-") }

// packageTarget is the key of an install target alalanet's reader names (npm:@scope/name@1.2.0, pypi:name[extra]>=2):
// its ecosystem and bare name when what follows the name is, by a strict grammar, a registry version, range or tag
// (npm: npmVersion after one "@") or extras and a PEP 440 specifier list (PyPI: pypiRest); "" for anything else — a
// git, URL or file source, an alias, an option, a space — which no exception covers.
func packageTarget(t string) string {
	eco, rest, _ := strings.Cut(t, ":")
	switch eco {
	case "npm":
		name := rest
		if i := strings.IndexByte(rest[min(1, len(rest)):], '@'); i >= 0 {
			name = rest[:i+1]
			if !npmVersion.MatchString(rest[i+2:]) {
				return ""
			}
		}
		return "npm:" + name // a name no exception has never matches one
	case "pypi":
		end := strings.IndexFunc(rest, func(c rune) bool {
			return !(c < utf8.RuneSelf && (c == '.' || c == '_' || c == '-' || unicode.IsLetter(c) || unicode.IsDigit(c)))
		})
		name, more := rest, ""
		if end >= 0 {
			name, more = rest[:end], rest[end:]
		}
		if !pypiName.MatchString(name) || !pypiRest.MatchString(more) {
			return ""
		}
		return "pypi:" + pypiNorm(name)
	}
	return ""
}

// serverSpec is the key of an exception's MCP server: https, the host in lower case without the default port, the path
// without a trailing slash; "" when it is not such a URL or carries a user, a query or a fragment.
func serverSpec(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(s, "#") {
		return ""
	}
	return serverKey(u)
}

// serverTarget is the key of a server's URL as a hold names it (its query is not part of who the server is).
func serverTarget(s string) string {
	s = strings.TrimPrefix(s, "remote-mcp:") // the form install_check and the hook's answer name a remote server by
	u, err := url.Parse(s)
	if err != nil {
		return ""
	}
	return serverKey(u)
}

func serverKey(u *url.URL) string {
	if !strings.EqualFold(u.Scheme, "https") || u.User != nil || u.Host == "" || u.Opaque != "" {
		return ""
	}
	host := strings.TrimSuffix(strings.ToLower(u.Host), ":443")
	return "https://" + host + strings.TrimRight(u.EscapedPath(), "/")
}

// Hold is what alalanet held: its kind, its targets, and the reason codes alalanet gave for it (install_check's, the
// readers' unread:… and check_incomplete:… among them). An exception covers a hold only when every code is one
// coverable names for the kind; no codes, or one it does not name (a registry moved, a maintainer changed, a code
// added later), is not covered.
type Hold struct {
	Kind    Kind
	Targets []string
	Reasons []string
}

// coverable: the codes an exception ("this package is ours", "this server is approved") may cover — what makes a
// package or a server unknown, not what says it changed or could not be read. An entry ending in ":" covers that code
// with any detail (name_like_official:<name>).
var coverable = map[Kind][]string{
	Package:   {"new_package", "runs_install_script", "name_like_official:"},
	MCPServer: {"unverified_yet"},
}

// Coverable reports whether an exception may cover a hold of kind k with reason code.
func Coverable(k Kind, code string) bool {
	for _, c := range coverable[k] {
		if prefix, ok := strings.CutSuffix(c, ":"); ok {
			if rest, ok := strings.CutPrefix(code, prefix+":"); ok && rest != "" {
				return true
			}
		} else if code == c {
			return true
		}
	}
	return false
}

func reasonsCoverable(k Kind, codes []string) bool {
	if len(codes) == 0 {
		return false
	}
	for _, c := range codes {
		if !Coverable(k, c) {
			return false
		}
	}
	return true
}

// Layer is one policy and where it comes from.
type Layer struct {
	Source          Source
	Policy          Policy
	TrustExceptions bool // a Repo layer's exceptions apply only when the developer or the organisation trusts them
}

func (l Layer) exceptionsApply() bool {
	return l.Source == Managed || l.Source == User || l.TrustExceptions
}

// Decide applies the layers to alalanet's verdict for an install or a server (allow, hold or block). A block is Deny and
// an allow is Allow whatever the layers say; a hold (or a verdict this package does not know, read as a hold no
// exception covers) is each layer's opinion — Allow when its live exceptions cover every target, else its on_hold for
// the kind, else none — and the strictest opinion wins; with no opinion, Ask.
func Decide(layers []Layer, verdict string, h Hold, now time.Time) Action {
	switch verdict {
	case "allow":
		return Allow
	case "block":
		return Deny
	case "hold":
	default:
		h.Reasons = nil // a verdict this package does not know: no exception covers it
	}
	// The organisation's word on every layer that is neither its own nor the developer's (a repository's, or one of no
	// source): repository_exceptions: never, and the scopes such a layer's exceptions must stay in (round 4, S2).
	repoNever, scopes := false, []string(nil)
	for _, l := range layers {
		if l.Source == Managed {
			repoNever = repoNever || l.Policy.RepositoryExceptionsNever
			scopes = append(scopes, l.Policy.RepositoryExceptionScopes...)
		}
	}
	var out Action
	for _, l := range layers {
		op := l.Policy.OnHold.of(h.Kind)
		bound := l.Source != Managed && l.Source != User
		live := l.Policy.Live(now)
		if bound {
			var in []Exception
			for _, e := range live {
				if !repoNever && inScopes(scopes, e) {
					in = append(in, e)
				}
			}
			live = in
		}
		if l.exceptionsApply() && reasonsCoverable(h.Kind, h.Reasons) && covered(live, h) {
			op = Allow
		}
		if op != "" && (out == "" || rank(op) > rank(out)) {
			out = op
		}
	}
	if out == "" {
		return Ask
	}
	return out
}

func covered(live []Exception, h Hold) bool {
	if len(h.Targets) == 0 {
		return false
	}
	for _, t := range h.Targets {
		key := ""
		switch h.Kind {
		case Package:
			key = packageTarget(t)
		case MCPServer:
			key = serverTarget(t)
		}
		if !excepted(live, h.Kind, key) {
			return false
		}
	}
	return true
}

// excepted: an exception of the kind names the key (an exception that is not one Parse takes names nothing).
func excepted(live []Exception, k Kind, key string) bool {
	for _, e := range live {
		spec := serverSpec(e.MCPServer)
		if k == Package {
			spec = packageSpec(e.Package)
		}
		if spec != "" && spec == key {
			return true
		}
	}
	return false
}

// Payment is one payment an agent is about to make: the x402 payTo, the host asking, and the amount in micro-dollars
// (AmountKnown false when it could not be read as dollars).
type Payment struct {
	PayTo, Host string
	MicroUSD    int64
	AmountKnown bool
}

// DecidePayment applies the layers to alalanet's verdict for a payment. A block is Deny. Every layer's ceiling and
// receivers bind (an unknown amount under a ceiling, or a receiver none of a layer's entries names, is Deny); a listed
// receiver never relaxes a hold, which is the strictest on_hold.payments, else Ask.
func DecidePayment(layers []Layer, verdict string, p Payment) Action {
	if verdict == "block" {
		return Deny
	}
	known := p.AmountKnown && p.MicroUSD >= 0
	for _, l := range layers {
		pay := l.Policy.Payments
		if pay.HasMax && (!known || p.MicroUSD > pay.MaxPerCallMicroUSD) {
			return Deny
		}
		if pay.HasReceivers && !listed(pay.Receivers, p) {
			return Deny
		}
	}
	if verdict == "allow" {
		return Allow
	}
	var out Action
	for _, l := range layers {
		if op := l.Policy.OnHold.Payments; op != "" && (out == "" || rank(op) > rank(out)) {
			out = op
		}
	}
	if out == "" {
		return Ask
	}
	return out
}

func listed(rs []Receiver, p Payment) bool {
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(p.Host)), ".")
	payTo := strings.TrimSpace(p.PayTo)
	for _, r := range rs {
		switch {
		case r.PayTo != "" && payTo != "" && evmAddr.MatchString(r.PayTo) && evmAddr.MatchString(payTo) && strings.EqualFold(r.PayTo, payTo):
			return true
		case r.PayTo != "" && payTo != "" && !evmAddr.MatchString(r.PayTo) && r.PayTo == payTo:
			return true
		case r.Host != "" && host != "" && r.Host == host:
			return true
		}
	}
	return false
}

// clean keeps an error's text on one line, bounded, without a token.
func clean(s string) string {
	s = TokenLike.ReplaceAllString(s, "aln_…")
	s = strings.Join(strings.Fields(s), " ")
	return clip(s)
}

func clip(s string) string {
	if utf8.RuneCountInString(s) <= 120 {
		return s
	}
	return string([]rune(s)[:120]) + "…"
}
