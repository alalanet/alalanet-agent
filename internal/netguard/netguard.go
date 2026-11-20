// Package netguard builds HTTP clients that refuse to connect to private, loopback,
// link-local and other non-public addresses (SSRF protection for the prober and claim checks).
// The check runs on the resolved IP at dial time, so DNS rebinding and redirects are covered.
// A client can also refuse hosts by name (Options.Refuse: the opt-out list), checked before every
// request by the name net/http will dial and again at the dial itself.
package netguard

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"syscall"
	"time"
)

var ErrBlocked = errors.New("destination address is not public")

var blocked = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
	"192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
	"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
	"::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23",
	"2001:db8::/32", "2002::/16", "3fff::/20", "fc00::/7", "fe80::/10", "ff00::/8",
)

// globalUnicast6 is IANA's global unicast space for IPv6: an address outside it is not public, whatever
// net/netip calls it (SEC-15). That refuses the IPv4-translated ::ffff:0:0:0/96 (SIIT, RFC 2765), the
// IPv4-compatible ::/96, site-local fec0::/10 and 5f00::/16 with every range not yet allocated.
var globalUnicast6 = netip.MustParsePrefix("2000::/3")

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// Public reports whether addr is a globally routable unicast address.
func Public(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || !addr.IsGlobalUnicast() || (addr.Is6() && !globalUnicast6.Contains(addr)) {
		return false
	}
	for _, p := range blocked {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

type Options struct {
	Timeout      time.Duration // whole request
	AllowPrivate bool          // tests only
	MaxRedirects int
	UserAgent    string
	// HeaderTimeout: how long to wait for the response headers (default 8 s). Chain RPCs that compute
	// a large eth_getLogs before answering need longer.
	HeaderTimeout time.Duration
	// NoReuse: every request opens its own connection (a new lookup, TCP and TLS handshake) and closes
	// it afterwards; no keep-alive, no HTTP/2. For the outbound sentinel, whose request must prove that
	// a new connection can be opened now: a kept connection goes on answering while the resolver or
	// every new flow fails (ADR-0134).
	NoReuse bool
	// Refuse, when set, is asked about the host of every request before it is sent, redirects
	// included, by the name net/http will dial for it (DialName), and again at every connection, by the
	// name being dialed. A host it refuses gets neither: the request fails with an error wrapping
	// ErrRefused. The prober's clients refuse the hosts on the opt-out list (OPT-1, ADR-0154).
	Refuse func(ctx context.Context, host string) bool
	// RedirectPorts: the ports a redirect may go to, over https only (nil: 443 and 8443). With
	// AllowPrivate and no RedirectPorts the scheme and port rule is lifted: local servers are plain
	// http on random ports. Tests of the rule set both.
	RedirectPorts []string
	// BodyAcrossHosts: a 307 or 308 may re-send the request's body to another host (stripped of every
	// header off the safelist). Only for clients whose bodies are public constants: the prober's.
	BodyAcrossHosts bool
	// AddressAs: a request whose URL names an IP address is sent as to this host name: its TLS handshake names and
	// verifies it (SNI, the certificate) and its Host header is it (PUBLISH-WITNESS-DEPLOY: the primary reaches the
	// standby's witness by address, its certificate by alalanet.com, as the standby's feed reaches the primary). A URL
	// that names a host is sent as it is. "": none.
	AddressAs string
	// EveryRequest: the scheme, port and userinfo rule of a redirect (https on RedirectPorts, no userinfo)
	// holds for every request, the first one too (SEC-10-FIRSTHOP). For clients whose first URLs a checked
	// server or chain data names: the prober's. Lifted with the redirect rule (AllowPrivate without
	// RedirectPorts).
	EveryRequest bool
	// OnRedirect, when set, hears of every redirect the outbound policy refused or stripped, by one of the
	// fixed names of RedirectCounters (SEC-11-COUNTERS): never a host, a URL or anything a server chose. It is
	// told once per hop, at the transport, so a hop only judged (HopRefused) is not counted.
	OnRedirect func(name string)
}

// The daily counters of the redirect policy (Options.OnRedirect), fixed names: a redirect refused for its scheme
// (CheckRedirect's refusal of a scheme other than http and https too), its port, its userinfo, the body it would
// re-send to another host, or the payment header it would carry; and a redirect followed past the chain's first
// host whose first request carried a header off the safelist (Referer aside): one that did not follow, whether
// the policy took it off or net/http did (Authorization and Cookie, for an unrelated host, before the transport
// sees the hop; ADR-0214 round 2).
const (
	CountRefusedScheme   = "out.redirect.refused.scheme"
	CountRefusedPort     = "out.redirect.refused.port"
	CountRefusedUserinfo = "out.redirect.refused.userinfo"
	CountRefusedBody     = "out.redirect.refused.body"
	CountRefusedPayment  = "out.redirect.refused.payment"
	CountStripped        = "out.redirect.stripped"
)

// RedirectCounters are every name Options.OnRedirect is told.
func RedirectCounters() []string {
	return []string{CountRefusedScheme, CountRefusedPort, CountRefusedUserinfo, CountRefusedBody, CountRefusedPayment, CountStripped}
}

// redirectCounts names the counter of each refusal a redirect can get (redirectHop's reasons).
var redirectCounts = map[string]string{
	reasonScheme: CountRefusedScheme, reasonPort: CountRefusedPort, reasonUserinfo: CountRefusedUserinfo,
	reasonBody: CountRefusedBody, reasonPayment: CountRefusedPayment,
}

// ErrPolicy wraps a request the outbound policy refused, a redirect's or (Options.EveryRequest) a first one:
// nothing was sent to its target.
var ErrPolicy = errors.New("redirect refused")

// The fixed texts of the policy's refusals (PolicyReason).
const (
	reasonScheme   = "redirect to a non-https URL refused"
	reasonPort     = "redirect to a port that is not checked refused"
	reasonUserinfo = "redirect to a URL with credentials refused"
	reasonBody     = "redirect would re-send a body to another host, refused"
	reasonPayment  = "a payment is not sent on a redirect"
	// A first request off the rule (Options.EveryRequest).
	reasonFirstScheme   = "request to a non-https URL refused"
	reasonFirstPort     = "request to a port that is not checked refused"
	reasonFirstUserinfo = "request to a URL with credentials refused"
)

var defaultRedirectPorts = []string{"443", "8443"}

// PolicyReasons are every text PolicyReason gives for a refusal.
func PolicyReasons() []string {
	return []string{reasonScheme, reasonPort, reasonUserinfo, reasonBody, reasonPayment, reasonFirstScheme, reasonFirstPort, reasonFirstUserinfo}
}

// policyError is a refusal by the redirect policy; its text is one of the fixed reasons, with no URL,
// host or address in it.
type policyError struct{ reason string }

func (e *policyError) Error() string        { return e.reason }
func (e *policyError) Is(target error) bool { return target == ErrPolicy }

// IsPolicy reports whether err came from the outbound redirect policy.
func IsPolicy(err error) bool { return errors.Is(err, ErrPolicy) }

// PolicyReason is the fixed text of a policy refusal in err, or "" when err is not one.
func PolicyReason(err error) string {
	var pe *policyError
	if errors.As(err, &pe) {
		return pe.reason
	}
	return ""
}

// acrossHosts are the only headers a redirect carries once its chain has left the first host and port:
// what describes the request, nothing that names or authorises its sender. Everything else — credentials,
// cookies, API keys, signatures, and any header added later — stays with the first host.
// Mcp-Session-Id is the remote server's own value, not ours: a listed MCP server that moved hosts with a
// 307 or 308 issues it from the new host, and every later request of the read goes to the listed URL and
// is redirected again; without it the moved server would read as down, while agents' clients (fetch
// keeps it) reach it.
var acrossHosts = map[string]bool{
	"Accept": true, "Accept-Encoding": true, "Content-Type": true, "User-Agent": true,
	"Mcp-Protocol-Version": true, "Mcp-Session-Id": true, "Origin": true,
}

// paymentHeaders never follow a redirect, on any host: a signed payment goes only where it was asked for.
var paymentHeaders = map[string]bool{"X-Payment": true, "Payment-Signature": true}

// ErrRefused wraps a request that Options.Refuse kept from its host: nothing was sent there and no
// connection was opened. It is not an answer, and not a failure of the network.
var ErrRefused = errors.New("destination refused")

// IsRefused reports whether err came from Options.Refuse.
func IsRefused(err error) bool { return errors.Is(err, ErrRefused) }

// refusingDial dials addr unless refuse turns its host away: the last check, on the name net/http
// actually dials (its own mapping of the URL's host).
func refusingDial(refuse func(context.Context, string) bool, dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		if refuse(ctx, host) {
			return nil, fmt.Errorf("%w: %s", ErrRefused, host)
		}
		return dial(ctx, network, addr)
	}
}

// DialName is the name net/http dials for a URL whose host is host: host itself when it is ASCII,
// otherwise net/http's own IDNA mapping of it (UTS #46, as its transport's canonicalAddr applies it),
// by which fullwidth letters, ideographic full stops, soft hyphens and the like become the ASCII name
// they reach. It is read from net/http: a request goes through a transport whose dialer records the
// address and refuses, so it is the running Go's mapping exactly and nothing is sent anywhere. A host
// net/http cannot map comes back as given, which is what net/http then dials.
func DialName(host string) string {
	if ascii(host) {
		return host
	}
	var addr string
	ctx := context.WithValue(context.Background(), dialNameKey{}, &addr)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://dial-name.invalid/", nil)
	if err != nil {
		return host
	}
	req.URL.Host = host
	_, _ = nameTransport.RoundTrip(req) // fails at the dial, after the address is recorded
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return host
}

func ascii(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

type dialNameKey struct{}

var errNamed = errors.New("netguard: named, not dialed")

// nameTransport only names: its dialer records the address it is asked for and refuses it.
var nameTransport = &http.Transport{
	Proxy:             nil,
	DisableKeepAlives: true,
	DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
		if p, ok := ctx.Value(dialNameKey{}).(*string); ok {
			*p = addr
		}
		return nil, errNamed
	},
}

// Client returns an http.Client whose every connection is checked by Public.
func Client(o Options) *http.Client {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   dialControl(o.AllowPrivate),
	}
	dial := dialer.DialContext
	if o.Refuse != nil {
		dial = refusingDial(o.Refuse, dial)
	}
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           dial,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: headerTimeout(o.HeaderTimeout),
	}
	if o.AddressAs != "" {
		tr.DialTLSContext = addressAsTLS(dial, o.AddressAs)
	}
	if o.NoReuse {
		tr.DisableKeepAlives, tr.ForceAttemptHTTP2 = true, false
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{} // not nil: HTTP/2 stays off
	}
	ports := o.RedirectPorts
	if ports == nil && !o.AllowPrivate {
		ports = defaultRedirectPorts
	}
	check := checkRedirect(o.MaxRedirects, nil, o.OnRedirect)
	c := &http.Client{
		Transport: uaTransport{rt: tr, ua: o.UserAgent, refuse: o.Refuse, ports: ports, bodyAcross: o.BodyAcrossHosts, every: o.EveryRequest,
			note: o.OnRedirect, addressAs: o.AddressAs},
		Timeout:       o.Timeout,
		CheckRedirect: check,
	}
	return c
}

// NoRedirects is c that follows no redirect: a 3xx comes back as the answer to the request, with nothing sent to
// its Location. Its transport, and with it every rule of c's, is c's own. For a request that carries a key, an
// Authorization header or a payment through a client that otherwise follows redirects (SEC-11-NOREDIRECT).
func NoRedirects(c *http.Client) *http.Client {
	n := *c
	n.CheckRedirect = CheckRedirect(0, nil)
	return &n
}

// SameHostOnly is c that follows a redirect only when c would, the chain's first request is a GET, and the redirect
// goes to https on that request's exact host and port; any other redirect comes back as the answer, with nothing sent to its
// Location (not a refusal: nothing is counted). For reads that carry a credential whose only redirect is its own
// host's: GitHub's token reads, whose renamed repositories answer 301 on api.github.com (ADR-0214 round 2). A
// client without a CheckRedirect keeps net/http's limit of 10.
func SameHostOnly(c *http.Client) *http.Client {
	n := *c
	next := c.CheckRedirect
	n.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if next != nil {
			if err := next(req, via); err != nil {
				return err
			}
		} else if len(via) >= 10 { // net/http's own rule when a client sets none
			return errors.New("stopped after 10 redirects")
		}
		first := via[0] // a GET stays a GET on every redirect: net/http changes only POST and other methods
		if first.Method != http.MethodGet || req.URL.Scheme != "https" || !strings.EqualFold(req.URL.Host, first.URL.Host) {
			return http.ErrUseLastResponse
		}
		return nil
	}
	return &n
}

// CheckRedirectOf is CheckRedirect for a caller that replaces c's own (a longer limit, a count of the hops): a
// redirect to a scheme other than http and https is still told to the OnRedirect of c's transport, when c is this
// package's (ADR-0214 round 2: the prober's tools/list read).
func CheckRedirectOf(c *http.Client, limit int, followed *int) func(*http.Request, []*http.Request) error {
	var note func(string)
	if t, ok := c.Transport.(uaTransport); ok {
		note = t.note
	}
	return checkRedirect(limit, followed, note)
}

// CheckRedirect is the redirect limit of Client: at most limit redirects are followed (the answer to
// the last request is then returned as it is), to http and https only; every hop's connection is
// checked as the first one is (Public, in the dialer). followed, when not nil, is set to the number of
// redirects followed so far. The rest of the redirect policy (https on 443 or 8443, headers, bodies,
// payments) is the transport's (uaTransport.redirectHop): a caller that replaces CheckRedirect keeps it.
func CheckRedirect(limit int, followed *int) func(*http.Request, []*http.Request) error {
	return checkRedirect(limit, followed, nil)
}

// checkRedirect is CheckRedirect that tells note (when not nil) of a redirect it refuses for its scheme: the
// transport never sees that one. The limit is not a refusal of the policy.
func checkRedirect(limit int, followed *int, note func(string)) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) > limit {
			return http.ErrUseLastResponse
		}
		if req.URL.Scheme != "https" && req.URL.Scheme != "http" {
			if note != nil {
				note(CountRefusedScheme)
			}
			return fmt.Errorf("redirect to scheme %q refused", req.URL.Scheme)
		}
		if followed != nil {
			*followed = len(via)
		}
		return nil
	}
}

// dialControl is the dialer's check of every address it connects to: a public one only, unless
// allowPrivate (tests and local runs).
func dialControl(allowPrivate bool) func(network, address string, _ syscall.RawConn) error {
	return func(network, address string, _ syscall.RawConn) error {
		if allowPrivate {
			return nil
		}
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrBlocked, address)
		}
		if !Public(ap.Addr()) {
			return fmt.Errorf("%w: %s", ErrBlocked, ap.Addr())
		}
		return nil
	}
}

func headerTimeout(d time.Duration) time.Duration {
	if d <= 0 {
		return 8 * time.Second
	}
	return d
}

type uaTransport struct {
	rt         http.RoundTripper
	ua         string
	refuse     func(context.Context, string) bool // Options.Refuse
	ports      []string                           // a redirect's allowed ports, over https; nil: the rule is lifted
	bodyAcross bool                               // Options.BodyAcrossHosts
	every      bool                               // Options.EveryRequest: the first request is held to ports too
	note       func(name string)                  // Options.OnRedirect
	addressAs  string                             // Options.AddressAs
}

// addressAsRoots are the roots addressAsTLS verifies against (nil: the system's); tests set their server's.
var addressAsRoots *x509.CertPool

// addressAsTLS dials TLS naming name when the address dialed is an IP literal, and as net/http would otherwise (the
// dialed host's own name).
func addressAsTLS(dial func(context.Context, string, string) (net.Conn, error), name string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		sni := host
		if net.ParseIP(host) != nil {
			sni = name
		}
		raw, err := dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		c := tls.Client(raw, &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, RootCAs: addressAsRoots}) // HTTP/1.1: the rounds are small
		if err := c.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, err
		}
		return c, nil
	}
}

// count tells t's OnRedirect of name, when it has one.
func (t uaTransport) count(name string) {
	if t.note != nil && name != "" {
		t.note(name)
	}
}

func (t uaTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	// Every request, a redirect's too and one that would go over a kept connection, is asked about
	// before it is sent: the dial's check alone would miss a connection opened before the refusal.
	if t.refuse != nil {
		if host := DialName(r.URL.Hostname()); t.refuse(r.Context(), host) {
			if r.Body != nil {
				r.Body.Close()
			}
			return nil, fmt.Errorf("%w: %s", ErrRefused, host)
		}
	}
	if r.Response != nil { // a redirect: net/http sets Response on every request it makes for one
		hop, stripped, err := t.redirectHop(r)
		if err != nil {
			t.count(redirectCounts[PolicyReason(err)])
			if r.Body != nil {
				r.Body.Close()
			}
			return nil, err
		}
		if stripped {
			t.count(CountStripped)
		}
		r = hop
	} else if err := t.firstRefusal(r.URL); err != nil {
		if r.Body != nil {
			r.Body.Close()
		}
		return nil, err
	}
	if t.ua != "" && r.Header.Get("User-Agent") == "" {
		r = r.Clone(r.Context())
		r.Header.Set("User-Agent", t.ua)
	}
	if t.addressAs != "" && net.ParseIP(r.URL.Hostname()) != nil {
		r = r.Clone(r.Context())
		r.Host = t.addressAs
	}
	return t.rt.RoundTrip(r)
}

// Guarded reports whether c's transport is this package's own, unwrapped: the one whose refusal and redirect
// policy HopRefused applies. A client it is not for (a wrapper around it included) makes HopRefused answer nil.
func Guarded(c *http.Client) bool {
	_, ok := c.Transport.(uaTransport)
	return ok
}

// FirstRefused is what c's transport would answer a first request to raw without sending it: an error wrapping
// ErrPolicy when c holds every request to the rule (Options.EveryRequest) and raw is off it; nil when it would be
// sent, when raw does not parse (the request fails its own way), and for a client that is not this package's. A
// reader that takes a budget for each read, or records what it did not read, asks it first (SEC-10-FIRSTHOP).
func FirstRefused(c *http.Client, raw string) error {
	t, ok := c.Transport.(uaTransport)
	if !ok {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	return t.firstRefusal(u)
}

// firstRefusal is the rule of a first request (Options.EveryRequest): ErrPolicy with the first request's text
// when u is off it, nil when the client does not hold first requests to it or the rule is lifted (ports nil).
func (t uaTransport) firstRefusal(u *url.URL) error {
	if !t.every || t.ports == nil {
		return nil
	}
	if reason := firstReasons[offRule(u, t.ports)]; reason != "" {
		return &policyError{reason}
	}
	return nil
}

// HopRefused is what c's transport would answer req, a redirect net/http is about to follow (CheckRedirect
// runs before the transport), without sending it: an error wrapping ErrRefused (Options.Refuse) or ErrPolicy
// (the redirect policy, redirectHop); nil when it would be sent, and for a client that is not this package's.
// A redirect hook that takes a budget for each hop asks it first, so that a hop never sent takes nothing
// (AG-1 round 3).
func HopRefused(c *http.Client, req *http.Request) error {
	t, ok := c.Transport.(uaTransport)
	if !ok {
		return nil
	}
	if t.refuse != nil {
		if host := DialName(req.URL.Hostname()); t.refuse(req.Context(), host) {
			return fmt.Errorf("%w: %s", ErrRefused, host)
		}
	}
	_, _, err := t.redirectHop(req)
	return err
}

// redirectHop is the outbound policy for one redirect (SEC-10, SEC-11), judged before anything is sent
// to its target: a payment header never follows; the target is https on an allowed port, without
// userinfo (unless the rule is lifted: t.ports nil); Referer is dropped; and once the chain has left its
// first host and port, a body is not re-sent (unless t.bodyAcross) and only the acrossHosts headers go on.
// It returns the request to send, a copy when it changes anything, and whether a header off the safelist did not
// follow: the hop is past the first host and the chain's first request carried one (Referer, which every hop
// loses, aside), whether this policy takes it off here or net/http already did.
func (t uaTransport) redirectHop(r *http.Request) (_ *http.Request, stripped bool, _ error) {
	for k := range r.Header {
		if paymentHeaders[http.CanonicalHeaderKey(k)] {
			return nil, false, &policyError{reasonPayment}
		}
	}
	if t.ports != nil {
		if reason := redirectReasons[offRule(r.URL, t.ports)]; reason != "" {
			return nil, false, &policyError{reason}
		}
	}
	r = r.Clone(r.Context())
	r.Header.Del("Referer")
	if leftFirstHost(r) {
		if r.Body != nil && r.Body != http.NoBody && !t.bodyAcross {
			return nil, false, &policyError{reasonBody}
		}
		for k := range r.Header {
			if !acrossHosts[http.CanonicalHeaderKey(k)] {
				delete(r.Header, k)
			}
		}
		stripped = offSafelist(firstRequest(r).Header)
	}
	return r, stripped, nil
}

// firstRequest is the first request of r's redirect chain, as its caller sent it.
func firstRequest(r *http.Request) *http.Request {
	for r.Response != nil && r.Response.Request != nil {
		r = r.Response.Request
	}
	return r
}

// offSafelist reports whether h holds a header that does not go on past the chain's first host (acrossHosts),
// Referer aside.
func offSafelist(h http.Header) bool {
	for k := range h {
		if k := http.CanonicalHeaderKey(k); !acrossHosts[k] && k != "Referer" {
			return true
		}
	}
	return false
}

// A URL's place against the rule of scheme, userinfo and port (offRule).
const (
	onRule = iota
	offScheme
	offUserinfo
	offPort
)

// The refusals' texts by the rule u is off, on a redirect and on a first request.
var (
	redirectReasons = [...]string{offScheme: reasonScheme, offUserinfo: reasonUserinfo, offPort: reasonPort}
	firstReasons    = [...]string{offScheme: reasonFirstScheme, offUserinfo: reasonFirstUserinfo, offPort: reasonFirstPort}
)

// offRule is which part of the outbound rule u breaks, judged in this order: its scheme is not https, it
// carries userinfo (net/http would turn it into an Authorization header), its port (443 when none is written)
// is not one of ports. onRule when it breaks none.
func offRule(u *url.URL, ports []string) int {
	if u.Scheme != "https" {
		return offScheme
	}
	if u.User != nil {
		return offUserinfo
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	if !slices.Contains(ports, port) {
		return offPort
	}
	return onRule
}

// leftFirstHost reports whether any request of r's redirect chain, r included, went to another host or
// port than the chain's first request: net/http copies the first request's headers onto every hop, so
// a chain that comes back to its first host stays stripped. Hosts are compared exactly (a sub-domain is
// another host).
func leftFirstHost(r *http.Request) bool {
	var keys []string
	for q := r; q != nil; q = q.Response.Request {
		keys = append(keys, hostPort(q.URL))
		if q.Response == nil {
			break
		}
	}
	for _, k := range keys {
		if k != keys[len(keys)-1] {
			return true
		}
	}
	return false
}

// hostPort is u's host as net/http dials it (DialName: its IDNA mapping, not Unicode case folding, which
// reads U+0130 as ASCII i while the dial goes to an xn-- name — review F1), lower case, and its port, the
// scheme's default when none is written.
func hostPort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	return strings.ToLower(DialName(u.Hostname())) + " " + port
}

// ReadLimited reads at most n bytes of the body and reports whether it was truncated.
func ReadLimited(r io.Reader, n int64) ([]byte, bool, error) {
	b, err := io.ReadAll(io.LimitReader(r, n+1))
	if int64(len(b)) > n {
		return b[:n], true, err
	}
	return b, false, err
}

// IsBlocked reports whether err came from the address guard.
func IsBlocked(err error) bool { return errors.Is(err, ErrBlocked) }

// Ctx is a helper for a bounded context.
func Ctx(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, d)
}
