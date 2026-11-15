package safe

import (
	"regexp"
	"strings"
)

// Credentials in what alalanet publishes (ADR-0171). A signed statement goes into a public, append-only log
// and a page is public: a key there cannot be taken back. tokenShapes are the board's list (ADR-0038,
// internal/agents/secrets.go) and the shapes the review of 849ddec named, each specific enough not to match a
// hash, an address, a public key, an id or a package name, so that the log's backstop (attest.Sign) can refuse
// every statement that holds one. The catalogue's rule for a caller's URL (catalog.SecretBearing) and a
// listing's published form (catalog.Published) use the same list.

type tokenShape struct {
	name string
	re   *regexp.Regexp
	// mixed: the match must hold an upper-case letter, a lower-case letter and a digit. sk-… is also how an
	// npm package's name may start, and an npm name is lower case.
	mixed bool
}

var tokenShapes = []tokenShape{
	{name: "Nostr secret key (nsec)", re: regexp.MustCompile(`\bnsec1[02-9ac-hj-np-z]{58}\b`)},
	{name: "PEM private key", re: regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{name: "AWS access key", re: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{name: "OpenAI or Anthropic API key", re: regexp.MustCompile(`\bsk-(?:ant-|proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}`), mixed: true},
	{name: "GitHub token", re: regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{40,}`)},
	{name: "Slack token", re: regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`)},
	{name: "alalanet bearer token", re: regexp.MustCompile(`\baln_[A-Za-z0-9_-]{20,}`)},
	{name: "Ethereum private key", re: regexp.MustCompile(`(?i)(?:private[_ ]?key|privkey|secret)["':= ]+(?:0x)?[0-9a-f]{64}\b`)},
	{name: "GitLab token", re: regexp.MustCompile(`\bgl(?:pat|dt|rt|ptt|soat|cbt|imt|ft|agent|oas)-[A-Za-z0-9_-]{20,}`)},
	{name: "Stripe key", re: regexp.MustCompile(`\b[rs]k_(?:live|test)_[A-Za-z0-9]{10,}`)},
	{name: "Google API key", re: regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}`)},
	{name: "JSON Web Token", re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.`)},
	{name: "npm token", re: regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`)},
	{name: "PyPI token", re: regexp.MustCompile(`\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}`)},
	{name: "webhook secret", re: regexp.MustCompile(`\bwhsec_[A-Za-z0-9+/=_-]{20,}`)},
	{name: "Slack webhook", re: regexp.MustCompile(`hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9_/-]{20,}`)},
	{name: "Discord webhook", re: regexp.MustCompile(`discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]{30,}`)},
	{name: "Telegram bot token", re: regexp.MustCompile(`\b(?:bot)?[0-9]{8,10}:AA[A-Za-z0-9_-]{33}\b`)},
}

// urlUser: a URL with a user or password (scheme://user[:password]@host). The run before "@" holds no "/",
// "?" or "#": https://host/@scope/pkg and https://host/?q=a@b name no user.
var urlUser = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^/?#@\s"'<>\\]*@`)

// TokenShape names the first known token shape in s, or "".
func TokenShape(s string) string {
	for _, sh := range tokenShapes {
		for _, m := range sh.re.FindAllString(s, -1) {
			if !sh.mixed || mixedCase(m) {
				return sh.name
			}
		}
	}
	return ""
}

// Credential names the first credential in s, a URL with a user or password or a known token shape, or "".
func Credential(s string) string {
	if urlUser.MatchString(s) {
		return "a user or password in a URL"
	}
	return TokenShape(s)
}

// RedactTokens is s with every known token shape (tokenShapes, the mixed-case rule kept) shown as REDACTED, and the
// user part of every URL it quotes dropped (scheme://user@host reads scheme://host): what Credential finds is gone. It is
// for text a statement quotes that a third party wrote — a server's tool and serverInfo names, its error
// messages and payment terms, a public repository's file paths and names (ADR-0171, round 2): the author of
// such text must not be able to veto alalanet's signed record of itself by putting a token shape in it, so
// the shape is masked, while Attester.Sign still refuses one anywhere else.
func RedactTokens(s string) string {
	for _, sh := range tokenShapes {
		s = sh.re.ReplaceAllStringFunc(s, func(m string) string {
			if sh.mixed && !mixedCase(m) {
				return m
			}
			return "REDACTED"
		})
	}
	// A user or password in a URL the text quotes is dropped: the URL reads scheme://host (round 3, X4).
	return urlUser.ReplaceAllStringFunc(s, func(m string) string { return m[:strings.Index(m, "://")+3] })
}

func mixedCase(s string) bool {
	return strings.ContainsAny(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") && strings.ContainsAny(s, "abcdefghijklmnopqrstuvwxyz") && strings.ContainsAny(s, "0123456789")
}
