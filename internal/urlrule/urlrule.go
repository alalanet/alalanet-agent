// Package urlrule says what of a URL may leave a machine or be published (ADR-0171), without the store: whether a URL
// carries a credential, whether its query holds plain inputs only, how a listing's URL is published, and which hosts
// are no public DNS name. internal/catalog and internal/app publish with it; alalanet-agent decides with it what of a
// configured MCP server's URL it may look up at alalanet (VERIFY-AUTO-1).
package urlrule

import (
	"net"
	"net/url"
	"strings"

	"github.com/alalanet/alalanet-agent/internal/safe"
)

// SecretBearing reports whether a URL looks like it carries a credential (ADR-0171): a user or password; a
// known token shape anywhere in it (safe.TokenShape: the host too); a query or fragment pair named like a key
// or token (camelCase split: apiToken, secretKey), a bare token as a pair, or a value that looks random; a
// path segment or path parameter that does. The query and the fragment are split on "&" and ";" as written:
// Go's own parser drops a pair that holds a ";", and with it the name that would have been read. A URL that
// does not parse is treated as one that carries a key. Such URLs may be probed for the caller who sent them
// but are never catalogued or signed: the catalogue and the log are public.
func SecretBearing(raw string) bool { return secretBearing(raw, 2) }

// secretBearing reads a URL given as a query value (?next=https://…) at most depth levels down.
func secretBearing(raw string, depth int) bool {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || safe.TokenShape(raw) != "" {
		return true
	}
	for _, seg := range strings.Split(u.EscapedPath(), "/") {
		s, err := url.PathUnescape(seg)
		if err != nil {
			return true
		}
		if tokenIn(s) || safe.TokenShape(s) != "" {
			return true
		}
		// path parameters: /pay;jsessionid=…
		if _, params, ok := strings.Cut(s, ";"); ok {
			for _, p := range splitPairs(params) {
				if secretPair(p, depth) {
					return true
				}
			}
		}
	}
	for _, part := range []string{u.RawQuery, u.EscapedFragment()} {
		for _, p := range splitPairs(part) {
			if secretPair(p, depth) {
				return true
			}
		}
	}
	return false
}

// splitPairs splits a query or a fragment into its pairs on "&" and ";", as written.
func splitPairs(q string) []string {
	return strings.FieldsFunc(q, func(r rune) bool { return r == '&' || r == ';' })
}

// secretPair: a pair whose name is a credential's, a bare token, or a value that looks like one.
func secretPair(p string, depth int) bool {
	rawName, rawValue, hasValue := strings.Cut(p, "=")
	name, err1 := url.QueryUnescape(rawName)
	value, err2 := url.QueryUnescape(rawValue)
	if err1 != nil || err2 != nil {
		return true
	}
	if credentialName(name) || tokenIn(name) || safe.TokenShape(name) != "" {
		return true
	}
	if !hasValue {
		return false
	}
	if strings.Contains(value, "://") {
		return depth > 0 && secretBearing(value, depth-1) // a URL: read as one, not as a token
	}
	return tokenIn(value) || safe.TokenShape(value) != ""
}

// credentialWords: names, joined (api_key and apiKey are apikey) or as one word of a name (x-api-key,
// X-Amz-Signature, accessToken).
var credentialWords = map[string]bool{"key": true, "apikey": true, "token": true, "accesstoken": true, "authtoken": true, "secret": true,
	"clientsecret": true, "auth": true, "authorization": true, "sig": true, "signature": true, "session": true, "sessionid": true,
	"password": true, "pass": true, "passwd": true, "pwd": true, "credential": true, "credentials": true, "jwt": true, "bearer": true,
	// ADR-0171: the shapes the review of 849ddec measured and their all-lower-case spellings
	"apitoken": true, "apisecret": true, "accesskey": true, "secretkey": true, "privatekey": true, "privkey": true, "refreshtoken": true,
	"idtoken": true, "appsecret": true, "appkey": true, "authkey": true, "sessiontoken": true, "sessionkey": true, "securitytoken": true,
	"signingkey": true, "masterkey": true, "passphrase": true, "mnemonic": true, "jsessionid": true, "phpsessid": true, "sid": true, "cookie": true}

// publicNames: names whose words include a credential's but which name public values (a wallet's public key,
// a token contract on a chain, a search keyword).
var publicNames = map[string]bool{"publickey": true, "pubkey": true, "tokenid": true, "tokenaddress": true, "tokensymbol": true,
	"tokenmint": true, "keyword": true, "keywords": true}

func credentialName(k string) bool {
	joined := strings.NewReplacer("_", "", "-", "", ".", "").Replace(strings.ToLower(k))
	if publicNames[joined] {
		return false
	}
	if credentialWords[joined] {
		return true
	}
	for _, w := range nameWords(k) {
		if credentialWords[w] {
			return true
		}
	}
	return false
}

// nameWords: a name's words in lower case, split at every character that is not a letter or a digit and at a
// change to upper case (apiToken: api, token; AWSAccessKeyId: aws, access, key, id).
func nameWords(k string) []string {
	var words []string
	var w []rune
	rs := []rune(k)
	flush := func() {
		if len(w) > 0 {
			words = append(words, strings.ToLower(string(w)))
			w = w[:0]
		}
	}
	for i, r := range rs {
		lower, upper, digit := r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9'
		switch {
		case !lower && !upper && !digit:
			flush()
			continue
		case upper && i > 0 && (rs[i-1] >= 'a' && rs[i-1] <= 'z' || rs[i-1] >= '0' && rs[i-1] <= '9'):
			flush() // apiToken
		case upper && i > 0 && rs[i-1] >= 'A' && rs[i-1] <= 'Z' && i+1 < len(rs) && rs[i+1] >= 'a' && rs[i+1] <= 'z':
			flush() // AWSAccess
		}
		w = append(w, r)
	}
	flush()
	return words
}

// tokenRune: the characters of a token, standard base64 and base64url included (a "/" inside a value).
func tokenRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_.~=+/", r)
}

// tokenIn: a run of token characters in s that looks random (a ":" or a "," between runs: bot<id>:<token>).
func tokenIn(s string) bool {
	for _, run := range strings.FieldsFunc(s, func(r rune) bool { return !tokenRune(r) }) {
		if TokenLike(run) {
			return true
		}
	}
	return false
}

// TokenLike: 16 to 4096 token characters that look random (ADR-0171): upper case, lower case and a digit
// (a nanoid is 21); or 24 or more of two of these classes with two digits (the rule before, which flags a
// UUID, a hex hash or a ULID too); or 24 or more of mixed case with few vowels, a token without digits
// (GetWeatherForecastForCity has words, and their vowels). Public on-chain identifiers, 0x and 40 or 64 hex
// digits, are not secrets.
func TokenLike(s string) bool {
	if len(s) < 16 || len(s) > 4096 {
		return false
	}
	if (strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X")) && (len(s) == 42 || len(s) == 66) && strings.Trim(s[2:], "0123456789abcdefABCDEF") == "" {
		return false
	}
	var lower, upper, digit, vowel int
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			lower++
		case r >= 'A' && r <= 'Z':
			upper++
		case r >= '0' && r <= '9':
			digit++
		case tokenRune(r):
			continue
		default:
			return false
		}
		if strings.ContainsRune("aeiouAEIOU", r) {
			vowel++
		}
	}
	classes := 0
	for _, n := range []int{lower, upper, digit} {
		if n > 0 {
			classes++
		}
	}
	switch {
	case upper > 0 && lower > 0 && digit > 0:
		return true
	case len(s) >= 24 && classes >= 2 && digit >= 2:
		return true
	case len(s) >= 24 && upper >= 3 && lower >= 3 && 10*vowel < 3*(upper+lower):
		return true
	}
	return false
}

// plainInputs are the query names a URL no listing names may keep in what alalanet publishes (ADR-0171): inputs
// that say nothing of an account or a person. A search term, a place finer than a city, an id or an address is
// not among them: what a caller typed there is the caller's.
var plainInputs = map[string]bool{
	"format": true, "output": true, "lang": true, "language": true, "locale": true, "units": true, "unit": true, "currency": true,
	"vs_currency": true, "limit": true, "offset": true, "page": true, "per_page": true, "page_size": true, "pagesize": true, "size": true,
	"count": true, "sort": true, "order": true, "detail": true, "details": true, "pretty": true, "verbose": true, "version": true, "v": true,
	"mode": true, "type": true, "category": true, "interval": true, "period": true, "days": true, "range": true, "window": true,
	"network": true, "chain": true, "symbol": true, "symbols": true, "asset": true, "coin": true, "pair": true, "ticker": true,
	"city": true, "country": true, "date": true, "since": true, "until": true, "start": true, "end": true, "tools": true, "model": true,
}

// QuerySafe reports whether a URL's query holds plain inputs only (ADR-0171): every pair a name from
// plainInputs, its value at most 128 characters, with no "@" (an address of mail), no "://" (a URL) and nothing
// SecretBearing would read as a key. A URL without a query is safe; one that does not parse is not. Only such a
// query of a URL no listing names joins the catalogue or a signed statement; another is the caller's.
func QuerySafe(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	for _, p := range splitPairs(u.RawQuery) {
		rawName, rawValue, _ := strings.Cut(p, "=")
		name, err1 := url.QueryUnescape(rawName)
		value, err2 := url.QueryUnescape(rawValue)
		if err1 != nil || err2 != nil || !plainInputs[strings.ToLower(name)] || len(value) > 128 ||
			strings.Contains(value, "@") || strings.Contains(value, "://") || tokenIn(value) || safe.TokenShape(value) != "" {
			return false
		}
	}
	return true
}

// Redacted stands for a value Published leaves out.
const Redacted = "REDACTED"

// Published is a listing's URL as alalanet publishes it, in signed statements and on its pages (ADR-0171): the
// value of a query pair named like a credential (credentialName: auth, demo_token, key…), and a query pair or a
// path segment that holds a known token shape, is shown as REDACTED; a user, a password and a fragment are
// dropped. The rest is left as written, and a URL with none of these is returned unchanged. The listing itself
// stays as its catalogue publishes it: the prober reads it, and agents get it from the API. Production held two
// such listings, both from the MCP Registry: hosait.com ?auth= and app.openlmnp.fr ?demo_token= (2026-11-14).
func Published(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return raw
	}
	changed := u.User != nil || u.Fragment != ""
	segs := strings.Split(u.EscapedPath(), "/")
	for i, seg := range segs {
		s, err := url.PathUnescape(seg)
		if err != nil {
			s = seg
		}
		if safe.TokenShape(s) != "" || safe.TokenShape(seg) != "" {
			segs[i], changed = Redacted, true
		}
	}
	var q strings.Builder
	start := 0
	for i := 0; i <= len(u.RawQuery); i++ {
		if i < len(u.RawQuery) && u.RawQuery[i] != '&' && u.RawQuery[i] != ';' {
			continue
		}
		p := u.RawQuery[start:i]
		rawName, rawValue, hasValue := strings.Cut(p, "=")
		name, err1 := url.QueryUnescape(rawName)
		value, err2 := url.QueryUnescape(rawValue)
		if err1 != nil {
			name = rawName
		}
		if err2 != nil {
			value = rawValue
		}
		switch {
		case safe.TokenShape(name) != "" || safe.TokenShape(rawName) != "":
			p, changed = Redacted, true
		case hasValue && rawValue != "" && rawValue != Redacted && (credentialName(name) || safe.TokenShape(value) != "" || safe.TokenShape(rawValue) != ""):
			p, changed = rawName+"="+Redacted, true
		}
		q.WriteString(p)
		if i < len(u.RawQuery) {
			q.WriteByte(u.RawQuery[i])
		}
		start = i + 1
	}
	if !changed {
		return raw
	}
	out := u.Scheme + "://" + u.Host + strings.Join(segs, "/")
	if u.RawQuery != "" || u.ForceQuery {
		out += "?" + q.String()
	}
	return out
}

// privateSuffixes: names only private networks use (RFC 6762, RFC 8375, ICANN's never-delegated names).
var privateSuffixes = []string{".local", ".internal", ".lan", ".home", ".corp", ".localdomain", ".intranet", ".private", ".home.arpa", ".localhost"}

// PrivateHost: an IP address, a name without a dot, or a name under privateSuffixes.
func PrivateHost(h string) bool {
	h = strings.TrimSuffix(h, ".")
	if h == "" || net.ParseIP(h) != nil || !strings.Contains(h, ".") {
		return true
	}
	for _, suf := range privateSuffixes {
		if strings.HasSuffix(h, suf) {
			return true
		}
	}
	return false
}
