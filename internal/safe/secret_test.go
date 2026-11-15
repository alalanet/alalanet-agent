package safe

import (
	"strings"
	"testing"
)

// The known credential shapes (ADR-0171): what the log's backstop refuses and what the catalogue's rule and
// a listing's published form treat as a key. Every token here is built from parts or plainly fake: gitleaks
// reads this file.

func TestTokenShapeFindsKnownCredentials(t *testing.T) {
	bech := "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	for name, s := range map[string]string{
		"a Nostr secret key":           "nsec1" + strings.Repeat(bech, 2)[:58],
		"a PEM private key":            "-----BEGIN " + "EC PRIVATE KEY-----",
		"an AWS access key":            "AK" + "IA" + "IOSFODNN7" + "EXAMPLE",
		"an OpenAI key":                "sk-" + "proj-" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv",
		"an Anthropic key":             "sk-" + "ant-" + "api03-" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv",
		"a GitHub token":               "gh" + "p_" + strings.Repeat("aB3d", 9),
		"a GitHub fine-grained token":  "github" + "_pat_" + strings.Repeat("aB3d_", 9),
		"a Slack token":                "xo" + "xb-" + "1234567890123-1234567890123-AbCdEfGhIjKl",
		"an alalanet bearer token":     "al" + "n_" + strings.Repeat("Ab1-", 6),
		"an Ethereum private key":      "private_key" + "=" + "0x" + strings.Repeat("ab12", 16),
		"a GitLab personal token":      "gl" + "pat-" + "fAkE1" + strings.Repeat("x", 15),
		"a GitLab deploy token":        "gl" + "dt-" + "fAkE1" + strings.Repeat("x", 15),
		"a Stripe secret key":          "sk_" + "live_" + "51Hc9d2Q8vX",
		"a Stripe restricted test key": "rk_" + "test_" + "51Hc9d2Q8vX",
		"a Google API key":             "AI" + "za" + "SyD-9tSrke72" + strings.Repeat("Q", 23),
		"a JWT":                        "ey" + "JhbGciOiJIUzI1NiJ9" + ".ey" + "JzdWIiOiIxMjM0NTY3ODkwIn0" + ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
		"an npm token":                 "np" + "m_" + strings.Repeat("aB3d", 9),
		"a webhook secret":             "wh" + "sec_" + strings.Repeat("0f", 24),
		"a Slack webhook":              "https://hooks.slack.com/services/" + "T0123ABCD/B0123ABCD/" + strings.Repeat("aB3d", 6),
		"a Telegram bot token":         "bot123456789:" + "AA" + strings.Repeat("Hd", 16) + "x",
	} {
		for _, in := range []string{s, "https://x.example/pay?k=" + s, "text " + s + " text"} {
			if got := TokenShape(in); got == "" {
				t.Errorf("%s: TokenShape(%q) found nothing", name, in)
			}
			if got := Credential(in); got == "" {
				t.Errorf("%s: Credential(%q) found nothing", name, in)
			}
		}
	}
}

func TestTokenShapeLeavesPublicValues(t *testing.T) {
	for _, s := range []string{
		"sk-translator-plugin-for-mcp-servers", // an npm name: lower case, no digit
		"install:npm:@scope/name@1.2.3",
		"https://www.npmjs.com/package/@scope/name",
		"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
		"0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		"550e8400-e29b-41d4-a716-446655440000",
		"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
		"bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
		"skill_source_not_checked:gitlab",
		"added: get_secret, create_token, rotate_api_key",
		"data:application/json;base64,eyJuYW1lIjoiYWdlbnQifQ==", // base64 JSON is no JWT
		"xoxo-gossip-girl-fan-club",
		"sha256 " + strings.Repeat("ab12", 16),
		"https://hosait.example/mcp?auth=REDACTED",
	} {
		if got := TokenShape(s); got != "" {
			t.Errorf("TokenShape(%q) = %q", s, got)
		}
		if got := Credential(s); got != "" {
			t.Errorf("Credential(%q) = %q", s, got)
		}
	}
}

func TestCredentialFindsAUserInAURL(t *testing.T) {
	for s, want := range map[string]bool{
		"https://user:pw@x.example/pay":              true,
		"https://user@x.example/pay":                 true,
		"ssh://git@git.corp/team/skills.git":         true,
		"install:skill-source:https://a:b@h/x@git":   true,
		"see HTTPS://U:P@X.EXAMPLE now":              true,
		"https://x.example/@scope/pkg":               false,
		"https://x.example?q=a@b":                    false,
		"https://x.example#a@b":                      false,
		"git@github.com:owner/repo.git":              false, // the scp form names the SSH user, not a key: the F1 fix drops it anyway
		"mailto:info@alalanet.com":                   false,
		"write to info@alalanet.com":                 false,
		"https://x.example/a%40b":                    false,
		"https://www.npmjs.com/package/@scope/a@1.0": false,
	} {
		if got := Credential(s) != ""; got != want {
			t.Errorf("Credential(%q) = %v, want %v", s, got, want)
		}
	}
}

// RedactTokens masks a token shape in third-party text and leaves the rest, the mixed-case rule kept: an npm
// name that starts with sk- stays (ADR-0171, round 2).
func TestRedactTokens(t *testing.T) {
	gh := "gh" + "p_" + strings.Repeat("aB3d", 9)
	sk := "sk-" + "proj-" + "AbCdEf0123456789GhIjKlMnOp"
	for in, want := range map[string]string{
		"added: delete_all_files, " + sk:             "added: delete_all_files, REDACTED",
		"initialize error: token " + gh + " refused": "initialize error: token REDACTED refused",
		"sk-translator-plugin-for-mcp-servers":       "sk-translator-plugin-for-mcp-servers",
		"HTTP 503 (text/html)":                       "HTTP 503 (text/html)",
	} {
		got := RedactTokens(in)
		if got != want {
			t.Errorf("RedactTokens(%q) = %q, want %q", in, got, want)
		}
		if TokenShape(got) != "" {
			t.Errorf("RedactTokens(%q) left a shape: %q", in, got)
		}
	}
}

// Round 3 (X4): a URL with a user part in third-party text loses the user part, so Credential finds nothing left.
func TestRedactTokensDropsAUserInAQuotedURL(t *testing.T) {
	for in, want := range map[string]string{
		"maintenance, see https://status" + "@seller.example/": "maintenance, see https://seller.example/",
		"acme://ops" + "@seller.example":                       "acme://seller.example",
		"git via ssh://git:pw" + "@host.example/r.git now":     "git via ssh://host.example/r.git now",
		"write to ops@seller.example":                          "write to ops@seller.example",
	} {
		got := RedactTokens(in)
		if got != want || Credential(got) != "" {
			t.Errorf("RedactTokens(%q) = %q, want %q", in, got, want)
		}
	}
}
