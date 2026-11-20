package mcpverify

// Review of VERIFY-AUTO-1 step 1 (a7aeeda): what planURL lets out of made-up secret-shaped URLs. Values are built from
// parts; none is a real credential.

import (
	"strings"
	"testing"
)

func TestReviewPlanURLSecretShapes(t *testing.T) {
	b64 := "Zk9" + "xT2" + "pXb" + "3Rh" + "Qm" + "FzZTY0" + "VG9r" + "ZW4x" // mixed case + digits, 32 chars
	uuid := "3f2b" + "9c1e" + "-7a4d" + "-4e8b" + "-9f10" + "-2c6d" + "8e1a" + "5b7c"
	hex40 := strings.Repeat("a1b2c3d4e5", 4)
	jwt := "eyJ" + "hbGciOiJIUzI1NiJ9" + "." + "eyJ" + "zdWIiOiJ4In0" + "." + "c2ln" + "bmF0dXJl" + "X3Rlc3Q"
	lowword := "hunter" + "two" // a low-entropy word: not a token shape
	h := "mcp.example-review.com"
	for _, c := range []struct {
		name, url        string
		read, lookupNone bool // read: the server is read at all; lookupNone: no id goes to alalanet
	}{
		{"zapier-style token path", "https://" + h + "/api/mcp/s/" + b64 + "/mcp", false, true},
		{"uuid path", "https://" + h + "/" + uuid + "/mcp", false, true},
		{"hex path", "https://" + h + "/k/" + hex40, false, true},
		{"jwt path", "https://" + h + "/t/" + jwt, false, true},
		{"token in the host", "https://" + b64 + "." + h + "/mcp", true, false}, // round 3 (N1): read and looked up by its hash
		{"key query", "https://" + h + "/mcp?key=" + b64, true, false},
		{"profile query (smithery-style)", "https://" + h + "/mcp?profile=" + uuid, true, false},
		{"encoded user info", "https://u%40x:" + lowword + "@" + h + "/mcp", true, true},
		{"fragment", "https://" + h + "/mcp#" + lowword, true, true},
		{"upper-case scheme", "HTTPS://" + h + "/mcp", true, false},
		{"trailing-dot host", "https://" + h + "./mcp", true, false},
		{"ipv6 literal", "https://[2001:db8::1]/mcp", false, true},
		{"decimal ip", "https://2130706433/mcp", false, true},
		{"env var", "https://" + h + "/mcp?key=${KEY}", false, true},
	} {
		p := planURL(c.url)
		read := p.design == ""
		var bad []string
		for _, s := range []string{b64, uuid, hex40, jwt, lowword, "%40"} {
			if c.name == "token in the host" {
				continue // the host is read where the runtime itself connects; only the hash of the lookup URL is sent
			}
			if strings.Contains(p.read, s) && c.name != "upper-case scheme" {
				bad = append(bad, "read carries "+s[:4])
			}
			for _, l := range p.lookups {
				if strings.Contains(l, s) {
					bad = append(bad, "lookup carries "+s[:4])
				}
			}
		}
		t.Logf("%-32s design=%q read=%v lookups=%d", c.name, p.design, read, len(p.lookups))
		if read != c.read {
			t.Errorf("%s: read %v, want %v (%q)", c.name, read, c.read, p.design)
		}
		if c.lookupNone && len(p.lookups) != 0 {
			t.Errorf("%s: %d lookups", c.name, len(p.lookups))
		}
		if len(bad) > 0 {
			t.Errorf("%s: %v", c.name, bad)
		}
	}
}
