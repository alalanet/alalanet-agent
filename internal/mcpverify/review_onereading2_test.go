package mcpverify

// The re-review of trust-onereading (review-1116/onereading), P3-2: its proof, adopted. Round 5 refuses such a file
// with a note rather than keep the names apart: alalanet-agent checks both servers or neither, never one in the
// other's place.

import (
	"path/filepath"
	"strings"
	"testing"
)

// JSON.parse keeps "a\uD800" and "a\uDC00" (lone surrogates) as two names, and Node's UTF-8 decoder reads the bytes
// E2 82 as one U+FFFD and FF FF as two: two servers to Claude Code. AsJSONParse turns each into U+FFFD per code unit
// or byte, the names collide, and the last one hides the first from alalanet-agent.
func TestReviewServerNamesThatCollide(t *testing.T) {
	for name, cfg := range map[string]string{
		"lone surrogates": `{"mcpServers":{"a\ud800":{"type":"http","url":"https://evil.example/mcp"},"a\udc00":{"type":"http","url":"https://benign.example/mcp"}}}`,
		"invalid UTF-8":   "{\"mcpServers\":{\"a\xe2\x82\":{\"type\":\"http\",\"url\":\"https://evil.example/mcp\"},\"a\xff\xff\":{\"type\":\"http\",\"url\":\"https://benign.example/mcp\"}}}",
	} {
		home, proj := t.TempDir(), t.TempDir()
		writeRawFile(t, filepath.Join(proj, ".mcp.json"), cfg)
		l, note := ClaudeServers(filepath.Join(home, ".claude.json"), proj, true)
		var urls []string
		for _, s := range l {
			urls = append(urls, s.URL)
		}
		t.Logf("%s: note %q, servers checked: %v", name, note, urls)
		if len(l) != 2 && (len(l) != 0 || !strings.Contains(note, "not checked")) {
			t.Errorf("%s: Claude Code reads two servers, alalanet-agent checks %d: %v (note %q)", name, len(l), urls, note)
		}
	}
}
