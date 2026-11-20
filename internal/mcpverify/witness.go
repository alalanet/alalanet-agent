package mcpverify

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/alalanet/alalanet-agent/internal/tooldigest"
)

// ServiceID is the id alalanet gives a listing of protocol proto at url (store.ServiceID: the first 10 bytes of
// sha256(proto|url), in lower-case base32). The lookup sends this hash of the catalogue's spelling of the URL, never
// the URL (TestServiceIDIsTheStoresOwn proves the two the same).
func ServiceID(proto, url string) string {
	sum := sha256.Sum256([]byte(proto + "|" + url))
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:10]))
}

// witnessOutcome is alalanet's public record of a listing: listed 1, not listed -1, or 0 when it could not be asked;
// the set it serves alalanet now and the one before (GET /v1/services/{id}/tools).
type witnessOutcome struct {
	listed   int
	failed   string
	current  string
	sigs     []tooldigest.ToolSig
	previous string
}

type witness struct {
	http      *http.Client
	api       string
	userAgent string
}

type toolsAnswer struct {
	Current *struct {
		Hash  string               `json:"hash"`
		Tools []tooldigest.ToolSig `json:"tools"`
	} `json:"current"`
	Previous *struct {
		Hash string `json:"hash"`
	} `json:"previous"`
}

// ask looks the listing up by the ids of its candidate URLs, in App.lookup's order (without the query first): one GET
// per id, with no header but the User-Agent, no token and no body; the answer's descriptions are not kept.
func (w witness) ask(ctx context.Context, lookups []string) witnessOutcome {
	if len(lookups) == 0 {
		return witnessOutcome{}
	}
	for _, u := range lookups {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(w.api, "/")+"/v1/services/"+ServiceID("mcp", u)+"/tools", nil)
		if err != nil {
			return witnessOutcome{failed: "ALALANET_API is not a URL"}
		}
		req.Header.Set("User-Agent", w.userAgent)
		req.Header.Set("Accept", "application/json")
		resp, err := w.http.Do(req)
		if err != nil {
			return witnessOutcome{failed: "alalanet could not be reached"}
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, maxToolsBody+1))
		resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusNotFound:
			continue
		case resp.StatusCode != http.StatusOK || err != nil || len(b) > maxToolsBody:
			return witnessOutcome{failed: "alalanet did not answer as it does"}
		}
		var a toolsAnswer
		if json.Unmarshal(b, &a) != nil {
			return witnessOutcome{failed: "alalanet did not answer as it does"}
		}
		out := witnessOutcome{listed: 1}
		if a.Current != nil && hex64(a.Current.Hash) {
			out.current = a.Current.Hash
			out.sigs = a.Current.Tools // their descriptions are not kept (keep)
		}
		if a.Previous != nil && hex64(a.Previous.Hash) {
			out.previous = a.Previous.Hash
		}
		return out
	}
	return witnessOutcome{listed: -1}
}

func hex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	return strings.Trim(s, "0123456789abcdef") == ""
}
