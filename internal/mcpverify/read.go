package mcpverify

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/alalanet/alalanet-agent/internal/netguard"
	"github.com/alalanet/alalanet-agent/internal/safe"
	"github.com/alalanet/alalanet-agent/internal/tooldigest"
	"github.com/alalanet/alalanet-agent/internal/urlrule"
)

// The protocol versions alalanet's prober speaks (internal/prober/check.go): the legacy handshake, and the first
// stateless revision, whose servers refuse initialize.
const (
	protoLegacy = "2025-06-18"
	protoModern = "2026-07-28"
	maxInitBody = 64 << 10
	// maxToolsBody: the prober's own cap on a tools/list answer (1 MiB); a longer one is not read, never a match.
	maxToolsBody = 1 << 20
)

// readOutcome is what one anonymous read of a server's tools/list gave.
type readOutcome struct {
	design string // why the server cannot be read by design (auth, stdio, SSE, a private host); "" otherwise
	failed string // why the read failed this time; "" otherwise
	hash   string
	sigs   []tooldigest.ToolSig
	flags  []string
	scope  string // tools/list cacheScope (2026-07-28): public or private
	ttlMs  int64
	descs  []sig // per tool sha256(name 0x00 description), for the agent's copy (agentview.go)
}

// plan is what of a configured URL is used: the URL read (without user info, a fragment or a query that is not plain
// inputs, so the read is anonymous) and the listing URLs it may be looked up as (their ids, never the URLs, are sent).
type plan struct {
	design  string // the URL is not read at all, and why
	read    string
	lookups []string
}

// planURL decides what of a configured URL leaves the machine (ADR-0171's publication rule, stricter): nothing for a
// private host, a plain http URL, a URL that names an environment variable or one that carries a key in its path (a
// segment that looks random) or a known token shape anywhere (urlrule.SecretBearing). A host whose label only looks
// random (Cloud Run, Lambda function URLs, previews) is read, pinned and looked up as any other: the runtime connects
// there itself, and the lookup sends a hash of the URL, which cannot be inverted (review N1). The read drops the user info, the fragment and a query that is not plain inputs; the lookup is the
// catalogue's spelling of the URL (catalog.CleanURL: the host in lower case, no fragment), never for a URL with user
// info or a fragment, and with its query only when the query is plain inputs.
func planURL(raw string) plan {
	if strings.Contains(raw, "${") {
		return plan{design: "its URL names an environment variable"}
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return plan{design: "its URL cannot be read"}
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		return plan{design: "it is reached over plain http"}
	default:
		return plan{design: "its URL is not an https URL"}
	}
	host := strings.ToLower(u.Hostname())
	if urlrule.PrivateHost(host) {
		return plan{design: "its host is not a public DNS name"}
	}
	base := url.URL{Scheme: "https", Host: strings.ToLower(u.Host), Path: u.Path, RawPath: u.RawPath}
	if urlrule.SecretBearing(base.String()) {
		return plan{design: "its host or path looks like it carries a key"}
	}
	p := plan{read: base.String()}
	withQuery := ""
	if u.RawQuery != "" && urlrule.QuerySafe(raw) && !urlrule.SecretBearing(raw) {
		q := base
		q.RawQuery = u.RawQuery
		p.read, withQuery = q.String(), q.String()
	}
	if u.User != nil || u.Fragment != "" || u.RawFragment != "" {
		return p // read anonymously; never looked up
	}
	if port := u.Port(); port != "" && port != "443" && port != "8443" {
		return p // the catalogue lists none
	}
	for _, c := range []string{base.String(), withQuery} {
		if c != "" && safe.EscapeHidden(c) == c {
			p.lookups = append(p.lookups, c)
		}
	}
	return p
}

// reader reads tools/list anonymously, as alalanet-agent: its own client identity, no headers of the configuration.
type reader struct {
	http      *http.Client
	userAgent string
}

// newReadClient is a client that connects to public addresses only (netguard), follows no redirect and sends no
// cookie; allowPrivate is for tests only.
func newReadClient(userAgent string, allowPrivate bool) *http.Client {
	c := netguard.Client(netguard.Options{AllowPrivate: allowPrivate, UserAgent: userAgent, NoReuse: true})
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

// message is one JSON-RPC response as the MCP clients read it (tooldigest.Members: exact names, the last of a
// repeated name whole).
type message struct {
	result, err json.RawMessage
	ambiguous   bool
}

// post sends one JSON-RPC message and returns the response with id want (none for a notification), the session the
// server gave, and the status.
func (r reader) post(ctx context.Context, target, body string, headers map[string]string, want int64, limit int64) (*message, string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(body))
	if err != nil {
		return nil, "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("User-Agent", r.userAgent)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return nil, "", 0, err
	}
	defer resp.Body.Close()
	session := resp.Header.Get("Mcp-Session-Id")
	if want < 0 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, session, resp.StatusCode, nil
	}
	body2 := io.LimitReader(resp.Body, limit+1)
	var m *message
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Type"))), "text/event-stream") {
		m, err = readSSE(body2, want, limit)
	} else {
		var b []byte
		if b, err = io.ReadAll(body2); err == nil {
			if int64(len(b)) > limit {
				err = errTooLong
			} else {
				m = pick(b, want)
			}
		}
	}
	return m, session, resp.StatusCode, err
}

var errTooLong = errors.New("the answer is longer than alalanet-agent reads")

// readSSE reads an event stream until the response with id want: it does not wait for the stream to end.
func readSSE(r io.Reader, want int64, limit int64) (*message, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), int(limit)+1)
	var data bytes.Buffer
	var read int64
	flush := func() *message {
		defer data.Reset()
		if data.Len() == 0 {
			return nil
		}
		return pick(data.Bytes(), want)
	}
	for sc.Scan() {
		line := sc.Bytes()
		if read += int64(len(line)) + 1; read > limit {
			return nil, errTooLong
		}
		switch {
		case len(line) == 0:
			if m := flush(); m != nil {
				return m, nil
			}
		case bytes.HasPrefix(line, []byte("data:")):
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.Write(bytes.TrimPrefix(bytes.TrimPrefix(line, []byte("data:")), []byte(" ")))
		}
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, errTooLong
		}
		return nil, err
	}
	return flush(), nil
}

var envelope = tooldigest.Names("id", "result", "error", "method")

// pick is msg when it is the response to request want: no method, a result or an error, and the request's own integer
// as its id.
func pick(msg []byte, want int64) *message {
	msg = bytes.TrimSpace(msg)
	if !json.Valid(msg) || len(msg) == 0 || msg[0] != '{' {
		return nil
	}
	var v [4]json.RawMessage
	amb, err := tooldigest.Members(msg, envelope, v[:])
	if err != nil || v[3] != nil || (v[1] == nil && v[2] == nil) || len(v[0]) == 0 || v[0][0] == '"' {
		return nil
	}
	if f, err := strconv.ParseFloat(string(v[0]), 64); err != nil || f != float64(want) {
		return nil
	}
	m := &message{result: v[1], ambiguous: amb}
	if v[2] != nil && string(v[2]) != "null" {
		m.err = v[2]
	}
	return m
}

// errorCode is a JSON-RPC error's code and message.
func errorCode(e json.RawMessage) (int, string) {
	var v [2]json.RawMessage
	if _, err := tooldigest.Members(e, tooldigest.Names("code", "message"), v[:]); err != nil {
		return 0, ""
	}
	var code int
	var msg string
	_ = tooldigest.DecodeFields(v[:], &code, &msg)
	return code, msg
}

// modernOnly: the answer to the legacy initialize comes from a server that speaks only the stateless protocol (the
// prober's modernOnly).
func modernOnly(status int, m *message) bool {
	if (status != http.StatusOK && status != http.StatusBadRequest && status != http.StatusNotFound) || m == nil || m.err == nil {
		return false
	}
	code, msg := errorCode(m.err)
	switch code {
	case -32601, -32022, -32020:
		return true
	}
	msg = strings.ToLower(msg)
	return strings.Contains(msg, "unsupported protocol version") || strings.Contains(msg, "unsupported mcp protocol version")
}

func designStatus(code int) bool {
	return code == http.StatusUnauthorized || code == http.StatusForbidden || code == http.StatusPaymentRequired
}

// read reads the server's tools/list once, anonymously: initialize, notifications/initialized and tools/list (or one
// stateless tools/list for a server of 2026-07-28 and later), then digests the list with tooldigest, the instructions
// judged with the tools as the prober judges them.
func (r reader) read(ctx context.Context, target, version string) readOutcome {
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"` + protoLegacy +
		`","capabilities":{},"clientInfo":{"name":"alalanet-agent","version":"` + jsonText(version) + `"}}}`
	m, session, status, err := r.post(ctx, target, init, map[string]string{"MCP-Protocol-Version": protoLegacy}, 1, maxInitBody)
	switch {
	case netguard.IsBlocked(err):
		return readOutcome{design: "its host resolves to an address that is not public"}
	case err != nil:
		return readOutcome{failed: failure(err)}
	case designStatus(status):
		return readOutcome{design: "it needs authorization (HTTP " + strconv.Itoa(status) + ")"}
	}
	var tools *message
	var instructions tooldigest.Instructions
	switch {
	case modernOnly(status, m):
		req := `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"` + protoModern +
			`","io.modelcontextprotocol/clientInfo":{"name":"alalanet-agent","version":"` + jsonText(version) + `"},"io.modelcontextprotocol/clientCapabilities":{}}}}`
		tools, _, status, err = r.post(ctx, target, req, map[string]string{"MCP-Protocol-Version": protoModern, "Mcp-Method": "tools/list"}, 2, maxToolsBody)
	case status != http.StatusOK:
		return readOutcome{failed: "HTTP " + strconv.Itoa(status) + " to initialize"}
	case m == nil || m.err != nil || len(m.result) == 0:
		if m != nil && m.err != nil {
			if code, msg := errorCode(m.err); code == -32001 || strings.Contains(strings.ToLower(msg), "auth") {
				return readOutcome{design: "it needs authorization"}
			}
		}
		return readOutcome{failed: "no answer to initialize"}
	default:
		if m.ambiguous {
			return readOutcome{failed: "its answer reads differently to different MCP clients"}
		}
		var v [1]json.RawMessage
		_, _ = tooldigest.Members(m.result, tooldigest.Names("protocolVersion"), v[:])
		var negotiated string
		_ = tooldigest.DecodeFields(v[:], &negotiated)
		// As the prober reads them (FN10-C1 round 3): a repeated name whose last value is null gives the Go SDK
		// client's text, and every string the name gives is judged.
		instructions = tooldigest.ReadInstructions(m.result)
		if len(negotiated) != 10 {
			negotiated = protoLegacy
		}
		h := map[string]string{"MCP-Protocol-Version": negotiated}
		if session != "" {
			h["Mcp-Session-Id"] = session
		}
		if _, _, _, err = r.post(ctx, target, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, h, -1, 0); err == nil {
			tools, _, status, err = r.post(ctx, target, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`, h, 2, maxToolsBody)
		}
		if session != "" {
			defer r.close(ctx, target, h)
		}
	}
	switch {
	case err != nil:
		return readOutcome{failed: failure(err)}
	case designStatus(status):
		return readOutcome{design: "it needs authorization (HTTP " + strconv.Itoa(status) + ")"}
	case status < 200 || status > 299:
		return readOutcome{failed: "HTTP " + strconv.Itoa(status) + " to tools/list"}
	case tools == nil || tools.err != nil || len(tools.result) == 0:
		return readOutcome{failed: "no tools/list result"}
	case tools.ambiguous:
		return readOutcome{failed: "its answer reads differently to different MCP clients"}
	}
	return digestList(tools.result, instructions)
}

// digestList digests a tools/list result. A list that is not the whole list (another page, more than MaxTools tools,
// a member that reads differently to different clients) is not read: it is never a match.
func digestList(result json.RawMessage, instructions tooldigest.Instructions) readOutcome {
	list, cursor, amb, err := tooldigest.ReadList(result)
	if err != nil {
		return readOutcome{failed: "its tools/list result is not a tool list"}
	}
	if amb {
		return readOutcome{failed: "its tool list reads differently to different MCP clients"}
	}
	if len(cursor) > 0 && string(cursor) != "null" {
		return readOutcome{failed: "its tool list has more pages than alalanet-agent reads"}
	}
	if len(list) > tooldigest.MaxTools {
		return readOutcome{failed: "its tool list is longer than alalanet-agent reads"}
	}
	st := &tooldigest.ServerText{}
	flags := instructions.Flags(st)
	hash, sigs, toolFlags, ambTools, ok := tooldigest.DigestTools(list, st)
	if !ok {
		return readOutcome{failed: "a tool of its list is not a tool"}
	}
	if ambTools {
		return readOutcome{failed: "a tool of its list reads differently to different MCP clients"}
	}
	out := readOutcome{hash: hash, sigs: sigs, flags: union(flags, toolFlags)}
	var defs []tooldigest.ToolDef
	for _, raw := range list {
		if t, _, err := tooldigest.ReadTool(raw); err == nil {
			defs = append(defs, t)
		}
	}
	out.descs = keepSigs(descSigs(defs))
	var v [2]json.RawMessage
	_, _ = tooldigest.Members(result, tooldigest.Names("cacheScope", "ttlMs"), v[:])
	var scope string
	var ttl float64
	if tooldigest.DecodeFields(v[:1], &scope) == nil && (scope == "public" || scope == "private") {
		out.scope = scope // the two values of SEP-2549; anything else is not kept (review F3)
	}
	if tooldigest.DecodeFields(v[1:], &ttl) == nil && ttl > 0 && ttl < 1e15 {
		out.ttlMs = int64(ttl)
	}
	return out
}

func (r reader) close(ctx context.Context, target string, h map[string]string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, target, nil)
	if err != nil {
		return
	}
	for k, v := range h {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", r.userAgent)
	if resp, err := r.http.Do(req); err == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
	}
}

// failure names a failed read without its URL: net/http's errors carry it.
func failure(err error) string {
	switch {
	case errors.Is(err, errTooLong):
		return "its answer is longer than alalanet-agent reads"
	case errors.Is(err, context.DeadlineExceeded):
		return "it did not answer in time"
	}
	return "it could not be reached"
}

func union(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string{}, a...), b...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// jsonText is s as the inside of a JSON string.
func jsonText(s string) string {
	b, _ := json.Marshal(s)
	return string(b[1 : len(b)-1])
}
