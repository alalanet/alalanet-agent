package main

// Batch P3 review 1116 (ADR-0150 round 7, R7-P3-1/2): through main, every hook codex path. A block's stderr is
// exactly the JSON answer's reason and a newline; a call that goes on has exit 0 and no reason on stderr.

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestReviewP3B2CodexStderrEveryPath(t *testing.T) {
	hold := func(w http.ResponseWriter) {
		_, _ = w.Write([]byte(mustJSON(map[string]any{"hookSpecificOutput": map[string]string{
			"hookEventName": "PreToolUse", "permissionDecision": "ask", "permissionDecisionReason": "alalanet install_check: HOLD — p3b2"}})))
	}
	deny := func(w http.ResponseWriter) {
		_, _ = w.Write([]byte(mustJSON(map[string]any{"hookSpecificOutput": map[string]string{
			"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "alalanet install_check: BLOCK — p3b2"}})))
	}
	allow := func(w http.ResponseWriter) {
		_, _ = w.Write([]byte(mustJSON(map[string]any{"hookSpecificOutput": map[string]string{
			"hookEventName": "PreToolUse", "permissionDecision": "allow", "permissionDecisionReason": "fine"}})))
	}
	// a repository whose .alalanet.yml does not parse: a policy note on stderr before the answer
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".alalanet.yml"), []byte("version: 1\n\"zz-p3b2 note\": 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name   string
		input  string
		answer func(w http.ResponseWriter)
		env    []string
		block  bool
		stderr string // a non-block's stderr must contain it ("" for empty)
	}{
		{"unknown form", `{"a":1}`, nil, nil, true, ""},
		{"not an install", codexInput("Bash", "ls -la"), nil, nil, false, ""},
		{"mcp-approve", codexInput("Bash", "alalanet-agent mcp-approve x"), nil, nil, true, ""},
		{"server hold, bad policy", codexInputIn(repo, placeholderInstall), hold, nil, true, ""},
		{"server deny, bad policy", codexInputIn(repo, placeholderInstall), deny, nil, true, ""},
		{"server allow, bad policy", codexInputIn(repo, placeholderInstall), allow, nil, false, "zz-p3b2 note"},
		{"unreachable, fail closed", codexInput("Bash", placeholderInstall), func(w http.ResponseWriter) { w.WriteHeader(503) }, []string{"ALALANET_FAIL_CLOSED=1"}, true, ""},
		{"unreachable", codexInput("Bash", placeholderInstall), func(w http.ResponseWriter) { w.WriteHeader(503) }, nil, false, "goes ahead unchecked"},
	} {
		env := append([]string{"ALALANET_API=http://127.0.0.1:1"}, c.env...)
		if c.answer != nil {
			f := &fakeHook{answer: c.answer}
			srv := f.server(t)
			env = append([]string{"ALALANET_API=" + srv.URL}, c.env...)
		}
		exit, stdout, stderr := runCodexMain(t, c.input, env...)
		if c.block {
			if exit != 2 {
				t.Errorf("%s: exit %d, want 2", c.name, exit)
				continue
			}
			if want := jsonReason(t, stdout) + "\n"; stderr != want {
				t.Errorf("%s: stderr %q, want exactly the reason %q", c.name, stderr, want)
			}
			continue
		}
		if exit != 0 || stdout != "" || c.stderr == "" && stderr != "" || !strings.Contains(stderr, c.stderr) {
			t.Errorf("%s: exit %d, stdout %q, stderr %q (want it to hold %q)", c.name, exit, stdout, stderr, c.stderr)
		}
	}
}

// The batch P3 review's P3-8 (H3, H4): the hook request's header values and Host, not only their names. Accept-Encoding
// is Go's own "gzip" and the Host is ALALANET_API's: neither can carry anything of the machine (its home folder, a
// path), as /privacy says nothing else is sent.
func TestReviewP3B2HookHeaderValuesAndHost(t *testing.T) {
	token := "alalanet" + "-test-" + "token-p3b2"
	in := shellForms(placeholderInstall)["codex Bash"]
	type seen struct {
		host string
		h    http.Header
		n    int64
	}
	for name := range hookRuntimes {
		for _, tok := range []string{"", token} {
			got := make(chan seen, 4)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n, _ := io.Copy(io.Discard, r.Body)
				got <- seen{r.Host, r.Header.Clone(), n}
				_, _ = w.Write([]byte(`{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"alalanet install_check: BLOCK — p3b2"}}`))
			}))
			var out bytes.Buffer
			home := t.TempDir()
			err := runHookContext(t.Context(), name, strings.NewReader(in), &out, hookCall{client: &http.Client{}, api: srv.URL, token: tok, home: home})
			srv.Close()
			if err != nil {
				t.Fatal(err)
			}
			close(got)
			var reqs []seen
			for s := range got {
				reqs = append(reqs, s)
			}
			what := name + map[bool]string{true: " with a token", false: ""}[tok != ""]
			if len(reqs) != 1 {
				t.Fatalf("%s: %d requests", what, len(reqs))
			}
			s := reqs[0]
			if want := strings.TrimPrefix(srv.URL, "http://"); s.host != want {
				t.Errorf("%s: Host %q, want ALALANET_API's %q", what, s.host, want)
			}
			if v := s.h.Values("Accept-Encoding"); len(v) != 1 || v[0] != "gzip" {
				t.Errorf("%s: Accept-Encoding %q, want Go's own gzip", what, v)
			}
			if v := s.h.Values("Content-Length"); len(v) != 1 || v[0] != strconv.FormatInt(s.n, 10) {
				t.Errorf("%s: Content-Length %q for a %d-byte body", what, v, s.n)
			}
			for k, v := range s.h {
				if len(v) != 1 {
					t.Errorf("%s: %s given %d times", what, k, len(v))
				}
				if strings.Contains(v[0], home) || strings.Contains(v[0], strings.ReplaceAll(home, "/", "-")) {
					t.Errorf("%s: %s carries the home folder: %q", what, k, v[0])
				}
			}
		}
	}
}
