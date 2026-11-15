package main

// Independent re-review of SEC9-AGENT round 2 (fc8b708): what one read_mail costs the alalanet-agent
// process, measured as its peak resident memory (the child's rusage), on the pages a server can send:
// an empty inbox, the worst page alalanet writes under the junk attack (199 wraps of 64 KiB of '<', six
// bytes each, indented, and the honest message), 96 MiB of blanks, one string that never closes.
// Untracked review file; no raw invisible character in the source.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/nbd-wtf/go-nostr"
)

func TestZZReviewR2ReadMailPeakRSS(t *testing.T) {
	if testing.Short() {
		t.Skip("memory")
	}
	recipientSK := nostr.GeneratePrivateKey()
	recipientPK, _ := nostr.GetPublicKey(recipientSK)
	keyFile := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyFile, []byte(recipientSK+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	junk := nostr.Event{Kind: 1059, CreatedAt: nostr.Now(), Content: strings.Repeat("<", 64<<10-600), Tags: nostr.Tags{{"p", recipientPK}}}
	_ = junk.Sign(nostr.GeneratePrivateKey())
	canonical, _ := json.Marshal(junk)
	honest := zzWrap(t, nostr.GeneratePrivateKey(), recipientPK, `{"id":"","pubkey":"`+strings.Repeat("0", 64)+`","created_at":1763100000,"kind":14,"tags":[],"content":"the honest message","sig":""}`)
	honestJSON, _ := json.Marshal(honest)
	var worst bytes.Buffer
	var raws []json.RawMessage
	for i := 0; i < 199; i++ {
		raws = append(raws, canonical)
	}
	raws = append(raws, honestJSON)
	enc := json.NewEncoder(&worst)
	enc.SetEscapeHTML(true)
	enc.SetIndent("", "  ")
	_ = enc.Encode(map[string]any{"messages": raws, "next_since": 1763100000, "next_after_id": honest.ID, "note": "x"})
	blanks := bytes.Repeat([]byte(" "), 1<<20)
	letters := bytes.Repeat([]byte("A"), 1<<20)
	cases := []struct {
		name  string
		serve func(w http.ResponseWriter, r *http.Request)
	}{
		{"an empty inbox", func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"messages":[],"next_since":0,"next_after_id":""}`)
		}},
		{"the worst page alalanet writes (74 MiB)", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(worst.Bytes()) }},
		{"blanks forever inside the list", func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"messages":[`)
			for r.Context().Err() == nil {
				if _, err := w.Write(blanks); err != nil {
					return
				}
			}
		}},
		{"one string that never closes", func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"messages":["`)
			for r.Context().Err() == nil {
				if _, err := w.Write(letters); err != nil {
					return
				}
			}
		}},
	}
	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/mail" {
				http.NotFound(w, r)
				return
			}
			c.serve(w, r)
		}))
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		cmd := exec.Command(os.Args[0], "-test.run=^TestZZReviewSEC9AgentChild$")
		cmd.Env = append(os.Environ(), zzChildEnv+"=mcp", "ALALANET_API="+srv.URL, "ALALANET_AGENT_KEY_FILE="+keyFile)
		client := mcp.NewClient(&mcp.Implementation{Name: "zz-review-r2", Version: "0"}, nil)
		sess, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		start := time.Now()
		res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "read_mail", Arguments: map[string]any{}})
		took := time.Since(start)
		summary := ""
		if err != nil {
			summary = "call error: " + err.Error()
		} else {
			for _, cc := range res.Content {
				if tc, ok := cc.(*mcp.TextContent); ok {
					summary = tc.Text
				}
			}
			if len(summary) > 160 {
				summary = summary[:160] + "..."
			}
			if res.IsError {
				summary = "tool error: " + summary
			}
		}
		_ = sess.Close()
		cancel()
		srv.Close()
		rss := int64(-1)
		if cmd.ProcessState != nil {
			if ru, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage); ok {
				rss = ru.Maxrss // bytes on darwin
			}
		}
		t.Logf("%-42s peak RSS of alalanet-agent mcp %6.1f MiB; read_mail took %v: %s", c.name, float64(rss)/(1<<20), took, summary)
	}
}
