package mcpverify

// Review of VERIFY-AUTO-1 round 2 (8f23a0e): probes. Values built from parts; hosts made up.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// R2-A: the F8 rule's cost: realistic public hostnames of hosting platforms (made up) that would now be unread.
func TestReviewR2KeyLabelCost(t *testing.T) {
	for _, h := range []string{
		"weather-mcp-server-abc123xyz-uc.a.run.app",                    // Cloud Run, old form
		"weather-mcp-service-123456789012.us-central1.run.app",         // Cloud Run, new form
		"4fqx2kz7h3m5n8p1r6t9w0y2b4c6d8e1.lambda-url.us-east-1.on.aws", // Lambda function URL
		"mcp-server-production-2024.up.railway.app",
		"my-mcp-git-feature-x-team42.vercel.app",
		"docs-mcp-v2-eu-west-1-prod01.example.com",
		"mcp.example.com",
		"api.githubcopilot.com",
	} {
		p := planURL("https://" + h + "/mcp")
		t.Logf("%-62s design=%q", h, p.design)
		// Round 3 (N1): a random-looking host is read, pinned and looked up like any other.
		if p.design != "" || len(p.lookups) != 1 {
			t.Errorf("%s: design %q, %d lookups", h, p.design, len(p.lookups))
		}
	}
}

// R2-B: a state file that does not load: a listed server serving a changed known tool is no longer held (the
// witness comparison is skipped too), by default it goes ahead.
func TestReviewR2UnloadableStateSkipsWitnessHold(t *testing.T) {
	url := "https://" + hostA + "/mcp"
	r := newRig(t, map[string]string{hostA: changed})
	r.list(t, url, base, "")
	if err := os.MkdirAll(r.v.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.v.StateDir, stateName), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := r.v.Check(context.Background(), srv(url), "s")
	t.Logf("unloadable state, listed server with a changed tool: %v %q", out.Kind, out.Reasons)
	if out.Kind != Hold {
		t.Errorf("a changed known tool against alalanet's record is %v with the state unloadable (want hold)", out.Kind)
	}
}

// R2-C: alalanet answering 503: how many lookups do five checks within a minute send? (/privacy: "at most once per
// server every 10 minutes").
func TestReviewR2LookupsWhenAlalanetFails(t *testing.T) {
	url := "https://" + hostA + "/mcp?lang=en"
	r := newRig(t, map[string]string{hostA: base})
	var mu sync.Mutex
	n := 0
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		n++
		mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer failing.Close()
	r.v.API = failing.URL
	for i := range 5 {
		r.v.Now = func() time.Time { return time.Now().Add(time.Duration(i) * 10 * time.Second) }
		r.v.Check(context.Background(), srv(url), "s")
	}
	mu.Lock()
	defer mu.Unlock()
	t.Logf("five checks in 40 s, alalanet failing: %d lookups sent", n)
	if n > 2 {
		t.Errorf("%d lookups in 40 s for one server (the /privacy sentence says at most once per 10 minutes)", n)
	}
}

// R2-D: sixteen hooks at a first sight and an approval among them: one pin, of the approved set, approved.
func TestReviewR2CASUnderConcurrency(t *testing.T) {
	url := "https://" + hostA + "/mcp"
	for round := range 5 {
		r := newRig(t, map[string]string{hostA: base})
		ctx := context.Background()
		var wg sync.WaitGroup
		var approveErr error
		for i := range 16 {
			wg.Go(func() {
				v := *r.v
				v.Now = func() time.Time { return time.Now().Add(time.Hour) } // every hook reads
				v.Check(ctx, srv(url), fmt.Sprintf("s%d", i))
			})
			if i == 8 {
				wg.Go(func() {
					a, err := r.v.Approve(ctx, srv(url))
					if err == nil {
						err = a.Pin()
					}
					approveErr = err
				})
			}
		}
		wg.Wait()
		b, err := os.ReadFile(filepath.Join(r.v.StateDir, stateName))
		if err != nil {
			t.Fatal(err)
		}
		var st stateFile
		if err := json.Unmarshal(b, &st); err != nil || len(st.Servers) != 1 {
			t.Fatalf("round %d: %v, %d", round, err, len(st.Servers))
		}
		for _, e := range st.Servers {
			if e.Pin == nil || e.Pin.Hash != hashOf(t, base) {
				t.Errorf("round %d: pin %+v", round, e.Pin)
			}
			if approveErr == nil && !e.Pin.Approved {
				t.Errorf("round %d: the approval was overwritten by a parallel hook", round)
			}
			if approveErr != nil {
				t.Logf("round %d: approve: %v", round, approveErr)
			}
		}
		left, _ := filepath.Glob(filepath.Join(r.v.StateDir, "*"))
		if len(left) != 1 {
			t.Errorf("round %d: files left %v", round, left)
		}
	}
}

// R2-E: the streamed Claude Code file: malformed shapes fail to "no servers" with a note; secrets of other projects
// are not kept; the last duplicate wins as in JSON.parse.
func TestReviewR2ClaudeFileShapes(t *testing.T) {
	dir := t.TempDir()
	cwd := "/home/dev/proj"
	other := "/home/dev/other"
	sec := "hdr" + "-secret-" + "77aa"
	good := `{"numStartups":3,"projects":{"` + other + `":{"mcpServers":{"o":{"type":"http","url":"https://o.example.com/mcp","headers":{"Authorization":"Bearer ` + sec + `"}}},"history":[` + strings.Repeat(`{"display":"x"},`, 1000) + `{"display":"y"}]},"` + cwd + `":{"mcpServers":{"l":{"type":"http","url":"https://l.example.com/mcp"}}}},"mcpServers":{"u":{"type":"http","url":"https://first.example.com/mcp"}},"mcpServers":{"u":{"type":"http","url":"https://u.example.com/mcp"}}}`
	for _, c := range []struct {
		name, body string
		want       int  // servers
		note       bool // a note is given
	}{
		{"good", good, 2, false},
		{"truncated", good[:len(good)/2], 0, true},
		{"not an object", `[1,2]`, 0, true},
		{"projects an array", `{"projects":[1],"mcpServers":{"u":{"url":"https://u.example.com/mcp"}}}`, 1, false},
		{"mcpServers an array", `{"mcpServers":[1,2]}`, 0, false},
		{"trailing garbage", `{"mcpServers":{"u":{"url":"https://u.example.com/mcp"}}} garbage`, 1, false},
		{"empty", ``, 0, true},
		{"invalid utf-8 in history", `{"projects":{"/x":{"h":"` + "\xff\xfe" + `"}},"mcpServers":{"u":{"url":"https://u.example.com/mcp"}}}`, 1, false},
	} {
		p := filepath.Join(dir, c.name+".json")
		if err := os.WriteFile(p, []byte(c.body), 0o600); err != nil {
			t.Fatal(err)
		}
		list, note := ClaudeServers(p, cwd, false)
		t.Logf("%-26s %d servers, note %q", c.name, len(list), note)
		if len(list) != c.want || (note != "") != c.note {
			t.Errorf("%s: %d servers (want %d), note %q", c.name, len(list), c.want, note)
		}
		for _, s := range list {
			if s.Name == "u" && s.URL != "https://u.example.com/mcp" {
				t.Errorf("%s: duplicate mcpServers: got %s (JSON.parse keeps the last)", c.name, s.URL)
			}
			if s.Name == "o" {
				t.Errorf("%s: another folder's server listed", c.name)
			}
		}
	}
	// What the parse keeps for the session: no other folder's data.
	cf, _ := readClaudeFile(filepath.Join(dir, "good.json"), map[string]bool{cwd: true})
	b, _ := json.Marshal(cf)
	if strings.Contains(string(b), sec) || strings.Contains(string(b), "history") {
		t.Errorf("the parse kept another folder's data: %s", b)
	}
}

// R2-F: the streamed read's cost on a large file: the hook pays it on every MCP call.
func TestReviewR2ClaudeFileCost(t *testing.T) {
	if testing.Short() {
		t.Skip("writes 128 MB")
	}
	p := filepath.Join(t.TempDir(), "big.json")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(f, `{"projects":{`)
	entry := `{"history":[` + strings.Repeat(`{"display":"some long prompt text here, with words","pastedContents":{}},`, 200) + `{}]}`
	for i := 0; ; i++ {
		if i > 0 {
			fmt.Fprint(f, ",")
		}
		fmt.Fprintf(f, `"/home/dev/p%d":%s`, i, entry)
		if fi, _ := f.Stat(); fi.Size() > 128<<20 {
			break
		}
	}
	fmt.Fprint(f, `},"mcpServers":{"u":{"type":"http","url":"https://u.example.com/mcp"}}}`)
	f.Close()
	start := time.Now()
	list, note := ClaudeServers(p, "/home/dev/p1", false)
	t.Logf("128 MiB file: %d servers, note %q, %v", len(list), note, time.Since(start))
}
