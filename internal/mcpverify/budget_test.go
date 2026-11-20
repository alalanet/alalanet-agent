package mcpverify

import (
	"context"
	"crypto/tls"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alalanet/alalanet-agent/internal/mcpverify/mcptest"
)

// TestMCPVerifyBudgetsAreTheDocumented: the read's and the record's budgets are 3 s and 2 s (the hook's 5 s is
// their sum); the tests below derive their bounds from these, so a change of either is seen here.
func TestMCPVerifyBudgetsAreTheDocumented(t *testing.T) {
	if defaultRead != 3*time.Second || defaultWitness != 2*time.Second || maxLockWait != 2*time.Second {
		t.Fatalf("read %v, record %v, lock wait %v", defaultRead, defaultWitness, maxLockWait)
	}
}

// TestMCPVerifyBudgetConfigured: a configured ReadBudget is the read's deadline, not the default; a server slower than
// it is not checked, "in time".
func TestMCPVerifyBudgetConfigured(t *testing.T) {
	url := "https://" + hostA + "/mcp"
	r := newRig(t, map[string]string{hostA: base})
	r.mcp[hostA].Delay = 10 * time.Second
	var sent func() []mcptest.Sent
	r.v.ReadHTTP, sent = mcptest.Deadlines(r.v.ReadHTTP)
	r.v.ReadBudget = 200 * time.Millisecond
	start := time.Now()
	out := r.v.Check(context.Background(), srv(url), "s")
	if out.Kind != NotChecked || !strings.Contains(out.Reasons[0], "in time") {
		t.Fatalf("%+v", out)
	}
	if why := mcptest.WithinBudget(start, sent(), r.v.ReadBudget); why != "" {
		t.Error(why)
	}
}

// TestMCPTestGoneClientIsNotAnswered: the fake server, waiting out its Delay, answers nothing to a client that went
// away. It used to return from the handler, and net/http then wrote an empty 200: a client whose deadline closed
// the connection could read that answer in the window between its TLS close_notify and the socket's close (the
// transport uses a response that races its own cancel), and the read said "no answer to initialize" instead of
// "it did not answer in time" (pipeline 763, TestMCPVerifyBudget under load ~50). Here the window is held open: the
// client half-closes (close_notify, still reading) and must read no byte before the server closes.
func TestMCPTestGoneClientIsNotAnswered(t *testing.T) {
	m := mcptest.NewMCP(base)
	t.Cleanup(m.Srv.Close)
	m.Delay = 10 * time.Second
	conn, err := tls.Dial("tcp", m.Srv.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // the fake's own certificate
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	req := "POST /mcp HTTP/1.1\r\nHost: " + hostA + "\r\nContent-Type: application/json\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\n\r\n" + body
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatal(err)
	}
	// A guard against a hang only: the server answers (or closes) right after the close_notify, and an answer after
	// its 10 s Delay would be a whole one, which fails below as well.
	_ = conn.SetReadDeadline(time.Now().Add(time.Minute))
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(conn)
	if ne, ok := err.(interface{ Timeout() bool }); ok && ne.Timeout() {
		t.Fatalf("the server neither answered nor closed in a minute: %q", got)
	}
	if len(got) != 0 {
		t.Fatalf("a client that went away was answered: %q", got)
	}
}
