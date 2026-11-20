package mcpverify

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// racingTransport sends each request over a TLS connection of its own to addr. When the request's context ends
// before an answer, it does what net/http's transport does when a response races its cancel and wins (transport.go,
// persistConn.roundTrip: "Check for a response racing the context close, and use the response if available"): its
// side of the connection is closed (TLS close_notify, the first thing tls.Conn.Close sends) and an answer the server
// still sends is used. A loaded machine opens that window at random (pipeline 763, load ~50); here it is always open.
type racingTransport struct{ addr string }

func (rt racingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	d := tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // the fake's own certificate
	c, err := d.DialContext(req.Context(), "tcp", rt.addr)
	if err != nil {
		return nil, err
	}
	conn := c.(*tls.Conn)
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	type answer struct {
		resp *http.Response
		err  error
	}
	got := make(chan answer, 1)
	go func() {
		resp, err := http.ReadResponse(bufio.NewReader(conn), req)
		got <- answer{resp, err}
	}()
	var a answer
	select {
	case a = <-got:
	case <-req.Context().Done():
		_ = conn.CloseWrite()
		_ = conn.SetReadDeadline(time.Now().Add(time.Minute)) // a hang guard only: the fake's Delay ends sooner
		if a = <-got; a.err != nil {
			conn.Close()
			return nil, req.Context().Err()
		}
	}
	if a.err != nil {
		conn.Close()
		return nil, a.err
	}
	a.resp.Body = closeBoth{ReadCloser: a.resp.Body, conn: conn}
	return a.resp, nil
}

type closeBoth struct {
	io.ReadCloser
	conn io.Closer
}

func (c closeBoth) Close() error {
	err := c.ReadCloser.Close()
	_ = c.conn.Close()
	return err
}

// TestMCPVerifyBudgetResponseRacingTheCancel: pipeline 763's failure with its window held open. The read's deadline
// passes while the fake waits out its Delay; the client's close reaches the fake, and the fake must not answer it.
// When it answered (an empty 200 from a handler that returned), the read said "no answer to initialize"; it is "it
// did not answer in time".
func TestMCPVerifyBudgetResponseRacingTheCancel(t *testing.T) {
	url := "https://" + hostA + "/mcp"
	r := newRig(t, map[string]string{hostA: base})
	r.mcp[hostA].Delay = 10 * time.Second
	r.v.ReadHTTP = &http.Client{Transport: racingTransport{addr: r.mcp[hostA].Srv.Listener.Addr().String()},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r.v.ReadBudget = 200 * time.Millisecond
	out := r.v.Check(context.Background(), srv(url), "s")
	if out.Kind != NotChecked || !strings.Contains(out.Reasons[0], "in time") {
		t.Fatalf("%+v", out)
	}
}
