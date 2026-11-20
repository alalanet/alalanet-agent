package netguard

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// PUBLISH-WITNESS-DEPLOY: AddressAs sends a request to an IP address as to a host name — the TLS handshake names and
// verifies it, the Host header is it — and leaves a URL that names a host as it is.
func TestAddressAs(t *testing.T) {
	var sni, host string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host = r.Host
		_, _ = io.WriteString(w, "ok")
	}))
	srv.TLS = &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) { sni = h.ServerName; return nil, nil }}
	srv.StartTLS()
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	addressAsRoots = pool
	defer func() { addressAsRoots = nil }()
	port := srv.URL[strings.LastIndex(srv.URL, ":"):]
	get := func(c *http.Client, u string) error {
		resp, err := c.Get(u)
		if err == nil {
			_ = resp.Body.Close()
		}
		return err
	}
	// httptest's certificate names example.com (and 127.0.0.1): by address, as example.com
	c := Client(Options{AllowPrivate: true, AddressAs: "example.com"})
	if err := get(c, "https://127.0.0.1"+port+"/witness/add-checkpoint"); err != nil {
		t.Fatalf("by address as example.com: %v", err)
	}
	if sni != "example.com" || host != "example.com" {
		t.Fatalf("SNI %q, Host %q: want example.com for both", sni, host)
	}
	// a name its certificate does not hold: the handshake fails
	c = Client(Options{AllowPrivate: true, AddressAs: "alalanet.com"})
	if err := get(c, "https://127.0.0.1"+port+"/"); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("as a name the certificate does not hold: %v, want a certificate error", err)
	}
	// a URL that names a host is left as it is: localhost, verified as localhost (not in the certificate: refused)
	sni, host = "", ""
	c = Client(Options{AllowPrivate: true, AddressAs: "example.com"})
	if err := get(c, "https://localhost"+port+"/"); err == nil {
		t.Fatalf("a URL by name was sent as example.com (SNI %q, Host %q)", sni, host)
	}
	// without AddressAs the address is verified as itself (127.0.0.1 is in httptest's certificate) and named so
	c = Client(Options{AllowPrivate: true})
	c.Transport.(uaTransport).rt.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: pool}
	sni, host = "", ""
	if err := get(c, "https://127.0.0.1"+port+"/"); err != nil || host != "127.0.0.1"+port {
		t.Fatalf("without AddressAs: %v, Host %q", err, host)
	}
}
