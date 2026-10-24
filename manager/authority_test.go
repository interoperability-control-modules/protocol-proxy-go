package manager

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"

	"github.com/eclipse-volttron/protocol-proxy-go/ipc"
)

func parsePEM(t *testing.T, text string) *x509.Certificate {
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		t.Fatal("not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestAuthorityIssuesVerifiableCertificates(t *testing.T) {
	a, err := NewAuthority("protocol-proxy manager test")
	if err != nil {
		t.Fatal(err)
	}
	ca := parsePEM(t, a.CAPEM)
	if !ca.IsCA || ca.MaxPathLen != 0 || !ca.MaxPathLenZero || ca.Subject.CommonName != "protocol-proxy manager test" {
		t.Fatalf("CA %+v", ca.Subject)
	}
	m, err := a.Issue("abcdef", "127.0.0.1", "localhost")
	if err != nil {
		t.Fatal(err)
	}
	leaf := parsePEM(t, m.Cert)
	if leaf.Subject.CommonName != "abcdef" || leaf.IsCA || len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) ||
		len(leaf.DNSNames) != 2 || leaf.DNSNames[0] != "abcdef" || leaf.DNSNames[1] != "localhost" {
		t.Fatalf("leaf %+v %v %v", leaf.Subject, leaf.IPAddresses, leaf.DNSNames)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
			t.Fatalf("leaf does not verify for %v: %v", usage, err)
		}
	}
	if _, err := tls.X509KeyPair([]byte(m.Cert), []byte(m.Key)); err != nil {
		t.Fatalf("key pair: %v", err)
	}
	line, _ := m.Line()
	back, err := ipc.ParseTLSMaterial(line)
	if err != nil || back.Cert != m.Cert {
		t.Fatalf("material line round trip: %v", err)
	}
	other, _ := NewAuthority("other")
	stranger, _ := other.Issue("abcdef")
	if _, err := parsePEM(t, stranger.Cert).Verify(x509.VerifyOptions{Roots: pool}); err == nil {
		t.Fatal("a certificate from another authority verified")
	}
}

func TestIssuedMaterialHandshakesMutually(t *testing.T) {
	a, _ := NewAuthority("m")
	server, _ := a.Issue("server", "127.0.0.1")
	client, _ := a.Issue("client")
	serverCfg, err := server.ServerConfig()
	if err != nil {
		t.Fatal(err)
	}
	clientCfg, err := client.ClientConfig("server")
	if err != nil {
		t.Fatal(err)
	}
	l, err := tls.Listen("tcp4", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan string, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			done <- err.Error()
			return
		}
		defer c.Close()
		if err := c.(*tls.Conn).Handshake(); err != nil {
			done <- err.Error()
			return
		}
		done <- ipc.PeerCommonName(c.(*tls.Conn).ConnectionState())
	}()
	c, err := tls.Dial("tcp4", l.Addr().String(), clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if cn := ipc.PeerCommonName(c.ConnectionState()); cn != "server" {
		t.Fatalf("server presented %q", cn)
	}
	if got := <-done; got != "client" {
		t.Fatalf("client presented %q", got)
	}
}
