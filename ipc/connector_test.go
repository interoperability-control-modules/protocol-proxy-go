package ipc

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/eclipse-volttron/protocol-proxy-go/logs"
)

type pair struct {
	manager, proxy         *Connector
	managerPeer, proxyPeer *Peer // the manager as the proxy sees it, the proxy as the manager sees it
}

// loopback wires two connectors as a manager and a proxy that know each other, both listening on 127.0.0.1.
func loopback(t *testing.T, persistent bool, key []byte, material map[string]*TLSMaterial) *pair {
	t.Helper()
	logger := logs.New(logs.DEBUG, &logs.StreamSink{W: &testWriter{t}})
	managerID, proxyID := NewUUID(), NewUUID()
	managerToken, proxyToken := NewUUID(), NewUUID()
	var managerTLS, proxyTLS *TLSMaterial
	if material != nil {
		managerTLS, proxyTLS = material["manager"], material["proxy"]
	}
	manager, err := New(Options{ID: managerID, Token: managerToken, Name: "manager", Persistent: persistent,
		CompressThreshold: DefaultCompressThreshold, Cipher: CipherAES256GCM, TLS: managerTLS, Logger: logger,
		Features: ConnectorFeatures})
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := New(Options{ID: proxyID, Token: proxyToken, Name: "proxy", Persistent: persistent,
		CompressThreshold: DefaultCompressThreshold, Cipher: CipherChaCha20Poly1305, TLS: proxyTLS, Logger: logger,
		Features: ConnectorFeatures})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []*Connector{manager, proxy} {
		if err := c.Listen("127.0.0.1", 0); err != nil {
			t.Fatal(err)
		}
		c.Serve()
	}
	address := func(c *Connector) string {
		host, port := c.ListenAddress()
		return net.JoinHostPort(host, fmt.Sprint(port))
	}
	p := &pair{manager: manager, proxy: proxy}
	p.managerPeer = &Peer{ID: managerID, Token: managerToken, Address: address(manager), Key: key, TLS: managerTLS != nil}
	p.proxyPeer = &Peer{ID: proxyID, Token: proxyToken, Address: address(proxy), Key: key, TLS: proxyTLS != nil}
	p.managerPeer.SetFeatures(ConnectorFeatures)
	p.proxyPeer.SetFeatures(ConnectorFeatures)
	proxy.AddPeer(p.managerPeer)
	manager.AddPeer(p.proxyPeer)
	proxy.RegisterHandler("ECHO", func(_ *Header, payload []byte) ([]byte, error) { return payload, nil }, true)
	proxy.RegisterHandler("FAIL", func(_ *Header, _ []byte) ([]byte, error) { return nil, fmt.Errorf("boom") }, true)
	proxy.RegisterHandler("SILENT", func(_ *Header, _ []byte) ([]byte, error) { return nil, nil }, false)
	t.Cleanup(func() { manager.Stop(); proxy.Stop() })
	return p
}

type testWriter struct{ t *testing.T }

func (w *testWriter) Write(b []byte) (int, error) {
	w.t.Log(strings.TrimRight(string(b), "\n"))
	return len(b), nil
}

func request(t *testing.T, from *Connector, to *Peer, method string, payload []byte, version uint16) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reply, err := from.Request(ctx, to, &Message{Method: method, Payload: payload, Version: version})
	if err != nil {
		t.Fatalf("%s: %v", method, err)
	}
	return reply
}

func errorReply(t *testing.T, reply []byte) map[string]string {
	t.Helper()
	var out map[string]string
	if err := json.Unmarshal(reply, &out); err != nil || out["status"] != "error" {
		t.Fatalf("not an error reply: %s", reply)
	}
	return out
}

func TestPerMessageRequestResponse(t *testing.T) {
	p := loopback(t, false, nil, nil)
	small := []byte(`{"n": 1, "text": "héllo"}`)
	if reply := request(t, p.manager, p.proxyPeer, "ECHO", small, 2); !bytes.Equal(reply, small) {
		t.Fatalf("echo returned %q", reply)
	}
	if reply := request(t, p.manager, p.proxyPeer, "ECHO", small, 1); !bytes.Equal(reply, small) {
		t.Fatalf("version 1 echo returned %q", reply)
	}
	large := bytes.Repeat([]byte("x"), 65536) // above the compression threshold: compressed on the wire
	if reply := request(t, p.manager, p.proxyPeer, "ECHO", large, 2); !bytes.Equal(reply, large) {
		t.Fatal("64 KiB echo differs")
	}
	if reply := request(t, p.manager, p.proxyPeer, "ECHO", nil, 2); len(reply) != 0 {
		t.Fatalf("empty payload echoed as %q", reply)
	}
	out := errorReply(t, request(t, p.manager, p.proxyPeer, "NOPE", []byte(`{}`), 2))
	if out["error"] != "Unknown method NOPE" || out["method"] != "NOPE" {
		t.Fatal(out)
	}
	out = errorReply(t, request(t, p.manager, p.proxyPeer, "SILENT", nil, 2))
	if out["error"] != "Method SILENT provides no response" {
		t.Fatal(out)
	}
	if out = errorReply(t, request(t, p.manager, p.proxyPeer, "FAIL", nil, 2)); out["error"] != "boom" {
		t.Fatal(out)
	}
	if p.proxyPeer.Linked() || p.managerPeer.Linked() {
		t.Fatal("per-message traffic left a persistent connection")
	}
	if _, ok := p.proxy.LastActivity(); !ok {
		t.Fatal("last activity not recorded")
	}
}

func TestPersistentConnectionBothWays(t *testing.T) {
	p := loopback(t, true, nil, nil)
	p.manager.RegisterHandler("REGISTER_PEER", func(_ *Header, _ []byte) ([]byte, error) {
		return []byte(`{"registered": true, "features": ["compress"]}`), nil
	}, true)
	// the proxy dials once with the keep-alive bit; the manager adopts the connection
	reply := request(t, p.proxy, p.managerPeer, "REGISTER_PEER", []byte(`{"address": "127.0.0.1", "port": 1}`), 2)
	if !strings.Contains(string(reply), "registered") {
		t.Fatal(string(reply))
	}
	deadline := time.Now().Add(2 * time.Second)
	for !p.proxyPeer.Linked() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !p.proxyPeer.Linked() {
		t.Fatal("the manager did not adopt the proxy's keep-alive connection")
	}
	link := p.proxyPeer.Connection()
	// requests from the manager travel back on the adopted connection and interleave
	results := make(chan error, 5)
	for i := 0; i < 5; i++ {
		go func(i int) {
			payload := []byte(fmt.Sprintf(`{"i": %d}`, i))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			reply, err := p.manager.Request(ctx, p.proxyPeer, &Message{Method: "ECHO", Payload: payload})
			if err == nil && !bytes.Equal(reply, payload) {
				err = fmt.Errorf("reply %q", reply)
			}
			results <- err
		}(i)
	}
	for i := 0; i < 5; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if p.proxyPeer.Connection() != link {
		t.Fatal("the manager redialled instead of using the adopted connection")
	}
	// a frame above the persistent threshold takes a connection of its own; the link survives
	large := bytes.Repeat([]byte("y"), 300000)
	if reply := request(t, p.manager, p.proxyPeer, "ECHO", large, 2); !bytes.Equal(reply, large) {
		t.Fatal("300 KB echo differs")
	}
	if p.proxyPeer.Connection() != link {
		t.Fatal("the large frame disturbed the persistent connection")
	}
	// a lost connection fails the requests pending on it and the next send redials
	p.proxy.RegisterHandler("HANG", func(_ *Header, _ []byte) ([]byte, error) {
		time.Sleep(2 * time.Second)
		return []byte("late"), nil
	}, true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := p.manager.Request(ctx, p.proxyPeer, &Message{Method: "HANG"})
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	link.Close()
	if err := <-done; err == nil || !strings.Contains(err.Error(), "lost") {
		t.Fatalf("pending request did not fail with the connection: %v", err)
	}
	if reply := request(t, p.manager, p.proxyPeer, "ECHO", []byte("again"), 2); string(reply) != "again" {
		t.Fatal(string(reply))
	}
	if p.proxyPeer.Connection() == nil || p.proxyPeer.Connection() == link {
		t.Fatal("the manager did not redial a persistent connection")
	}
}

func TestEncryptionIsFixedPerPeer(t *testing.T) {
	key, _ := NewKey()
	p := loopback(t, true, key, nil)
	large := bytes.Repeat([]byte("z"), 65536) // compressed, then encrypted (AES-GCM from the manager's side)
	if reply := request(t, p.manager, p.proxyPeer, "ECHO", large, 2); !bytes.Equal(reply, large) {
		t.Fatal("encrypted echo differs")
	}
	// the proxy replies with its own cipher (ChaCha20) since the manager advertised both; both directions worked
	// a clear-text frame from a peer that must encrypt is refused: build one by hand
	clear, _ := New(Options{ID: p.manager.ID(), Token: p.manager.Token(), Name: "impostor", Logger: p.manager.log})
	clear.AddPeer(&Peer{ID: p.proxyPeer.ID, Token: p.proxyPeer.Token, Address: p.proxyPeer.Address})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := clear.Request(ctx, clear.Peer(p.proxyPeer.ID), &Message{Method: "ECHO", Payload: []byte("hi")}); err == nil {
		t.Fatal("a clear-text frame was answered by a peer that shares a key")
	}
	// and an encrypted frame under the wrong key fails authentication
	wrongKey, _ := NewKey()
	wrong, _ := New(Options{ID: p.manager.ID(), Token: p.manager.Token(), Name: "wrong-key", Logger: p.manager.log})
	wrong.AddPeer(&Peer{ID: p.proxyPeer.ID, Token: p.proxyPeer.Token, Address: p.proxyPeer.Address, Key: wrongKey})
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if _, err := wrong.Request(ctx2, wrong.Peer(p.proxyPeer.ID), &Message{Method: "ECHO", Payload: []byte("hi")}); err == nil {
		t.Fatal("a frame under the wrong key was answered")
	}
	// the real manager still works afterwards
	if reply := request(t, p.manager, p.proxyPeer, "ECHO", []byte("ok"), 2); string(reply) != "ok" {
		t.Fatal(string(reply))
	}
}

func TestUnauthenticatedFramesAreDropped(t *testing.T) {
	p := loopback(t, false, nil, nil)
	stranger, _ := New(Options{ID: NewUUID(), Token: NewUUID(), Name: "stranger", Logger: p.manager.log})
	stranger.AddPeer(&Peer{ID: p.proxyPeer.ID, Token: p.proxyPeer.Token, Address: p.proxyPeer.Address})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	reply, err := stranger.Request(ctx, stranger.Peer(p.proxyPeer.ID), &Message{Method: "ECHO", Payload: []byte("hi")})
	if err != nil || len(reply) != 0 {
		t.Fatalf("unknown sender got %q, %v (expected an empty reply)", reply, err)
	}
	badToken, _ := New(Options{ID: p.manager.ID(), Token: NewUUID(), Name: "bad-token", Logger: p.manager.log})
	badToken.AddPeer(&Peer{ID: p.proxyPeer.ID, Token: p.proxyPeer.Token, Address: p.proxyPeer.Address})
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	reply, err = badToken.Request(ctx2, badToken.Peer(p.proxyPeer.ID), &Message{Method: "ECHO", Payload: []byte("hi")})
	if err != nil || len(reply) != 0 {
		t.Fatalf("wrong token got %q, %v (expected an empty reply)", reply, err)
	}
}

// ---- TLS -----------------------------------------------------------------------------------------------------------

type authority struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	pem  string
}

func newAuthority(t *testing.T) *authority {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "protocol-proxy manager"},
		NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign, MaxPathLen: 0, MaxPathLenZero: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &authority{key: key, cert: cert, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

func (a *authority) issue(t *testing.T, commonName string) *TLSMaterial {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: commonName},
		NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, DNSNames: []string{commonName}}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key) // the Python CA writes PKCS8
	return &TLSMaterial{CA: a.pem, Cert: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		Key: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))}
}

func TestTLSMutualAuthentication(t *testing.T) {
	ca := newAuthority(t)
	managerID, proxyID := NewUUID(), NewUUID()
	material := map[string]*TLSMaterial{"manager": ca.issue(t, managerID.Hex()), "proxy": ca.issue(t, proxyID.Hex())}
	// loopback draws its own ids; rebuild the pair with the ids the certificates name
	logger := logs.New(logs.DEBUG, &logs.StreamSink{W: &testWriter{t}})
	manager, _ := New(Options{ID: managerID, Token: NewUUID(), Name: "manager", Persistent: true, TLS: material["manager"], Logger: logger})
	proxy, _ := New(Options{ID: proxyID, Token: NewUUID(), Name: "proxy", Persistent: true, TLS: material["proxy"], Logger: logger})
	for _, c := range []*Connector{manager, proxy} {
		if err := c.Listen("127.0.0.1", 0); err != nil {
			t.Fatal(err)
		}
		c.Serve()
	}
	t.Cleanup(func() { manager.Stop(); proxy.Stop() })
	host, port := proxy.ListenAddress()
	proxyPeer := &Peer{ID: proxyID, Token: proxy.Token(), Address: net.JoinHostPort(host, fmt.Sprint(port)), TLS: true}
	manager.AddPeer(proxyPeer)
	host, port = manager.ListenAddress()
	managerPeer := &Peer{ID: managerID, Token: manager.Token(), Address: net.JoinHostPort(host, fmt.Sprint(port)), TLS: true}
	proxy.AddPeer(managerPeer)
	proxy.RegisterHandler("ECHO", func(_ *Header, payload []byte) ([]byte, error) { return payload, nil }, true)
	if reply := request(t, manager, proxyPeer, "ECHO", []byte("over tls"), 2); string(reply) != "over tls" {
		t.Fatal(string(reply))
	}
	// a client whose certificate does not chain to the CA is refused
	otherCA := newAuthority(t)
	impostor, _ := New(Options{ID: managerID, Token: manager.Token(), Name: "impostor", TLS: otherCA.issue(t, managerID.Hex()), Logger: logger})
	impostor.AddPeer(&Peer{ID: proxyID, Token: proxy.Token(), Address: proxyPeer.Address, TLS: true})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := impostor.Request(ctx, impostor.Peer(proxyID), &Message{Method: "ECHO", Payload: []byte("hi")}); err == nil {
		t.Fatal("a certificate from another CA was accepted")
	}
	// a certificate from the right CA naming another id is refused on the frame (sender id must match the CN)
	wrongName, _ := New(Options{ID: managerID, Token: manager.Token(), Name: "wrong-name", TLS: ca.issue(t, NewUUID().Hex()), Logger: logger})
	wrongName.AddPeer(&Peer{ID: proxyID, Token: proxy.Token(), Address: proxyPeer.Address, TLS: true})
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	if _, err := wrongName.Request(ctx2, wrongName.Peer(proxyID), &Message{Method: "ECHO", Payload: []byte("hi")}); err == nil {
		t.Fatal("a frame whose sender id differs from its certificate was answered")
	}
	// a plain connection to a TLS listener fails
	plain, _ := New(Options{ID: managerID, Token: manager.Token(), Name: "plain", Logger: logger})
	plain.AddPeer(&Peer{ID: proxyID, Token: proxy.Token(), Address: proxyPeer.Address})
	ctx3, cancel3 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel3()
	if _, err := plain.Request(ctx3, plain.Peer(proxyID), &Message{Method: "ECHO", Payload: []byte("hi")}); err == nil {
		t.Fatal("a plain frame reached a TLS-only listener")
	}
}

func TestListenerFallsBackToTheRange(t *testing.T) {
	c, _ := New(Options{ID: NewUUID(), Token: NewUUID()})
	if err := c.Listen("127.0.0.1", 0); err != nil {
		t.Fatal(err)
	}
	defer c.Stop()
	host, port := c.ListenAddress()
	if host != "127.0.0.1" || port < MinPort || port > MaxPort {
		t.Fatalf("listening on %s:%d", host, port)
	}
	d, _ := New(Options{ID: NewUUID(), Token: NewUUID()})
	if err := d.Listen("localhost", port); err != nil { // taken: falls back to the next free port in the range
		t.Fatal(err)
	}
	defer d.Stop()
	if _, p2 := d.ListenAddress(); p2 == port || p2 < MinPort || p2 > MaxPort {
		t.Fatalf("second listener on %d", p2)
	}
}
