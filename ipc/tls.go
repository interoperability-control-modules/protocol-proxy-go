package ipc

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
)

// TLSMaterial is the JSON line of PEM material a manager writes to a proxy's stdin with --ipc-tls true: the
// manager's CA certificate, this end's certificate (naming the proxy's id) and its private key (PROTOCOL.md §5 TLS).
type TLSMaterial struct {
	CA   string `json:"ca"`
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

// ParseTLSMaterial reads the JSON line.
func ParseTLSMaterial(line []byte) (*TLSMaterial, error) {
	var m TLSMaterial
	if err := json.Unmarshal(line, &m); err != nil {
		return nil, fmt.Errorf("TLS material is not a JSON object: %w", err)
	}
	if m.CA == "" || m.Cert == "" || m.Key == "" {
		return nil, errors.New("TLS material must carry ca, cert and key")
	}
	return &m, nil
}

// Line is the JSON line form (what a manager writes).
func (m *TLSMaterial) Line() ([]byte, error) {
	line, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return append(line, '\n'), nil
}

func (m *TLSMaterial) pool() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(m.CA)) {
		return nil, errors.New("TLS material: the CA is not a PEM certificate")
	}
	return pool, nil
}

// ServerConfig is the TLS 1.3 configuration for accepted connections: present our certificate, require the client's
// and verify it against the manager's CA. Hostnames are not checked; the frame's sender id is checked against the
// certificate's common name instead (frame identity).
func (m *TLSMaterial) ServerConfig() (*tls.Config, error) {
	cert, err := tls.X509KeyPair([]byte(m.Cert), []byte(m.Key))
	if err != nil {
		return nil, fmt.Errorf("TLS material: %w", err)
	}
	pool, err := m.pool()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}, nil
}

// ClientConfig is the TLS 1.3 configuration for dialled connections: present our certificate and require the
// server's to chain to the manager's CA and, when expectCN is given, to name that peer id in its common name.
// Hostnames are not verified (the CA is private to one manager), as in the Python reference.
func (m *TLSMaterial) ClientConfig(expectCN string) (*tls.Config, error) {
	cert, err := tls.X509KeyPair([]byte(m.Cert), []byte(m.Key))
	if err != nil {
		return nil, fmt.Errorf("TLS material: %w", err)
	}
	pool, err := m.pool()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{cert},
		ServerName:         expectCN,
		InsecureSkipVerify: true, // the chain is verified below, without a hostname check
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("the peer presented no certificate")
			}
			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			intermediates := x509.NewCertPool()
			for _, raw := range rawCerts[1:] {
				if c, err := x509.ParseCertificate(raw); err == nil {
					intermediates.AddCert(c)
				}
			}
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: intermediates,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
				return fmt.Errorf("the peer's certificate does not chain to the manager's CA: %w", err)
			}
			if expectCN != "" && leaf.Subject.CommonName != expectCN {
				return fmt.Errorf("the peer's certificate names %q, expected %q", leaf.Subject.CommonName, expectCN)
			}
			return nil
		},
	}, nil
}

// PeerCommonName is the common name of the certificate the other end presented, or "" when there is none.
func PeerCommonName(state tls.ConnectionState) string {
	if len(state.PeerCertificates) == 0 {
		return ""
	}
	return state.PeerCertificates[0].Subject.CommonName
}
