package manager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/eclipse-volttron/protocol-proxy-go/ipc"
)

// CertificateLifetime is how long the CA and every certificate it issues are valid.
const CertificateLifetime = 366 * 24 * time.Hour

// Authority is an in-memory certificate authority, one per manager, issuing certificates to the manager itself and
// to its proxies (PROTOCOL.md §5, TLS). Both ends of a TLS connection then require the other's certificate to chain
// to it; the common name carries the peer's id, which is what the connector verifies. Nothing touches the disk.
type Authority struct {
	key   *ecdsa.PrivateKey
	cert  *x509.Certificate
	CAPEM string
}

// NewAuthority makes a CA named name: an EC P-256 key and a self-signed certificate with the CA basic constraint
// (path length 0) and the certificate-signing key usages, as the Python reference issues them.
func NewAuthority(name string) (*Authority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(CertificateLifetime),
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Authority{key: key, cert: cert, CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}, nil
}

// Issue makes a certificate and key for one end: commonName is the peer's id (hex), ipAddresses are added as
// subject alternative names (an unparsable address becomes a DNS name, as in Python). The certificate is usable as
// server and client.
func (a *Authority) Issue(commonName string, ipAddresses ...string) (*ipc.TLSMaterial, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(CertificateLifetime),
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:              []string{commonName},
	}
	for _, address := range ipAddresses {
		if ip := net.ParseIP(address); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, address)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, &key.PublicKey, a.key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &ipc.TLSMaterial{
		CA:   a.CAPEM,
		Cert: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		Key:  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
	}, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 127)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("certificate serial: %w", err)
	}
	return serial, nil
}
