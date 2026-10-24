package proxy

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/eclipse-volttron/protocol-proxy-go/ipc"
)

// Handshake is what the manager writes to stdin, then closes (PROTOCOL.md §1): the proxy's token and the manager's
// token as 32 hex characters each, the 32-byte AEAD key as 64 hex characters with --encrypt true, and one JSON line of
// TLS material with --ipc-tls true.
type Handshake struct {
	ProxyToken   ipc.UUID
	ManagerToken ipc.UUID
	Key          []byte
	TLS          *ipc.TLSMaterial
}

const tokenHexLength = 32
const keyHexLength = 64

// ReadHandshake reads the handshake from r.
func ReadHandshake(r io.Reader, encrypt, ipcTLS bool) (*Handshake, error) {
	br := bufio.NewReader(r)
	tokens := make([]byte, 2*tokenHexLength)
	if n, err := io.ReadFull(br, tokens); err != nil {
		return nil, fmt.Errorf("expected %d hex characters (proxy token + manager token) on stdin, got %d bytes; proxies"+
			" are meant to be launched by a ProtocolProxyManager", 2*tokenHexLength, n)
	}
	hs := &Handshake{}
	var err error
	if hs.ProxyToken, err = ipc.ParseUUID(string(tokens[:tokenHexLength])); err != nil {
		return nil, fmt.Errorf("proxy token on stdin: %w", err)
	}
	if hs.ManagerToken, err = ipc.ParseUUID(string(tokens[tokenHexLength:])); err != nil {
		return nil, fmt.Errorf("manager token on stdin: %w", err)
	}
	if encrypt {
		keyHex := make([]byte, keyHexLength)
		if n, err := io.ReadFull(br, keyHex); err != nil {
			return nil, fmt.Errorf("--encrypt is set but no %d-byte key followed the tokens on stdin (got %d bytes)",
				keyHexLength/2, n)
		}
		if hs.Key, err = hex.DecodeString(string(keyHex)); err != nil {
			return nil, fmt.Errorf("AEAD key on stdin is not hex: %w", err)
		}
	}
	if ipcTLS {
		line, err := br.ReadBytes('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		if strings.TrimSpace(string(line)) == "" {
			return nil, errors.New("--ipc-tls is set but no TLS material (one JSON line) followed on stdin")
		}
		if hs.TLS, err = ipc.ParseTLSMaterial(line); err != nil {
			return nil, err
		}
	}
	return hs, nil
}
