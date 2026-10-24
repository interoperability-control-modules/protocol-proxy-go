package ipc

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// Features a peer may advertise in REGISTER_PEER or its reply (PROTOCOL.md §7).
const (
	FeaturePing        = "ping"
	FeatureLog         = "log"
	FeatureSetLogLevel = "set_log_level"
	FeatureCompress    = "compress"
	FeatureChaCha20    = "aead-chacha20poly1305"
	FeatureAES256GCM   = "aead-aes256gcm"
)

// AEAD cipher names as the --cipher option and the REGISTER_PEER "cipher" field spell them.
const (
	CipherChaCha20Poly1305 = "chacha20-poly1305"
	CipherAES256GCM        = "aes-256-gcm"
	CipherAuto             = "auto"
	// BaselineCipher is the AEAD every implementation must accept.
	BaselineCipher = CipherChaCha20Poly1305
)

// Sizes of the encryption construct (§5) and the sender's defaults (§2, §4).
const (
	KeyBytes                  = 32
	NonceBytes                = 12
	TagBytes                  = 16
	DefaultCompressThreshold  = 4096
	DefaultPersistentMaxFrame = 256 * 1024
)

// ConnectorFeatures is what this implementation understands as a receiver (advertised by a manager in its reply).
var ConnectorFeatures = []string{FeatureCompress, FeatureChaCha20, FeatureAES256GCM}

// CipherFeature is the feature a peer must advertise to be sent the cipher, and whether the header's AES-GCM bit is
// set with it.
func CipherFeature(name string) (feature string, aesGCM bool, err error) {
	switch name {
	case CipherChaCha20Poly1305:
		return FeatureChaCha20, false, nil
	case CipherAES256GCM:
		return FeatureAES256GCM, true, nil
	}
	return "", false, fmt.Errorf("unknown cipher %q; choose from %s, %s or auto", name, CipherChaCha20Poly1305, CipherAES256GCM)
}

// ResolveCipher turns a --cipher value into a cipher name: a known name as given, "auto" (or empty) by CPU
// detection (AES-256-GCM on a CPU with AES instructions, else the baseline), as the Python connectors do.
func ResolveCipher(name string) (string, error) {
	switch name {
	case "", CipherAuto:
		if CPUHasAES() {
			return CipherAES256GCM, nil
		}
		return BaselineCipher, nil
	}
	if _, _, err := CipherFeature(name); err != nil {
		return "", err
	}
	return name, nil
}

// CPUHasAES reads /proc/cpuinfo for an "aes" flag (x86 AES-NI or Arm AES); false where that cannot be read.
func CPUHasAES() bool {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return false
	}
	return cpuinfoHasAES(string(data))
}

func cpuinfoHasAES(cpuinfo string) bool {
	for _, line := range strings.Split(cpuinfo, "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "flags", "features":
			for _, flag := range strings.Fields(value) {
				if flag == "aes" {
					return true
				}
			}
			return false
		}
	}
	return false
}

// Compress is zlib (zlib framing, default level) as a sender applies it behind bit 1 (§4).
func Compress(payload []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(payload); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Decompress undoes Compress.
func Decompress(payload []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("corrupt compressed payload: %w", err)
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("corrupt compressed payload: %w", err)
	}
	return out, nil
}

// NewAEAD is the cipher for a 32-byte key: AES-256-GCM when aesGCM, else ChaCha20-Poly1305.
func NewAEAD(key []byte, aesGCM bool) (cipher.AEAD, error) {
	if len(key) != KeyBytes {
		return nil, fmt.Errorf("AEAD key must be %d bytes, got %d", KeyBytes, len(key))
	}
	if aesGCM {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	}
	return chacha20poly1305.New(key)
}

// NewKey is a fresh random 32-byte AEAD key.
func NewKey() ([]byte, error) {
	key := make([]byte, KeyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// Seal is the encrypted wire payload of plaintext: a random 12-byte nonce, the AEAD ciphertext and the 16-byte tag,
// with header (the whole header as sent, version word included) as the associated data (§5).
func Seal(key, header, plaintext []byte, aesGCM bool) ([]byte, error) {
	nonce := make([]byte, NonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return SealWithNonce(key, nonce, header, plaintext, aesGCM)
}

// SealWithNonce is Seal with a caller-chosen nonce (for the deterministic test vectors).
func SealWithNonce(key, nonce, header, plaintext []byte, aesGCM bool) ([]byte, error) {
	if len(nonce) != NonceBytes {
		return nil, fmt.Errorf("nonce must be %d bytes, got %d", NonceBytes, len(nonce))
	}
	aead, err := NewAEAD(key, aesGCM)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, NonceBytes+len(plaintext)+TagBytes)
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plaintext, header), nil
}

// ErrAuthentication is returned when an encrypted payload fails to authenticate (forged, corrupted, or replayed
// under another header).
var ErrAuthentication = errors.New("encrypted payload failed authentication")

// Open decrypts a wire payload sealed by Seal under the same key and header.
func Open(key, header, body []byte, aesGCM bool) ([]byte, error) {
	if len(body) < NonceBytes+TagBytes {
		return nil, errors.New("encrypted payload is too short")
	}
	aead, err := NewAEAD(key, aesGCM)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, body[:NonceBytes], body[NonceBytes:], header)
	if err != nil {
		return nil, ErrAuthentication
	}
	return plain, nil
}

// HasFeature reports whether a feature list names a feature.
func HasFeature(features []string, feature string) bool {
	for _, f := range features {
		if f == feature {
			return true
		}
	}
	return false
}
