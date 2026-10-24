package ipc

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

// UUID is a 16-byte identifier as the Python side's uuid.UUID: proxy ids, tokens and remote ids are all UUIDs.
type UUID [16]byte

// NoRemote is the all-zero remote id a version 2 header carries when the message concerns no remote.
var NoRemote UUID

// ParseUUID reads a UUID as 32 hex characters or in the canonical 8-4-4-4-12 form, either case.
func ParseUUID(s string) (UUID, error) {
	var u UUID
	clean := strings.ReplaceAll(strings.TrimSpace(s), "-", "")
	clean = strings.TrimPrefix(strings.TrimSuffix(clean, "}"), "{")
	if len(clean) != 32 {
		return u, fmt.Errorf("badly formed UUID %q", s)
	}
	raw, err := hex.DecodeString(clean)
	if err != nil {
		return u, fmt.Errorf("badly formed UUID %q: %w", s, err)
	}
	copy(u[:], raw)
	return u, nil
}

// MustUUID is ParseUUID for literals; it panics on a bad value.
func MustUUID(s string) UUID {
	u, err := ParseUUID(s)
	if err != nil {
		panic(err)
	}
	return u
}

// NewUUID is a random (version 4) UUID.
func NewUUID() UUID {
	var u UUID
	if _, err := rand.Read(u[:]); err != nil {
		panic(err)
	}
	u[6] = (u[6] & 0x0f) | 0x40
	u[8] = (u[8] & 0x3f) | 0x80
	return u
}

// Hex is the 32 lower-case hex characters (Python's uuid.hex), the form used on the command line and in JSON.
func (u UUID) Hex() string { return hex.EncodeToString(u[:]) }

// String is the canonical dashed form (Python's str(uuid)).
func (u UUID) String() string {
	h := u.Hex()
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// IsZero reports whether the UUID is all zeros (no remote).
func (u UUID) IsZero() bool { return u == NoRemote }
