// Package ipc implements the protocol-proxy wire contract (PROTOCOL.md): frame headers, payload transforms
// (compression, AEAD encryption), TCP transport with per-message and persistent connections, optional TLS, and the
// dispatch of frames to handlers, as a manager in any language and the Python connectors expect.
package ipc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"unicode/utf8"
)

// Frame layout constants (PROTOCOL.md §3).
const (
	VersionWordBytes = 2  // the big-endian version word that starts every frame
	HeaderLengthV1   = 76 // bytes after the version word in a version 1 header
	HeaderLengthV2   = 94 // bytes after the version word in a version 2 header
	MethodNameBytes  = 32 // method_name field: UTF-8, NUL-padded
	RequestIDMaxV1   = 0xFFFF
	RequestIDMaxV2   = 0xFFFFFFFF

	BitResponseExpected = 0
	BitCompressed       = 1
	BitEncrypted        = 2
	BitKeepAlive        = 3
	BitAESGCM           = 4

	// DefaultVersion is the header version a sender uses unless told otherwise.
	DefaultVersion uint16 = 2
)

// Header is the fixed header of a frame, either version. RemoteID is zero when absent (and always on version 1).
type Header struct {
	Version          uint16
	DataLength       uint64
	MethodName       string
	RequestID        uint32
	SenderID         UUID
	SenderToken      UUID
	ResponseExpected bool
	Compressed       bool
	Encrypted        bool
	KeepAlive        bool
	AESGCM           bool
	RemoteID         UUID
}

// ErrUnknownVersion is returned for a version word other than 1 or 2.
var ErrUnknownVersion = errors.New("unknown protocol version")

// HeaderLength is the number of header bytes that follow the version word for a header version.
func HeaderLength(version uint16) (int, error) {
	switch version {
	case 1:
		return HeaderLengthV1, nil
	case 2:
		return HeaderLengthV2, nil
	}
	return 0, fmt.Errorf("%w (%d)", ErrUnknownVersion, version)
}

// RequestIDMax is the largest request id the version's field holds.
func RequestIDMax(version uint16) uint32 {
	if version == 1 {
		return RequestIDMaxV1
	}
	return RequestIDMaxV2
}

// Bitflags is the header's flag word.
func (h *Header) Bitflags() uint16 {
	var flags uint16
	set := func(on bool, bit uint) {
		if on {
			flags |= 1 << bit
		}
	}
	set(h.ResponseExpected, BitResponseExpected)
	set(h.Compressed, BitCompressed)
	set(h.Encrypted, BitEncrypted)
	set(h.KeepAlive, BitKeepAlive)
	set(h.AESGCM, BitAESGCM)
	return flags
}

func (h *Header) setBitflags(flags uint16) {
	h.ResponseExpected = flags&(1<<BitResponseExpected) != 0
	h.Compressed = flags&(1<<BitCompressed) != 0
	h.Encrypted = flags&(1<<BitEncrypted) != 0
	h.KeepAlive = flags&(1<<BitKeepAlive) != 0
	h.AESGCM = flags&(1<<BitAESGCM) != 0
}

// Pack is the header on the wire, version word included: version 1 is `>HQ32sH16s16sH` (78 bytes), version 2
// `>HQ32sI16s16sH16s` (96 bytes). A Version of 0 packs as version 2.
func (h *Header) Pack() ([]byte, error) {
	version := h.Version
	if version == 0 {
		version = DefaultVersion
	}
	length, err := HeaderLength(version)
	if err != nil {
		return nil, err
	}
	if h.RequestID > RequestIDMax(version) {
		return nil, fmt.Errorf("request id %d does not fit the version %d header (maximum %d)", h.RequestID, version,
			RequestIDMax(version))
	}
	method := []byte(h.MethodName)
	if len(method) > MethodNameBytes {
		return nil, fmt.Errorf("method name %q is longer than %d bytes", h.MethodName, MethodNameBytes)
	}
	if version == 1 && !h.RemoteID.IsZero() {
		return nil, errors.New("a version 1 header cannot carry a remote id")
	}
	buf := make([]byte, 0, VersionWordBytes+length)
	buf = binary.BigEndian.AppendUint16(buf, version)
	buf = binary.BigEndian.AppendUint64(buf, h.DataLength)
	buf = append(buf, method...)
	buf = append(buf, make([]byte, MethodNameBytes-len(method))...)
	if version == 1 {
		buf = binary.BigEndian.AppendUint16(buf, uint16(h.RequestID))
	} else {
		buf = binary.BigEndian.AppendUint32(buf, h.RequestID)
	}
	buf = append(buf, h.SenderID[:]...)
	buf = append(buf, h.SenderToken[:]...)
	buf = binary.BigEndian.AppendUint16(buf, h.Bitflags())
	if version == 2 {
		buf = append(buf, h.RemoteID[:]...)
	}
	return buf, nil
}

// Unpack reads a header from its wire bytes (version word included). Extra bytes after the header are ignored.
func Unpack(raw []byte) (Header, error) {
	var h Header
	if len(raw) < VersionWordBytes {
		return h, errors.New("header shorter than the version word")
	}
	h.Version = binary.BigEndian.Uint16(raw)
	length, err := HeaderLength(h.Version)
	if err != nil {
		return h, err
	}
	if len(raw) < VersionWordBytes+length {
		return h, fmt.Errorf("version %d header needs %d bytes, got %d", h.Version, VersionWordBytes+length, len(raw))
	}
	b := raw[VersionWordBytes:]
	h.DataLength = binary.BigEndian.Uint64(b)
	b = b[8:]
	method := bytes.TrimRight(b[:MethodNameBytes], "\x00")
	if !utf8.Valid(method) {
		return h, errors.New("method name is not valid UTF-8")
	}
	h.MethodName = string(method)
	b = b[MethodNameBytes:]
	if h.Version == 1 {
		h.RequestID = uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	} else {
		h.RequestID = binary.BigEndian.Uint32(b)
		b = b[4:]
	}
	copy(h.SenderID[:], b)
	b = b[16:]
	copy(h.SenderToken[:], b)
	b = b[16:]
	h.setBitflags(binary.BigEndian.Uint16(b))
	b = b[2:]
	if h.Version == 2 {
		copy(h.RemoteID[:], b)
	}
	return h, nil
}

// RequestIDs draws request ids per header version, cycling from 1 (as the Python connectors do: 1 .. max-1).
type RequestIDs struct {
	mu   sync.Mutex
	next map[uint16]uint32
}

// Next is the next request id that fits the given header version.
func (r *RequestIDs) Next(version uint16) uint32 {
	if version == 0 {
		version = DefaultVersion
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.next == nil {
		r.next = map[uint16]uint32{}
	}
	id := r.next[version]
	if id == 0 || id >= RequestIDMax(version) {
		id = 1
	}
	r.next[version] = id + 1
	return id
}
