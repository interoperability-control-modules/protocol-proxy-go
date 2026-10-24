package ipc

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// MaxFrameBytes bounds a frame's payload so a bad length word cannot ask for an absurd allocation.
const MaxFrameBytes = 1 << 30

// Conn is one TCP (or TLS) connection: a framed reader, a serialised writer and, while it stays open, the request ids
// awaiting responses on it (failed when it is lost). A per-message connection carries one frame and its reply; a
// persistent one carries frames in both directions until a side closes (PROTOCOL.md §2).
type Conn struct {
	c          *Connector
	nc         net.Conn
	r          *bufio.Reader
	accepted   bool
	persistent atomic.Bool
	mu         sync.Mutex
	peerID     UUID // the authenticated peer at the other end, once known
	tlsPeer    string
	writeMu    sync.Mutex
	urgent     atomic.Int32 // ordinary writers waiting for or holding the write lock; low-priority ones yield
	pending    map[uint32]struct{}
	closed     chan struct{}
	closeOnce  sync.Once
}

func newConn(c *Connector, nc net.Conn, accepted bool) *Conn {
	return &Conn{c: c, nc: nc, r: bufio.NewReaderSize(nc, 64*1024), accepted: accepted,
		pending: map[uint32]struct{}{}, closed: make(chan struct{})}
}

// Alive reports whether the connection is still open.
func (conn *Conn) Alive() bool {
	select {
	case <-conn.closed:
		return false
	default:
		return true
	}
}

// Persistent reports whether frames in both directions travel on this connection until a side closes it.
func (conn *Conn) Persistent() bool { return conn.persistent.Load() }

// PeerID is the authenticated peer at the other end, zero when not yet known.
func (conn *Conn) PeerID() UUID {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.peerID
}

func (conn *Conn) setPeerID(id UUID) {
	conn.mu.Lock()
	conn.peerID = id
	conn.mu.Unlock()
}

// TLSPeer is the common name of the certificate the other end presented, "" on a plain connection.
func (conn *Conn) TLSPeer() string {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.tlsPeer
}

// RemoteAddr is the other end's address.
func (conn *Conn) RemoteAddr() string {
	if addr := conn.nc.RemoteAddr(); addr != nil {
		return addr.String()
	}
	return "an unknown peer"
}

// Close closes the connection once.
func (conn *Conn) Close() {
	conn.closeOnce.Do(func() {
		close(conn.closed)
		_ = conn.nc.Close()
	})
}

// makePersistent marks the connection persistent toward peerID: no idle deadline (idle is normal; TCP keepalive
// notices a dead peer) and keepalive probes on.
func (conn *Conn) makePersistent(peerID UUID) {
	conn.persistent.Store(true)
	conn.setPeerID(peerID)
	_ = conn.nc.SetDeadline(time.Time{})
	setTCPKeepAlive(conn.nc)
}

// peekedConn is a net.Conn whose first bytes were already read (to tell TLS from plain); Read returns them first.
type peekedConn struct {
	net.Conn
	head []byte
}

func (p *peekedConn) Read(b []byte) (int, error) {
	if len(p.head) > 0 {
		n := copy(b, p.head)
		p.head = p.head[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

func setTCPKeepAlive(nc net.Conn) {
	if tc, ok := nc.(*tls.Conn); ok {
		nc = tc.NetConn()
	}
	if pc, ok := nc.(*peekedConn); ok {
		nc = pc.Conn
	}
	if tc, ok := nc.(*net.TCPConn); ok {
		_ = tc.SetKeepAliveConfig(net.KeepAliveConfig{Enable: true, Idle: 15 * time.Second, Interval: 5 * time.Second, Count: 4})
	}
}

// write sends a whole frame. A low-priority frame (a LOG batch) waits, up to half a second, while any ordinary frame
// is waiting or being written, so logging rides in the gaps of protocol traffic instead of ahead of it (§9).
func (conn *Conn) write(frame []byte, lowPriority bool) error {
	if lowPriority {
		deadline := time.Now().Add(500 * time.Millisecond)
		for conn.urgent.Load() > 0 && conn.Alive() && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
	} else {
		conn.urgent.Add(1)
		defer conn.urgent.Add(-1)
	}
	conn.writeMu.Lock()
	defer conn.writeMu.Unlock()
	if !conn.Alive() {
		return errors.New("connection closed")
	}
	_, err := conn.nc.Write(frame)
	return err
}

func (conn *Conn) addPending(id uint32) {
	conn.mu.Lock()
	conn.pending[id] = struct{}{}
	conn.mu.Unlock()
}

func (conn *Conn) removePending(id uint32) {
	conn.mu.Lock()
	delete(conn.pending, id)
	conn.mu.Unlock()
}

func (conn *Conn) takePending() []uint32 {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	ids := make([]uint32, 0, len(conn.pending))
	for id := range conn.pending {
		ids = append(ids, id)
	}
	conn.pending = map[uint32]struct{}{}
	return ids
}

// readFrame reads one frame: the raw header bytes as sent (version word included, the AEAD associated data), the
// parsed header and the payload as it is on the wire. io.EOF when the peer closed between frames.
func readFrame(r io.Reader) (raw []byte, h Header, payload []byte, err error) {
	word := make([]byte, VersionWordBytes)
	if _, err = io.ReadFull(r, word); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			err = io.EOF
		}
		return nil, h, nil, err
	}
	version := binary.BigEndian.Uint16(word)
	length, err := HeaderLength(version)
	if err != nil {
		return nil, h, nil, err
	}
	raw = make([]byte, VersionWordBytes+length)
	copy(raw, word)
	if _, err = io.ReadFull(r, raw[VersionWordBytes:]); err != nil {
		return nil, h, nil, fmt.Errorf("connection closed inside a header: %w", err)
	}
	if h, err = Unpack(raw); err != nil {
		return nil, h, nil, err
	}
	if h.DataLength > MaxFrameBytes {
		return nil, h, nil, fmt.Errorf("frame of %d bytes refused (limit %d)", h.DataLength, MaxFrameBytes)
	}
	payload = make([]byte, h.DataLength)
	if _, err = io.ReadFull(r, payload); err != nil {
		return nil, h, nil, fmt.Errorf("connection closed inside the payload of %s (request_id %d): %w", h.MethodName,
			h.RequestID, err)
	}
	return raw, h, payload, nil
}
