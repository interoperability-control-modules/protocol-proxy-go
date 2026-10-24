package ipc

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eclipse-volttron/protocol-proxy-go/logs"
)

// MethodResponse is the method name of a reply frame.
const MethodResponse = "RESPONSE"

// Port range a listener falls back to when no port is given (PROTOCOL.md §2).
const (
	MinPort = 22801
	MaxPort = 22899
)

const logName = "protocol_proxy_go.ipc"

// Message is what a caller sends: a method, its payload (UTF-8 JSON before compression or encryption; empty allowed),
// whether a RESPONSE is awaited, the remote it concerns (version 2 only) and the header version (0: version 2).
type Message struct {
	Method           string
	Payload          []byte
	RequestID        uint32 // 0: drawn when the message is sent
	ResponseExpected bool
	RemoteID         UUID
	Version          uint16
	// LowPriority frames (LOG batches) are written on a persistent connection only when no other frame is waiting.
	LowPriority bool
}

// Handler serves one method. It returns the reply payload (nil for none); an error becomes the error reply of §8.
type Handler func(h *Header, payload []byte) ([]byte, error)

// HandlerInfo is a registered handler.
type HandlerInfo struct {
	Handler          Handler
	Method           string
	ProvidesResponse bool
	Timeout          time.Duration
}

// Peer is a known remote system: who it is, how to reach it, what it shares with us.
type Peer struct {
	ID    UUID
	Token UUID
	Name  string
	// Address is where the peer listens ("host:port"), "" when unknown or not dialable; DialAddress overrides it.
	Address     string
	DialAddress string
	// Persistent is the connection policy toward this peer; nil uses the connector's default.
	Persistent *bool
	// Key is the 32-byte AEAD key shared with the peer, nil for clear text. Fixed for the peer's lifetime.
	Key []byte
	// TLS: every connection with this peer is TLS, mutually verified against the manager's CA.
	TLS bool

	mu       sync.Mutex
	features []string
	conn     *Conn
	dialMu   sync.Mutex
	lastSeen time.Time
}

// Features is what the peer advertised (REGISTER_PEER or its reply); nil before registration.
func (p *Peer) Features() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.features
}

// SetFeatures records what the peer advertised.
func (p *Peer) SetFeatures(features []string) {
	p.mu.Lock()
	p.features = append([]string(nil), features...)
	p.mu.Unlock()
}

// Connection is the open persistent connection to the peer, nil when there is none alive.
func (p *Peer) Connection() *Conn {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn != nil && p.conn.Alive() {
		return p.conn
	}
	return nil
}

// Linked reports whether a persistent connection with the peer is open.
func (p *Peer) Linked() bool { return p.Connection() != nil }

// LastSeen is when a frame from the peer last arrived (zero: never).
func (p *Peer) LastSeen() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastSeen
}

func (p *Peer) setConn(conn *Conn) (previous *Conn) {
	p.mu.Lock()
	previous, p.conn = p.conn, conn
	p.mu.Unlock()
	return previous
}

// Options configure a Connector.
type Options struct {
	ID    UUID
	Token UUID
	Name  string
	// Persistent is the default connection policy toward peers: one connection kept open per peer (true) or a
	// connection per message (false).
	Persistent bool
	// PersistentMaxFrame: a frame larger than this takes a connection of its own even toward a persistent peer
	// (0: the default of 256 KiB; negative: never).
	PersistentMaxFrame int
	// CompressThreshold: payloads larger than this are compressed toward a peer that advertised compress
	// (negative: never; 0: everything). Use DefaultCompressThreshold for the Python default.
	CompressThreshold int
	// Cipher is the AEAD this end uses when it encrypts (a resolved name, see ResolveCipher); "" is the baseline.
	Cipher string
	// TLS material makes every accepted connection TLS and lets this end dial TLS peers.
	TLS *TLSMaterial
	// TLSOptional, with TLS material, makes the listener accept plain connections too, telling them apart by the
	// first byte (a TLS record begins with 0x16, a frame with 0x00): a manager's listener (PROTOCOL.md §5, TLS).
	TLSOptional bool
	// Features is what this end advertises.
	Features []string
	Logger   *logs.Logger
	// DialTimeout bounds a connect (default 30 s); IOTimeout bounds a per-message connection's wait for its frame
	// or reply (default 30 s); HandlerTimeout bounds a handler (default 30 s).
	DialTimeout    time.Duration
	IOTimeout      time.Duration
	HandlerTimeout time.Duration
}

type remoteKey struct {
	method string
	remote UUID
}

type result struct {
	payload []byte
	err     error
}

// Connector is one end of the IPC: it listens, dials, authenticates frames, dispatches them to handlers and matches
// responses to requests. A proxy and a manager are both connectors.
type Connector struct {
	opts Options
	log  *logs.Logger
	ids  RequestIDs

	mu             sync.RWMutex
	peers          map[UUID]*Peer
	handlers       map[string]HandlerInfo
	remoteHandlers map[remoteKey]HandlerInfo
	waiters        map[uint32]chan result
	conns          map[*Conn]struct{}

	listener     net.Listener
	listenHost   string
	listenPort   int
	serverTLS    *tls.Config
	stopped      atomic.Bool
	startedAt    time.Time
	lastActivity atomic.Int64 // unix nanoseconds of the last frame received; 0 for none
	accepting    sync.WaitGroup
}

// New makes a connector. It does not listen until Listen is called.
func New(opts Options) (*Connector, error) {
	if opts.Logger == nil {
		opts.Logger = logs.New(logs.INFO, &logs.StreamSink{W: io.Discard})
	}
	if opts.Name == "" {
		opts.Name = opts.ID.String()
	}
	if opts.PersistentMaxFrame == 0 {
		opts.PersistentMaxFrame = DefaultPersistentMaxFrame
	}
	if opts.Cipher == "" {
		opts.Cipher = BaselineCipher
	} else if _, _, err := CipherFeature(opts.Cipher); err != nil {
		return nil, err
	}
	if opts.Features == nil {
		opts.Features = append([]string(nil), ConnectorFeatures...)
	}
	if opts.DialTimeout == 0 {
		opts.DialTimeout = 30 * time.Second
	}
	if opts.IOTimeout == 0 {
		opts.IOTimeout = 30 * time.Second
	}
	if opts.HandlerTimeout == 0 {
		opts.HandlerTimeout = 30 * time.Second
	}
	c := &Connector{opts: opts, log: opts.Logger, peers: map[UUID]*Peer{}, handlers: map[string]HandlerInfo{},
		remoteHandlers: map[remoteKey]HandlerInfo{}, waiters: map[uint32]chan result{}, conns: map[*Conn]struct{}{},
		startedAt: time.Now()}
	if opts.TLS != nil {
		cfg, err := opts.TLS.ServerConfig()
		if err != nil {
			return nil, err
		}
		c.serverTLS = cfg
	}
	return c, nil
}

// ID is this end's proxy id; Token its token; Name its name; Cipher the AEAD it encrypts with; Features what it
// advertises.
func (c *Connector) ID() UUID             { return c.opts.ID }
func (c *Connector) Token() UUID          { return c.opts.Token }
func (c *Connector) Name() string         { return c.opts.Name }
func (c *Connector) Cipher() string       { return c.opts.Cipher }
func (c *Connector) Features() []string   { return append([]string(nil), c.opts.Features...) }
func (c *Connector) Logger() *logs.Logger { return c.log }

// StartedAt is when the connector was created; Uptime the seconds since.
func (c *Connector) StartedAt() time.Time { return c.startedAt }
func (c *Connector) Uptime() float64      { return time.Since(c.startedAt).Seconds() }

// LastActivity is when the last frame was received, and whether one ever was.
func (c *Connector) LastActivity() (time.Time, bool) {
	ns := c.lastActivity.Load()
	if ns == 0 {
		return time.Time{}, false
	}
	return time.Unix(0, ns), true
}

// ---- peers and handlers ---------------------------------------------------------------------------------------------

// AddPeer makes a peer known: frames from it authenticate by its id and token.
func (c *Connector) AddPeer(peer *Peer) {
	c.mu.Lock()
	c.peers[peer.ID] = peer
	c.mu.Unlock()
}

// Peer is the known peer with that id, or nil.
func (c *Connector) Peer(id UUID) *Peer {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.peers[id]
}

// RemovePeer forgets a peer and closes its persistent connection.
func (c *Connector) RemovePeer(id UUID) {
	c.mu.Lock()
	peer := c.peers[id]
	delete(c.peers, id)
	c.mu.Unlock()
	if peer != nil {
		if conn := peer.setConn(nil); conn != nil {
			conn.Close()
		}
	}
}

// RegisterHandler registers the handler for a method. The first registration wins; a later one is a confirmation
// and returns false (as in the Python connectors).
func (c *Connector) RegisterHandler(method string, handler Handler, providesResponse bool) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.handlers[method]; exists {
		return false
	}
	c.handlers[method] = HandlerInfo{Handler: handler, Method: method, ProvidesResponse: providesResponse,
		Timeout: c.opts.HandlerTimeout}
	return true
}

// RegisterRemoteHandler registers the handler for a method tagged with a remote id (version 2 headers); it replaces
// any earlier handler for the same pair.
func (c *Connector) RegisterRemoteHandler(method string, remote UUID, handler Handler, providesResponse bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.remoteHandlers[remoteKey{method, remote}] = HandlerInfo{Handler: handler, Method: method,
		ProvidesResponse: providesResponse, Timeout: c.opts.HandlerTimeout}
}

// UnregisterHandler removes a method handler (remote zero) or a remote's handler; returns whether one was there.
func (c *Connector) UnregisterHandler(method string, remote UUID) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if remote.IsZero() {
		_, ok := c.handlers[method]
		delete(c.handlers, method)
		return ok
	}
	_, ok := c.remoteHandlers[remoteKey{method, remote}]
	delete(c.remoteHandlers, remoteKey{method, remote})
	return ok
}

// RemoteCount is the number of distinct remotes with their own handlers (the PING reply's "remotes").
func (c *Connector) RemoteCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	seen := map[UUID]struct{}{}
	for key := range c.remoteHandlers {
		seen[key.remote] = struct{}{}
	}
	return len(seen)
}

// findHandler: the remote's own handler if the frame names a remote it has, else the method's.
func (c *Connector) findHandler(h *Header) (HandlerInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !h.RemoteID.IsZero() {
		if info, ok := c.remoteHandlers[remoteKey{h.MethodName, h.RemoteID}]; ok {
			return info, true
		}
	}
	info, ok := c.handlers[h.MethodName]
	return info, ok
}

// ---- payload policy -------------------------------------------------------------------------------------------------

// ErrorPayload is the JSON error reply of §8.
func ErrorPayload(method, text string) []byte {
	out, _ := json.Marshal(map[string]string{"status": "error", "error": text, "method": method})
	return out
}

func (c *Connector) isPersistent(peer *Peer) bool {
	if peer.Persistent != nil {
		return *peer.Persistent
	}
	return c.opts.Persistent
}

// cipherFor: ours, unless the peer has advertised features that do not include it, then the baseline.
func (c *Connector) cipherFor(peer *Peer) (aesGCM bool) {
	feature, aes, _ := CipherFeature(c.opts.Cipher)
	if features := peer.Features(); len(features) > 0 && !HasFeature(features, feature) {
		return false
	}
	return aes
}

// frame is the wire bytes of a message toward peer: compressed when the peer takes it and the payload is above the
// threshold, then encrypted when a key is shared with it; the header as sent is the associated data.
func (c *Connector) frame(msg *Message, keepAlive bool, peer *Peer) ([]byte, error) {
	payload := msg.Payload
	compressed := false
	if peer != nil && c.opts.CompressThreshold >= 0 && len(payload) > c.opts.CompressThreshold &&
		HasFeature(peer.Features(), FeatureCompress) {
		z, err := Compress(payload)
		if err != nil {
			return nil, err
		}
		payload, compressed = z, true
	}
	version := msg.Version
	if version == 0 {
		version = DefaultVersion
	}
	h := Header{Version: version, MethodName: msg.Method, RequestID: msg.RequestID, SenderID: c.opts.ID,
		SenderToken: c.opts.Token, ResponseExpected: msg.ResponseExpected, Compressed: compressed, KeepAlive: keepAlive}
	if version >= 2 {
		h.RemoteID = msg.RemoteID
	}
	if peer == nil || peer.Key == nil {
		h.DataLength = uint64(len(payload))
		hb, err := h.Pack()
		if err != nil {
			return nil, err
		}
		return append(hb, payload...), nil
	}
	h.Encrypted, h.AESGCM = true, c.cipherFor(peer)
	h.DataLength = uint64(len(payload) + NonceBytes + TagBytes)
	hb, err := h.Pack()
	if err != nil {
		return nil, err
	}
	body, err := Seal(peer.Key, hb, payload, h.AESGCM)
	if err != nil {
		return nil, err
	}
	return append(hb, body...), nil
}

// openFrame is the payload as the sender had it. The mode is fixed per peer: a clear-text frame from a peer we
// share a key with, or an encrypted one from a peer we do not, is refused (§5).
func (c *Connector) openFrame(peer *Peer, h *Header, rawHeader, payload []byte) ([]byte, error) {
	var key []byte
	if peer != nil {
		key = peer.Key
	}
	if h.Encrypted {
		if key == nil {
			return nil, fmt.Errorf("encrypted %s from %s, with whom no key is shared", h.MethodName, h.SenderID)
		}
		plain, err := Open(key, rawHeader, payload, h.AESGCM)
		if err != nil {
			return nil, fmt.Errorf("encrypted %s from %s: %w", h.MethodName, h.SenderID, err)
		}
		payload = plain
	} else if key != nil {
		return nil, fmt.Errorf("clear-text %s from %s, who must encrypt", h.MethodName, h.SenderID)
	}
	if h.Compressed {
		return Decompress(payload)
	}
	return payload, nil
}

// frameIdentityOK: over TLS the sender id must be the certificate's common name; a peer marked TLS must not arrive
// in the clear.
func (c *Connector) frameIdentityOK(h *Header, tlsPeer string, peer *Peer) bool {
	if tlsPeer != "" {
		if h.SenderID.Hex() != tlsPeer {
			c.log.Warningf(logName, "%s: frame from %s over a TLS connection authenticated as %s; dropped.", c.opts.Name,
				h.SenderID, tlsPeer)
			return false
		}
		return true
	}
	if peer != nil && peer.TLS {
		c.log.Warningf(logName, "%s: clear-text frame from %s, who must use TLS; dropped.", c.opts.Name, h.SenderID)
		return false
	}
	return true
}

// ---- listening ------------------------------------------------------------------------------------------------------

// Listen binds the inbound listener: address:port when port > 0 and free, else the first free port in 22801..22899
// on address. With TLS material the listener accepts TLS only. Serve must be called to accept connections.
func (c *Connector) Listen(address string, port int) error {
	if address == "" {
		address = "localhost"
	}
	var l net.Listener
	var err error
	if port > 0 {
		l, err = net.Listen("tcp4", net.JoinHostPort(address, strconv.Itoa(port)))
		if err != nil {
			c.log.Warningf(logName, "Unable to bind to provided inbound socket %s:%d. Trying next available. - %v", address,
				port, err)
		}
	}
	if l == nil {
		for p := MinPort; p <= MaxPort; p++ {
			if l, err = net.Listen("tcp4", net.JoinHostPort(address, strconv.Itoa(p))); err == nil {
				break
			}
		}
		if l == nil {
			return fmt.Errorf("unable to bind inbound socket to %s on any port in range %d - %d: %w", address, MinPort,
				MaxPort, err)
		}
	}
	host, portText, _ := net.SplitHostPort(l.Addr().String())
	c.listenHost = host
	c.listenPort, _ = strconv.Atoi(portText)
	if c.serverTLS != nil && !c.opts.TLSOptional {
		l = tls.NewListener(l, c.serverTLS)
	}
	c.listener = l
	c.log.Infof(logName, "Created new inbound server socket: %s:%d.", c.listenHost, c.listenPort)
	return nil
}

// ListenAddress is the bound host and port (after Listen).
func (c *Connector) ListenAddress() (string, int) { return c.listenHost, c.listenPort }

// Serve accepts connections until Stop; it returns at once, accepting in the background.
func (c *Connector) Serve() {
	if c.listener == nil {
		return
	}
	c.accepting.Add(1)
	go func() {
		defer c.accepting.Done()
		for !c.stopped.Load() {
			nc, err := c.listener.Accept()
			if err != nil {
				if c.stopped.Load() {
					return
				}
				c.log.Warningf(logName, "%s: Error accepting a connection: %v", c.opts.Name, err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			if c.serverTLS != nil && c.opts.TLSOptional {
				go c.serveSniffed(nc)
				continue
			}
			conn := newConn(c, nc, true)
			_ = nc.SetDeadline(time.Now().Add(c.opts.IOTimeout))
			c.track(conn)
			go c.serve(conn)
		}
	}()
}

// serveSniffed serves an accepted connection that may be TLS or plain: the first byte tells (a TLS ClientHello
// record starts with 0x16, a frame's version word with 0x00), as the Python manager's listener does.
func (c *Connector) serveSniffed(nc net.Conn) {
	_ = nc.SetReadDeadline(time.Now().Add(c.opts.IOTimeout))
	head := make([]byte, 1)
	if _, err := io.ReadFull(nc, head); err != nil {
		c.log.Debugf(logName, "%s: connection from %s ended before any data: %v", c.opts.Name, nc.RemoteAddr(), err)
		_ = nc.Close()
		return
	}
	var wrapped net.Conn = &peekedConn{Conn: nc, head: head}
	if head[0] == 0x16 {
		wrapped = tls.Server(wrapped, c.serverTLS)
	}
	conn := newConn(c, wrapped, true)
	_ = wrapped.SetDeadline(time.Now().Add(c.opts.IOTimeout))
	c.track(conn)
	c.serve(conn)
}

// Stop closes the listener and every connection; pending requests fail.
func (c *Connector) Stop() {
	if !c.stopped.CompareAndSwap(false, true) {
		return
	}
	if c.listener != nil {
		_ = c.listener.Close()
	}
	c.mu.Lock()
	conns := make([]*Conn, 0, len(c.conns))
	for conn := range c.conns {
		conns = append(conns, conn)
	}
	c.mu.Unlock()
	for _, conn := range conns {
		c.drop(conn, "closed")
	}
	c.accepting.Wait()
}

// Stopped reports whether Stop was called.
func (c *Connector) Stopped() bool { return c.stopped.Load() }

func (c *Connector) track(conn *Conn) {
	c.mu.Lock()
	c.conns[conn] = struct{}{}
	c.mu.Unlock()
}

// drop forgets a connection: closes it, fails the requests awaiting responses on it, detaches it from its peer.
func (c *Connector) drop(conn *Conn, reason string) {
	c.mu.Lock()
	delete(c.conns, conn)
	c.mu.Unlock()
	conn.Close()
	peerID := conn.PeerID()
	if ids := conn.takePending(); len(ids) > 0 {
		c.failWaiters(ids, fmt.Errorf("connection to %s lost: %s", peerID, reason))
	}
	if !peerID.IsZero() {
		if peer := c.Peer(peerID); peer != nil {
			peer.mu.Lock()
			if peer.conn == conn {
				peer.conn = nil
				if !c.stopped.Load() && reason != "closed" {
					c.log.Infof(logName, "%s: persistent connection to %s %s.", c.opts.Name, peerID, reason)
				}
			}
			peer.mu.Unlock()
		}
	}
}

// ---- serving --------------------------------------------------------------------------------------------------------

func (c *Connector) touch(peer *Peer) {
	now := time.Now()
	c.lastActivity.Store(now.UnixNano())
	if peer != nil {
		peer.mu.Lock()
		peer.lastSeen = now
		peer.mu.Unlock()
	}
}

// serve reads and dispatches frames on a connection until the other side closes it, it fails, or we stop.
func (c *Connector) serve(conn *Conn) {
	reason := "closed by the peer"
	defer func() { c.drop(conn, reason) }()
	if tc, ok := conn.nc.(*tls.Conn); ok {
		ctx, cancel := context.WithTimeout(context.Background(), c.opts.IOTimeout)
		err := tc.HandshakeContext(ctx)
		cancel()
		if err != nil {
			reason = "closed"
			c.log.Warningf(logName, "%s: TLS handshake with %s failed: %v", c.opts.Name, conn.RemoteAddr(), err)
			return
		}
		conn.mu.Lock()
		conn.tlsPeer = PeerCommonName(tc.ConnectionState())
		conn.mu.Unlock()
	}
	for !c.stopped.Load() {
		rawHeader, h, payload, err := readFrame(conn.r)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				if !conn.Alive() {
					reason = "closed"
				} else {
					reason = err.Error()
					c.log.Warningf(logName, "%s: Error serving %s: %v", c.opts.Name, conn.RemoteAddr(), err)
				}
			}
			return
		}
		peer := c.Peer(h.SenderID)
		c.touch(peer)
		if !c.frameIdentityOK(&h, conn.TLSPeer(), peer) {
			continue
		}
		if peer == nil || peer.Token != h.SenderToken {
			c.log.Warningf(logName, "%s: %s from unauthenticated sender %s at %s dropped.", c.opts.Name, h.MethodName,
				h.SenderID, conn.RemoteAddr())
			if h.ResponseExpected && h.MethodName != MethodResponse {
				c.reply(conn, &h, nil, nil)
			}
			if !conn.Persistent() {
				return
			}
			continue
		}
		plain, err := c.openFrame(peer, &h, rawHeader, payload)
		if err != nil {
			c.log.Warningf(logName, "%s: Dropping %s from %s: %v", c.opts.Name, h.MethodName, h.SenderID, err)
			reason = "closed"
			return
		}
		if h.KeepAlive && !conn.Persistent() {
			c.adopt(conn, peer)
		}
		if h.MethodName == MethodResponse {
			conn.removePending(h.RequestID)
			c.deliverResponse(&h, plain)
			if !conn.Persistent() {
				reason = "closed"
				return
			}
			continue
		}
		info, found := c.findHandler(&h)
		if !found {
			c.log.Warningf(logName, "%s: Received unknown method name: %s from %s with request ID: %d", c.opts.Name,
				h.MethodName, conn.RemoteAddr(), h.RequestID)
		}
		if owed := c.unanswerable(&h, info, found); owed != nil {
			c.reply(conn, &h, owed, peer)
		}
		if conn.Persistent() {
			if found {
				go c.dispatch(conn, &h, plain, info, peer)
			}
			continue
		}
		if found {
			c.dispatch(conn, &h, plain, info, peer)
		}
		reason = "closed"
		return // per message: one frame, its reply if any, then close
	}
}

// adopt: a frame with the keep-alive bit arrived on an accepted connection from an authenticated peer; send to the
// peer on this connection from now on (replacing any earlier one).
func (c *Connector) adopt(conn *Conn, peer *Peer) {
	conn.makePersistent(peer.ID)
	if previous := peer.setConn(conn); previous != nil && previous != conn && previous.Alive() {
		c.log.Infof(logName, "%s: %s opened a new persistent connection; closing the earlier one.", c.opts.Name, peer.ID)
		c.drop(previous, "closed")
	}
}

// unanswerable: the error reply owed when a request expects a response no handler will give.
func (c *Connector) unanswerable(h *Header, info HandlerInfo, found bool) []byte {
	if !h.ResponseExpected {
		return nil
	}
	if !found {
		return ErrorPayload(h.MethodName, "Unknown method "+h.MethodName)
	}
	if !info.ProvidesResponse {
		return ErrorPayload(h.MethodName, "Method "+h.MethodName+" provides no response")
	}
	return nil
}

func (c *Connector) dispatch(conn *Conn, h *Header, payload []byte, info HandlerInfo, peer *Peer) {
	done := make(chan result, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- result{err: fmt.Errorf("handler panicked: %v", r)}
			}
		}()
		out, err := info.Handler(h, payload)
		done <- result{payload: out, err: err}
	}()
	var res result
	timer := time.NewTimer(info.Timeout)
	defer timer.Stop()
	select {
	case res = <-done:
	case <-timer.C:
		text := fmt.Sprintf("Operation timed out after %g seconds", info.Timeout.Seconds())
		c.log.Warningf(logName, "%s: Callback %s %s", c.opts.Name, h.MethodName, text)
		res = result{payload: ErrorPayload(h.MethodName, text)}
	}
	if res.err != nil {
		c.log.Warningf(logName, "%s: Callback %s raised: %v", c.opts.Name, h.MethodName, res.err)
		res.payload = ErrorPayload(h.MethodName, res.err.Error())
	}
	if info.ProvidesResponse {
		c.reply(conn, h, res.payload, peer)
	}
}

// reply writes the RESPONSE to a request on the connection it arrived on, in the request's header version.
func (c *Connector) reply(conn *Conn, h *Header, payload []byte, peer *Peer) {
	if payload == nil {
		payload = []byte{}
	}
	msg := &Message{Method: MethodResponse, Payload: payload, RequestID: h.RequestID, Version: h.Version}
	frame, err := c.frame(msg, conn.Persistent(), peer)
	if err == nil {
		err = conn.write(frame, false)
	}
	if err != nil && !c.stopped.Load() {
		c.log.Warningf(logName, "%s: Unable to answer %s (request_id: %d): %v", c.opts.Name, h.MethodName, h.RequestID, err)
	}
}

// ---- responses ------------------------------------------------------------------------------------------------------

func (c *Connector) addWaiter(id uint32) chan result {
	ch := make(chan result, 1)
	c.mu.Lock()
	c.waiters[id] = ch
	c.mu.Unlock()
	return ch
}

func (c *Connector) removeWaiter(id uint32) {
	c.mu.Lock()
	delete(c.waiters, id)
	c.mu.Unlock()
}

func (c *Connector) deliverResponse(h *Header, payload []byte) {
	c.mu.Lock()
	ch := c.waiters[h.RequestID]
	delete(c.waiters, h.RequestID)
	c.mu.Unlock()
	if ch == nil {
		c.log.Warningf(logName, "Received response %d from %s containing %q, but no request awaits it.", h.RequestID,
			h.SenderID, string(payload))
		return
	}
	ch <- result{payload: payload}
}

func (c *Connector) failWaiters(ids []uint32, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, id := range ids {
		if ch := c.waiters[id]; ch != nil {
			delete(c.waiters, id)
			ch <- result{err: err}
		}
	}
}

// ---- sending --------------------------------------------------------------------------------------------------------

// Send writes a message that expects no response. An open persistent connection to the peer is used when there is
// one; otherwise a persistent peer gets one dialled and any other peer gets a connection for this message alone.
func (c *Connector) Send(peer *Peer, msg *Message) error {
	msg.ResponseExpected = false
	_, err := c.send(peer, msg)
	return err
}

// Request sends a message and waits for its RESPONSE payload until ctx ends.
func (c *Connector) Request(ctx context.Context, peer *Peer, msg *Message) ([]byte, error) {
	msg.ResponseExpected = true
	ch, err := c.send(peer, msg)
	if err != nil {
		return nil, err
	}
	select {
	case res := <-ch:
		return res.payload, res.err
	case <-ctx.Done():
		c.removeWaiter(msg.RequestID)
		return nil, fmt.Errorf("%s (request_id %d) to %s: %w", msg.Method, msg.RequestID, peer.ID, ctx.Err())
	}
}

func (c *Connector) send(peer *Peer, msg *Message) (chan result, error) {
	if peer == nil {
		return nil, errors.New("send needs a peer")
	}
	address := peer.DialAddress
	if address == "" {
		address = peer.Address
	}
	link := peer.Connection()
	if address == "" && link == nil {
		return nil, fmt.Errorf("refusing to send to %s: no open connection and no address to dial", peer.ID)
	}
	if msg.RequestID == 0 {
		msg.RequestID = c.ids.Next(msg.Version)
	}
	var ch chan result
	if msg.ResponseExpected {
		ch = c.addWaiter(msg.RequestID)
	}
	fail := func(err error) (chan result, error) {
		if ch != nil {
			c.removeWaiter(msg.RequestID)
		}
		if !c.stopped.Load() {
			c.log.Warningf(logName, "%s: Unable to send %s (request_id: %d) to %s: %v", c.opts.Name, msg.Method,
				msg.RequestID, peer.ID, err)
		}
		return nil, err
	}
	if link == nil && !c.isPersistent(peer) {
		if err := c.sendPerMessage(peer, address, msg); err != nil {
			return fail(err)
		}
		return ch, nil
	}
	frame, err := c.frame(msg, true, peer)
	if err != nil {
		return fail(err)
	}
	if address != "" && c.opts.PersistentMaxFrame > 0 && len(frame) > c.opts.PersistentMaxFrame {
		if err := c.sendPerMessage(peer, address, msg); err != nil { // its own connection
			return fail(err)
		}
		return ch, nil
	}
	if link == nil {
		if link, err = c.link(peer, address); err != nil {
			return fail(err)
		}
	}
	if msg.ResponseExpected {
		link.addPending(msg.RequestID)
	}
	if err := link.write(frame, msg.LowPriority); err != nil {
		link.removePending(msg.RequestID)
		return fail(err)
	}
	return ch, nil
}

// sendPerMessage dials a connection for this message alone: write the frame and, when a reply is expected, serve
// the connection until the reply (or EOF) arrives; otherwise close at once.
func (c *Connector) sendPerMessage(peer *Peer, address string, msg *Message) error {
	frame, err := c.frame(msg, false, peer)
	if err != nil {
		return err
	}
	nc, err := c.dial(peer, address)
	if err != nil {
		return err
	}
	conn := newConn(c, nc, false)
	conn.setPeerID(peer.ID)
	if tc, ok := nc.(*tls.Conn); ok {
		conn.tlsPeer = PeerCommonName(tc.ConnectionState())
	}
	c.track(conn)
	if !msg.ResponseExpected {
		err := conn.write(frame, false)
		c.drop(conn, "closed")
		return err
	}
	_ = nc.SetDeadline(time.Now().Add(c.opts.IOTimeout))
	conn.addPending(msg.RequestID)
	if err := conn.write(frame, false); err != nil {
		c.drop(conn, "closed")
		return err
	}
	go c.serve(conn)
	return nil
}

// link is the peer's open persistent connection, dialled now if it has none.
func (c *Connector) link(peer *Peer, address string) (*Conn, error) {
	peer.dialMu.Lock()
	defer peer.dialMu.Unlock()
	if conn := peer.Connection(); conn != nil {
		return conn, nil
	}
	if address == "" {
		return nil, fmt.Errorf("no open connection to %s and no address to dial", peer.ID)
	}
	nc, err := c.dial(peer, address)
	if err != nil {
		return nil, err
	}
	conn := newConn(c, nc, false)
	conn.makePersistent(peer.ID)
	if tc, ok := nc.(*tls.Conn); ok {
		conn.tlsPeer = PeerCommonName(tc.ConnectionState())
	}
	c.track(conn)
	peer.setConn(conn)
	go c.serve(conn)
	c.log.Infof(logName, "%s: opened a persistent connection to %s @ %s.", c.opts.Name, peer.ID, address)
	return conn, nil
}

// dial connects to address, over TLS (verifying the certificate names the peer) when the peer is a TLS peer.
func (c *Connector) dial(peer *Peer, address string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: c.opts.DialTimeout}
	if !peer.TLS {
		return dialer.Dial("tcp4", address)
	}
	if c.opts.TLS == nil {
		return nil, fmt.Errorf("%s requires TLS but this end has no TLS material", peer.ID)
	}
	cfg, err := c.opts.TLS.ClientConfig(peer.ID.Hex())
	if err != nil {
		return nil, err
	}
	tc, err := tls.DialWithDialer(dialer, "tcp4", address, cfg)
	if err != nil {
		return nil, err
	}
	return tc, nil
}
