// Package manager is a ProtocolProxyManager: it launches proxy processes described by manifests (PROTOCOL.md §1a),
// hands each its tokens, key and TLS material on stdin (§1), accepts their registration (§7), reads their logs from
// the pipes and from LOG batches (§9), keeps them alive with PING (§10), terminates them on Stop and relaunches them
// on the next request after a loss. It is built on the same ipc.Connector as a proxy, so a Go program can host
// proxies written in any language.
//
// Typical use:
//
//	m, _ := manager.New(manager.Options{Manifest: mf})
//	m.Start()
//	p, _ := m.GetProxy([]any{"device-1"}, map[string]any{"host": "10.0.0.5"})
//	m.WaitRegistered(p, 20*time.Second)
//	reply, _ := m.Call(ctx, p, "READ_POINTS", payload)
package manager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eclipse-volttron/protocol-proxy-go/ipc"
	"github.com/eclipse-volttron/protocol-proxy-go/logs"
	"github.com/eclipse-volttron/protocol-proxy-go/manifest"
)

const logName = "protocol_proxy_go.manager"

// Core method names (PROTOCOL.md §8).
const (
	MethodRegisterPeer = "REGISTER_PEER"
	MethodPing         = "PING"
	MethodLog          = "LOG"
	MethodSetLogLevel  = "SET_LOG_LEVEL"
)

// Liveness defaults (§10) and the process clean-up (§1).
const (
	DefaultHeartbeatInterval = 10 * time.Second
	DefaultHeartbeatTimeout  = 5 * time.Second
	DefaultHeartbeatMisses   = 3
	DefaultTerminateTimeout  = 5 * time.Second
	DialRetryInterval        = time.Second
)

// EnvPython names the interpreter {python} resolves to when Options.Python is empty; the default is python3.
const EnvPython = "PROTOCOL_PROXY_PYTHON"

// ManagerOnlyOptions are GetProxy options the manager consumes itself; everything else travels to the proxy as
// --name value.
var ManagerOnlyOptions = map[string]bool{"manager_callbacks": true, "dial": true, "ssh_host": true, "ssh_options": true,
	"ssh_forward": true, "remote_python": true, "remote_env": true}

// Options configure a Manager.
type Options struct {
	// Manifest describes what this manager launches and how it keys the processes (required).
	Manifest *manifest.Manifest
	// Name is this end's proxy name in log lines (default "Manager").
	Name string
	// InboundAddress and InboundPort are the listener; port 0 (or one in use) takes the first free port in
	// 22801..22899. Proxies are told --manager-address InboundAddress.
	InboundAddress string
	InboundPort    int
	// Persistent is the default connection policy toward proxies (a per-proxy "persistent" launch option wins).
	Persistent bool
	// Encrypt gives every proxy an AEAD key unless its launch options say encrypt=false; Cipher is the AEAD this end
	// uses ("auto", "aes-256-gcm" or "chacha20-poly1305").
	Encrypt bool
	Cipher  string
	// IPCTLS makes TLS the default for every proxy (a per-proxy "ipc_tls" launch option wins).
	IPCTLS bool
	// CompressThreshold: payloads above it are compressed toward proxies that advertised compress (0: 4096; negative:
	// never).
	CompressThreshold int
	// Heartbeat: PING every registered proxy each HeartbeatInterval (0: 10 s), expecting a reply within
	// HeartbeatTimeout (0: 5 s); HeartbeatMisses (0: 3) consecutive misses lose the proxy. NoHeartbeat disables it.
	HeartbeatInterval time.Duration
	HeartbeatTimeout  time.Duration
	HeartbeatMisses   int
	NoHeartbeat       bool
	// Python is what {python} in a manifest command resolves to: this, else $PROTOCOL_PROXY_PYTHON, else "python3".
	Python string
	// Logger is the manager's own log (default: INFO to stderr as readable text).
	Logger *logs.Logger
	// Records receives the launched proxies' log records (default: LoggerRecordHandler{Logger}).
	Records RecordHandler
	// ProxyLogLevel gates the proxies' records in this process and is passed to them as --log-level (0: INFO).
	ProxyLogLevel logs.Level
	// Environment is added to every proxy's environment after the manifest's.
	Environment map[string]string
}

// Manager launches and talks to the proxies of one manifest.
type Manager struct {
	opts     Options
	Manifest *manifest.Manifest
	conn     *ipc.Connector
	log      *logs.Logger
	records  RecordHandler
	cipher   string

	// Authority is this manager's certificate authority; Material its own certificate (used on TLS connections).
	Authority *Authority
	Material  *ipc.TLSMaterial

	mu           sync.Mutex
	proxies      map[ipc.UUID]*Proxy
	ids          map[string]ipc.UUID       // process key -> proxy id, kept across relaunches
	shared       map[string]map[string]any // must_match options of the first remote of each process
	lost         []func(p *Proxy, reason string)
	stoppingPIDs map[int]bool
	started      bool

	heartbeatOnce sync.Once
	stopHeartbeat chan struct{}
	stopped       atomic.Bool
}

// New makes a manager. It issues itself a CA and a certificate at once, so any proxy may be launched with TLS.
func New(opts Options) (*Manager, error) {
	if opts.Manifest == nil {
		return nil, errors.New("a manager needs a Manifest")
	}
	if opts.Name == "" {
		opts.Name = "Manager"
	}
	if opts.InboundAddress == "" {
		opts.InboundAddress = "localhost"
	}
	if opts.HeartbeatInterval == 0 {
		opts.HeartbeatInterval = DefaultHeartbeatInterval
	}
	if opts.HeartbeatTimeout == 0 {
		opts.HeartbeatTimeout = DefaultHeartbeatTimeout
	}
	if opts.HeartbeatMisses == 0 {
		opts.HeartbeatMisses = DefaultHeartbeatMisses
	}
	if opts.ProxyLogLevel == 0 {
		opts.ProxyLogLevel = logs.INFO
	}
	if opts.Logger == nil {
		opts.Logger = logs.New(logs.INFO, &logs.StreamSink{W: os.Stderr})
	}
	if opts.Records == nil {
		opts.Records = LoggerRecordHandler{Logger: opts.Logger}
	}
	cipher, err := ipc.ResolveCipher(opts.Cipher)
	if err != nil {
		return nil, err
	}
	threshold := opts.CompressThreshold
	if threshold == 0 {
		threshold = ipc.DefaultCompressThreshold
	}
	id := ipc.NewUUID()
	authority, err := NewAuthority("protocol-proxy manager " + id.String())
	if err != nil {
		return nil, err
	}
	material, err := authority.Issue(id.Hex(), opts.InboundAddress)
	if err != nil {
		return nil, err
	}
	conn, err := ipc.New(ipc.Options{ID: id, Token: ipc.NewUUID(), Name: opts.Name, Persistent: opts.Persistent,
		CompressThreshold: threshold, Cipher: cipher, TLS: material, TLSOptional: true, Features: ipc.ConnectorFeatures,
		Logger: opts.Logger})
	if err != nil {
		return nil, err
	}
	m := &Manager{opts: opts, Manifest: opts.Manifest, conn: conn, log: opts.Logger, records: opts.Records, cipher: cipher,
		Authority: authority, Material: material, proxies: map[ipc.UUID]*Proxy{}, ids: map[string]ipc.UUID{},
		shared: map[string]map[string]any{}, stoppingPIDs: map[int]bool{}, stopHeartbeat: make(chan struct{})}
	conn.RegisterHandler(MethodRegisterPeer, m.handleRegisterPeer, true)
	conn.RegisterHandler(MethodLog, m.handleLog, false)
	return m, nil
}

// Conn is the manager's connector (to register further handlers, e.g. for a proxy's unsolicited pushes).
func (m *Manager) Conn() *ipc.Connector { return m.conn }

// ID is the manager's proxy id; Token its token; Cipher the AEAD it encrypts with; Logger its log.
func (m *Manager) ID() ipc.UUID         { return m.conn.ID() }
func (m *Manager) Token() ipc.UUID      { return m.conn.Token() }
func (m *Manager) Cipher() string       { return m.cipher }
func (m *Manager) Logger() *logs.Logger { return m.log }
func (m *Manager) Options() Options     { return m.opts }

// Start binds the listener and begins accepting connections.
func (m *Manager) Start() error {
	if err := m.conn.Listen(m.opts.InboundAddress, m.opts.InboundPort); err != nil {
		return err
	}
	m.conn.Serve()
	m.mu.Lock()
	m.started = true
	m.mu.Unlock()
	return nil
}

// ListenAddress is the bound host and port (after Start).
func (m *Manager) ListenAddress() (string, int) { return m.conn.ListenAddress() }

// Python is what {python} resolves to for this manager.
func (m *Manager) Python() string {
	if m.opts.Python != "" {
		return m.opts.Python
	}
	if env := os.Getenv(EnvPython); env != "" {
		return env
	}
	return "python3"
}

// ---- proxies --------------------------------------------------------------------------------------------------------

// Proxies lists the proxies this manager currently knows.
func (m *Manager) Proxies() []*Proxy {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Proxy, 0, len(m.proxies))
	for _, p := range m.proxies {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ProxyByID is the known proxy with that id, or nil.
func (m *Manager) ProxyByID(id ipc.UUID) *Proxy {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.proxies[id]
}

func (m *Manager) isCurrent(p *Proxy) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.proxies[p.ID] == p
}

// OnProxyLost registers callback(proxy, reason), called whenever a proxy this manager launched is lost: its process
// exited, it missed too many heartbeats, or it never registered. By then the proxy is already removed, so the next
// GetProxy for its key launches a fresh process; users typically re-run their setup from the callback.
func (m *Manager) OnProxyLost(callback func(p *Proxy, reason string)) {
	m.mu.Lock()
	m.lost = append(m.lost, callback)
	m.mu.Unlock()
}

func (m *Manager) notifyLost(p *Proxy, reason string) {
	m.mu.Lock()
	callbacks := make([]func(*Proxy, string), len(m.lost))
	copy(callbacks, m.lost)
	m.mu.Unlock()
	for _, callback := range callbacks {
		func() {
			defer func() {
				if r := recover(); r != nil {
					m.log.Warningf(logName, "PPM: proxy-lost callback panicked for %s: %v", p.ID, r)
				}
			}()
			callback(p, reason)
		}()
	}
}

// loseProxy forgets a proxy, stops its process if it is still running, and tells the listeners.
func (m *Manager) loseProxy(p *Proxy, reason string) {
	m.mu.Lock()
	current := m.proxies[p.ID] == p
	if current {
		delete(m.proxies, p.ID)
	}
	m.mu.Unlock()
	if !current {
		return
	}
	m.conn.RemovePeer(p.ID)
	p.markLost(reason)
	if p.Running() {
		go m.terminate(p, DefaultTerminateTimeout)
	}
	m.notifyLost(p, reason)
}

// GetProxy is the proxy for uniqueRemoteID, launching its process when none runs for its key. The options are the
// proxy's launch options (Python kwargs spelling, underscores): they select the process through the manifest's
// identity, are checked against its must_match, and travel to the proxy as --name value, except the manager-only
// ones (ManagerOnlyOptions). "encrypt", "cipher", "ipc_tls", "persistent" and "manager_dials" also configure this
// end's side of the connection; "dial" ("host:port") is where to reach a proxy launched with manager_dials.
// The manager must have been started.
func (m *Manager) GetProxy(uniqueRemoteID []any, options map[string]any) (*Proxy, error) {
	if options == nil {
		options = map[string]any{}
	}
	key := m.Manifest.ProcessKey(uniqueRemoteID, options)
	keyText := PyTuple(key)

	m.mu.Lock()
	if !m.started {
		m.mu.Unlock()
		return nil, errors.New("the manager has not been started")
	}
	if m.stopped.Load() {
		m.mu.Unlock()
		return nil, errors.New("the manager is stopped")
	}
	if first, known := m.shared[keyText]; known {
		if conflicts := m.Manifest.Identity.Conflicts(first, options); len(conflicts) > 0 {
			m.mu.Unlock()
			return nil, fmt.Errorf("remote %s would share proxy process %s but differs in %s, which the %s manifest"+
				" requires to match", PyTuple(uniqueRemoteID), keyText, strings.Join(conflicts, ", "), m.Manifest.Name)
		}
	} else {
		shared := map[string]any{}
		for _, k := range m.Manifest.Identity.MustMatch {
			shared[k] = options[k]
		}
		m.shared[keyText] = shared
	}
	id, known := m.ids[keyText]
	if !known {
		id = ipc.NewUUID()
		m.ids[keyText] = id
	}
	if p, running := m.proxies[id]; running {
		m.mu.Unlock()
		return p, nil
	}
	p, err := m.prepare(id, keyText, key, options)
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	m.conn.AddPeer(p.Peer)
	m.proxies[id] = p
	m.mu.Unlock()

	if err := m.launch(p); err != nil {
		m.mu.Lock()
		if m.proxies[id] == p {
			delete(m.proxies, id)
		}
		m.mu.Unlock()
		m.conn.RemovePeer(id)
		return nil, err
	}
	if p.Peer.DialAddress != "" {
		go m.dialUntilRegistered(p)
	}
	m.startHeartbeat()
	m.log.Infof(logName, "PPM: Proxy %s created, waiting for registration before sending.", id)
	return p, nil
}

// prepare builds the proxy's peer, launch command and handshake from its options (the manager lock is held).
func (m *Manager) prepare(id ipc.UUID, name string, key []any, options map[string]any) (*Proxy, error) {
	launch := map[string]any{}
	for k, v := range options {
		if v != nil && !ManagerOnlyOptions[k] {
			launch[k] = v
		}
	}
	prefix, python, err := m.launcherPrefix(options)
	if err != nil {
		return nil, err
	}
	if len(prefix) > 0 && optBool(options["ssh_forward"], true) {
		if _, given := launch["manager_address"]; !given {
			launch["manager_address"] = "127.0.0.1" // the forwarded port on the proxy's host
		}
	}
	if _, given := launch["log_level"]; !given {
		launch["log_level"] = logs.LevelName(m.opts.ProxyLogLevel)
	}
	if m.opts.Encrypt {
		if _, given := launch["encrypt"]; !given {
			launch["encrypt"] = true
		}
	}
	encrypt := optBool(launch["encrypt"], false)
	if encrypt {
		if _, given := launch["cipher"]; !given {
			launch["cipher"] = m.cipher // one choice for both ends unless the caller says otherwise
		}
	}
	if m.opts.IPCTLS {
		if _, given := launch["ipc_tls"]; !given {
			launch["ipc_tls"] = true
		}
	}
	useTLS := optBool(launch["ipc_tls"], false)
	managerAddress := m.opts.InboundAddress
	if v, given := launch["manager_address"]; given {
		managerAddress = fmt.Sprint(v)
		delete(launch, "manager_address")
	}
	var persistent *bool
	if v, given := launch["persistent"]; given {
		b := optBool(v, false)
		persistent = &b
	}
	dial, err := dialTarget(options)
	if err != nil {
		return nil, err
	}
	if dial != "" {
		t := true
		persistent = &t
	}
	names := make([]string, 0, len(launch))
	for k := range launch {
		names = append(names, k)
	}
	sort.Strings(names)
	_, port := m.conn.ListenAddress()
	standard := []string{"--proxy-id", id.Hex(), "--proxy-name", name, "--manager-id", m.conn.ID().Hex(),
		"--manager-address", managerAddress, "--manager-port", strconv.Itoa(port)}
	for _, k := range names {
		standard = append(standard, "--"+strings.ReplaceAll(k, "_", "-"), OptionString(launch[k]))
	}
	command := append(append([]string(nil), prefix...), m.Manifest.LaunchCommand(python, standard)...)

	peer := &ipc.Peer{ID: id, Token: ipc.NewUUID(), Name: name, Persistent: persistent, DialAddress: dial, TLS: useTLS}
	if encrypt {
		if peer.Key, err = ipc.NewKey(); err != nil {
			return nil, err
		}
	}
	p := newProxy(id, name, key, peer, command, m.opts.ProxyLogLevel)
	if useTLS {
		if p.material, err = m.Authority.Issue(id.Hex()); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// launcherPrefix is how the proxy command is wrapped: locally nothing, {python} this manager's interpreter. With
// "ssh_host" the prefix is ssh -o BatchMode=yes [-R <manager port>:127.0.0.1:<manager port>] [ssh_options...] host
// env <marker> [remote_env...], and {python} is "remote_python" (default python3).
func (m *Manager) launcherPrefix(options map[string]any) (prefix []string, python string, err error) {
	host, _ := options["ssh_host"].(string)
	if host == "" {
		return nil, m.Python(), nil
	}
	prefix = []string{"ssh", "-o", "BatchMode=yes"}
	if optBool(options["ssh_forward"], true) {
		_, port := m.conn.ListenAddress()
		prefix = append(prefix, "-R", fmt.Sprintf("%d:127.0.0.1:%d", port, port))
	}
	switch sshOptions := options["ssh_options"].(type) {
	case []string:
		prefix = append(prefix, sshOptions...)
	case []any:
		for _, o := range sshOptions {
			prefix = append(prefix, fmt.Sprint(o))
		}
	case nil:
	default:
		return nil, "", fmt.Errorf("ssh_options must be a list of strings, got %T", sshOptions)
	}
	prefix = append(prefix, host, "env", logs.LaunchedByManagerEnv+"=1")
	switch remoteEnv := options["remote_env"].(type) {
	case map[string]string:
		keys := make([]string, 0, len(remoteEnv))
		for k := range remoteEnv {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			prefix = append(prefix, k+"="+remoteEnv[k])
		}
	case map[string]any:
		keys := make([]string, 0, len(remoteEnv))
		for k := range remoteEnv {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			prefix = append(prefix, k+"="+fmt.Sprint(remoteEnv[k]))
		}
	case nil:
	default:
		return nil, "", fmt.Errorf("remote_env must be a map of strings, got %T", remoteEnv)
	}
	python = "python3"
	if rp, _ := options["remote_python"].(string); rp != "" {
		python = rp
	}
	return prefix, python, nil
}

// dialTarget is where the manager must dial a proxy launched with manager_dials: the "dial" option ("host:port",
// or [host, port]), else the proxy's inbound_address/inbound_port launch options. "" for a proxy that dials in.
func dialTarget(options map[string]any) (string, error) {
	if !optBool(options["manager_dials"], false) {
		return "", nil
	}
	switch dial := options["dial"].(type) {
	case string:
		if dial != "" {
			return dial, nil
		}
	case []any:
		if len(dial) == 2 {
			return net.JoinHostPort(fmt.Sprint(dial[0]), fmt.Sprint(dial[1])), nil
		}
	case []string:
		if len(dial) == 2 {
			return net.JoinHostPort(dial[0], dial[1]), nil
		}
	}
	port, given := options["inbound_port"]
	if !given || port == nil {
		return "", errors.New("manager_dials=true needs the proxy's inbound_port (and inbound_address) or a dial=host:port")
	}
	address := "localhost"
	if a, given := options["inbound_address"]; given && a != nil && fmt.Sprint(a) != "" {
		address = fmt.Sprint(a)
	}
	return net.JoinHostPort(address, fmt.Sprint(port)), nil
}

// WaitRegistered waits for the proxy to register. When it has not done so within timeout it is removed (its
// process terminated) and an error returned; a proxy lost meanwhile returns its reason at once.
func (m *Manager) WaitRegistered(p *Proxy, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-p.registered:
		return nil
	case <-p.lostCh:
		return fmt.Errorf("proxy %s lost before registering: %s", p.Name, p.LostReason())
	case <-timer.C:
		m.log.Warningf(logName, "Peer %s did not register within %g seconds. Removing peer.", p.ID, timeout.Seconds())
		m.loseProxy(p, fmt.Sprintf("did not register within %g seconds", timeout.Seconds()))
		return fmt.Errorf("proxy %s did not register within %s", p.Name, timeout)
	}
}

// dialUntilRegistered: for a proxy that cannot dial in, open the persistent connection to it and PING until it has
// registered over that connection (it adopts the connection once the frame authenticates as this manager).
func (m *Manager) dialUntilRegistered(p *Proxy) {
	for m.isCurrent(p) && !p.Registered() && !m.stopped.Load() {
		ctx, cancel := context.WithTimeout(context.Background(), m.opts.HeartbeatTimeout)
		_, err := m.conn.Request(ctx, p.Peer, &ipc.Message{Method: MethodPing})
		cancel()
		if err != nil {
			m.log.Debugf(logName, "PPM: %s not reachable yet at %s: %v", p.Name, p.Peer.DialAddress, err)
			select {
			case <-p.lostCh:
				return
			case <-time.After(DialRetryInterval):
			}
			continue
		}
		select {
		case <-p.registered:
		case <-p.lostCh:
			return
		case <-time.After(DialRetryInterval):
		}
	}
}

// ---- requests ---------------------------------------------------------------------------------------------------------

// Request sends a message to a proxy and waits for its reply until ctx ends.
func (m *Manager) Request(ctx context.Context, p *Proxy, msg *ipc.Message) ([]byte, error) {
	return m.conn.Request(ctx, p.Peer, msg)
}

// Call is Request with a method name and payload.
func (m *Manager) Call(ctx context.Context, p *Proxy, method string, payload []byte) ([]byte, error) {
	return m.conn.Request(ctx, p.Peer, &ipc.Message{Method: method, Payload: payload})
}

// Send writes a message that expects no reply.
func (m *Manager) Send(p *Proxy, msg *ipc.Message) error { return m.conn.Send(p.Peer, msg) }

// SetProxyLogLevel changes a running proxy's log level (SET_LOG_LEVEL) and gates its records here at the same level.
// It returns the proxy's reply ({"level": ...}).
func (m *Manager) SetProxyLogLevel(ctx context.Context, p *Proxy, level logs.Level) ([]byte, error) {
	p.setLogLevel(level)
	payload, _ := json.Marshal(map[string]string{"level": logs.LevelName(level)})
	return m.Call(ctx, p, MethodSetLogLevel, payload)
}

// ---- registration and logs --------------------------------------------------------------------------------------------

// Registration is the REGISTER_PEER payload (§7).
type Registration struct {
	Address  string   `json:"address"`
	Port     int      `json:"port"`
	ProxyID  string   `json:"proxy_id"`
	Token    string   `json:"token"`
	Features []string `json:"features"`
	Cipher   string   `json:"cipher"`
}

func (m *Manager) handleRegisterPeer(h *ipc.Header, payload []byte) ([]byte, error) {
	refused := []byte("false")
	p := m.ProxyByID(h.SenderID)
	if p == nil {
		m.log.Errorf(logName, "PPM: Received registration message from unknown peer: %s.", h.SenderID)
		return refused, nil
	}
	var reg Registration
	if err := json.Unmarshal(payload, &reg); err != nil || reg.Address == "" || reg.Port == 0 {
		m.log.Errorf(logName, "PPM: Failed to register peer: %s with message: %s.", p.ID, string(payload))
		return refused, nil
	}
	p.Peer.Address = net.JoinHostPort(reg.Address, strconv.Itoa(reg.Port))
	p.Peer.SetFeatures(reg.Features)
	p.markRegistered(reg.Cipher)
	encrypts := ""
	if reg.Cipher != "" && p.Peer.Key != nil {
		encrypts = "; encrypts with " + reg.Cipher
	}
	m.log.Infof(logName, "PPM: Successfully registered peer: %s @ %s (features: %s%s)", p.ID, p.Peer.Address,
		strings.Join(reg.Features, ", "), encrypts)
	reply, _ := json.Marshal(map[string]any{"registered": true, "features": m.conn.Features()})
	return reply, nil
}

func (m *Manager) handleLog(h *ipc.Header, payload []byte) ([]byte, error) {
	p := m.ProxyByID(h.SenderID)
	if p == nil {
		m.log.Warningf(logName, "PPM: LOG batch from unknown peer %s ignored.", h.SenderID)
		return nil, nil
	}
	records, err := RecordsFromBatch(payload, p.LoggerName(m.Manifest.Name), p.PID(), p.Name)
	if err != nil {
		m.log.Warningf(logName, "PPM: Undecodable LOG batch from %s: %v", p.Name, err)
		return nil, nil
	}
	level := p.LogLevel()
	for _, record := range records {
		if record.Level >= level {
			m.records.HandleRecord(record)
		}
	}
	return nil, nil
}

// ---- heartbeat ----------------------------------------------------------------------------------------------------

func (m *Manager) startHeartbeat() {
	if m.opts.NoHeartbeat {
		return
	}
	m.heartbeatOnce.Do(func() { go m.heartbeatLoop() })
}

func (m *Manager) heartbeatLoop() {
	ticker := time.NewTicker(m.opts.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopHeartbeat:
			return
		case <-ticker.C:
			for _, p := range m.proxiesToPing() {
				go m.ping(p)
			}
		}
	}
}

// proxiesToPing: registered proxies with a running process that this manager is not stopping (a stopping proxy
// refuses connections, which is not a miss).
func (m *Manager) proxiesToPing() []*Proxy {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Proxy
	for _, p := range m.proxies {
		if p.Registered() && p.PID() != 0 && !m.stoppingPIDs[p.PID()] {
			out = append(out, p)
		}
	}
	return out
}

func (m *Manager) ping(p *Proxy) {
	ctx, cancel := context.WithTimeout(context.Background(), m.opts.HeartbeatTimeout)
	defer cancel()
	reply, err := m.conn.Request(ctx, p.Peer, &ipc.Message{Method: MethodPing})
	if err == nil {
		p.heartbeatAnswered(reply)
		return
	}
	why := err.Error()
	if errors.Is(err, context.DeadlineExceeded) {
		why = fmt.Sprintf("no reply within %g s", m.opts.HeartbeatTimeout.Seconds())
	}
	if !m.isCurrent(p) {
		return
	}
	missed, lost := p.heartbeatMissed(m.opts.HeartbeatMisses)
	if lost {
		m.log.Warningf(logName, "PPM: %s missed heartbeat %d of %d (%s).", p.Name, missed, m.opts.HeartbeatMisses, why)
		m.loseProxy(p, fmt.Sprintf("missed %d heartbeats", missed))
	} else {
		m.log.Infof(logName, "PPM: %s missed heartbeat %d of %d (%s).", p.Name, missed, m.opts.HeartbeatMisses, why)
	}
}

// ProxyHealth is one proxy's liveness as the manager sees it.
type ProxyHealth struct {
	ProxyID    string         `json:"proxy_id"`
	State      string         `json:"state"`
	LastSeen   *float64       `json:"last_seen"`
	Missed     int            `json:"missed"`
	Features   []string       `json:"features"`
	Persistent bool           `json:"persistent"`
	Connected  bool           `json:"connected"`
	PID        int            `json:"pid"`
	Report     map[string]any `json:"report"`
}

// Health is the liveness of every proxy this manager knows, by proxy name: the state machine (launching, registered,
// healthy, unhealthy, lost), when it was last heard from, consecutive misses, its features, pid and last PING report.
func (m *Manager) Health() map[string]ProxyHealth {
	out := map[string]ProxyHealth{}
	for _, p := range m.Proxies() {
		p.mu.Lock()
		h := ProxyHealth{ProxyID: p.ID.String(), State: p.state, Missed: p.missed, PID: p.pid, Report: p.health,
			Features: p.Peer.Features(), Connected: p.Peer.Linked()}
		if !p.lastSeen.IsZero() {
			seen := float64(p.lastSeen.UnixNano()) / 1e9
			h.LastSeen = &seen
		}
		p.mu.Unlock()
		if p.Peer.Persistent != nil {
			h.Persistent = *p.Peer.Persistent
		} else {
			h.Persistent = m.opts.Persistent
		}
		if h.Features == nil {
			h.Features = []string{}
		}
		out[p.Name] = h
	}
	return out
}

// ---- stopping -------------------------------------------------------------------------------------------------------

// Stop stops the manager and, with terminateProxies, the proxies it launched: SIGTERM each process, SIGKILL after
// timeout (0: 5 s), so a stopped manager leaves no orphans. A caller that hands its processes over passes false.
func (m *Manager) Stop(terminateProxies bool, timeout time.Duration) {
	if !m.stopped.CompareAndSwap(false, true) {
		return
	}
	if timeout == 0 {
		timeout = DefaultTerminateTimeout
	}
	close(m.stopHeartbeat)
	m.conn.Stop()
	if !terminateProxies {
		return
	}
	var wg sync.WaitGroup
	for _, p := range m.Proxies() {
		if p.Running() {
			wg.Add(1)
			go func(p *Proxy) {
				defer wg.Done()
				m.terminate(p, timeout)
			}(p)
		}
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2*timeout + time.Second):
	}
}

// Stopped reports whether Stop was called.
func (m *Manager) Stopped() bool { return m.stopped.Load() }

// ---- helpers --------------------------------------------------------------------------------------------------------

// optBool reads a boolean launch option as the Python manager's str2bool does (a bool, or its command-line spelling).
func optBool(value any, fallback bool) bool {
	switch v := value.(type) {
	case nil:
		return fallback
	case bool:
		return v
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "1", "true", "t", "yes", "y", "on":
			return true
		case "0", "false", "f", "no", "n", "off", "":
			return false
		}
	}
	return fallback
}

// OptionString is a launch option's command-line value: booleans as true/false, everything else as printed.
func OptionString(value any) string {
	switch v := value.(type) {
	case bool:
		if v {
			return "true"
		}
		return "false"
	case string:
		return v
	}
	return fmt.Sprint(value)
}

// PyTuple renders a process key as Python's repr of a tuple would ("('mqtt', 'broker', 1883)"), which is the proxy
// name a Python manager would give the same process, so logs read alike across managers.
func PyTuple(key []any) string {
	parts := make([]string, 0, len(key))
	for _, item := range key {
		parts = append(parts, pyRepr(item))
	}
	if len(parts) == 1 {
		return "(" + parts[0] + ",)"
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

func pyRepr(value any) string {
	switch v := value.(type) {
	case nil:
		return "None"
	case bool:
		if v {
			return "True"
		}
		return "False"
	case string:
		if strings.Contains(v, "'") && !strings.Contains(v, "\"") {
			return "\"" + v + "\""
		}
		return "'" + strings.ReplaceAll(v, "'", "\\'") + "'"
	case float64:
		if v == float64(int64(v)) {
			return strconv.FormatInt(int64(v), 10)
		}
		return strconv.FormatFloat(v, 'g', -1, 64)
	}
	return fmt.Sprint(value)
}
