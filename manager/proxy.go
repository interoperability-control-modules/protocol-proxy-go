package manager

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/eclipse-volttron/protocol-proxy-go/ipc"
	"github.com/eclipse-volttron/protocol-proxy-go/logs"
)

// Proxy is a launched proxy process as the manager sees it: its peer on the IPC, its process and its liveness.
type Proxy struct {
	// Peer is the proxy's identity on the connector (id, token, address, key, TLS, features).
	Peer *ipc.Peer
	ID   ipc.UUID
	// Name is the proxy name it was launched with (the process key as a Python tuple); Key the process key itself.
	Name string
	Key  []any
	// Command is the argv it was launched with.
	Command []string

	material *ipc.TLSMaterial

	mu         sync.Mutex
	cmd        *process
	pid        int
	state      string
	lastSeen   time.Time
	missed     int
	health     map[string]any
	logLevel   logs.Level
	cipher     string
	lostReason string

	registered chan struct{}
	regOnce    sync.Once
	lostCh     chan struct{}
	lostOnce   sync.Once
}

func newProxy(id ipc.UUID, name string, key []any, peer *ipc.Peer, command []string, level logs.Level) *Proxy {
	return &Proxy{Peer: peer, ID: id, Name: name, Key: key, Command: command, state: "launching", logLevel: level,
		registered: make(chan struct{}), lostCh: make(chan struct{})}
}

// Registered reports whether the manager has accepted the proxy's REGISTER_PEER.
func (p *Proxy) Registered() bool {
	select {
	case <-p.registered:
		return true
	default:
		return false
	}
}

// RegisteredCh is closed when the proxy registers.
func (p *Proxy) RegisteredCh() <-chan struct{} { return p.registered }

// Lost is closed when the manager has given the proxy up (process exit, missed heartbeats, no registration).
func (p *Proxy) Lost() <-chan struct{} { return p.lostCh }

// LostReason is why the proxy was lost, "" while it is current.
func (p *Proxy) LostReason() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lostReason
}

func (p *Proxy) markRegistered(cipher string) {
	p.mu.Lock()
	p.state = "registered"
	p.lastSeen = time.Now()
	p.cipher = cipher
	p.mu.Unlock()
	p.regOnce.Do(func() { close(p.registered) })
}

func (p *Proxy) markLost(reason string) {
	p.mu.Lock()
	p.state = "lost"
	p.lostReason = reason
	p.mu.Unlock()
	p.lostOnce.Do(func() { close(p.lostCh) })
}

// State is the liveness state machine: launching, registered, healthy, unhealthy, lost.
func (p *Proxy) State() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state
}

// Cipher is the AEAD the proxy said it encrypts with in REGISTER_PEER ("" when it does not encrypt).
func (p *Proxy) Cipher() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cipher
}

// Health is the proxy's last PING report (uptime, remotes, busy, last_activity), nil before any.
func (p *Proxy) Health() map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.health
}

// LogLevel gates the proxy's records in the manager's process.
func (p *Proxy) LogLevel() logs.Level {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.logLevel
}

func (p *Proxy) setLogLevel(level logs.Level) {
	p.mu.Lock()
	p.logLevel = level
	p.mu.Unlock()
}

// LoggerName is the manager-side logger the proxy's records are handled under.
func (p *Proxy) LoggerName(manifestName string) string { return ProxyLoggerName(manifestName, p.Name) }

// heartbeatAnswered: any reply (an old proxy answers with an unknown-method error, which still proves it alive).
func (p *Proxy) heartbeatAnswered(reply []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lastSeen = time.Now()
	p.missed = 0
	p.state = "healthy"
	var report map[string]any
	if err := json.Unmarshal(reply, &report); err == nil && report != nil && report["status"] != "error" {
		p.health = report
	}
}

// heartbeatMissed counts an unanswered PING; lost is true once misses in a row reach the limit.
func (p *Proxy) heartbeatMissed(limit int) (missed int, lost bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.missed++
	p.state = "unhealthy"
	if p.missed >= limit {
		p.state = "lost"
		return p.missed, true
	}
	return p.missed, false
}

// ---- process ------------------------------------------------------------------------------------------------------

func (p *Proxy) setProcess(proc *process) {
	p.mu.Lock()
	p.cmd = proc
	p.pid = proc.pid
	p.mu.Unlock()
}

func (p *Proxy) proc() *process {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cmd
}

// PID is the process id, 0 before launch.
func (p *Proxy) PID() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pid
}

// Running reports whether the process has been started and has not exited.
func (p *Proxy) Running() bool {
	proc := p.proc()
	return proc != nil && proc.running()
}

// ExitCode is the process's exit code once it has exited (-1 when it was killed by a signal).
func (p *Proxy) ExitCode() (code int, exited bool) {
	proc := p.proc()
	if proc == nil {
		return 0, false
	}
	return proc.exitCode()
}

// Wait waits up to timeout for the process to exit and returns its exit code; exited is false if it has not.
func (p *Proxy) Wait(timeout time.Duration) (code int, exited bool) {
	proc := p.proc()
	if proc == nil {
		return 0, false
	}
	select {
	case <-proc.exited:
	case <-time.After(timeout):
	}
	return proc.exitCode()
}

// Exited is closed when the process has exited (nil before launch).
func (p *Proxy) Exited() <-chan struct{} {
	proc := p.proc()
	if proc == nil {
		return nil
	}
	return proc.exited
}
