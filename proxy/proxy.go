package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/eclipse-volttron/protocol-proxy-go/ipc"
	"github.com/eclipse-volttron/protocol-proxy-go/logs"
)

const logName = "protocol_proxy_go.proxy"

// Core method names (PROTOCOL.md §8).
const (
	MethodRegisterPeer = "REGISTER_PEER"
	MethodPing         = "PING"
	MethodLog          = "LOG"
	MethodSetLogLevel  = "SET_LOG_LEVEL"
)

// Features this proxy advertises in REGISTER_PEER.
var Features = []string{ipc.FeaturePing, ipc.FeatureLog, ipc.FeatureSetLogLevel, ipc.FeatureCompress,
	ipc.FeatureChaCha20, ipc.FeatureAES256GCM}

// Timing of the contract: registration (§7), log batches (§9), the parent watch (§1) and the hard exit.
const (
	RegistrationAttempts   = 2
	RegistrationTimeout    = 5 * time.Second
	RegistrationRetryDelay = 20 * time.Second
	LogFlushInterval       = 200 * time.Millisecond
	LogBatchSize           = 64
	ManagerWatchInterval   = time.Second
	ManagerWaitLogInterval = 30 * time.Second
	HardExitGrace          = 15 * time.Second
)

// Proxy is a running proxy process: its connector, its manager peer and the lifecycle around them.
type Proxy struct {
	Opts    *Options
	Conn    *ipc.Connector
	Log     *logs.Logger
	Manager *ipc.Peer

	stderr     logs.Sink // where records go when not shipped over the socket
	queue      *logs.Queue
	registered atomic.Bool
	stopping   atomic.Bool
	stopOnce   sync.Once
	done       chan struct{}
	stopCh     chan struct{}
	exitCode   atomic.Int32
	parentPID  int
	flusherWG  sync.WaitGroup
}

// New makes a proxy from its options and the stdin handshake. logger's current sink is remembered as the stderr
// channel; records go there until registration and again at exit.
func New(opts *Options, hs *Handshake, logger *logs.Logger) (*Proxy, error) {
	if opts.Encrypt && hs.Key == nil {
		return nil, fmt.Errorf("%s: --encrypt is set but no key was provided on stdin", opts.ProxyName)
	}
	if opts.IPCTLS && hs.TLS == nil {
		return nil, fmt.Errorf("%s: --ipc-tls is set but no TLS material was provided on stdin", opts.ProxyName)
	}
	cipher, err := ipc.ResolveCipher(opts.Cipher)
	if err != nil {
		return nil, err
	}
	threshold := opts.CompressThreshold
	if threshold < 0 {
		threshold = ipc.DefaultCompressThreshold
	}
	conn, err := ipc.New(ipc.Options{ID: opts.ProxyID, Token: hs.ProxyToken, Name: opts.ProxyName,
		Persistent: opts.Persistent, CompressThreshold: threshold, Cipher: cipher, TLS: hs.TLS,
		Features: Features, Logger: logger})
	if err != nil {
		return nil, err
	}
	manager := &ipc.Peer{ID: opts.ManagerID, Token: hs.ManagerToken, Name: "manager", Key: hs.Key, TLS: hs.TLS != nil}
	if !opts.ManagerDials {
		manager.Address = fmt.Sprintf("%s:%d", opts.ManagerAddress, opts.ManagerPort)
	}
	conn.AddPeer(manager)
	p := &Proxy{Opts: opts, Conn: conn, Log: logger, Manager: manager, stderr: logger.Sink(), done: make(chan struct{}),
		stopCh: make(chan struct{}), parentPID: os.Getppid()}
	conn.RegisterHandler(MethodSetLogLevel, p.handleSetLogLevel, true)
	conn.RegisterHandler(MethodPing, p.handlePing, true)
	return p, nil
}

// RegisterHandler adds a protocol method.
func (p *Proxy) RegisterHandler(method string, handler ipc.Handler, providesResponse bool) {
	p.Conn.RegisterHandler(method, handler, providesResponse)
}

// Registered reports whether the manager accepted REGISTER_PEER.
func (p *Proxy) Registered() bool { return p.registered.Load() }

// ---- core methods ---------------------------------------------------------------------------------------------------

// HealthReport is the PING reply (§8).
type HealthReport struct {
	Uptime       float64 `json:"uptime"`
	Remotes      int     `json:"remotes"`
	Busy         bool    `json:"busy"`
	LastActivity *string `json:"last_activity"`
}

// Health is what a PING reply carries for a connector.
func Health(conn *ipc.Connector) HealthReport {
	report := HealthReport{Uptime: float64(int64(conn.Uptime()*1000+0.5)) / 1000, Remotes: conn.RemoteCount()}
	if last, ok := conn.LastActivity(); ok {
		iso := last.UTC().Format("2006-01-02T15:04:05.000000-07:00")
		report.LastActivity = &iso
	}
	return report
}

func (p *Proxy) handlePing(_ *ipc.Header, _ []byte) ([]byte, error) {
	return json.Marshal(Health(p.Conn))
}

// SetLogLevelReply applies a SET_LOG_LEVEL payload ({"level": "DEBUG"}) to the logger and returns the reply:
// {"level": "<level in force>"}, or the error reply of §8 for an invalid level.
func SetLogLevelReply(logger *logs.Logger, payload []byte) []byte {
	var request struct {
		Level any `json:"level"`
	}
	if err := json.Unmarshal(payload, &request); err != nil {
		return ipc.ErrorPayload(MethodSetLogLevel, "Invalid log level: "+err.Error())
	}
	level, err := logs.ParseLevel(request.Level)
	if err != nil {
		return ipc.ErrorPayload(MethodSetLogLevel, "Invalid log level: "+err.Error())
	}
	logger.SetLevel(level)
	out, _ := json.Marshal(map[string]string{"level": logs.LevelName(logger.Level())})
	return out
}

func (p *Proxy) handleSetLogLevel(_ *ipc.Header, payload []byte) ([]byte, error) {
	reply := SetLogLevelReply(p.Log, payload)
	p.Log.Infof(logName, "%s: log level set to %s.", p.Opts.ProxyName, logs.LevelName(p.Log.Level()))
	return reply, nil
}

// ---- registration ---------------------------------------------------------------------------------------------------

// Registration is the REGISTER_PEER payload (§7).
type Registration struct {
	Address  string   `json:"address"`
	Port     int      `json:"port"`
	ProxyID  string   `json:"proxy_id"`
	Token    string   `json:"token"`
	Features []string `json:"features"`
	Cipher   string   `json:"cipher"`
}

func (p *Proxy) registrationMessage() (*ipc.Message, error) {
	host, port := p.Conn.ListenAddress()
	payload, err := json.Marshal(Registration{Address: host, Port: port, ProxyID: p.Opts.ProxyID.Hex(),
		Token: p.Conn.Token().Hex(), Features: Features, Cipher: p.Conn.Cipher()})
	if err != nil {
		return nil, err
	}
	return &ipc.Message{Method: MethodRegisterPeer, Payload: payload, ResponseExpected: true}, nil
}

// RegistrationAccepted reads the manager's reply: {"registered": true, "features": [...]} from a current manager
// (features returned), plain true/false from an older one.
func RegistrationAccepted(reply []byte) (accepted bool, features []string) {
	var value any
	if err := json.Unmarshal(reply, &value); err != nil {
		return false, nil
	}
	switch v := value.(type) {
	case bool:
		return v, nil
	case map[string]any:
		if list, ok := v["features"].([]any); ok {
			for _, item := range list {
				if s, ok := item.(string); ok {
					features = append(features, s)
				}
			}
		}
		if registered, ok := v["registered"]; ok {
			b, _ := registered.(bool)
			return b, features
		}
		return v["status"] != "error", features
	}
	return false, nil
}

// managerWhere names the manager for log lines: its address, or the connection it opened to us.
func (p *Proxy) managerWhere() string {
	if p.Manager.Address != "" {
		return p.Manager.Address
	}
	return "the manager-initiated connection"
}

func (p *Proxy) waitForManager() bool {
	waited := time.Duration(0)
	for !p.stopping.Load() && !p.Manager.Linked() {
		if waited%ManagerWaitLogInterval < 100*time.Millisecond {
			host, port := p.Conn.ListenAddress()
			p.Log.Infof(logName, "%s: waiting for the manager to connect to %s:%d.", p.Opts.ProxyName, host, port)
		}
		select {
		case <-p.stopCh:
			return false
		case <-time.After(100 * time.Millisecond):
		}
		waited += 100 * time.Millisecond
	}
	return !p.stopping.Load()
}

func (p *Proxy) register() bool {
	if p.Opts.ManagerDials && !p.waitForManager() {
		return false
	}
	for attempt := 1; attempt <= RegistrationAttempts; attempt++ {
		ok := func() bool {
			msg, err := p.registrationMessage()
			if err != nil {
				p.Log.Warningf(logName, "%s: Error building registration (attempt %d): %v", p.Opts.ProxyName, attempt, err)
				return false
			}
			ctx, cancel := context.WithTimeout(context.Background(), RegistrationTimeout)
			defer cancel()
			reply, err := p.Conn.Request(ctx, p.Manager, msg)
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					p.Log.Warningf(logName, "%s: No registration response from manager within %g seconds (attempt %d).",
						p.Opts.ProxyName, RegistrationTimeout.Seconds(), attempt)
				} else {
					p.Log.Warningf(logName, "%s: Error sending registration (attempt %d): %v", p.Opts.ProxyName, attempt, err)
				}
				return false
			}
			accepted, features := RegistrationAccepted(reply)
			if accepted {
				p.Manager.SetFeatures(features)
			}
			return accepted
		}()
		if ok {
			p.registered.Store(true)
			p.Log.Infof(logName, "%s: Registered with manager @ %s.", p.Opts.ProxyName, p.managerWhere())
			return true
		}
		if attempt < RegistrationAttempts {
			select {
			case <-p.stopCh:
				return false
			case <-time.After(RegistrationRetryDelay):
			}
		}
	}
	p.Log.Errorf(logName, "%s: Unable to register with Proxy Manager @ %s after %d attempts.", p.Opts.ProxyName,
		p.managerWhere(), RegistrationAttempts)
	return false
}

// ---- logging over the socket ----------------------------------------------------------------------------------------

func (p *Proxy) onRegistered() {
	stream, isStream := p.stderr.(*logs.StreamSink)
	if !p.Opts.SocketLogging || !isStream || !stream.JSON {
		return
	}
	p.queue = logs.NewQueue()
	p.Log.SetSink(p.queue)
	p.flusherWG.Add(1)
	go p.flushLoop()
	p.Log.Infof(logName, "%s: logging over the IPC socket from here on.", p.Opts.ProxyName)
}

func (p *Proxy) flushLoop() {
	defer p.flusherWG.Done()
	for !p.stopping.Load() {
		deadline := time.Now().Add(LogFlushInterval)
		for !p.stopping.Load() && time.Now().Before(deadline) && p.queue.Len() < LogBatchSize {
			select {
			case <-p.stopCh:
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
		p.flushLogs()
	}
}

// flushLogs ships one LOG batch (no response expected); records that cannot be sent go to stderr.
func (p *Proxy) flushLogs() {
	records, dropped := p.queue.Drain(LogBatchSize)
	if len(records) == 0 && dropped == 0 {
		return
	}
	payload, err := logs.MarshalBatch(records, dropped)
	if err == nil {
		err = p.Conn.Send(p.Manager, &ipc.Message{Method: MethodLog, Payload: payload, LowPriority: true})
	}
	if err != nil {
		for _, record := range records {
			logs.WriteJSONLine(os.Stderr, record)
		}
	}
}

func (p *Proxy) stopSocketLogging() {
	if p.queue == nil {
		return
	}
	queue := p.queue
	p.Log.SetSink(p.stderr)
	p.flusherWG.Wait()
	records, dropped := queue.Drain(0)
	for _, record := range records {
		p.stderr.Emit(record)
	}
	if dropped > 0 {
		p.Log.Warningf(logName, "%d log records were dropped (rate or queue limit)", dropped)
	}
	p.queue = nil
}

// ---- lifecycle ------------------------------------------------------------------------------------------------------

// Run creates the listener, registers with the manager, then serves until stopped by SIGTERM, the loss of the parent
// process, or Stop. It returns the process exit code: 0 after a clean stop, 1 when registration or setup failed.
func (p *Proxy) Run() int {
	if err := p.Conn.Listen(p.Opts.InboundAddress, p.Opts.InboundPort); err != nil {
		p.Log.Errorf(logName, "%s: %v", p.Opts.ProxyName, err)
		return 1
	}
	p.Conn.Serve()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	go func() {
		select {
		case sig := <-signals:
			p.Log.Infof(logName, "%s: received %s; stopping.", p.Opts.ProxyName, sig)
			p.armHardExit(sig.String())
			p.Stop()
		case <-p.stopCh:
		}
	}()
	go p.watchManager()
	if !p.register() {
		if !p.stopping.Load() {
			p.exitCode.Store(1)
		}
		p.Stop()
		<-p.done
		return int(p.exitCode.Load())
	}
	p.onRegistered()
	<-p.done
	return int(p.exitCode.Load())
}

// watchManager stops the proxy when the process that launched it is gone (an orphan is re-parented).
func (p *Proxy) watchManager() {
	ticker := time.NewTicker(ManagerWatchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			if os.Getppid() != p.parentPID {
				p.Log.Warningf(logName, "%s: the manager process (%d) is gone. Stopping.", p.Opts.ProxyName, p.parentPID)
				p.armHardExit("the manager was lost")
				p.Stop()
				return
			}
		}
	}
}

// armHardExit guarantees the process ends: exit 1 after HardExitGrace if the orderly stop has not finished.
func (p *Proxy) armHardExit(reason string) {
	go func() {
		select {
		case <-p.done:
		case <-time.After(HardExitGrace):
			p.Log.Errorf(logName, "%s: still running %g s after %s; exiting now.", p.Opts.ProxyName, HardExitGrace.Seconds(), reason)
			os.Exit(1)
		}
	}()
}

// Stop stops serving: the log queue is written to stderr, the listener and every connection are closed.
func (p *Proxy) Stop() {
	p.stopOnce.Do(func() {
		p.stopping.Store(true)
		close(p.stopCh)
		p.stopSocketLogging()
		p.Conn.Stop()
		close(p.done)
	})
}

// Done is closed when the proxy has stopped.
func (p *Proxy) Done() <-chan struct{} { return p.done }
