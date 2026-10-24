// Package conformance checks a proxy executable against PROTOCOL.md through the Go manager, the counterpart of the
// Python harness (protocol_proxy.conformance): the proxy under test is whatever a manifest launches, in any
// language. Each check launches it with one combination of options and exercises the core contract: registration
// with its feature list, PING, the error reply for an unknown method, SET_LOG_LEVEL when advertised, header version
// 1, a LOG batch over the socket when advertised, per-message and persistent connections, encryption with each AEAD the proxy advertises, optionally TLS and
// manager-initiated registration, and a clean exit on SIGTERM. An echo method, if the proxy has one, round-trips
// payloads large enough to be compressed. The check names and the report format are the Python harness's.
package conformance

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/eclipse-volttron/protocol-proxy-go/ipc"
	"github.com/eclipse-volttron/protocol-proxy-go/logs"
	"github.com/eclipse-volttron/protocol-proxy-go/manager"
	"github.com/eclipse-volttron/protocol-proxy-go/manifest"
)

// Check is one result.
type Check struct {
	Name    string `json:"name"`
	Passed  bool   `json:"-"`
	Detail  string `json:"detail"`
	Skipped bool   `json:"-"`
}

// Status is pass, FAIL or skip.
func (c Check) Status() string {
	if c.Skipped {
		return "skip"
	}
	if c.Passed {
		return "pass"
	}
	return "FAIL"
}

// Report is the outcome of a run.
type Report struct {
	Manifest *manifest.Manifest
	Checks   []Check
	Features []string
}

// OK is true when every check passed or was skipped.
func (r *Report) OK() bool {
	for _, c := range r.Checks {
		if !c.Passed && !c.Skipped {
			return false
		}
	}
	return true
}

func (r *Report) add(name string, passed bool, detail string) {
	r.Checks = append(r.Checks, Check{Name: name, Passed: passed, Detail: detail})
}

func (r *Report) skip(name, detail string) {
	r.Checks = append(r.Checks, Check{Name: name, Passed: true, Detail: detail, Skipped: true})
}

// Text is the report in the Python harness's layout.
func (r *Report) Text() string {
	width := 10
	passed, failed, skipped := 0, 0, 0
	for _, c := range r.Checks {
		if len(c.Name) > width {
			width = len(c.Name)
		}
		switch {
		case c.Skipped:
			skipped++
		case c.Passed:
			passed++
		default:
			failed++
		}
	}
	verdict := "all checks pass"
	if !r.OK() {
		verdict = "FAILURES"
	}
	lines := []string{fmt.Sprintf("%s: %s (%d passed, %d failed, %d skipped)", r.Manifest.Name, verdict, passed, failed, skipped)}
	for _, c := range r.Checks {
		lines = append(lines, fmt.Sprintf("  %-4s %-*s  %s", c.Status(), width, c.Name, c.Detail))
	}
	return strings.Join(lines, "\n")
}

// JSON is the machine-readable report.
func (r *Report) JSON() ([]byte, error) {
	type check struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Detail string `json:"detail"`
	}
	checks := make([]check, 0, len(r.Checks))
	for _, c := range r.Checks {
		checks = append(checks, check{c.Name, c.Status(), c.Detail})
	}
	features := r.Features
	if features == nil {
		features = []string{}
	}
	return json.MarshalIndent(map[string]any{"proxy": r.Manifest.Name, "ok": r.OK(), "features": features,
		"checks": checks}, "", " ")
}

// Options configure a run.
type Options struct {
	// LaunchOptions are passed to every launch (the proxy's protocol options).
	LaunchOptions map[string]any
	// EchoMethod is a method of the proxy that replies with its payload; "" skips the payload checks.
	EchoMethod string
	// TLS and ManagerDials also run those optional transports.
	TLS          bool
	ManagerDials bool
	// Timeout bounds registration and each reply (default 20 s).
	Timeout time.Duration
	// Python is what {python} resolves to (see manager.Options.Python).
	Python string
	// Logger receives the manager's and the proxies' logs (default: nothing).
	Logger *logs.Logger
}

// LogBatchWait is how long a proxy that advertises log has to deliver a record over the socket once it has
// something to say (the Python harness's LOG_BATCH_WAIT).
const LogBatchWait = 3 * time.Second

// capture keeps every record the manager handles for the proxy under test and still forwards them to the run's
// logger. The proxy is launched at INFO (manager.Options.ProxyLogLevel) so the switch to socket logging and
// SET_LOG_LEVEL's confirmation are shipped; the logger decides what a reader sees.
type capture struct {
	forward manager.RecordHandler
	mu      sync.Mutex
	records []manager.Record
}

func (c *capture) HandleRecord(r manager.Record) {
	c.mu.Lock()
	c.records = append(c.records, r)
	c.mu.Unlock()
	c.forward.HandleRecord(r)
}

func (c *capture) byChannel(channel string) []manager.Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []manager.Record
	for _, r := range c.records {
		if r.Channel == channel {
			out = append(out, r)
		}
	}
	return out
}

// session is one launched proxy under one manager configuration.
type session struct {
	manager *manager.Manager
	proxy   *manager.Proxy
	timeout time.Duration
	capture *capture
}

// waitForRecords is the records that arrived by channel ("socket" or "stderr"), waiting up to timeout for the first.
func (s *session) waitForRecords(channel string, timeout time.Duration) []manager.Record {
	deadline := time.Now().Add(timeout)
	for {
		if found := s.capture.byChannel(channel); len(found) > 0 || !time.Now().Before(deadline) {
			return found
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (s *session) request(method string, payload []byte, version uint16) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	return s.manager.Request(ctx, s.proxy, &ipc.Message{Method: method, Payload: payload, Version: version})
}

func (s *session) requestJSON(method string, body any) (any, error) {
	var payload []byte
	if body != nil {
		payload, _ = json.Marshal(body)
	}
	reply, err := s.request(method, payload, 0)
	if err != nil {
		return nil, err
	}
	if len(reply) == 0 {
		return nil, nil
	}
	var value any
	if err := json.Unmarshal(reply, &value); err != nil {
		return nil, fmt.Errorf("reply is not JSON: %q", string(reply))
	}
	return value, nil
}

// exitCode stops the manager (SIGTERM to the proxy) and returns the proxy's exit code, ok false if it did not exit.
func (s *session) exitCode() (int, bool) {
	s.manager.Stop(true, 5*time.Second)
	return s.proxy.Wait(10 * time.Second)
}

func (s *session) close() {
	if !s.manager.Stopped() {
		s.manager.Stop(true, 5*time.Second)
	}
}

func detail(v any) string {
	out, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(out)
}

func pyList(items []string) string {
	quoted := make([]string, 0, len(items))
	for _, item := range items {
		quoted = append(quoted, "'"+item+"'")
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

func isHealth(v any) bool {
	h, ok := v.(map[string]any)
	if !ok {
		return false
	}
	_, uptime := h["uptime"].(float64)
	_, remotes := h["remotes"].(float64)
	_, busy := h["busy"].(bool)
	_, last := h["last_activity"]
	return uptime && remotes && busy && last
}

func hasUptime(v any) bool {
	h, ok := v.(map[string]any)
	if !ok {
		return false
	}
	_, has := h["uptime"]
	return has
}

// Run runs every check against the proxy the manifest launches.
func Run(mf *manifest.Manifest, opts Options) *Report {
	if opts.Timeout == 0 {
		opts.Timeout = 20 * time.Second
	}
	logger := opts.Logger
	if logger == nil {
		logger = logs.New(logs.CRITICAL+1, &logs.StreamSink{W: discard{}})
	}
	report := &Report{Manifest: mf}

	// open launches a session with a manager configured by mo and the launch options; it records the registration
	// check and returns nil when the proxy did not register.
	open := func(name string, mo manager.Options, launch map[string]any) *session {
		mo.Manifest = mf
		mo.NoHeartbeat = true
		mo.Python = opts.Python
		mo.Logger = logger
		mo.ProxyLogLevel = logs.INFO
		cap := &capture{forward: manager.LoggerRecordHandler{Logger: logger}}
		mo.Records = cap
		m, err := manager.New(mo)
		if err == nil {
			err = m.Start()
		}
		if err != nil {
			report.add(name+": registration", false, fmt.Sprintf("%T: %v", err, err))
			return nil
		}
		options := map[string]any{}
		for k, v := range opts.LaunchOptions {
			options[k] = v
		}
		for k, v := range launch {
			options[k] = v
		}
		s := &session{manager: m, timeout: opts.Timeout, capture: cap}
		p, err := m.GetProxy([]any{"conformance"}, options)
		if err != nil {
			m.Stop(true, 5*time.Second)
			report.add(name+": registration", false, fmt.Sprintf("%T: %v", err, err))
			return nil
		}
		s.proxy = p
		if err := m.WaitRegistered(p, opts.Timeout); err != nil {
			report.add(name+": registration", false, fmt.Sprintf("no registration within %gs", opts.Timeout.Seconds()))
			s.close()
			return nil
		}
		report.add(name+": registration", true, "features "+pyList(p.Peer.Features()))
		return s
	}
	exit := func(s *session, name string) {
		code, exited := s.exitCode()
		if exited {
			report.add(name, code == 0, fmt.Sprintf("exit code %d", code))
		} else {
			report.add(name, false, "exit code None")
		}
		s.close()
	}

	// ---- 1. per-message connections: the core contract ----------------------------------------------------------
	if s := open("per-message", manager.Options{}, map[string]any{"persistent": false}); s != nil {
		report.Features = s.proxy.Peer.Features()
		health, err := s.requestJSON("PING", nil)
		if err != nil {
			report.add("ping reply", false, fmt.Sprintf("%T: %v", err, err))
		} else {
			report.add("ping reply", isHealth(health), detail(health))
		}
		reply, err := s.requestJSON("NO_SUCH_METHOD_CONFORMANCE", map[string]any{"x": 1})
		if err != nil {
			report.add("unknown method answered with an error reply", false, fmt.Sprintf("%T: %v", err, err))
		} else {
			r, ok := reply.(map[string]any)
			_, hasMethod := r["method"]
			_, hasError := r["error"]
			report.add("unknown method answered with an error reply", ok && r["status"] == "error" && hasMethod && hasError, detail(reply))
		}
		if ipc.HasFeature(report.Features, ipc.FeatureSetLogLevel) {
			reply, err := s.requestJSON("SET_LOG_LEVEL", map[string]string{"level": "DEBUG"})
			if err != nil {
				report.add("SET_LOG_LEVEL", false, fmt.Sprintf("%T: %v", err, err))
			} else {
				r, ok := reply.(map[string]any)
				report.add("SET_LOG_LEVEL", ok && r["level"] == "DEBUG", detail(reply))
				_, _ = s.requestJSON("SET_LOG_LEVEL", map[string]string{"level": "INFO"})
			}
		} else {
			report.skip("SET_LOG_LEVEL", "not advertised")
		}
		if ipc.HasFeature(report.Features, ipc.FeatureLog) {
			// The proxy has had something to say since it registered (its switch to the socket, SET_LOG_LEVEL's
			// confirmation), so a batch must have been shipped by now or very soon.
			records := s.waitForRecords("socket", LogBatchWait)
			if len(records) > 0 {
				report.add("LOG batch over the socket", true, fmt.Sprintf("%d record(s), first: %q", len(records), records[0].Message))
			} else {
				report.add("LOG batch over the socket", false, fmt.Sprintf("no record over the socket within %gs (%d by stderr)",
					LogBatchWait.Seconds(), len(s.capture.byChannel("stderr"))))
			}
		} else {
			report.skip("LOG batch over the socket", "not advertised")
		}
		if raw, err := s.request("PING", nil, 1); err != nil {
			report.add("header version 1 accepted", false, fmt.Sprintf("%T: %v", err, err))
		} else {
			var health any
			_ = json.Unmarshal(raw, &health)
			report.add("header version 1 accepted", hasUptime(health), detail(health))
		}
		if opts.EchoMethod != "" {
			name := "echo round trip, small and 64 KiB"
			small, _ := json.Marshal(map[string]any{"n": 1, "text": "héllo"})
			large, _ := json.Marshal(map[string]string{"blob": strings.Repeat("x", 65536)})
			if err := echo(s, opts.EchoMethod, small, large); err != nil {
				report.add(name, false, err.Error())
			} else {
				via := "uncompressed (compress not advertised)"
				if ipc.HasFeature(report.Features, ipc.FeatureCompress) {
					via = "compressed on the wire"
				}
				report.add(name, true, via)
			}
		} else {
			report.skip("echo round trip, small and 64 KiB", "no echo method given")
		}
		exit(s, "clean exit on SIGTERM")
	}

	// ---- 2. persistent connection -----------------------------------------------------------------------------------
	if s := open("persistent", manager.Options{}, map[string]any{"persistent": true}); s != nil {
		name := "persistent: five pings on one connection"
		ok, last := true, ""
		for i := 0; i < 5 && ok; i++ {
			health, err := s.requestJSON("PING", nil)
			if err != nil {
				ok, last = false, fmt.Sprintf("%T: %v", err, err)
			} else if !hasUptime(health) {
				ok, last = false, detail(health)
			}
		}
		if ok && !s.proxy.Peer.Linked() {
			ok, last = false, "no persistent connection held"
		}
		if ok {
			report.add(name, true, "connection held")
		} else {
			report.add(name, false, last)
		}
		if opts.EchoMethod != "" {
			large, _ := json.Marshal(map[string]string{"blob": strings.Repeat("y", 300000)}) // above persistent_max_frame
			if err := echo(s, opts.EchoMethod, large); err != nil {
				report.add("persistent: 300 KB frame takes its own connection", false, err.Error())
			} else {
				report.add("persistent: 300 KB frame takes its own connection", true, "")
			}
		}
		exit(s, "persistent: clean exit on SIGTERM")
	}

	// ---- 3. encryption, each AEAD the proxy advertises ----------------------------------------------------------------
	for _, c := range []struct{ cipher, feature string }{{ipc.CipherChaCha20Poly1305, ipc.FeatureChaCha20},
		{ipc.CipherAES256GCM, ipc.FeatureAES256GCM}} {
		name := fmt.Sprintf("encrypted (%s)", c.cipher)
		if !ipc.HasFeature(report.Features, c.feature) {
			report.skip(name, c.feature+" not advertised")
			continue
		}
		s := open(name, manager.Options{Encrypt: true, Cipher: c.cipher}, map[string]any{"persistent": true})
		if s == nil {
			continue
		}
		health, err := s.requestJSON("PING", nil)
		if err != nil {
			report.add(name+": ping", false, fmt.Sprintf("%T: %v", err, err))
		} else {
			report.add(name+": ping", hasUptime(health) && s.proxy.Peer.Key != nil, detail(health))
			if opts.EchoMethod != "" {
				large, _ := json.Marshal(map[string]string{"blob": strings.Repeat("z", 65536)})
				err := echo(s, opts.EchoMethod, large)
				report.add(name+": 64 KiB echo (compress then encrypt)", err == nil, errText(err))
			}
		}
		exit(s, name+": clean exit")
	}

	// ---- 4. optional transports -------------------------------------------------------------------------------------
	if opts.TLS {
		if s := open("tls", manager.Options{IPCTLS: true}, map[string]any{"persistent": true}); s != nil {
			health, err := s.requestJSON("PING", nil)
			if err != nil {
				report.add("tls: ping", false, fmt.Sprintf("%T: %v", err, err))
			} else {
				report.add("tls: ping", hasUptime(health) && s.proxy.Peer.TLS, detail(health))
			}
			exit(s, "tls: clean exit")
		}
	} else {
		report.skip("tls", "not requested (--tls)")
	}
	if opts.ManagerDials {
		port, err := freePort()
		if err != nil {
			report.add("manager-dials: registration", false, err.Error())
		} else if s := open("manager-dials", manager.Options{}, map[string]any{"manager_dials": true,
			"inbound_address": "127.0.0.1", "inbound_port": port}); s != nil {
			health, err := s.requestJSON("PING", nil)
			if err != nil {
				report.add("manager-dials: ping over the manager-initiated connection", false, fmt.Sprintf("%T: %v", err, err))
			} else {
				report.add("manager-dials: ping over the manager-initiated connection", hasUptime(health), detail(health))
			}
			exit(s, "manager-dials: clean exit")
		}
	} else {
		report.skip("manager-dials", "not requested (--manager-dials)")
	}
	return report
}

func echo(s *session, method string, payloads ...[]byte) error {
	for _, payload := range payloads {
		reply, err := s.request(method, payload, 0)
		if err != nil {
			return fmt.Errorf("%T: %w", err, err)
		}
		if string(reply) != string(payload) {
			return fmt.Errorf("echo of %d bytes came back as %d bytes", len(payload), len(reply))
		}
	}
	return nil
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func freePort() (int, error) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
