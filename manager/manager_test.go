package manager

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/eclipse-volttron/protocol-proxy-go/ipc"
	"github.com/eclipse-volttron/protocol-proxy-go/logs"
	"github.com/eclipse-volttron/protocol-proxy-go/manifest"
)

var (
	buildOnce sync.Once
	echoDir   string
	buildErr  error
)

// echoManifest builds the Go echo proxy once and returns a manifest that launches it, with extra TOML appended.
func echoManifest(t *testing.T, extra string) *manifest.Manifest {
	t.Helper()
	buildOnce.Do(func() {
		echoDir, buildErr = os.MkdirTemp("", "ppgo-echo-")
		if buildErr != nil {
			return
		}
		cmd := exec.Command("go", "build", "-o", filepath.Join(echoDir, "echo-proxy"), "../cmd/echo-proxy")
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = err
			t.Logf("go build: %s", out)
		}
	})
	if buildErr != nil {
		t.Skipf("cannot build echo-proxy: %v", buildErr)
	}
	text := "[proxy]\nname = \"echo-test\"\ncommand = [\"{manifest_dir}/echo-proxy\"]\n" + extra
	m, err := manifest.Parse(text, filepath.Join(echoDir, "proxy.toml"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

type collector struct {
	mu      sync.Mutex
	records []Record
}

func (c *collector) HandleRecord(r Record) {
	c.mu.Lock()
	c.records = append(c.records, r)
	c.mu.Unlock()
}

func (c *collector) find(pred func(Record) bool) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, r := range c.records {
		if pred(r) {
			return true
		}
	}
	return false
}

func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func quietLogger() *logs.Logger { return logs.New(logs.CRITICAL+1, &logs.StreamSink{W: os.Stderr}) }

func startManager(t *testing.T, opts Options) (*Manager, *collector) {
	t.Helper()
	records := &collector{}
	if opts.Logger == nil {
		opts.Logger = quietLogger()
	}
	opts.Records = records
	m, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Stop(true, 5*time.Second) })
	return m, records
}

func TestManagerLaunchesTalksAndLogs(t *testing.T) {
	m, records := startManager(t, Options{Manifest: echoManifest(t, ""), HeartbeatInterval: 200 * time.Millisecond,
		HeartbeatTimeout: time.Second})
	p, err := m.GetProxy([]any{"device"}, map[string]any{"persistent": true})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.WaitRegistered(p, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if p.Name != "('device',)" || !ipc.HasFeature(p.Peer.Features(), ipc.FeatureLog) || p.Cipher() == "" {
		t.Fatalf("registration: name %q features %v cipher %q", p.Name, p.Peer.Features(), p.Cipher())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reply, err := m.Call(ctx, p, "PING", nil)
	if err != nil {
		t.Fatal(err)
	}
	var health map[string]any
	if err := json.Unmarshal(reply, &health); err != nil || health["uptime"] == nil {
		t.Fatalf("PING reply %s", reply)
	}
	reply, err = m.Call(ctx, p, "ECHO", []byte(`{"n": 1}`))
	if err != nil || string(reply) != `{"n": 1}` {
		t.Fatalf("ECHO: %v %s", err, reply)
	}
	reply, err = m.SetProxyLogLevel(ctx, p, logs.DEBUG)
	if err != nil || string(reply) != `{"level":"DEBUG"}` {
		t.Fatalf("SET_LOG_LEVEL: %v %s", err, reply)
	}
	if p.LogLevel() != logs.DEBUG {
		t.Fatal("the proxy's records are not gated at the new level")
	}
	again, err := m.GetProxy([]any{"device"}, nil)
	if err != nil || again != p {
		t.Fatalf("a second GetProxy for the same key must return the same proxy: %v", err)
	}
	waitFor(t, "a record read from the stderr pipe", 5*time.Second, func() bool {
		return records.find(func(r Record) bool { return r.Channel == "stderr" && strings.Contains(r.Message, "Launching Proxy") })
	})
	waitFor(t, "a record received in a LOG batch", 5*time.Second, func() bool {
		return records.find(func(r Record) bool { return r.Channel == "socket" && r.Proxy == p.Name && r.PID == p.PID() })
	})
	waitFor(t, "a heartbeat to be answered", 5*time.Second, func() bool { return p.State() == "healthy" })
	h := m.Health()[p.Name]
	if h.State != "healthy" || h.PID != p.PID() || h.Report["uptime"] == nil || !h.Persistent || !h.Connected {
		t.Fatalf("health %+v", h)
	}
	m.Stop(true, 5*time.Second)
	code, exited := p.Wait(10 * time.Second)
	if !exited || code != 0 {
		t.Fatalf("exit code %d (exited %v)", code, exited)
	}
	waitFor(t, "the proxy's stop to be read from its stderr (the queue drained at exit)", 5*time.Second, func() bool {
		return records.find(func(r Record) bool { return r.Channel == "stderr" && strings.Contains(r.Message, "; stopping.") })
	})
}

func TestManagerRelaunchesAfterTheProcessExits(t *testing.T) {
	m, _ := startManager(t, Options{Manifest: echoManifest(t, ""), NoHeartbeat: true})
	var mu sync.Mutex
	var lost []string
	m.OnProxyLost(func(p *Proxy, reason string) {
		mu.Lock()
		lost = append(lost, reason)
		mu.Unlock()
	})
	p, err := m.GetProxy([]any{"d"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.WaitRegistered(p, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	first := p.PID()
	syscall.Kill(first, syscall.SIGKILL)
	waitFor(t, "the lost callback", 5*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(lost) == 1 && strings.Contains(lost[0], "process exited with code -1")
	})
	if m.ProxyByID(p.ID) != nil || p.LostReason() == "" {
		t.Fatal("the lost proxy is still known")
	}
	relaunched, err := m.GetProxy([]any{"d"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if relaunched == p || relaunched.ID != p.ID {
		t.Fatal("the relaunch must be a new proxy under the same id")
	}
	if err := m.WaitRegistered(relaunched, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if relaunched.PID() == first {
		t.Fatal("same pid")
	}
}

func TestManagerLosesAnUnresponsiveProxy(t *testing.T) {
	m, _ := startManager(t, Options{Manifest: echoManifest(t, ""), HeartbeatInterval: 100 * time.Millisecond,
		HeartbeatTimeout: 300 * time.Millisecond, HeartbeatMisses: 2})
	lost := make(chan string, 1)
	m.OnProxyLost(func(p *Proxy, reason string) { lost <- reason })
	p, err := m.GetProxy([]any{"d"}, map[string]any{"persistent": true})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.WaitRegistered(p, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "a first heartbeat", 5*time.Second, func() bool { return p.State() == "healthy" })
	syscall.Kill(p.PID(), syscall.SIGSTOP)
	select {
	case reason := <-lost:
		if reason != "missed 2 heartbeats" {
			t.Fatalf("reason %q", reason)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a stopped proxy was not lost")
	}
	syscall.Kill(p.PID(), syscall.SIGCONT)
	if _, exited := p.Wait(10 * time.Second); !exited {
		t.Fatal("the lost proxy's process was not terminated")
	}
}

func TestManagerEncryptionTLSAndPlainOnOneListener(t *testing.T) {
	m, _ := startManager(t, Options{Manifest: echoManifest(t, ""), NoHeartbeat: true, Encrypt: true, IPCTLS: true,
		Cipher: ipc.CipherChaCha20Poly1305})
	secure, err := m.GetProxy([]any{"secure"}, map[string]any{"persistent": true})
	if err != nil {
		t.Fatal(err)
	}
	plain, err := m.GetProxy([]any{"plain"}, map[string]any{"persistent": false, "ipc_tls": false, "encrypt": false})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []*Proxy{secure, plain} {
		if err := m.WaitRegistered(p, 10*time.Second); err != nil {
			t.Fatal(p.Name, err)
		}
	}
	if !secure.Peer.TLS || secure.Peer.Key == nil || secure.Cipher() != ipc.CipherChaCha20Poly1305 {
		t.Fatalf("secure peer: tls %v key %v cipher %q", secure.Peer.TLS, secure.Peer.Key != nil, secure.Cipher())
	}
	if plain.Peer.TLS || plain.Peer.Key != nil {
		t.Fatalf("plain peer: tls %v key %v", plain.Peer.TLS, plain.Peer.Key != nil)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, p := range []*Proxy{secure, plain} {
		payload := []byte(`{"blob": "` + strings.Repeat("x", 70000) + `"}`)
		reply, err := m.Call(ctx, p, "ECHO", payload)
		if err != nil || string(reply) != string(payload) {
			t.Fatalf("%s: ECHO %v", p.Name, err)
		}
	}
	if !strings.Contains(strings.Join(secure.Command, " "), "--ipc-tls true") || !strings.Contains(strings.Join(secure.Command, " "), "--encrypt true") ||
		!strings.Contains(strings.Join(secure.Command, " "), "--cipher chacha20-poly1305") {
		t.Fatalf("launch command %v", secure.Command)
	}
}

func TestManagerDialsTheProxy(t *testing.T) {
	m, _ := startManager(t, Options{Manifest: echoManifest(t, ""), NoHeartbeat: true})
	port := 22890
	p, err := m.GetProxy([]any{"remote"}, map[string]any{"manager_dials": true, "inbound_address": "127.0.0.1", "inbound_port": port})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.WaitRegistered(p, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if p.Peer.DialAddress != "127.0.0.1:22890" || !p.Peer.Linked() {
		t.Fatalf("dial %q linked %v", p.Peer.DialAddress, p.Peer.Linked())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := m.Call(ctx, p, "PING", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := m.GetProxy([]any{"nowhere"}, map[string]any{"manager_dials": true}); err == nil {
		t.Fatal("manager_dials without a port was accepted")
	}
}

func TestManagerKeysProcessesAndRefusesConflicts(t *testing.T) {
	extra := "[identity]\nkeys = [\"host\"]\nmust_match = [\"username\"]\n[identity.normalize]\nhost = [\"strip\", \"lowercase\"]\n"
	m, _ := startManager(t, Options{Manifest: echoManifest(t, extra), NoHeartbeat: true})
	a, err := m.GetProxy([]any{"a"}, map[string]any{"host": " Broker ", "username": "u"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.GetProxy([]any{"b"}, map[string]any{"host": "broker", "username": "u"})
	if err != nil || b != a {
		t.Fatalf("two remotes of one broker must share a process: %v", err)
	}
	if a.Name != "('echo-test', 'broker')" {
		t.Fatalf("process key %q", a.Name)
	}
	if _, err := m.GetProxy([]any{"c"}, map[string]any{"host": "broker", "username": "v"}); err == nil ||
		!strings.Contains(err.Error(), "differs in username") {
		t.Fatalf("conflict not refused: %v", err)
	}
	command := strings.Join(a.Command, " ")
	if !strings.Contains(command, "--host  Broker  ") || !strings.Contains(command, "--username u") {
		t.Fatalf("protocol options not passed as given: %v", a.Command)
	}
	if err := m.WaitRegistered(a, 10*time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestWaitRegisteredGivesUpAndTerminates(t *testing.T) {
	text := "[proxy]\nname = \"sleeper\"\ncommand = [\"/bin/sh\", \"-c\", \"exec sleep 30\", \"sh\"]\n" // the options become $1..
	mf, err := manifest.Parse(text, "")
	if err != nil {
		t.Fatal(err)
	}
	m, _ := startManager(t, Options{Manifest: mf, NoHeartbeat: true})
	lost := make(chan string, 1)
	m.OnProxyLost(func(p *Proxy, reason string) { lost <- reason })
	p, err := m.GetProxy([]any{"s"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.WaitRegistered(p, 500*time.Millisecond); err == nil {
		t.Fatal("sleep registered?")
	}
	select {
	case reason := <-lost:
		if !strings.Contains(reason, "did not register") {
			t.Fatalf("reason %q", reason)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no lost callback")
	}
	if _, exited := p.Wait(10 * time.Second); !exited {
		t.Fatal("the process was not terminated")
	}
	if _, err := m.GetProxy([]any{"s"}, nil); err != nil {
		t.Fatal("relaunch refused:", err)
	}
}

func TestLaunchFailureIsReported(t *testing.T) {
	mf, _ := manifest.Parse("[proxy]\nname = \"missing\"\ncommand = [\"/nonexistent/binary\"]\n", "")
	m, _ := startManager(t, Options{Manifest: mf, NoHeartbeat: true})
	if _, err := m.GetProxy([]any{"x"}, nil); err == nil {
		t.Fatal("launching a missing binary succeeded")
	}
	if len(m.Proxies()) != 0 {
		t.Fatal("a failed launch left a proxy behind")
	}
}
