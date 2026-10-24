package manager

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/eclipse-volttron/protocol-proxy-go/logs"
)

// process is one launched proxy process: the command, its exit, and the pipes the manager reads its logs from.
type process struct {
	cmd    *exec.Cmd
	pid    int
	exited chan struct{}
	mu     sync.Mutex
	code   int
	done   bool
}

func (proc *process) running() bool {
	select {
	case <-proc.exited:
		return false
	default:
		return true
	}
}

func (proc *process) exitCode() (int, bool) {
	proc.mu.Lock()
	defer proc.mu.Unlock()
	return proc.code, proc.done
}

// environment is a launched proxy's environment: the manager's, the manifest's, the options', and the marker that
// selects the JSON log channel.
func (m *Manager) environment() []string {
	env := map[string]string{}
	for _, kv := range os.Environ() {
		for i := 0; i < len(kv); i++ {
			if kv[i] == '=' {
				env[kv[:i]] = kv[i+1:]
				break
			}
		}
	}
	for k, v := range m.Manifest.ResolvedEnvironment(m.Python()) {
		env[k] = v
	}
	for k, v := range m.opts.Environment {
		env[k] = v
	}
	env[logs.LaunchedByManagerEnv] = "1"
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+env[k])
	}
	return out
}

// launch starts the proxy's process, writes the stdin handshake (§1) and starts the pipe readers and the watcher.
func (m *Manager) launch(p *Proxy) error {
	if len(p.Command) == 0 {
		return fmt.Errorf("%s: empty launch command", m.Manifest.Name)
	}
	cmd := exec.Command(p.Command[0], p.Command[1:]...)
	cmd.Env = m.environment()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	// The pipes are made here rather than by exec.Cmd so that Wait does not close them under the readers: the readers
	// see EOF when the process (and anything it passed them to) is gone, as the Python manager's readers do.
	outR, outW, err := os.Pipe()
	if err != nil {
		return err
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		_ = outR.Close()
		_ = outW.Close()
		return err
	}
	cmd.Stdout, cmd.Stderr = outW, errW
	if err := cmd.Start(); err != nil {
		for _, f := range []*os.File{outR, outW, errR, errW} {
			_ = f.Close()
		}
		return fmt.Errorf("%s: unable to launch %v: %w", m.Manifest.Name, p.Command, err)
	}
	_ = outW.Close()
	_ = errW.Close()
	proc := &process{cmd: cmd, pid: cmd.Process.Pid, exited: make(chan struct{})}
	p.setProcess(proc)
	m.log.Infof(logName, "proxy %s has PID %d", p.Name, proc.pid)
	loggerName := p.LoggerName(m.Manifest.Name)
	go readRecords(outR, "stdout", loggerName, proc.pid, p.Name, p.LogLevel, m.records)
	go readRecords(errR, "stderr", loggerName, proc.pid, p.Name, p.LogLevel, m.records)
	m.log.Infof(logName, "PPM: Created new ProtocolProxy %s with ID %s, pid: %d", p.Name, p.ID, proc.pid)

	handshake := []byte(p.Peer.Token.Hex() + m.conn.Token().Hex())
	if p.Peer.Key != nil {
		handshake = append(handshake, []byte(fmt.Sprintf("%x", p.Peer.Key))...)
	}
	if p.material != nil {
		line, err := p.material.Line()
		if err != nil {
			_ = stdin.Close()
			return err
		}
		handshake = append(handshake, line...)
	}
	_, writeErr := stdin.Write(handshake)
	_ = stdin.Close()
	go m.watch(p, proc)
	if writeErr != nil {
		m.log.Warningf(logName, "PPM: unable to write the handshake to %s (pid %d): %v", p.Name, proc.pid, writeErr)
	}
	return nil
}

// watch waits for the process to exit; when it does, the proxy is dropped (if it is still the current one for its
// id) so the next GetProxy relaunches, and the listeners are told so they can re-register.
func (m *Manager) watch(p *Proxy, proc *process) {
	err := proc.cmd.Wait()
	code := -1
	if proc.cmd.ProcessState != nil {
		code = proc.cmd.ProcessState.ExitCode()
	}
	if err != nil && code == 0 {
		code = -1
	}
	proc.mu.Lock()
	proc.code, proc.done = code, true
	proc.mu.Unlock()
	close(proc.exited)
	if m.isCurrent(p) {
		m.log.Warningf(logName, "PPM: %s process %d (proxy %s) exited with code %d. It will be relaunched on the next"+
			" request for it.", m.Manifest.Name, proc.pid, p.ID, code)
		m.loseProxy(p, fmt.Sprintf("process exited with code %d", code))
	} else {
		m.log.Debugf(logName, "PPM: %s process %d (proxy %s) exited with code %d after its peer was already replaced or"+
			" removed.", m.Manifest.Name, proc.pid, p.ID, code)
	}
}

// terminate stops a proxy's process: SIGTERM, then SIGKILL after timeout. While it runs the process is not pinged.
func (m *Manager) terminate(p *Proxy, timeout time.Duration) {
	proc := p.proc()
	if proc == nil || !proc.running() {
		return
	}
	m.mu.Lock()
	m.stoppingPIDs[proc.pid] = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.stoppingPIDs, proc.pid)
		m.mu.Unlock()
	}()
	m.log.Infof(logName, "Terminating %s with PID: %d", m.Manifest.Name, proc.pid)
	if err := proc.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		m.log.Warningf(logName, "Exception encountered attempting to terminate proxy process (%d): %v", proc.pid, err)
	}
	select {
	case <-proc.exited:
		return
	case <-time.After(timeout):
	}
	m.log.Infof(logName, "Killing %s with PID: %d", m.Manifest.Name, proc.pid)
	_ = proc.cmd.Process.Kill()
	select {
	case <-proc.exited:
	case <-time.After(timeout):
		m.log.Warningf(logName, "Failed to stop %s with PID: %d", m.Manifest.Name, proc.pid)
	}
}

// Terminate stops a proxy's process (SIGTERM, SIGKILL after timeout; 0: 5 s) without forgetting the proxy: the
// watcher then loses it and the next GetProxy relaunches.
func (m *Manager) Terminate(p *Proxy, timeout time.Duration) {
	if timeout == 0 {
		timeout = DefaultTerminateTimeout
	}
	m.terminate(p, timeout)
}

// SelfTest runs the manifest's self-test command, if it has one, and returns its failure (nil when it passes or
// there is none).
func (m *Manager) SelfTest(ctx context.Context) error {
	argv := m.Manifest.SelfTestCommand(m.Python())
	if argv == nil {
		return nil
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = m.environment()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s self test %v failed: %w\n%s", m.Manifest.Name, argv, err, out)
	}
	return nil
}
