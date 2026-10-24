// Command echo-proxy is a protocol-proxy process that speaks the wire contract of PROTOCOL.md and answers ECHO with
// its payload unchanged, for conformance testing of the Go port. It takes the standard command line of §1 and
// --self-test, which checks the implementation against the wire test vectors.
package main

import (
	"fmt"
	"os"

	"github.com/eclipse-volttron/protocol-proxy-go/ipc"
	"github.com/eclipse-volttron/protocol-proxy-go/logs"
	"github.com/eclipse-volttron/protocol-proxy-go/proxy"
)

const logName = "protocol_proxy_go.echo"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	opts, err := proxy.ParseArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, proxy.Usage)
		fmt.Fprintln(os.Stderr, "echo-proxy: error:", err)
		return 2
	}
	if opts.Help {
		fmt.Println(proxy.Usage)
		return 0
	}
	if opts.SelfTest {
		return proxy.RunSelfTest(opts.Vectors)
	}
	logger := configureLogging(opts.LogLevel)
	logger.Infof(logName, "Launching Proxy with parameters: %s", opts.Redacted())
	hs, err := proxy.ReadHandshake(os.Stdin, opts.Encrypt, opts.IPCTLS)
	if err != nil {
		logger.Errorf(logName, "Proxy Launch: %v", err)
		return 1
	}
	p, err := proxy.New(opts, hs, logger)
	if err != nil {
		logger.Errorf(logName, "Proxy Launch: %v", err)
		return 1
	}
	p.RegisterHandler("ECHO", func(_ *ipc.Header, payload []byte) ([]byte, error) { return payload, nil }, true)
	return p.Run()
}

// configureLogging: records to the file named by PROTOCOL_PROXY_LOG if set, otherwise to stderr as JSON lines when
// launched by a manager (environment marker and stderr a pipe), readable text otherwise. The --log-level option
// wins over PROTOCOL_PROXY_LOG_LEVEL; the default is INFO.
func configureLogging(levelOption string) *logs.Logger {
	level := logs.INFO
	for _, candidate := range []string{levelOption, os.Getenv("PROTOCOL_PROXY_LOG_LEVEL")} {
		if candidate == "" {
			continue
		}
		if parsed, err := logs.ParseLevel(candidate); err == nil {
			level = parsed
			break
		}
	}
	if path := os.Getenv("PROTOCOL_PROXY_LOG"); path != "" {
		if f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
			return logs.New(level, &logs.StreamSink{W: f})
		}
	}
	return logs.New(level, &logs.StreamSink{W: os.Stderr, JSON: logs.UseJSONChannel()})
}
