// Package proxy is a protocol-proxy process: it parses the standard command line of PROTOCOL.md §1, reads the stdin
// handshake, registers with the manager, answers the core methods (PING, SET_LOG_LEVEL), ships LOG batches, watches
// its parent and stops cleanly on SIGTERM. A protocol port builds on it by registering its own handlers.
package proxy

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/eclipse-volttron/protocol-proxy-go/ipc"
)

// Options are the standard launch options (every one `--name value`, booleans as true/false) plus whatever protocol
// options the manager appended, which this package keeps in Extra for the port to read.
type Options struct {
	ProxyID           ipc.UUID
	ProxyName         string
	ManagerID         ipc.UUID
	ManagerAddress    string
	ManagerPort       int
	InboundAddress    string
	InboundPort       int
	Encrypt           bool
	Cipher            string
	IPCTLS            bool
	ManagerDials      bool
	Persistent        bool
	SocketLogging     bool
	CompressThreshold int // negative: not given (the connector default applies)
	LogLevel          string
	// SelfTest: check the wire vectors and exit (--self-test, optionally --vectors <file>).
	SelfTest bool
	Vectors  string
	Help     bool
	// Extra holds the options this package does not know, by name as given (dashes, without the leading --).
	Extra map[string]string
}

// Usage describes the command line.
const Usage = `usage: echo-proxy --proxy-id <hex> --proxy-name <str> --manager-id <hex> [--manager-address <host>]
    [--manager-port <int>] [--inbound-address <host>] [--inbound-port <int>] [--encrypt true|false]
    [--cipher auto|aes-256-gcm|chacha20-poly1305] [--ipc-tls true|false] [--manager-dials true|false]
    [--persistent true|false] [--socket-logging true|false] [--compress-threshold <int>] [--log-level <LEVEL>]
    [--<protocol option> <value> ...]
       echo-proxy --self-test [--vectors <test_vectors.json>]`

// ParseBool reads a boolean option as the Python launcher does.
func ParseBool(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "t", "yes", "y", "on":
		return true, nil
	case "0", "false", "f", "no", "n", "off", "":
		return false, nil
	}
	return false, fmt.Errorf("expected a boolean value, got %q", value)
}

// ParseArgs parses the command line (without the program name).
func ParseArgs(args []string) (*Options, error) {
	opts := &Options{ManagerAddress: "localhost", ManagerPort: 22801, InboundAddress: "localhost", Cipher: ipc.CipherAuto,
		SocketLogging: true, CompressThreshold: -1, Extra: map[string]string{}}
	var haveProxyID, haveName, haveManagerID bool
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "--") {
			return nil, fmt.Errorf("unexpected argument %q (every option is --name value)", arg)
		}
		name, value, hasValue := strings.Cut(arg[2:], "=")
		name = strings.ToLower(name)
		if name == "help" || name == "h" {
			opts.Help = true
			return opts, nil
		}
		if name == "self-test" || name == "self_test" {
			opts.SelfTest = true
			if !hasValue && i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				value, i = args[i+1], i+1
			} else if !hasValue {
				value = "true"
			}
			if on, err := ParseBool(value); err == nil {
				opts.SelfTest = on
			} else {
				opts.Vectors = value
			}
			continue
		}
		if !hasValue {
			if i+1 >= len(args) {
				return nil, fmt.Errorf("option --%s needs a value", name)
			}
			value, i = args[i+1], i+1
		}
		var err error
		switch strings.ReplaceAll(name, "_", "-") {
		case "proxy-id":
			opts.ProxyID, err = ipc.ParseUUID(value)
			haveProxyID = true
		case "proxy-name":
			opts.ProxyName, haveName = value, true
		case "manager-id":
			opts.ManagerID, err = ipc.ParseUUID(value)
			haveManagerID = true
		case "manager-address":
			opts.ManagerAddress = value
		case "manager-port":
			opts.ManagerPort, err = strconv.Atoi(value)
		case "inbound-address":
			opts.InboundAddress = value
		case "inbound-port":
			opts.InboundPort, err = strconv.Atoi(value)
		case "encrypt":
			opts.Encrypt, err = ParseBool(value)
		case "cipher":
			opts.Cipher = value
			if value != ipc.CipherAuto {
				_, _, err = ipc.CipherFeature(value)
			}
		case "ipc-tls":
			opts.IPCTLS, err = ParseBool(value)
		case "manager-dials":
			opts.ManagerDials, err = ParseBool(value)
		case "persistent":
			opts.Persistent, err = ParseBool(value)
		case "socket-logging":
			opts.SocketLogging, err = ParseBool(value)
		case "compress-threshold":
			opts.CompressThreshold, err = strconv.Atoi(value)
		case "log-level":
			opts.LogLevel = value
		case "vectors":
			opts.Vectors = value
		default:
			opts.Extra[name] = value
		}
		if err != nil {
			return nil, fmt.Errorf("option --%s: %w", name, err)
		}
	}
	if opts.SelfTest {
		return opts, nil
	}
	var missing []string
	if !haveProxyID {
		missing = append(missing, "--proxy-id")
	}
	if !haveName {
		missing = append(missing, "--proxy-name")
	}
	if !haveManagerID {
		missing = append(missing, "--manager-id")
	}
	if len(missing) > 0 {
		return nil, errors.New("the following arguments are required: " + strings.Join(missing, ", "))
	}
	return opts, nil
}

var sensitiveKeys = []string{"password", "token", "secret", "credential"}

// Redacted is the options as a string with credential-like extra values masked, for the launch log line.
func (o *Options) Redacted() string {
	parts := []string{
		fmt.Sprintf("proxy_id=%s", o.ProxyID.Hex()), fmt.Sprintf("proxy_name=%q", o.ProxyName),
		fmt.Sprintf("manager_id=%s", o.ManagerID.Hex()), fmt.Sprintf("manager_address=%s", o.ManagerAddress),
		fmt.Sprintf("manager_port=%d", o.ManagerPort), fmt.Sprintf("inbound_address=%s", o.InboundAddress),
		fmt.Sprintf("inbound_port=%d", o.InboundPort), fmt.Sprintf("encrypt=%t", o.Encrypt), fmt.Sprintf("cipher=%s", o.Cipher),
		fmt.Sprintf("ipc_tls=%t", o.IPCTLS), fmt.Sprintf("manager_dials=%t", o.ManagerDials),
		fmt.Sprintf("persistent=%t", o.Persistent), fmt.Sprintf("socket_logging=%t", o.SocketLogging),
	}
	if o.CompressThreshold >= 0 {
		parts = append(parts, fmt.Sprintf("compress_threshold=%d", o.CompressThreshold))
	}
	for k, v := range o.Extra {
		lower := strings.ToLower(k)
		for _, s := range sensitiveKeys {
			if strings.Contains(lower, s) && v != "" {
				v = "***"
				break
			}
		}
		parts = append(parts, fmt.Sprintf("%s=%q", k, v))
	}
	return strings.Join(parts, " ")
}
