# protocol-proxy-go

A Go port of the protocol-proxy IPC library and an `echo-proxy` executable built on it. It speaks the wire
contract in the Python repository's `PROTOCOL.md` toward a `ProtocolProxyManager` in any language: version 1 and 2
frame headers, per-message and persistent TCP connections, zlib compression, ChaCha20-Poly1305 and AES-256-GCM
payload encryption, mutually authenticated TLS 1.3, registration, `PING`, `SET_LOG_LEVEL`, `LOG` batches, the stdin
handshake, the parent-PID watch and a clean exit on SIGTERM. Dependencies: the standard library and
`golang.org/x/crypto` (for ChaCha20-Poly1305). No cgo.

## Layout

| Path | What |
|---|---|
| `ipc/` | The wire contract: `header.go` (headers, request ids), `payload.go` (compression, AEAD, ciphers, features), `conn.go` (one connection, frame reader), `connector.go` (listener, dialer, authentication, dispatch, responses), `tls.go` (TLS material and configs), `vectors.go` (checks against `testdata/test_vectors.json`, a copy of the Python repository's). |
| `logs/` | Log records with the Python `LogRecord` attribute names: JSON lines on stderr, or a bounded rate-limited queue for `LOG` batches. |
| `proxy/` | A proxy process: command line (`options.go`), stdin handshake (`handshake.go`), registration, core methods and lifecycle (`proxy.go`), `--self-test` (`selftest.go`). |
| `cmd/echo-proxy/` | The executable: the standard command line plus an `ECHO` method that replies with its payload. |
| `proxy.toml` | The manifest a manager reads to launch `bin/echo-proxy` (name `echo-go`, header version 2). |

## Build and test

```sh
export PATH=/home/dmr/.local/go/bin:$PATH     # Go 1.23
go build -o bin/echo-proxy ./cmd/echo-proxy
go test ./...
./bin/echo-proxy --self-test                  # packs and unpacks every vector; exit 1 on any mismatch
./bin/echo-proxy --self-test path/to/test_vectors.json
```

## Conformance check

The Python harness launches the proxy through a real manager and checks every clause of the contract. From the
Python repository, with its virtual environment:

```sh
cd /home/dmr/Projects/volttron/modular/proxies/protocol-proxy
python -m protocol_proxy.conformance /home/dmr/Projects/volttron/modular/proxies/protocol-proxy-go/proxy.toml \
    --echo ECHO --tls --manager-dials -v
```

It reports `echo-go: all checks pass (25 passed, 0 failed, 0 skipped)`.

## Writing a proxy on the library

```go
opts, _ := proxy.ParseArgs(os.Args[1:])                       // the standard options; protocol options in opts.Extra
hs, _ := proxy.ReadHandshake(os.Stdin, opts.Encrypt, opts.IPCTLS)
logger := logs.New(logs.INFO, &logs.StreamSink{W: os.Stderr, JSON: logs.UseJSONChannel()})
p, _ := proxy.New(opts, hs, logger)
p.RegisterHandler("READ_POINTS", func(h *ipc.Header, payload []byte) ([]byte, error) { ... }, true)
os.Exit(p.Run())                                               // listens, registers, serves; 0 on SIGTERM
```

A handler's error becomes the `{"status": "error", ...}` reply of PROTOCOL.md §8. Pushes toward the manager go
through `p.Conn.Send` or `p.Conn.Request` with `p.Manager` as the peer; tag a push with `RemoteID` to have the
manager dispatch it by `(method, remote_id)`.

## Behaviour copied from the Python reference where PROTOCOL.md is silent

- Request ids cycle through 1 .. max-1 for each header version (Python `cycle(range(1, REQUEST_ID_MAX))`).
- A `RESPONSE` is sent in the header version of the request it answers (Python always sends version 2; both are
  accepted by the Python manager).
- A frame from an unknown sender or with a wrong token is dropped; if it expected a response it gets an empty
  `RESPONSE`, as §6 says. The Python connectors only check the token when adopting a keep-alive connection.
- `--cipher auto` picks AES-256-GCM when `/proc/cpuinfo` lists the `aes` flag, else ChaCha20-Poly1305.
- Before the manager's reply to `REGISTER_PEER` its features are unknown, so registration is never compressed and is
  encrypted with the proxy's configured cipher.
- The reply to a request is written on the connection it arrived on, with the keep-alive bit set only when that
  connection is persistent, and compressed when the sender advertised `compress`.
- Accepted connections idle out after 30 s until they are adopted as persistent; a handler is given 30 s.
- `LOG` batches are flushed every 0.2 s or at 64 records from a 2000-record queue limited to 50 records/s with a
  burst of 200, only in a manager-launched process (environment marker and stderr a pipe); whatever is still queued
  at exit is written to stderr as JSON lines.
- After a lost manager (parent PID changed) or SIGTERM the process exits 1 if the orderly stop has not completed in
  15 s.
