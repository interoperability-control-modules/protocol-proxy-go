# protocol-proxy-go

A Go port of the protocol-proxy IPC library, an `echo-proxy` executable built on it, and a `ProtocolProxyManager`
(the `manager` package) that launches and hosts proxies written in any language, with a `conformance` command that
checks a proxy against the contract through the Go manager. The proxy side speaks the wire contract in the Python
repository's `PROTOCOL.md` toward a `ProtocolProxyManager` in any language: version 1 and 2
frame headers, per-message and persistent TCP connections, zlib compression, ChaCha20-Poly1305 and AES-256-GCM
payload encryption, mutually authenticated TLS 1.3, registration, `PING`, `SET_LOG_LEVEL`, `LOG` batches, the stdin
handshake, the parent-PID watch and a clean exit on SIGTERM. Dependencies: the standard library,
`golang.org/x/crypto` (for ChaCha20-Poly1305) and `github.com/BurntSushi/toml` (manifests). No cgo.

## Layout

| Path | What |
|---|---|
| `ipc/` | The wire contract: `header.go` (headers, request ids), `payload.go` (compression, AEAD, ciphers, features), `conn.go` (one connection, frame reader), `connector.go` (listener, dialer, authentication, dispatch, responses), `tls.go` (TLS material and configs), `vectors.go` (checks against `testdata/test_vectors.json`, a copy of the Python repository's). |
| `logs/` | Log records with the Python `LogRecord` attribute names: JSON lines on stderr, or a bounded rate-limited queue for `LOG` batches. |
| `proxy/` | A proxy process: command line (`options.go`), stdin handshake (`handshake.go`), registration, core methods and lifecycle (`proxy.go`), `--self-test` (`selftest.go`). |
| `cmd/echo-proxy/` | The executable: the standard command line plus an `ECHO` method that replies with its payload. |
| `manifest/` | Proxy manifests (§1a): parsing and validation of `proxy.toml`, identity keys, normalisation and `must_match`, placeholder resolution, the discovery search path. |
| `manager/` | The manager: process launch and the stdin handshake, pipe and `LOG` record handling, registration, heartbeat and loss, relaunch, the TLS authority (`authority.go`). |
| `conformance/`, `cmd/conformance/` | The conformance checks of PROTOCOL.md §12 run through the Go manager, and their command. |
| `proxy.toml` | The manifest a manager reads to launch `bin/echo-proxy` (name `echo-go`, header version 2). |

## Build and test

```sh
export PATH=/home/dmr/.local/go/bin:$PATH     # Go 1.23
go build -o bin/echo-proxy ./cmd/echo-proxy
go build -o bin/conformance ./cmd/conformance
go test ./...                                 # the manager tests build and launch echo-proxy themselves
./bin/echo-proxy --self-test                  # packs and unpacks every vector; exit 1 on any mismatch
./bin/echo-proxy --self-test path/to/test_vectors.json
```

## Conformance check

Two harnesses check a proxy against PROTOCOL.md §12; a port is expected to pass every check that is not skipped
under both. The Go one launches the proxy through the Go manager:

```sh
./bin/conformance proxy.toml --echo ECHO --tls --manager-dials            # this port's echo proxy: 26 of 26
./bin/conformance ../protocol-proxy-c/proxy.toml --echo ECHO --tls --manager-dials
./bin/conformance ../protocol-proxy-julia/proxy.toml --echo ECHO --manager-dials   # TLS not implemented there
./bin/conformance echo-go --echo ECHO                                     # by name, through the manifest search path
```

Options: `--echo METHOD` (a method that replies with its payload, enabling the payload checks), `--tls`,
`--manager-dials`, `--option NAME=VALUE` (a launch option, repeatable), `--timeout S` (default 20), `--python PATH`
(what `{python}` resolves to), `--log FILE` (manager and proxy logs at DEBUG to a file), `--json`, `-v` (logs on
stderr). Exit 0 when every check passes or is skipped. The check names and the report layout are the Python
harness's, so the two reports compare line for line.

A Python proxy is checked the same way through a manifest whose command is the generic launcher, with `{python}`
pointed at the environment that has the proxy installed. The Python repository ships manifests for its test dummies
in `tests/manifests/` (their `[environment]` sets `PYTHONPATH = "{manifest_dir}/.."`; environment values take the same
`{manifest_dir}` and `{python}` placeholders as the command):

```sh
./bin/conformance ../protocol-proxy/tests/manifests/GeventDummy.toml --echo ECHO --tls --manager-dials \
    --python ~/Scratch/drivers_proxies/.venv/bin/python
./bin/conformance ../protocol-proxy/tests/manifests/AsyncioDummy.toml --echo ECHO --tls --manager-dials \
    --python ~/Scratch/drivers_proxies/.venv/bin/python
```

The 26 checks are those of PROTOCOL.md §12 plus "LOG batch over the socket" (when `log` is advertised, a record must
arrive in a `LOG` batch within 3 s of registration; the proxy is launched at `--log-level INFO` so its switch to
socket logging is shipped). Results on 2026-10-24 through the Go manager: Go 26 of 26, C 26 of 26, Python gevent and
asyncio dummies 26 of 26, Julia 23 of 23 (TLS not requested; it advertises `log` and passes the LOG check).

The Python harness launches the proxy through the Python manager and checks the same clauses. From the
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

## Manager

The `manager` package is the Go `ProtocolProxyManager`: it reads a manifest, launches the proxy process, writes the
tokens (and key and TLS material) to its stdin, reads its stdout and stderr, accepts its registration, pings it,
handles its `LOG` batches, terminates it on `Stop` and relaunches it on the next `GetProxy` after a loss. It is a
connector like a proxy (`m.Conn()`), so handlers for a proxy's unsolicited pushes are registered on it the same way.

```go
mf, _ := manifest.Find("mqtt")                        // or manifest.Load("path/proxy.toml")
m, _ := manager.New(manager.Options{Manifest: mf, Encrypt: true, IPCTLS: true, Persistent: true})
m.Start()                                             // listens on localhost, first free port in 22801..22899
m.OnProxyLost(func(p *manager.Proxy, reason string) { /* re-run setup: GetProxy + WaitRegistered */ })
p, err := m.GetProxy([]any{"mqtt", "broker"}, map[string]any{"host": "broker.example", "port": 1883, "username": "u"})
err = m.WaitRegistered(p, 20*time.Second)             // the process is terminated and forgotten on a timeout
reply, err := m.Call(ctx, p, "READ_POINTS", payload)  // or m.Request(ctx, p, &ipc.Message{...}), m.Send(p, msg)
reply, err = m.SetProxyLogLevel(ctx, p, logs.DEBUG)   // SET_LOG_LEVEL, and the records are gated here at that level
health := m.Health()                                  // state, last seen, misses, features, pid, last PING report
m.Stop(true, 5*time.Second)                           // SIGTERM every proxy, SIGKILL after the timeout
```

**Options** (`manager.Options`): `Manifest` (required); `InboundAddress`, `InboundPort` (the listener; proxies are told
`--manager-address InboundAddress`); `Persistent`, `Encrypt`, `Cipher`, `IPCTLS` as defaults for every proxy, each
overridable per launch through the options `persistent`, `encrypt`, `cipher`, `ipc_tls`; `CompressThreshold`;
`HeartbeatInterval` (10 s), `HeartbeatTimeout` (5 s), `HeartbeatMisses` (3), `NoHeartbeat`; `Python`; `Logger`
(the manager's own log); `Records` (where the proxies' records go); `ProxyLogLevel` (gates them and travels as
`--log-level`); `Environment`.

**GetProxy options** are the proxy's launch options in the Python kwargs spelling (`inbound_port`, not
`--inbound-port`); they select the process through the manifest's identity keys and are checked against its
`must_match`, then travel to the proxy as `--name value` (booleans as `true`/`false`), sorted by name after the
standard options. The manager-only ones are `dial` (`"host:port"`, where to reach a `manager_dials` proxy; default
its `inbound_address:inbound_port`), `ssh_host`, `ssh_options`, `ssh_forward`, `remote_python`, `remote_env`
(the SSH launcher prefix of PROTOCOL.md §1, composed as the Python manager composes it but not exercised by the tests
here) and `manager_callbacks` (ignored; register handlers on `m.Conn()` instead).

**Process keys and names.** The process key is `(manifest name, *normalised identity options)` when the manifest
names `keys`, else the caller's `uniqueRemoteID`; a proxy's name, as passed in `--proxy-name` and used in log lines,
is that key rendered as a Python tuple (`('mqtt', 'broker.example', 1883)`), which is what a Python manager would
call the same process. The proxy id for a key is kept across relaunches.

**Manifest discovery** (`manifest.SearchPath`) is the §1a list: the directories in `PROTOCOL_PROXY_MANIFESTS`
(prepended), `$XDG_CONFIG_HOME/protocol-proxy/manifests` (`~/.config`), `<prefix>/share/protocol-proxy/manifests`,
`$XDG_CONFIG_DIRS/protocol-proxy/manifests` (`/etc`), and `$XDG_DATA_DIRS/protocol-proxy/manifests`
(`/usr/local/share:/usr/share`). `<prefix>` is `PROTOCOL_PROXY_PREFIX` when set, else the directory above the running
executable's directory (a binary installed at `<prefix>/bin/x` looks in `<prefix>/share`), the Go counterpart of a
Python environment's `sys.prefix`. There is no Python entry-point fallback: Python proxies are found after
`protocol-proxy-manifests export` has copied their manifests into one of the directories. `manifest.Find(name)`,
`manifest.Load(path)` and `manifest.Discover()` are the entry points.

**`{python}`** in a manifest command resolves to `Options.Python`, else `$PROTOCOL_PROXY_PYTHON`, else `python3`
(behind an SSH prefix: `remote_python`, default `python3`). `{manifest_dir}` is the manifest file's directory.

**Logging hooks.** The manager's own records go to `Options.Logger` (a `logs.Logger`; default INFO, readable text on
stderr). A launched proxy's records, whether read as JSON lines from its stderr pipe, as plain lines from either pipe
(stdout INFO, stderr WARNING, or the level of a `<N>` syslog prefix) or received in `LOG` batches, are rebuilt as
`manager.Record` (level, message, the proxy's own logger name, the channel `stdout`/`stderr`/`socket`, pid, proxy
name, the raw fields) and handed to `Options.Records`, a `RecordHandler`; `RecordHandlerFunc` adapts a function and
the default `LoggerRecordHandler` forwards to the manager's logger under
`protocol_proxy.proxies.<manifest name>.<proxy name>`. Records below the proxy's level (`ProxyLogLevel`, changed by
`SetProxyLogLevel`) are dropped before the handler sees them. A `dropped` count in a batch becomes one WARNING.

**TLS.** Every manager creates an in-memory CA (`manager.Authority`, EC P-256, 366 days) and issues itself a
certificate at `New`; a proxy launched with TLS is issued one naming its id and receives `{"ca", "cert", "key"}` on
stdin. The manager's listener accepts plain and TLS connections on one port (`ipc.Options.TLSOptional`, the first
byte tells them apart), so TLS and plain proxies may share a manager.

**Liveness.** Registered proxies with a running process are pinged every `HeartbeatInterval`; any reply counts, and
`HeartbeatMisses` consecutive misses, a process exit, or no registration within `WaitRegistered`'s timeout lose the
proxy: it is forgotten, its process terminated, `OnProxyLost` callbacks run, and the next `GetProxy` for its key
relaunches it. A process the manager is itself terminating is not pinged.

### Manager-side behaviour taken from the Python reference

PROTOCOL.md describes the proxy's obligations in detail; these are what a manager port needed from the Python code:

- The manager's `REGISTER_PEER` reply advertises `compress`, `aead-chacha20poly1305` and `aead-aes256gcm` (not
  `ping`, `log` or `set_log_level`); a registration without `address` and `port`, or from an unknown sender, is
  answered with plain `false`.
- The handshake on stdin is written in one go and stdin closed: proxy token hex, manager token hex, key hex (only
  with `--encrypt true`), TLS material line (only with `--ipc-tls true`), nothing between them.
- A proxy is told `--log-level` with the level the manager handles its records at, `--encrypt true` and `--cipher
  <the manager's resolved cipher>` when the manager encrypts (so both ends pick one AEAD), `--ipc-tls true` when the
  manager defaults to TLS, and `--persistent` only when the caller gave it; the manager's own connection policy toward
  that proxy follows the same option. `manager_dials` forces a persistent policy.
- The peer is added to the connector before the process starts (its first frame must authenticate), with a fresh
  token and, when encrypting, a fresh 32-byte key; a relaunch gets new ones. Proxy ids per process key persist.
- With `manager_dials`, the manager dials the proxy's `inbound_address:inbound_port` (or `dial`) with a persistent
  connection and sends `PING` every second until the proxy's `REGISTER_PEER` arrives on it.
- `Stop` closes the manager's listener and connections first, then sends SIGTERM to every running proxy and SIGKILL
  after 5 s. The manager's pipe readers run until EOF regardless.
- Heartbeat: only registered proxies with a live process are pinged; a process being terminated by the manager is
  skipped; the miss counter resets on any reply, the state machine is launching, registered, healthy, unhealthy, lost.
- Plain stdout lines are INFO and plain stderr lines WARNING unless prefixed `<N>`; a JSON line is a record only when
  it is an object with a `msg` key; the proxy's own logger name becomes the record's remote name and the channel
  (`stdout`, `stderr`, `socket`) is kept.
- The Python asyncio proxy used to install its SIGTERM handler only after registration, so a SIGTERM in the few
  milliseconds after the registration reply killed it (exit by signal); the Go manager was fast enough to hit that
  window in `conformance`. Fixed in the Python repository on 2026-10-24 (handler armed before registration).
