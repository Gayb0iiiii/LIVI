# AX520 stock authentication prototype

This is source for review and synthetic testing. It has not been installed in the stock application, and it does not establish working CarPlay. It contains no stock binary, certificate, private key or extracted identity data.

Run the native suite from the repository root:

```sh
python3 scripts/ax520-stock-auth/run_tests.py
```

The suite needs Python 3, a Linux C compiler and pthread/dlopen development headers. It builds temporary native artifacts, uses a synthetic provider, and opens only local test sockets. It does not access the dongle. Tests cover versioned `LD_PRELOAD` interposition, normal selector forwarding, supervisor/child behavior, repeated forks, concurrency, bounded protocol handling, metadata pipes and relay backpressure.

## Interposer and current gates

`interposer.c` forwards the original `SetiAPI2CAddr` call without changing its arguments. Only after that call returns does it observe the known address `0x20` and path `ly_iap`. It never calls the setter to select a provider itself. A failed call or another selection clears readiness. This observation is not proof that a phone accepted authentication.

The original application’s certificate/signature calls and broker calls share one mutex because the inspected stock software uses global scratch storage. Stock calls retain their existing arguments and output ownership. Broker requests receive additional bounds. The inspected software selector and hardware initializer do not reenter these exported hooks; this limited static finding still needs target runtime validation.

There are three build modes:

- **Default:** forwards and serializes stock calls, optionally emitting metadata. It opens no listener and accepts no external signing requests.
- **`AX520_SYNTHETIC_TEST`:** enables a mock listener only when the setter, certificate, signature and explicit synthetic marker functions resolve to the same mock DSO. The real stock library lacks that marker. Protocol major 3 here belongs to the synthetic fixture.
- **`AX520_ENABLE_DEVICE_BRIDGE`:** requires ARM32 hard-float uClibc-ng 1.0.22 with NPTL, and the additional launch-time opt-in `AX520_DEVICE_BRIDGE=1`. All three resolved provider functions must belong to the same DSO at exactly `/mnt/customer/app/libiap_new.so`. Before launching, independently verify that file's SHA-256 is `19326c5b73c61fd5a604d114ad49035a3730c7d12bfacaef165f7048e8f42e53`. Path/ownership checks do not verify its contents. This mode has been cross-built, but has not yet been loaded into the real stock application.

Real-stock and synthetic compile flags are mutually exclusive. Setting the runtime opt-in cannot enable a default observer build or turn the synthetic build into a stock bridge. It is a launch-time opt-in, not a live revocation mechanism. No mode forces the provider selector. The stock software’s P-256 constants and 32-byte input / 64-byte output support the real mode's compatibility classification as protocol major 3; this is not a protocol-version getter or end-to-end validation.

The listener binds IPv4 `127.0.0.1`, defaults to port `15000`, and accepts a strict decimal `AX520_AUTH_PORT` from `1` to `65535`. It starts only following a normal setter call in a forked child. Constructor code starts no threads. Child fork handling closes inherited listener/client copies without shutting down the parent’s sockets and requires a fresh normal setter call. Loopback does not authenticate another local process; a trusted forwarding connection and verified target remain prerequisites.

The test wire format matches `iap2-mfi`:

| Request                                  | Response on success                             |
| ---------------------------------------- | ----------------------------------------------- |
| `01`                                     | Certificate bytes, length `1..4096`             |
| `02` + 16-bit big-endian length + digest | Exactly 32 input bytes; exactly 64 output bytes |
| `03`                                     | One byte: compatibility protocol major `3`      |

Responses are status byte (`0` success, `1` failure), 16-bit big-endian length, then payload. Errors have no payload. Unknown operations close the connection. Invalid signing lengths receive an error and close without reading the advertised body. Requests and queued mutex acquisition have a two-second deadline; response writes have a separate two-second deadline. No stale request starts a provider call after its queue deadline. Vendor functions already executing in the process cannot safely be cancelled; a hung vendor call remains a deployment risk. The server handles one connection at a time, with bounded idle waits.

Mode revocation shuts down an open broker session. `DestroyiAP2` teardown is not intercepted: independent review found that mode-2 finalization only logs, with no provider free, signer-state reset or auth-mode change. Software provider calls take no iAP context and allocate their output per call. Context teardown therefore is not evidenced to invalidate this provider. The stock process and its directly linked library must remain alive, and selector changes and all provider operations remain serialized. No speculative teardown hook is included.

## Metadata observer

Observation is disabled unless `AX520_OBSERVER_FDS=READ_FD:WRITE_FD` names a dedicated inherited pipe pair. Both descriptors must be at least 3, refer to the same FIFO, have the correct read/write direction, and the writer must already be nonblocking. A launcher must create this pipe before executing the application; no FIFO utility or filesystem log is used.

The interposer duplicates both descriptors with close-on-exec. The original descriptors remain caller-owned; the caller may close them, but must not change the shared pipe’s nonblocking status. Private duplicates live until process exit and are inherited by forked workers. Retaining a read end prevents `SIGPIPE` when the collector exits. A full pipe drops events immediately. There are no retries, payload logs, argument strings or writes to stdout/stderr.

Each event is one atomic 12-byte write:

| Bytes   | Meaning                         |
| ------- | ------------------------------- |
| `0..3`  | ASCII `AXOB`                    |
| `4`     | Format version `1`              |
| `5`     | Flags below                     |
| `6..7`  | Reserved zero                   |
| `8..11` | PID, unsigned 32-bit big-endian |

A load event has flags zero. Setter events have bit `0x01`; `0x02` means the normal known software selector was observed successfully in an eligible child; `0x04` means a child fork was observed; `0x08` means the original setter returned nonzero. Selected metadata does not mean a broker was enabled. No certificate/signature operation is initiated to produce these events.

## Stock lifecycle and target validation

The inspected stock `lyLink.sh` unpacks `lylink`, starts supporting services, waits for `/tmp/lyrcpok`, then starts `lylinkapp -w`. The application has a supervisor that forks and replaces its worker. Current process metadata corroborated separate supervisor and multithreaded worker processes; the shell, `hostapd` and `udhcpd` were separate processes. Their independence does not prove Wi-Fi survives an experimental application restart.

The target is ARMv7 Cortex-A7, Thumb-2, hard-float EABI with uClibc-ng 1.0.22 and NPTL. Real target pthread headers and support objects are required: never substitute guessed `pthread_mutex_t` storage. Stock libc exports `__register_atfork`, while `pthread_atfork` needs the matching upstream nonshared support object. The version script mirrors the stock `libiap.so` version node. Native success alone does not prove target loader, symbol-version, fork or mutex behavior.

Before any stock-process trial, build and run only the synthetic fixture under a compatible target runtime, verify dynamic dependencies and symbol bindings, then prepare a separate reviewed rollback path. The launcher preserves the original arguments and compares six selected environment values; it does not prove complete environment equivalence. Its detached watchdog makes recovery independent of the controlling Wi-Fi connection, subject to the documented process and kernel limits. Running the test suite makes no device changes. Invoking the separate launcher on a device stops and restores the stock application. Actual video, audio, touch and reconnection remain separate acceptance tests.

### Validation recorded on 2026-11-12

The native synthetic suite passed. A separate ARM build used official uClibc-ng 1.0.22 headers/startup objects, Debian GCC 14.2 for ARM hard-float, and the preserved stock libc. This was not the original vendor SDK. The observer linked with `-z defs`, the matching upstream `pthread_atfork.oS`, and the `libiap.so` symbol version node; its only dynamic dependency was `libc.so.0`.

Six synthetic observer scenarios and all eight relay tests passed under Cortex-A7 QEMU with the matching stock loader/libc. The observer scenarios covered baseline/interposed concurrency, metadata events, a full pipe, a closed collector and ARM32 descriptor-overflow rejection. No stock authentication library or application ran in those tests.

A subsequent bounded test on the actual dongle also completed both baseline and interposed mock runs, including fork and four threads. All 96 mock calls completed, with peak provider concurrency reduced from 4 to 1. Stock processes remained running and the temporary test files were removed. See the [device validation record](../../docs/AX520-STOCK-AUTH.md#prototype-validation-on-the-same-dongle) for hashes and limits. Real-stock mode additionally cross-links against that runtime, and emulator tests reject synthetic/wrong-path providers even with the runtime opt-in. Actual stock-process interposition, forwarding and phone acceptance through this bridge remain unverified.

Target-kernel synthetic recovery tests also passed: the launcher restored the mock application after original/trial workers left a live sibling thread behind a zombie main thread. An escaped mock worker correctly blocked a duplicate restoration. All mock processes and files were removed, and stock PIDs remained unchanged. A subsequent real-stock observer attempt stopped at its initial read-only preflight because Tailscale SSH required a new identity check; no stock trial was started.

The [bounded stock trial launcher](OBSERVER-TRIAL.md) defaults to observation and removes inherited bridge settings. A separate compile-time capability plus explicit `--device-bridge SECONDS` permits a trial of at most 300 seconds, then attempts one normal restoration. This new bridge-launcher mode has not been validated on the dongle; the earlier target recovery tests used its observer-only predecessor.

## Local byte relay

`relay.c` is a separate stdin/stdout relay for a system without `nc`. It always connects to IPv4 `127.0.0.1`; it cannot select a remote host. A native test build is:

```sh
cc -std=c11 -Wall -Wextra -Werror -O2 relay.c -o relay
```

Run `./relay [port]`. The default is `15000`, or `AX520_RELAY_PORT` when no argument is supplied. Ports must be decimal `1..65535`. `AX520_RELAY_IDLE_MS` accepts `1..60000` milliseconds, default `5000`; this also bounds connection establishment. Successful transfers refresh the idle deadline, so it is not a total session limit.

Each direction uses an 8 KiB buffer and nonblocking I/O. EOF on stdin shuts down only the socket’s write half while receiving continues. A peer write-half close does not discard remaining stdin. Use dedicated pipes: the relay temporarily sets stdin/stdout nonblocking and restores their flags on exit. It writes protocol bytes only to stdout and fixed payload-free error messages to stderr.

Exit status is `0` after both directions drain, `1` for connection/I/O/idle failure, and `2` for invalid configuration. Native tests exercise both half-close directions, simultaneous duplex transfers, full/broken output pipes, timeouts and malformed configuration. A native executable must not be copied to the ARM dongle. A compatible separately linked ARM relay and its transport framing still need validation before any device use.

## Optional host forwarder

`host_forward.py` provides a finite development connection from Cruiser's `127.0.0.1:15000` through the already established private shell tunnel at `127.0.0.1:12323`. Its only target argument is the separately verified relay's absolute path beneath `/tmp` on the dongle:

```sh
python3 scripts/ax520-stock-auth/host_forward.py /tmp/reviewed-trial/relay --seconds 180
```

It quotes the path and waits for an exact shell readiness marker before forwarding any client bytes. This prevents shell command read-ahead from consuming protocol bytes. The marker proves command consumption, not successful relay startup or artifact identity; those require separate checks. Both addresses are fixed to IPv4 loopback, active connections are capped at four, timeouts are finite, and the total lifetime cannot exceed 900 seconds. It logs no protocol payloads and installs no service. Thirteen local synthetic tests cover framing, quoting, half-closes, connection limits, timeout and shutdown behavior. The real tunnel/relay/provider chain remains unverified.
