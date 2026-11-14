# AX520 single-dongle radio session

This package supervises one **finite 300-second test session** using the
already-running, pinned AX520 authentication/ADB service. It does not enable a
new boot service, start another ADB server, change the authentication endpoint,
flash firmware, or write dongle partitions. Root coordination owns deployment
and actual phone testing. Offline tests do not establish wireless CarPlay.

The generated network and Bluetooth binaries are copied into a fresh private
`/tmp/ax520-radios-<run-id>` directory through ADB sync. The existing USB ADB
server carries the additional host-loopback forwards 15038 and 15039. The
stock AP remains active. Native Bluetooth ownership is finite and guarded;
stock processes and their UART descriptor remain present while paused.

## Prerequisites

- Existing authentication service reports `running`, with its current receipt,
  exact managed device owners, USB descriptor, and dedicated ADB server.
- A reviewed LIVI build contains the stock AP backend and external TAP/VHCI
  clients, plus its deployment-specific AppImage/core/helper hashes in the
  authentication package. **Do not relax old package pins to accommodate a new
  build.** Update and review them, then generate this manifest from that exact
  package. The loaded service still independently verifies its dependencies.
- Network relay from `network/`, and the separately reviewed **v4 300-second**
  Bluetooth relay. The supervisor reads the generated HCI binary's `--bounds`
  and requires the exact compiled 20s accept / 300s relay / 330s worker budget,
  10s controller restore, and short reap/resume limits. The frozen v2/v3 short
  proof artifacts cannot satisfy this gate.
- Host external-radio clients retry the two loopback endpoints and close their
  owned TAP/VHCI descriptors on connection loss. No pre-existing host TAP/HCI
  is accepted by the first-session preflight.
- The original auth service, installed hashes and generated binaries are
  preserved. The external HCI transport blocks stored-key commands and old-key
  responses; no pairing records or authentication credentials are copied by
  this package. This claim is limited to the external transport. Stock kernel
  initialization and the stock application may manage their own key store.

## Prepare and run

`build_manifest.py` takes reviewed local source/artifact paths, the corresponding
Pi destination paths, and an exclusive output filename. It hashes the exact
files and writes a private manifest. Generate it **after** final deployment pins
are updated. It does not contact a device or copy files. The manifest contains
no Wi-Fi password, Bluetooth key, phone address or authentication credential.

Copy `supervisor.py`, the private manifest and the generated artifacts to the
Pi. Use a fresh twelve-character lowercase hexadecimal run ID:

```sh
python3 supervisor.py --manifest /private/path/manifest.json \
  --state-dir /home/cruiser/LIVI/ax520-radio-state --run-id UNIQUE12HEX
```

Run it as Cruiser. Keep this process attached to a monitored terminal or a
properly tracked detached process; a signal requests cleanup. Do not enable
automatic restart for this finite test. The supervisor refuses a new session
if any previous journal has an unresolved outcome. It never erases prior
receipts or silently clears that block.

The network deadline begins slightly before Bluetooth setup, so the usable
combined window is slightly less than 300 seconds. The native Bluetooth
watchdog independently restores stock ownership after its own bounds if host
access is lost. A kernel-uninterruptible operation remains an explicitly
unverified recovery result; no automatic retry is allowed in that case.

## Receipts and cleanup

`<state-dir>/<run-id>/result.json` moves through launch intents and
`running_bounded`. `radio_transports_ready=true` means the stock HCI USER channel
is owned, a host HCI exists, and the host TAP has carrier plus usable IPv6
link-local. This is transport readiness, **not** completed Bluetooth pairing,
CarPlay authentication, video, audio or reconnection.

`native-status.json` contains selected guardian/result/counter metadata;
`network-status.json` contains frame counters and the stop reason. No packet
payload is saved. The finite native logs remain in the private stock RAM run
directory for exact recovery review; generated files are not removed during
cleanup, preserving evidence without consuming persistent partition space.

Cleanup first removes only exact owned forward mappings on the same ADB
PID/start, even if USB or the separate auth endpoint has disappeared. It then
signals exact PID/start/executable/hash owners and waits for native restoration.
A final native RESULT is insufficient: a bounded read-only check verifies the
exact guardian PID/start has exited before cleanup can pass. Absence, PID reuse,
and an already-exited zombie are recorded distinctly; a reused PID is never
signalled by this check. `native-status.json` records `guardian_exit`, and the
main receipt records `guardian_exit_verified`. A still-running guardian blocks
the next session. Cleanup also checks radio interfaces disappeared, stock Wi-Fi
flags returned, radio listeners closed, and authentication owners/USB remained
valid. These are structural restoration checks; they do not establish that the
previous phone Bluetooth connection was restored.

- `stopped_verified`: bounded execution ended and cleanup verified.
- `failed_restored`: execution failed, but cleanup verified.
- `failed_before_start`: preflight failed before any radio operation.
- `stopped_before_start`: a stop request arrived before the first radio operation.
- `restoration_unverified_no_retry`: preserve receipts and inspect before any
  new attempt. Never treat elapsed time as evidence of recovery.

The journal always keeps `wireless_carplay_verified=false`; a separate actual
phone/session test must establish that result. `stopped_verified` is not a
claim that wireless CarPlay worked.

## Offline validation

```sh
python3 -m unittest discover -s . -p test_supervisor.py -v
sh network/test.sh
```

Supervisor tests cover launch/forward response loss, ownership conflicts,
auth-unavailable forward cleanup, server PID reuse, native failed results,
cleanup ordering, stop requests, private ADB sync, exact guardian exit/PID reuse,
and unverified restoration.
Network tests use local sockets and wrapped fake interfaces, including the
300-second argument and prompt SIGTERM cleanup. They never touch a real radio.
