# Bounded AX520 Bluetooth relay source

This directory packages the frozen V4 source for one finite, 300-second fresh-pairing session. It contains no executable, stock SDK/library, firmware image, private receipt, phone identifier or pairing credential. The seven production source/header files match the reviewed V4 source hashes in [source-manifest.json](source-manifest.json).

The reviewed generated artifact is `ax520-hci-pairing-300s-v4-armv7`, SHA256:

```text
6feafed7f0ed3f3aacdd8fb091126d910d5d81c464c9f0d91fac6cbdfbfa34f4
```

Packaging did not change runtime behavior. The packaged build reproduced that hash byte-for-byte, and all 59 synthetic tests passed. Earlier short proofs established HCI ownership/restoration and an actual controller response through host VHCI; they do not establish working wireless CarPlay or recovery of a previous phone Bluetooth session.

## Build and test

Run the offline suite from the repository root:

```sh
python3 scripts/ax520-stock-auth/radios/bluetooth/run_tests.py
```

It requires Linux, Python 3 and a native C compiler. `--cc` selects the compiler executable. The runner compiles and tests in an isolated temporary directory, uses owned synthetic processes and local sockets, and removes generated files on exit. No dongle, root privileges, stock software or radio hardware is used. Tests cover process identity pins, failure/cancellation recovery, framing and partial I/O, deadlines/backpressure, stored-key/vendor guards, actual Reset sequencing, fresh pairing events, ACL/SCO, hashes and duration limits. The five-minute configuration is checked using immediate EOF plus short tests of the same deadline path; tests do not claim a five-minute live session occurred.

Build with a static ARMv7 hard-float **musl** compiler; no vendor SDK is needed:

```sh
python3 scripts/ax520-stock-auth/radios/bluetooth/build.py \
  --cc /absolute/path/to/arm-musl-gcc \
  --output /tmp/ax520-hci-pairing-300s-v4-armv7 \
  --verify-frozen
```

`ARM_MUSL_CC` can supply the compiler path. The output must be a new file. The builder checks that it is an ELF32 ARM executable without dynamic linking or an interpreter. `--verify-frozen` also requires the reviewed artifact hash; a different compiler/sysroot can produce a different artifact, which must be reviewed and pinned before deployment. Nothing is downloaded or installed automatically.

The reference toolchain was Debian GCC 14.2.0-19cross1, binutils 2.44, Linux headers 6.12.38 and musl commit `7813e9119eb5fe681b6750b8a033a0490bca0941`, built as a static ARM hard-float sysroot. The compiler flags include Cortex-A7, NEON and hard-float ABI. Exact source provenance and the frozen bounds are recorded in the source manifest. Keep generated outputs outside this source directory.

## Guarded external transport

The relay binds only `127.0.0.1:15039` on the dongle and accepts one client through the existing ADB forward. There is no greeting: each frame is a two-byte big-endian length followed by one complete H4 packet. Outer frames are limited to 4096 bytes, and Linux 4.9 host-to-HCI packets to 1028 bytes. TCP fragments/coalescing and partial writes are supported; HCI writes stay atomic.

The host's first packet must be its actual HCI Reset `01 03 0c 00`. Only the controller's actual successful Reset completion unlocks other commands, events and data. A subsequent Reset reestablishes this barrier. Nothing synthesizes a successful controller or authentication response.

The external transport rejects:

- Read/Write/Delete Stored Link Key commands `0x0c0d`, `0x0c11`, `0x0c12`.
- All vendor commands in OGF `0x3f`.
- Return Link Keys event `0x15`, vendor event `0xff`, and queued CommandComplete/CommandStatus replies for blocked opcodes.
- Malformed H4 packets, wrong directions, and traffic before successful Reset completion.

After Reset succeeds, standard fresh pairing traffic, Link Key Request/Notification events `0x17`/`0x18`, and valid ACL/SCO pass unchanged. Packet contents and pairing keys are never logged. Stock bond files are not read or copied by this code.

Only the host's `attach_external` path masks the three unsupported stored-key capability bits: byte 6 mask `0xe0`, absolute H4 offset 13, in a successful 71-byte Read Local Supported Commands completion. The stock relay leaves permitted real responses unchanged; existing host VHCI voice/flow-control adjustments are separate.

This guarantee applies to **our external transport**. Native `HCIDEVUP` restoration invokes stock-kernel initialization. Upstream Linux 4.9 can itself issue Read/Delete Stored Link Key when the controller advertises those operations and the broken-stored-key quirk is absent. The external relay cannot govern that native initialization and does not claim the stock kernel never manages its own controller key store. [Linux 4.9 initialization](https://github.com/torvalds/linux/blob/v4.9/net/bluetooth/hci_core.c)

## Runtime contract

The sibling [radio supervisor](../README.md) owns staging, reviewed deployment pins and actual phone testing. Before launching, freshly inspect the stock supervisor/worker PID and start times, their executable hash, and the UART-owning worker FD. No historical PID or start value is a valid assumption after a restart.

Read-only commands:

```sh
./ax520-hci-pairing-300s-v4-armv7 --bounds
./ax520-hci-pairing-300s-v4-armv7 --inspect SUP_PID WORKER_PID TTY_FD
```

`--bounds` performs no device access and returns:

```json
{
  "mode": "fresh_pairing_300s",
  "loopback_port": 15039,
  "accept_ms": 20000,
  "relay_ms": 300000,
  "worker_ms": 330000,
  "restore_ms": 10000,
  "worker_reap_ms": 1000,
  "restore_reap_ms": 1000,
  "resume_each_ms": 1000,
  "pending_io_stall_ms": 3000
}
```

For an authorized finite session, create a new empty root-owned 0700 directory in the dongle's `/tmp`, then use exact current pins:

```sh
./ax520-hci-pairing-300s-v4-armv7 --relay-launch NEW_ROOT_0700_RUN_DIR \
  SUP_PID SUP_START WORKER_PID WORKER_START BTAPP_SHA256 TTY_FD
```

The launcher returns JSON containing `watchdog_pid` and `started`. Its timestamped `status` records owned PID/start values. Wait for `relay_listening_loopback_only` before starting the host. `relay_host_connected` and `hci_user_owned` mark progression; final output contains packet counts, a numeric `relay_stop_reason` and one `RESULT` line.

The listener waits at most 20 seconds, before pausing any stock process. Relay operation lasts at most 300 seconds after ownership is acquired. The independent guardian caps its whole worker at 330 seconds, including acceptance and setup, so slow setup may shorten the active session. Restoration has a ten-second helper limit plus short reaping/resuming windows, giving a nominal userspace attempt budget below 345 seconds. There is no runtime argument for unbounded operation.

Close TCP or signal SIGTERM to the exact recorded watchdog PID/start to request cleanup. Its sole USER-owning worker must exit and be reaped before controller restoration. The original UP bit is restored, then the exact paused stock pair is resumed. Checks verify process identities, executable hash, the preserved UART FD, and hci0 topology. An unreaped HCI operation blocks concurrent recovery and leaves the stock pair paused with `restoration_unverified_no_retry`. Kernel-uninterruptible calls cannot be guaranteed to complete by a userspace deadline. Do not bypass the global lock; verify the recorded watchdog has exited before another activation.

| Stop reason | Meaning                           |
| ----------- | --------------------------------- |
| 1           | Peer EOF                          |
| 2           | Session deadline                  |
| 3           | Malformed packet/frame            |
| 4           | I/O failure                       |
| 5           | Pending I/O stalled               |
| 6           | Policy or Reset-barrier rejection |

`relay_complete_restored` means clean transport termination and verified **structural restoration**. It can include a session with no successful pairing. Bringing Bluetooth down disconnects prior links, and restoring the UP bit does **not** restore the previous phone Bluetooth session. Fresh pairing, CarPlay authentication, video, touch, audio and reconnection need actual device/user verification. No persistent boot service, firmware write or automatic retry is provided by this package.
