# Temporary stock trial launcher

`observer_trial.c` prepares one finite stock application trial and one attempt to restore the normal application. Its default build supports observation only. A separate compile-time capability and explicit command-line mode permit a bounded device-bridge trial. The launcher never executes signing requests or collects authentication payloads, and it does not install firmware. Each deployed artifact and target still require separate validation.

The production build has fixed targets: `/mnt/customer/app/lylinkapp -w`, working directory `/`, nice level `-15`, umask `0022`, stdin `/dev/null`, and normal stdout/stderr `/dev/console`. There is no option to select another executable or send arbitrary signals. The review command shape is:

```text
observer-trial SUPERVISOR_PID WORKER_PID /absolute/path/to/observer.so
```

Use freshly verified PIDs, not remembered ones. Before any real invocation, verify the stock library and launcher/shim hashes against the reviewed artifacts. The launcher verifies executable identity against a pinned file descriptor; it does not replace an external cryptographic hash check of the library or shim.

## Preconditions and operation

Before changing a stock process, the launcher:

1. Opens and retains the stock executable, shim, `/dev/null` and console descriptors.
2. Checks both recorded PIDs, start times, executable inode/path, exact two arguments, parent/child relationship, and that precisely those two stock processes are live.
3. Checks the known priority, umask, working directory and standard descriptors. It compares `WORKDIR`, `LD_LIBRARY_PATH`, `PATH`, `LY_PLATFORM`, `LY_MFI_I2C_BUS` and `LY_ENCRYPT_I2C_BUS` against its inherited environment. Other environment values are not compared, retained in a report, printed or written to files. This verifies a subset of the environment, not complete equivalence.
4. Rejects inherited preload, observer or device-bridge settings. Before either child launch, it removes preload, observer, device-bridge, auth-port and synthetic-mode settings. Production builds also remove inherited `AX520_TEST_*` fixture controls. Observation adds only its preload and metadata pipe pair; it leaves a bridge-capable shim disabled. The explicit bridge mode adds its own opt-in and fixed port only to the temporary trial child.
5. Tests priority-setting capability in its own short-lived child and prepares a private metadata status file under `/tmp`.

The detached watchdog calls `setsid()`, disconnects inherited terminal/network descriptors, and keeps the recovery resources open. It ignores hangup, handles termination by shortening observation, and restores the signal dispositions it changed before launching stock children. No `setsid`, `nohup`, `timeout`, `mkfifo` or other helper executable is required.

It stops the original supervisor and waits for an actual stopped state, then rechecks the exact worker before sending any worker signal. The worker gets a bounded `SIGTERM` interval followed by `SIGKILL` only if still matching and alive. While waiting for death, a transient unreadable identity is observed again within the same deadline: exit can remove `exe` after a live `stat` snapshot. Only proven death completes the wait, and uncertain identity never authorizes a signal. The stopped supervisor is then killed so it cannot respawn a competing worker. If the frozen-state checks fail while the original supervisor remains available, the watchdog resumes it and reports that outcome.

The trial runs in its own session, using the pinned observer library and a dedicated inherited nonblocking metadata pipe pair. Its stdout/stderr go to `/dev/null`. Default observation lasts at most 20 seconds; the explicit bridge trial accepts a duration from 1 to 300 seconds. Process stop waits use two-second intervals, and exec/startup checks use five-second intervals. These phase budgets do not guarantee recovery from a stuck kernel, power loss or a killed watchdog.

After observation, the watchdog terminates the owned trial group and requires its direct child to be reaped. It retains that child unreaped until group signals finish to avoid reusing its group ID. Before restoring stock, it verifies the old processes are gone and scans process identity metadata for any remaining exact stock executable, including a descendant that escaped the trial session. An unreadable relevant identity or remaining stock controller blocks restoration; the launcher does not kill an unidentified process or launch a duplicate controller.

A zombie main thread is not considered a dead process while sibling threads remain alive. The same bounded task check is used for original-process waits, trial-group cleanup, child discovery and duplicate-stock detection. Identity checks use a surviving task's executable and arguments when necessary, while signals still target the recorded process ID. The trial group receives a final `SIGKILL` before its leader is reaped, then must have no live tasks. An unavailable or empty task directory with the same leader still present is uncertain and blocks recovery; it is not treated as proof of death.

The normal application is launched once without preload, observer or bridge settings, using the original executable descriptor and inherited environment. A successful result requires a normal supervisor/worker pair with the expected metadata. Failure is reported as unverified, without repeated relaunch attempts. Process startup is not proof of CarPlay authentication, video, audio, touch or reconnection.

## Explicit bounded bridge trial

Only a launcher compiled with `-DAX520_LAUNCHER_ENABLE_BRIDGE` accepts:

```text
observer-trial --device-bridge SECONDS SUPERVISOR_PID WORKER_PID /absolute/path/to/bridge.so
```

`SECONDS` must be decimal digits representing `1..300`; there is no unbounded mode. The original three-argument command remains observation-only even in that build. An inherited `AX520_DEVICE_BRIDGE` is still rejected: the command-line mode supplies `AX520_DEVICE_BRIDGE=1` and `AX520_AUTH_PORT=15000` only while launching the trial. The restored process receives neither setting. The interposer itself binds only `127.0.0.1` and still waits for stock's normal provider selection. The launcher does not force that selection, test a signature, or infer authentication from a metadata event.

Before using this mode, verify the live provider SHA-256 is `19326c5b73c61fd5a604d114ad49035a3730c7d12bfacaef165f7048e8f42e53`, and verify the actual launcher and bridge artifacts against the reviewed build manifest. The separately cross-built bridge artifact reviewed here is `8e0800cb7eacad871813f126510941ebb7d45b69fab84245c3c130e728350d0e`; the default observer is `f4ab562368039395609002f081c43eb433233dd0daa55cfcc6bfcb999e2bfd04`. These checks belong to the deployment preflight, not an automatic hash implementation in this launcher. Its pinned descriptors prevent a path replacement from silently selecting another file, but do not protect against modifying the same inode in place.

The watchdog's `SIGTERM` handler requests early cleanup and one normal restore; it does not terminate the watchdog immediately. A request during process startup completes the bounded exec handshake before process-group cleanup, including when the signal interrupts that wait. Verify the recorded watchdog PID and start time before sending that signal. Do not use `SIGKILL`, which prevents recovery. Wait for a terminal status and verify the restored stock pair before retrying or removing files. Phase-specific stop and startup budgets still apply after an early-stop request.

A host forwarder and host application trial must end before this bridge window expires, with their own finite duration and restoration plan. `mode device_bridge` records the launcher choice; `observer selected` records the ordinary selector call. Neither proves that the listener started, that a phone accepted authentication, or that CarPlay works.

## Results and remaining risks

The initial caller exits after the watchdog is armed and prints its PID and private status-file path. The status contains fixed stage/result messages, optional restored PID, and `observer loaded` / `observer selected` metadata. It contains no environment values, certificate, challenge, signature or authentication key.

Linux 4.9 lacks pidfds. The launcher checks PID/start time/executable/parent immediately before each original-process signal, but a residual PID reuse or concurrent-exec race remains. The expected `-w` startup path uses `fork`; other stock paths can invoke helpers, so complete process-group containment is not assumed. Remaining exact-stock processes prevent duplicate restoration, while unrelated escaped helper processes are not targeted. Recovery is therefore best effort, not guaranteed.

Only volatile files and processes are involved. There are no persistent startup edits, firmware writes or reboots. The original backups remain outside this workflow.

## Synthetic validation

The root test command includes `tests/test_observer_trial.py`:

```sh
python3 scripts/ax520-stock-auth/run_tests.py
```

The fixture is a compiled synthetic supervisor/worker linked only to the synthetic provider. Bridge-mode tests cover rejection by an observer-only build, strict duration validation, trial-only opt-in and fixed port, removed restore settings, and early restoration following `SIGTERM`, both after selection and during a deliberately delayed exec handshake. No real bridge library or authentication requests are used. Tests also cover normal restoration, an early trial exit, failed restoration without retries, an escaped worker blocking duplicates, a worker ignoring `SIGTERM`, hangup after launcher exit, and rejection of mismatched environment, wrong worker, missing shim or bridge opt-in. Additional regressions create a zombie main thread with a paused live sibling in original, trial and escaped workers; they verify cleanup or blocked restoration as appropriate. A separate test makes task enumeration unavailable or empty while that real thread group remains alive and requires an uncertain result. These cases must also be validated on the target kernel before a stock-process trial. The native harness adopts and reaps its synthetic descendants so it does not leave orphan zombies in minimal CI containers; production code does not change subreaper state.

`AX520_LAUNCHER_TEST` requires compile-time `AX520_TEST_STOCK` and `AX520_TEST_CONSOLE` paths, changes nice level to `0`, and shortens observation to 500 ms, stop intervals to 500 ms and startup checks to 1500 ms. This permits a target-runtime synthetic trial in an isolated `/tmp` directory without targeting the actual stock executable. Do not use that build as a production launcher. The source needs the matching ARM/uClibc toolchain and target-runtime checks before stock use.
