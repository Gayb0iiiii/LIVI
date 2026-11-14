> For automatic startup after device/host reboot, use `boot.py` and `livi-ax520-auth.boot.service` as described in [the deployment guide](../README.md). This document describes the underlying current-boot attachment and rollback protocol.

# Current-boot AX520 authentication service

This is an offline candidate for Cruiser UID1000. It attaches to the two explicit
managed device owners already launched during this boot. It does not flash,
install a dongle boot hook, copy stock authentication components, or launch/stop
the stock app. Native helper managed modes still require live verification.

The Pi service has no runtime limit. It starts the pinned ADB34 foreground server
on loopback15037, targets USB `4-1`, verifies the device owners and stock SDK, adds
the loopback15000 forward, then selects only LIVI's `carPlayMfiEndpoint` field.
The existing normal ff575d0 core remains running. Its startup poll includes the
known temporary UI/compositor descendant-verifier failure.

## Files and placement

Copy this directory to `/home/cruiser/LIVI/ax520-current-boot-service`, owned by
Cruiser, with private directory permissions. Preserve the vendor modules exactly;
their hashes are pinned in `service.py`. The native helper manifests remain at:

- `/tmp/ax520-managed-bridge-candidate/MANIFEST.json`
- `/tmp/ax520-managed-usb-candidate/MANIFEST.json`

Use these device-side generated file names when activating:

- `/tmp/livi-ax520-bridge-<12hex>/bridge-trial`
- `/tmp/livi-ax520-bridge-<12hex>/bridge.so`
- `/tmp/ax520-adb-<12hex>/adb-trial`
- `/tmp/ax520-adb-<12hex>/libax520-ep0-audit.so`

Activate bridge first through independent control, verify its normal provider
selection, then activate USB. Capture the exact guard/status launch results.
Do not activate again after an uncertain launch until the existing state has
been inspected. Native helpers preserve their existing ownership checks.

## Capture current-boot receipt

On Cruiser, pass the actual run paths and bridge watchdog PID from the launch:

```
python3 capture_receipt.py --command \
  --usb-dir /tmp/ax520-adb-<actual12hex> \
  --bridge-dir /tmp/livi-ax520-bridge-<actual12hex> \
  --bridge-status /tmp/ax520-observer-trial-<actual6chars>/status \
  --bridge-guard-pid <actualpid>
```

Execute only that generated read-only command through the independent stock
shell. Feed its exact metadata output to the same command with `--parse` replacing
`--command`, adding `--output receipt.json`. Parsing must run on Cruiser because
it records Cruiser's current boot ID. The output is created once, mode0600.
The service checks process identities, executable and stock SDK hashes itself
through direct USB before exposing its provider to LIVI.

## Start for this boot

After the generated helpers are active and the normal ff575d0 GUI is started:

```
mkdir -p /home/cruiser/.config/systemd/user
cp livi-ax520-auth.service /home/cruiser/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user start livi-ax520-auth.service
```

Do not enable this current-boot unit at login. Its receipt is intentionally tied
to one host boot and exact device process instances. Boot persistence requires
a separate verified device bootstrap that supplies fresh identities.

The journal is `state/result.json`. `provider_protocol_verified` means only that
the expected metadata protocol responds. `authentication_verified` becomes true
only after a new allowlisted `wired: MFi auth succeeded` log event is observed.
The session observation records video/reconnection flags, but audible audio
still needs connected speakers and a physical check.

Normal `systemctl --user restart livi-ax520-auth.service` reattaches to the same
dongle processes. Normal stop shuts down only its owned host forward/server;
it leaves the device owners and selected endpoint intact. Device transport loss
causes host-only retry. It never periodically restarts the stock app.

An endpoint changed by someone else is not overwritten. An exclusive
`state/endpoint.intent` records the first write attempt; if that outcome is
unresolved or the endpoint is subsequently cleared, the service exits78 and
systemd does not restart it. Inspect that state before any explicit new attempt.

## Explicit rollback

First restore only LIVI's endpoint field using the existing verified CoreSession
helper, then stop this user service. If an active phone session prevents normal
idle application, an explicit supported applySettings action is needed before
teardown; do not silently assume a persisted field cleared a running helper.

Generate the device-side ordered script with:

```
python3 rollback.py receipt.json > rollback.sh
python3 rollback.py receipt.json --launch-command
```

Stage `rollback.sh` in the receipt's USB run directory using the existing verified
control route. Submit the generated launch command through the existing stock
TCP2323 shell, preferably through the independent Mac control route. If using an
ADB forward to stock2323, establish that control and submit the detached command
before the host ADB server is stopped. **Do not submit through `adb shell`:** its
children remain under the USB helper's subreaper and will be killed during USB
cleanup. The rollback script rejects that ancestry before signaling anything.

The script verifies exact guard PID/start/path/hash, asks the USB guard to restore
first, waits for `result_restored_device_state` plus guard exit, then signals the
bridge guard and waits for its native `result restored`. It writes only fixed
metadata to `<usb_dir>/rollback.status`. A pre-existing rollback status prevents
automatic repetition. Check the outcome through independent access after ADB
disappears. There is no claim yet that stock app restart preserves the ADB gadget.

## Offline verification

Run `python3 -m unittest discover -s . -p 'test_*.py'`. The suite checks receipt
identity constraints, metadata parsing, USB descriptor selection, endpoint
conflicts, startup races, host-only stop, and actual generated rollback shell
ordering/failure paths. Generated shell syntax also passed matching-stock
BusyBox under QEMU. The systemd unit passed `systemd-analyze verify` in system
mode; this build container has no usable user manager for `--user verify`.

Live acceptance still needs managed activation, service restart reattachment,
phone authentication and reconnect. Current-boot operation does not depend on
the future compressed-helper boot package.
