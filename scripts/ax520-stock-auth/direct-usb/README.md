# AX520 direct USB startup

This is the device-specific implementation deployed on Cruiser, using LIVI ff575d0 and the pinned AX520 stock image. It keeps authentication in the dongle's original stock process. It contains generated source and hashes only; no firmware, credentials or stock SDK binaries.

The pipeline is iPhone USB → LIVI on Cruiser → localhost:15000 → dedicated ADB USB transport → stock process on the AX520. The Mac Wi-Fi tunnel is unnecessary after bootstrap.

## Startup

`lyLink.sh` runs the original customer startup with its normal environment first. `ax520-start.sh` expands four generated gzip files into RAM, checks hashes, starts the managed bridge, then enables the stock ADB daemon. Configuration1 temporarily carries ADB; the original PTP link is saved for restoration. All other gadget configurations remain in place. The launcher publishes process metadata in `/tmp/livi-ax520-managed.boot` after readiness.

The stock firmware's existing `ly_boot_mode=adb` path selects `/mnt/UDISK/app/lyLink.sh`. This changes one boot environment key; it does not flash a firmware partition. The wrapper and compressed generated helpers live in UDISK. The original customer startup, stock application and SDK remain unchanged. Generated payloads occupy about68KB compressed. Stock BusyBox has no tar or gunzip applet, but its `gzip -dc` works.

USB bus numbers are discovered on each host boot; the iPhone is excluded by its descriptors.

The Pi user unit `host/livi-ax520-auth.boot.service` runs `host/boot.py`. It selects configuration1 before starting the pinned ADB34 server, discovers current device process identities, verifies their executable/library hashes, forwards only loopback15000 and selects LIVI's configured endpoint. Device loss retries host attachment. Restarting the host service leaves the stock processes and endpoint running. Cruiser has user lingering enabled, so the unit can start at boot.

The wired helper is verified by its root ownership, installed launch path and ancestry under the running core; a Bluetooth shared socket is not required.

Keep the custom ff575d0 AppImage installed. LIVI’s published Update button can replace it with a build that lacks this integration; the host service deliberately rejects an unverified build. The replaced AppImage and original firmware backups are preserved.

The host package is currently pinned to Cruiser's paths, UID1000, build ff575d0, a unique matching AX520 ADB interface and preserved kiosk unit. The `vendor/` modules are the exact reviewed runtime/protocol helpers used in deployment; the installer entry point in `vendor/verifier.py` is never executed. Do not treat these pins as a generic installer for other machines.

## Current operator commands

On Cruiser:

```sh
systemctl --user status livi-ax520-auth.service
systemctl --user restart livi-ax520-auth.service
cat ~/LIVI/ax520-current-boot-service/state/result.json
```

`provider_protocol_verified` confirms the provider response. Only a fresh phone success event sets `authentication_verified`; metadata readiness does not prove CarPlay. Audio requires connected speakers.

To return the dongle's next boot to normal stock, use its existing root shell to run `fw_setenv ly_boot_mode normal`, verify with `fw_printenv -n ly_boot_mode`, and reboot the dongle. Preserve the original LFWB backups. The generated helpers are not firmware backups. For an ordered current-session teardown, see `host/README.md` and `host/rollback.py`; detach USB before restarting the stock application.

## Source and verification

`usb.c` is the static ARM controller, with finite90s and explicit managed modes. Build it with an ARMv7 hard-float musl compiler and `-std=c11 -O2 -static -Wall -Wextra -Werror`. `audit.c`/`audit.map` is the exact-symbol metadata observer for stock adbd; it records only endpoint operation results, never payload buffers. It and the existing interposer/bridge launcher require the matching uClibc headers and loader ABI described in the parent documentation. Build the launcher with `AX520_LAUNCHER_ENABLE_BRIDGE` and `AX520_LAUNCHER_ENABLE_MANAGED`; default observer and finite bridge modes remain unchanged.

The device verifies exact binary hashes. A rebuild with different toolchain inputs needs updated, reviewed pins; source equivalence alone is insufficient. The live compressed artifacts and deployment receipt are backed up separately on Cruiser.

Live direct USB testing received phone authentication success and observed an active CarPlay video session. Audible audio remains unverified.

Synthetic checks:

```sh
python3 scripts/ax520-stock-auth/run_tests.py
python3 scripts/ax520-stock-auth/direct-usb/test_managed.py
python3 scripts/ax520-stock-auth/direct-usb/test_boot_script.py
python3 -m unittest discover -s scripts/ax520-stock-auth/direct-usb/host -p 'test_*.py'
```

The tests exercise managed lifetime, original finite behavior, exact process ownership, endpoint intent across restarts, configfs restoration, bootstrap ordering and corrupted payload rejection. Live results are recorded in the parent AX520 validation document.
