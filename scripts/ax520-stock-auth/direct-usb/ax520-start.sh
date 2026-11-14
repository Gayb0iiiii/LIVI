#!/bin/sh
# Generated helpers only. Firmware, SDK and identity material stay in place.
set -eu
umask 077
mkdir /tmp/livi-ax520-bootstrap.lock || exit 0
note() { printf '%s\n' "$1"; }
fail() { note "$1"; exit 1; }
digest() { sha256sum "$1" | awk '{print $1}'; }
check() { [ "$(digest "$1")" = "$2" ] || fail payload_or_stock_hash_changed; }
check /mnt/customer/app/lyLink.sh 72ce88bd523bc8c0262728bf9655d674e95330237bdd0741911b70b0e89c7b00
check /mnt/customer/app/libiap_new.so 19326c5b73c61fd5a604d114ad49035a3730c7d12bfacaef165f7048e8f42e53
check /mnt/customer/app/lylinkapp 55afbb890397b41d3393f1a98a82a5d425fb5fb78b97431f8dad48990ce509f2
check /lib/libc.so.0 41954a9a9fd14d262eada61caf8de98749385e2dde1ed1fac488437a45efb69a
check /lib/ld-uClibc.so.0 39d3f7d7b34448c8c7026b6b3fe46218366700fc0c768c285796d6fcb2acd8b6
run=$(sha256sum /proc/sys/kernel/random/boot_id | cut -c1-12)
case "$run" in *[!0-9a-f]*|'') fail boot_identity_invalid;; esac
[ "${#run}" = 12 ] || fail boot_identity_invalid
bridge=/tmp/livi-ax520-bridge-$run
usb=/tmp/ax520-adb-$run
mkdir "$bridge" "$usb"
unpack() {
    gzip -dc /mnt/UDISK/app/payload/"$1".gz > "$2"
    check "$2" "$3"
}
unpack bridge-trial "$bridge/bridge-trial" d153b306c18ee6a6cbd1e0047e6589d578062582b5cbe5c26514e19a720a339b
unpack bridge.so "$bridge/bridge.so" 8e0800cb7eacad871813f126510941ebb7d45b69fab84245c3c130e728350d0e
unpack adb-trial "$usb/adb-trial" 4c12528ad37c22be664f3330aaf56f5bba394162661859bed4d40811b3772768
unpack libax520-ep0-audit.so "$usb/libax520-ep0-audit.so" b6366dba53601046a50e311be820e62d9856e5519c9cf81607b41c447761bfc7
chmod 700 "$bridge/bridge-trial" "$usb/adb-trial"
chmod 600 "$bridge/bridge.so" "$usb/libax520-ep0-audit.so"
note helpers_verified
supervisor=
worker=
tries=0
while [ "$tries" -lt 60 ]; do
    pids=$(pidof lylinkapp || true)
    set -- $pids
    if [ "$#" = 2 ]; then
        for p in $pids; do
            parent=$(awk '{print $4}' /proc/"$p"/stat 2>/dev/null || true)
            if [ "$parent" = 1 ]; then supervisor=$p; fi
        done
        if [ -n "$supervisor" ]; then
            for p in $pids; do
                parent=$(awk '{print $4}' /proc/"$p"/stat 2>/dev/null || true)
                if [ "$parent" = "$supervisor" ]; then worker=$p; fi
            done
        fi
    fi
    if [ -n "$supervisor" ] && [ -n "$worker" ]; then break; fi
    supervisor=; worker=; tries=$((tries + 1)); sleep 1
done
[ -n "$supervisor" ] && [ -n "$worker" ] || fail stock_startup_not_ready
output=$("$bridge/bridge-trial" --managed-device-bridge "$supervisor" "$worker" "$bridge/bridge.so") || fail bridge_launch_unverified
set -- $output
[ "$#" = 2 ] || fail bridge_ack_invalid
guard=${1#watchdog=}
status=${2#status=}
case "$guard" in *[!0-9]*|'') fail bridge_guard_invalid;; esac
case "$status" in /tmp/ax520-observer-trial-??????/status) ;; *) fail bridge_status_invalid;; esac
tries=0
while [ "$tries" -lt 30 ]; do
    if grep -qx 'observer selected' "$status" && grep -qx 'observer loaded' "$status"; then break; fi
    if grep -q '^result ' "$status"; then fail bridge_exited; fi
    tries=$((tries + 1));sleep 1
done
grep -qx 'observer selected' "$status" || fail bridge_not_ready
note bridge_ready
"$usb/adb-trial" --managed "$usb" || fail usb_launch_unverified
tries=0
while [ "$tries" -lt 30 ]; do
    if grep -qx adb_usb_ready "$usb/status"; then break; fi
    if grep -q '^restoration_started$' "$usb/status"; then fail usb_restored; fi
    tries=$((tries + 1));sleep 1
done
grep -qx adb_usb_ready "$usb/status" || fail usb_not_ready
printf 'AX520_BOOT_V1\n%s\n%s\n%s\n%s\n' "$usb" "$bridge" "$status" "$guard" > /tmp/livi-ax520-managed.boot.next
mv /tmp/livi-ax520-managed.boot.next /tmp/livi-ax520-managed.boot
note ready
