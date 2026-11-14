#!/usr/bin/env python3
"""Generate one-shot ordered rollback; never contacts a device on import.

Submit the generated script through the existing stock TCP2323 shell, forwarded
through ADB if necessary. An adb-shell child remains owned by the USB subreaper
and cannot survive its cleanup, even when double-forked or placed in a session.
Only fixed metadata is recorded. Completion must be read through an independent
route or after access is restored: the ADB transport intentionally disappears.
"""
import argparse
import hashlib
import re
import sys
from pathlib import Path

from service import (BRIDGE_LAUNCHER_SHA, USB_SHA, Failure, load_receipt,
                     validate_receipt)


def generate_script(receipt):
    data = validate_receipt(receipt)
    usb = data['identities']['usb_guard']
    bridge = data['identities']['bridge_guard']
    for identity in (usb, bridge):
        if identity['group'] != identity['pid']:
            raise Failure('rollback_guard_session_invalid')
    # Values below have strict receipt grammar; none can inject shell syntax.
    definitions = [
        '#!/bin/sh', 'set -eu', 'umask 077', "trap '' HUP",
        'USB_DIR='+data['usb_dir'], 'BRIDGE_DIR='+data['bridge_dir'],
        'BRIDGE_STATUS='+data['bridge_status'],
        'USB_PID='+str(usb['pid']), 'USB_START='+str(usb['start']),
        'USB_PARENT='+str(usb['parent']), 'USB_GROUP='+str(usb['group']),
        'BRIDGE_PID='+str(bridge['pid']), 'BRIDGE_START='+str(bridge['start']),
        'BRIDGE_PARENT='+str(bridge['parent']), 'BRIDGE_GROUP='+str(bridge['group']),
        'USB_SHA='+USB_SHA, 'BRIDGE_SHA='+BRIDGE_LAUNCHER_SHA,
    ]
    body = r'''
# Private directories were created by the native owners; reject symlink swaps.
[ -d "$USB_DIR" ] && [ ! -L "$USB_DIR" ] || exit 3
[ -d "$BRIDGE_DIR" ] && [ ! -L "$BRIDGE_DIR" ] || exit 3
[ -d "${BRIDGE_STATUS%/status}" ] && [ ! -L "${BRIDGE_STATUS%/status}" ] || exit 3
# A prior attempt is evidence to inspect, never silently repeat or overwrite it.
(set -C; : > "$USB_DIR/rollback.status") 2>/dev/null || exit 3
note() { printf '%s\n' "$1" >> "$USB_DIR/rollback.status"; }
fail() { note "$1"; exit 1; }
regular() { [ -f "$1" ] && [ ! -L "$1" ]; }
identity() {
  # Guard comm names are fixed and contain no spaces, so stat fields are exact.
  [ "$(cat /proc/$1/comm 2>/dev/null)" = "$5" ] || return 1
  awk -v p="$1" -v s="$2" -v parent="$3" -v group="$4" '
    NF >= 22 && ("x"$1)==("x"p) && ("x"$4)==("x"parent) &&
    ("x"$5)==("x"group) && ("x"$22)==("x"s) && $3 ~ /^[RSDI]$/ {ok=1}
    END {exit !ok}' /proc/$1/stat 2>/dev/null
}
verified_guard() {
  identity "$1" "$2" "$3" "$4" "$5" || return 1
  regular "$6" || return 1
  [ "$(readlink /proc/$1/exe 2>/dev/null)" = "$6" ] || return 1
  [ "$(sha256sum /proc/$1/exe 2>/dev/null | awk '{print $1}')" = "$7" ] || return 1
  [ "$(sha256sum "$6" 2>/dev/null | awk '{print $1}')" = "$7" ] || return 1
  identity "$1" "$2" "$3" "$4" "$5"
}
usb_verified() {
  verified_guard "$USB_PID" "$USB_START" "$USB_PARENT" "$USB_GROUP" adb-trial "$USB_DIR/adb-trial" "$USB_SHA"
}
bridge_verified() {
  verified_guard "$BRIDGE_PID" "$BRIDGE_START" "$BRIDGE_PARENT" "$BRIDGE_GROUP" bridge-trial "$BRIDGE_DIR/bridge-trial" "$BRIDGE_SHA"
}
# Return 0 only when the recorded instance has exited (including zombie or PID
# reuse), 1 while still alive, 2 for unreadable/ambiguous evidence.
gone() {
  [ -d /proc/$1 ] || return 0
  snapshot=$(awk 'NF >= 22 {print $3,$22}' /proc/$1/stat 2>/dev/null) || {
    [ -d /proc/$1 ] || return 0
    return 2
  }
  [ -n "$snapshot" ] || return 2
  set -- "$2" $snapshot
  [ "$3" = "$1" ] || return 0
  case "$2" in Z|X) return 0;; R|S|D|I|T|t) return 1;; *) return 2;; esac
}
# Detaching does not escape a subreaper. Prove this control process has an
# independent ancestry before requesting teardown of the USB or bridge owner.
ancestor=$$
depth=0
while [ "$ancestor" != 1 ]; do
  [ "$depth" -lt 64 ] || fail result_ancestry_unverified
  case "$ancestor" in "$USB_PID"|"$BRIDGE_PID") fail result_owned_ancestry_rejected;; esac
  next=$(awk 'NF >= 22 {print $4}' /proc/$ancestor/stat 2>/dev/null) || fail result_ancestry_unverified
  case "$next" in ''|*[!0-9]*|0) fail result_ancestry_unverified;; esac
  [ "$next" != "$ancestor" ] || fail result_ancestry_unverified
  ancestor=$next
  depth=$((depth + 1))
done
usb_verified || fail result_usb_identity_unverified
bridge_verified || fail result_bridge_identity_unverified
regular "$USB_DIR/guard" || fail result_usb_guard_unverified
[ "$(cat "$USB_DIR/guard")" = "$USB_PID $USB_START 9223372036854775807" ] || fail result_usb_guard_unverified
regular "$USB_DIR/status" || fail result_usb_status_unverified
regular "$BRIDGE_STATUS" || fail result_bridge_status_unverified
grep -qx 'mode managed_usb' "$USB_DIR/status" || fail result_usb_mode_unverified
grep -qx 'mode managed_device_bridge' "$BRIDGE_STATUS" || fail result_bridge_mode_unverified
if grep -qE '^(restoration_started|result_)' "$USB_DIR/status"; then fail result_usb_already_stopping; fi
if grep -qE '^(result |stage trial_stopped)' "$BRIDGE_STATUS"; then fail result_bridge_already_stopping; fi
note verified_both_guards
# Hash/identity check repeated immediately before each signal; only one SIGTERM
# is issued. As with any PID based shell signal, no atomic pidfd is available.
usb_verified || fail result_usb_identity_changed
kill -TERM "$USB_PID" || fail result_usb_signal_failed
note usb_term_sent
count=0
while :; do
  regular "$USB_DIR/status" || fail result_usb_status_lost
  if grep -qx 'result_unverified_no_retry' "$USB_DIR/status"; then fail result_usb_restore_unverified; fi
  dead=0; gone "$USB_PID" "$USB_START" || dead=$?
  [ "$dead" -ne 2 ] || fail result_usb_exit_unverified
  if [ "$dead" = 0 ]; then
    [ "$(tail -n 1 "$USB_DIR/status")" = result_restored_device_state ] || fail result_usb_exited_without_restore
    [ ! -e "$USB_DIR/guard" ] && [ ! -L "$USB_DIR/guard" ] || fail result_usb_guard_not_released
    break
  fi
  [ "$count" -lt 60 ] || fail result_usb_restore_timeout
  count=$((count + 1)); sleep 1
done
note usb_restoration_verified
# USB cleanup must finish before stock restart, which can reconfigure gadget g1.
bridge_verified || fail result_bridge_identity_changed
regular "$BRIDGE_STATUS" || fail result_bridge_status_lost
if grep -q '^result ' "$BRIDGE_STATUS"; then fail result_bridge_already_stopping; fi
kill -TERM "$BRIDGE_PID" || fail result_bridge_signal_failed
note bridge_term_sent
count=0
while :; do
  regular "$BRIDGE_STATUS" || fail result_bridge_status_lost
  if grep -q '^result ' "$BRIDGE_STATUS" && ! grep -qx 'result restored' "$BRIDGE_STATUS"; then fail result_bridge_restore_unverified; fi
  dead=0; gone "$BRIDGE_PID" "$BRIDGE_START" || dead=$?
  [ "$dead" -ne 2 ] || fail result_bridge_exit_unverified
  if [ "$dead" = 0 ]; then
    [ "$(tail -n 1 "$BRIDGE_STATUS")" = 'result restored' ] || fail result_bridge_exited_without_restore
    grep -qE '^restored_pid [1-9][0-9]*$' "$BRIDGE_STATUS" || fail result_bridge_restored_pid_missing
    break
  fi
  [ "$count" -lt 45 ] || fail result_bridge_restore_timeout
  count=$((count + 1)); sleep 1
done
note bridge_restoration_verified
note 'result restored'
'''
    return '\n'.join(definitions) + '\n' + body


def detached_command(receipt, script_sha256):
    data = validate_receipt(receipt)
    if not isinstance(script_sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', script_sha256):
        raise Failure('rollback_script_hash_invalid')
    path = data['usb_dir'] + '/rollback.sh'
    # BusyBox in the saved stock image has no setsid/nohup. Ignoring HUP before
    # fork and redirecting all standard descriptors detaches the raw TCP shell.
    return ("if [ -f {p} ] && [ ! -L {p} ] && "
            "[ \"$(sha256sum {p} | awk '{{print $1}}')\" = {h} ]; then\n"
            "  trap '' HUP\n"
            "  /bin/sh {p} </dev/null >/dev/null 2>&1 &\n"
            "  echo AX520_ROLLBACK_SUBMITTED\n"
            "else echo AX520_ROLLBACK_REJECTED; fi\n").format(p=path, h=script_sha256)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('receipt', type=Path)
    parser.add_argument('--launch-command', action='store_true')
    args = parser.parse_args()
    data = load_receipt(args.receipt)
    script = generate_script(data)
    if args.launch_command:
        print(detached_command(data, hashlib.sha256(script.encode()).hexdigest()), end='')
    else:
        print(script, end='')


if __name__ == '__main__':
    try:
        main()
    except (Failure, OSError, ValueError) as error:
        print('rollback_generation_failed: '+type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
