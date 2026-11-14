#!/usr/bin/env python3
"""Generate a read-only capture command, then validate its returned metadata.

This script itself does not connect to a device. Use the existing independent
stock shell route for --command, then feed only that output to --parse. The
service independently verifies executable/SDK hashes over direct USB on start.
"""
import argparse
import json
import os
from pathlib import Path
import re
import sys
import service


def settings(args):
    if not re.fullmatch(r'/tmp/ax520-adb-[0-9a-f]{12}',args.usb_dir): raise service.Failure('usb_dir_invalid')
    if not re.fullmatch(r'/tmp/livi-ax520-bridge-[0-9a-f]{12}',args.bridge_dir): raise service.Failure('bridge_dir_invalid')
    if not re.fullmatch(r'/tmp/ax520-observer-trial-[A-Za-z0-9]{6}/status',args.bridge_status): raise service.Failure('bridge_status_invalid')
    if not 1 < args.bridge_guard_pid < 2**31: raise service.Failure('bridge_guard_pid_invalid')


def command(args):
    settings(args)
    return '\n'.join([
        'set -eu',
        'read usb_pid usb_start expiry < '+args.usb_dir+'/guard',
        '[ "$expiry" = 9223372036854775807 ]',
        "adb_pid=$(awk '$1==\"owned_adbd_pid\" {n++;p=$2} END{if(n!=1)exit 1; print p}' "+args.usb_dir+'/status)',
        "adb_start=$(awk '$1==\"owned_adbd_start\" {n++;p=$2} END{if(n!=1)exit 1; print p}' "+args.usb_dir+'/status)',
        "printf 'USB_FILE %s %s\\n' \"$usb_pid\" \"$usb_start\"",
        "printf 'ADB_FILE %s %s\\n' \"$adb_pid\" \"$adb_start\"",
        "awk '{print \"ID usb_guard\",$1,$4,$5,$22}' /proc/$usb_pid/stat",
        "awk '{print \"ID adbd\",$1,$4,$5,$22}' /proc/$adb_pid/stat",
        "awk '{print \"ID bridge_guard\",$1,$4,$5,$22}' /proc/%d/stat" % args.bridge_guard_pid,
        "for p in $(pidof lylinkapp); do awk '{print \"APP\",$1,$4,$5,$22}' /proc/$p/stat; done",
        "printf 'CAPTURE_DONE\\n'",
    ])


def parse(args, raw, host_boot_id):
    settings(args)
    lines = raw.replace('\r\n','\n').splitlines()
    if len(lines) != 8 or lines[-1] != 'CAPTURE_DONE': raise service.Failure('capture_incomplete')
    files = {}
    ids = {}
    apps = []
    for line in lines[:-1]:
        file_match = re.fullmatch(r'(USB_FILE|ADB_FILE) ([1-9][0-9]*) ([1-9][0-9]*)',line)
        id_match = re.fullmatch(r'ID (usb_guard|adbd|bridge_guard) ([1-9][0-9]*) ([1-9][0-9]*) ([1-9][0-9]*) ([1-9][0-9]*)',line)
        app_match = re.fullmatch(r'APP ([1-9][0-9]*) ([1-9][0-9]*) ([1-9][0-9]*) ([1-9][0-9]*)',line)
        if file_match:
            role,pid,start = file_match.groups()
            if role in files: raise service.Failure('duplicate_capture_row')
            files[role] = (int(pid),int(start))
        elif id_match:
            role,*values = id_match.groups()
            if role in ids: raise service.Failure('duplicate_capture_row')
            ids[role] = dict(zip(('pid','parent','group','start'),map(int,values)))
        elif app_match:
            apps.append(dict(zip(('pid','parent','group','start'),map(int,app_match.groups()))))
        else: raise service.Failure('capture_metadata_invalid')
    if set(ids) != {'usb_guard','adbd','bridge_guard'} or set(files) != {'USB_FILE','ADB_FILE'}:
        raise service.Failure('capture_roles_missing')
    for file_role,role in (('USB_FILE','usb_guard'),('ADB_FILE','adbd')):
        if files[file_role] != (ids[role]['pid'],ids[role]['start']): raise service.Failure('capture_identity_changed')
    if ids['bridge_guard']['pid'] != args.bridge_guard_pid: raise service.Failure('capture_guard_changed')
    supervisors = [row for row in apps if row['parent'] == args.bridge_guard_pid]
    if len(supervisors) != 1: raise service.Failure('capture_stock_supervisor_invalid')
    supervisor = supervisors[0]
    workers = [row for row in apps if row['parent'] == supervisor['pid']]
    if len(apps) != 2 or len(workers) != 1: raise service.Failure('capture_stock_worker_invalid')
    ids.update(supervisor=supervisor,worker=workers[0])
    return service.validate_receipt(dict(version=1,host_boot_id=host_boot_id,
        usb_dir=args.usb_dir,bridge_dir=args.bridge_dir,bridge_status=args.bridge_status,identities=ids))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--command',action='store_true')
    group.add_argument('--parse',action='store_true')
    parser.add_argument('--usb-dir',required=True)
    parser.add_argument('--bridge-dir',required=True)
    parser.add_argument('--bridge-status',required=True)
    parser.add_argument('--bridge-guard-pid',type=int,required=True)
    parser.add_argument('--output',type=Path)
    args = parser.parse_args()
    if args.command:
        print(command(args))
    else:
        if args.output is None: parser.error('--parse requires --output')
        raw = sys.stdin.read(8193)
        if len(raw) > 8192: raise service.Failure('capture_reply_too_large')
        result = parse(args,raw,Path('/proc/sys/kernel/random/boot_id').read_text().strip())
        os.umask(0o077)
        with args.output.open('x') as out:
            json.dump(result,out,indent=2)
            out.write('\n')
            out.flush()
            os.fsync(out.fileno())


if __name__ == '__main__': main()
