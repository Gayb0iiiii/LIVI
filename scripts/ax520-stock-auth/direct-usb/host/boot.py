#!/usr/bin/env python3
"""Attach through direct USB after a dongle/host reboot; never start stock code."""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import time
import types
import fcntl

import service as s
import capture_receipt as c

RECORD = '/tmp/livi-ax520-managed.boot'

def parse_record(raw):
    text = raw.replace(b'\r\n', b'\n').decode('ascii')
    match = re.fullmatch(r'AX520_BOOT_V1\n(/tmp/ax520-adb-[0-9a-f]{12})\n'
                        r'(/tmp/livi-ax520-bridge-[0-9a-f]{12})\n'
                        r'(/tmp/ax520-observer-trial-[A-Za-z0-9]{6}/status)\n'
                        r'([1-9][0-9]{0,9})\n', text)
    if not match: raise s.Failure('boot_record_invalid')
    usb, bridge, status, pid = match.groups()
    result = types.SimpleNamespace(usb_dir=usb,bridge_dir=bridge,
                                   bridge_status=status,bridge_guard_pid=int(pid))
    c.settings(result)
    return result

def write_receipt(root, receipt):
    destination = root/'receipt.json'
    old = json.loads(destination.read_text()) if destination.exists() else None
    if old == receipt: return
    if old is not None:
        s.validate_receipt(old)
        history = root/'history';history.mkdir(mode=0o700,exist_ok=True)
        prior = history/(str(time.time_ns())+'-receipt.json')
        prior.write_text(json.dumps(old,indent=2)+'\n');prior.chmod(0o600)
    temporary = root/'receipt.next'
    with temporary.open('w') as out:
        json.dump(receipt,out,indent=2);out.write('\n');out.flush();os.fsync(out.fileno())
    temporary.chmod(0o600);temporary.replace(destination)
    intent = root/'state/endpoint.intent'
    if intent.exists() and old is not None and old['host_boot_id'] != receipt['host_boot_id']:
        # Preserve the prior write intent. ensure_endpoint still refuses a
        # cleared/different endpoint; only its host-boot identity is refreshed.
        if intent.read_text() != old['host_boot_id']+'\n':
            raise s.Conflict('endpoint_intent_not_owned')
        intent.write_text(receipt['host_boot_id']+'\n')

def discover(runtime):
    runtime.start()
    with runtime.o.SmartADB(time.monotonic()+6) as client:
        args = parse_record(client.shell(runtime.transport,'cat '+RECORD))
    with runtime.o.SmartADB(time.monotonic()+10) as client:
        raw = client.shell(runtime.transport,c.command(args)).decode('ascii')
    runtime.receipt = c.parse(args,raw,Path('/proc/sys/kernel/random/boot_id').read_text().strip())
    runtime.verify_device()
    return runtime.receipt

def refresh_idle_helper(runtime):
    # A GUI started before USB readiness can have installed NoCoprocessor.
    # Re-apply the existing endpoint once after readiness, only while idle.
    if not runtime.report.get('reattached_existing_endpoint'): return
    deadline=time.monotonic()+25
    view=runtime.await_core(deadline)
    if view['sessions_total']: return
    current=runtime.host.helper(deadline)
    path=runtime.journal.parent/'helper-refresh.json'
    prior=json.loads(path.read_text()) if path.exists() else None
    core=runtime.report['current_core']
    if prior and prior.get('boot')==runtime.receipt['host_boot_id'] and prior['core']==core:
        if prior['state']=='pending':raise s.Conflict('helper_refresh_outcome_unresolved')
        if prior['helper']==current:return
    before=runtime.logs.read().get('endpoint_selected',0)
    with runtime.host.factory(deadline) as client:
        fresh=client.snapshot()
        if fresh['endpoint']!=s.ENDPOINT:raise s.Conflict('endpoint_changed_before_refresh')
        if fresh['sessions_total']:return
        path.write_text(json.dumps({'state':'pending','boot':runtime.receipt['host_boot_id'],'core':core,'helper':current})+'\n')
        client.action('applySettings')
    while not s.STOP and time.monotonic()<deadline:
        counts=runtime.logs.read()
        try:
            helper=runtime.host.helper(deadline)
            if helper!=current and counts.get('endpoint_selected',0)>before:
                path.write_text(json.dumps({'state':'verified','boot':runtime.receipt['host_boot_id'],'core':core,'helper':helper})+'\n')
                runtime.report['helper_provider_refreshed']=True
                runtime.save('running')
                return
        except (OSError,runtime.e.Failure,runtime.v.Failure):pass
        time.sleep(.2)
    raise s.Conflict('helper_refresh_outcome_unresolved')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-dir',type=Path,default=s.ROOT/'state')
    args=parser.parse_args()
    if os.getuid()!=1000 or os.geteuid()!=1000: raise s.Failure('requires_cruiser_uid')
    os.umask(0o077);args.state_dir.mkdir(mode=0o700,exist_ok=True)
    lock=(args.state_dir/'service.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    runtime=s.Runtime(None,args.state_dir/'result.json')
    for signum in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(signum,s.stop_request)
    code=0
    try:
        receipt=discover(runtime)
        write_receipt(s.ROOT,receipt)
        runtime.start_forward();runtime.ensure_endpoint();refresh_idle_helper(runtime)
        while not s.STOP:
            runtime.check();time.sleep(5)
    except Exception as error:
        runtime.report['error_type']=type(error).__name__
        if isinstance(error,(s.Failure,runtime.o.Failure,runtime.e.Failure,runtime.v.Failure)):
            runtime.report['error']=str(error)
        code=78 if isinstance(error,s.Conflict) else 1
    finally:
        runtime.close()
        if code:runtime.save('failed_host_cleaned_device_preserved')
    return code

if __name__=='__main__':raise SystemExit(main())
