#!/usr/bin/env python3
"""Current-boot AX520 host service; no live actions on import.

Attaches to previously activated, exact managed device owners. It never starts
or stops the stock application. Normal host stop leaves the device owners and
the selected LIVI endpoint intact for restart. Explicit rollback is separate.
"""
import argparse
import array
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import time

ROOT = Path(__file__).resolve().parent
ENDPOINT = '127.0.0.1:15000'
STOP = False
PINS = {
    'adb_observer': 'ddadaac2a6b21f0053e467ac3e76cf67351e2cc90711c5dce1a5b263610f2ffb',
    'endpoint': 'a2c8d72831f685f3118911518f34cc826c788bd0b9b0ef3cef26bb804269451e',
    'verifier': '6b811f7439c4c4b8cf53fb579c305f0415882a99f8ba5dcd94b6eb2898a2af3a',
}
USB_SHA = '4c12528ad37c22be664f3330aaf56f5bba394162661859bed4d40811b3772768'
BRIDGE_LAUNCHER_SHA = 'd153b306c18ee6a6cbd1e0047e6589d578062582b5cbe5c26514e19a720a339b'
BRIDGE_SHA = '8e0800cb7eacad871813f126510941ebb7d45b69fab84245c3c130e728350d0e'
ADBD_SHA = 'faddf86eafdb0d103d4570a1244a77e79f8e50c32104a3578012b2aeb1cecafc'
STOCK_HASHES = {
    '/mnt/customer/app/libiap_new.so': '19326c5b73c61fd5a604d114ad49035a3730c7d12bfacaef165f7048e8f42e53',
    '/mnt/customer/app/lylinkapp': '55afbb890397b41d3393f1a98a82a5d425fb5fb78b97431f8dad48990ce509f2',
    '/lib/libc.so.0': '41954a9a9fd14d262eada61caf8de98749385e2dde1ed1fac488437a45efb69a',
    '/lib/ld-uClibc.so.0': '39d3f7d7b34448c8c7026b6b3fe46218366700fc0c768c285796d6fcb2acd8b6',
}


class Failure(RuntimeError):
    """Only fixed metadata labels are written to the journal."""


class Conflict(Failure):
    """An external change must not be retried by systemd."""


def validate_receipt(data):
    fields = {'version','host_boot_id','usb_dir','bridge_dir','bridge_status','identities'}
    if not isinstance(data, dict) or set(data) != fields or type(data['version']) is not int or data['version'] != 1:
        raise Failure('receipt_schema_invalid')
    patterns = {
        'host_boot_id': r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',
        'usb_dir': r'/tmp/ax520-adb-[0-9a-f]{12}',
        'bridge_dir': r'/tmp/livi-ax520-bridge-[0-9a-f]{12}',
        'bridge_status': r'/tmp/ax520-observer-trial-[A-Za-z0-9]{6}/status',
    }
    for key, pattern in patterns.items():
        if not isinstance(data[key], str) or not re.fullmatch(pattern, data[key]):
            raise Failure('receipt_path_or_boot_invalid')
    ids = data['identities']
    if not isinstance(ids, dict) or set(ids) != {'usb_guard','adbd','bridge_guard','supervisor','worker'}:
        raise Failure('receipt_roles_invalid')
    for row in ids.values():
        if (not isinstance(row, dict) or set(row) != {'pid','parent','group','start'} or
                any(type(value) is not int or value < 1 or value > 2**63-1 for value in row.values()) or
                row['pid'] <= 1 or row['group'] <= 1 or row['pid'] > 2**31-1):
            raise Failure('receipt_identity_invalid')
    if len({row['pid'] for row in ids.values()}) != len(ids):
        raise Failure('receipt_duplicate_process')
    guard, supervisor, worker = (ids[x] for x in ('bridge_guard','supervisor','worker'))
    if (supervisor['parent'] != guard['pid'] or worker['parent'] != supervisor['pid'] or
            supervisor['group'] != supervisor['pid'] or worker['group'] != supervisor['pid']):
        raise Failure('receipt_bridge_relationship_invalid')
    return data


def load_receipt(path):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
            stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > 8192):
        raise Failure('receipt_file_invalid')
    data = validate_receipt(json.loads(path.read_text()))
    if data['host_boot_id'] != Path('/proc/sys/kernel/random/boot_id').read_text().strip():
        raise Failure('receipt_is_from_another_host_boot')
    return data


def device_check_command(receipt, full=True):
    data = validate_receipt(receipt)
    ids = data['identities']
    executables = {
        'usb_guard': (data['usb_dir']+'/adb-trial', USB_SHA),
        'adbd': ('/bin/adbd', ADBD_SHA),
        'bridge_guard': (data['bridge_dir']+'/bridge-trial', BRIDGE_LAUNCHER_SHA),
        'supervisor': ('/mnt/customer/app/lylinkapp', STOCK_HASHES['/mnt/customer/app/lylinkapp']),
        'worker': ('/mnt/customer/app/lylinkapp', STOCK_HASHES['/mnt/customer/app/lylinkapp']),
    }
    lines = [
        'set -eu',
        'fail() { echo AX520_MANAGED_REJECTED; exit 1; }',
        'check_process() {',
        '  current=$(awk \'{print $3,$4,$5,$22}\' /proc/$1/stat) || fail',
        '  case "$current" in "R $3 $4 $2"|"S $3 $4 $2"|"D $3 $4 $2") ;; *) fail;; esac',
        '  [ "$(readlink /proc/$1/exe)" = "$5" ] || fail',
        '}',
    ]
    checks = []
    for role, row in ids.items():
        checks.append('check_process {pid} {start} {parent} {group} {exe}'.format(**row, exe=executables[role][0]))
    lines.extend(checks)
    if full:
        for role, row in ids.items():
            digest = executables[role][1]
            lines.append('[ "$(sha256sum /proc/%d/exe | awk \'{print $1}\')" = %s ] || fail' % (row['pid'], digest))
        hashes = dict(STOCK_HASHES)
        hashes[data['bridge_dir']+'/bridge.so'] = BRIDGE_SHA
        for path, digest in hashes.items():
            lines.append('[ "$(sha256sum %s | awk \'{print $1}\')" = %s ] || fail' % (path, digest))
    lines.extend([
        '[ -f {d}/status ] && [ ! -L {d}/status ] || fail'.format(d=data['usb_dir']),
        "grep -qx 'mode managed_usb' {d}/status || fail".format(d=data['usb_dir']),
        "grep -qx 'adb_usb_ready' {d}/status || fail".format(d=data['usb_dir']),
        "if grep -q '^restoration_started$' {d}/status; then fail; fi".format(d=data['usb_dir']),
        '[ -f {p} ] && [ ! -L {p} ] || fail'.format(p=data['bridge_status']),
        "grep -qx 'mode managed_device_bridge' {p} || fail".format(p=data['bridge_status']),
        "grep -qx 'observer selected' {p} || fail".format(p=data['bridge_status']),
        "if grep -qE '^(result |stage trial_stopped|managed supervisor_)' {p}; then fail; fi".format(p=data['bridge_status']),
        '[ "$(cat /sys/kernel/config/usb_gadget/g1/UDC)" = b500000.usb ] || fail',
        '[ -e /sys/kernel/config/usb_gadget/g1/configs/b.1/ffs.adb ] || fail',
        "awk 'index($0,\"{p}\") {{found=1}} END {{exit !found}}' /proc/{pid}/maps || fail".format(p=data['bridge_dir']+'/bridge.so', pid=ids['worker']['pid']),
        "inode=$(awk 'NR>1{split($2,a,\":\"); if(a[2]==\"3A98\" && $4==\"0A\"){n++; if($2==\"0100007F:3A98\")v=$10}} END{if(n!=1 || !v)exit 1; print v}' /proc/net/tcp) || fail",
        "awk 'NR>1{split($2,a,\":\"); if(a[2]==\"3A98\" && $4==\"0A\")bad=1} END{exit bad}' /proc/net/tcp6 || fail",
        'found=0; for f in /proc/{pid}/fd/*; do if [ "$(readlink "$f" 2>/dev/null)" = "socket:[$inode]" ]; then found=1; fi; done'.format(pid=ids['worker']['pid']),
        '[ "$found" = 1 ] || fail',
    ])
    lines.extend(checks)
    lines.append('echo AX520_MANAGED_VERIFIED')
    return '\n'.join(lines)


def verify_device_response(payload):
    if payload.replace(b'\r\n', b'\n') != b'AX520_MANAGED_VERIFIED\n':
        raise Failure('device_owner_or_sdk_verification_failed')


def config1_adb_descriptor(raw):
    offset = 0
    config = None
    found = 0
    while offset < len(raw):
        if offset+2 > len(raw): return False
        size, kind = raw[offset:offset+2]
        if size < 2 or offset+size > len(raw): return False
        descriptor = raw[offset:offset+size]
        if kind == 2:
            if size < 9: return False
            config = descriptor[5]
        if kind == 4:
            if size < 9: return False
            if config == 1 and descriptor[5:8] == b'\xff\x42\x01': found += 1
        offset += size
    return found == 1

def find_usb_target(root=Path('/sys/bus/usb/devices')):
    candidates=[]
    for path in root.iterdir():
        if not re.fullmatch(r'[0-9]+-[0-9]+(?:\.[0-9]+)*',path.name):continue
        try:
            values=tuple((path/key).read_text().strip().lower() for key in
                         ('idVendor','idProduct','bcdDevice','bNumConfigurations'))
            if values==('05ac','12a8','0901','4') and config1_adb_descriptor((path/'descriptors').read_bytes()):
                candidates.append(path.name)
        except FileNotFoundError:continue
    if len(candidates)!=1:raise Failure('managed_usb_target_absent_or_ambiguous')
    return candidates[0]

def target_identity(target,root=Path('/sys/bus/usb/devices'),require_adb=True):
    device=root/target
    if ((device/'idVendor').read_text().strip(),(device/'idProduct').read_text().strip())!=('05ac','12a8'):
        raise Failure('usb_identity_changed')
    interfaces=[]
    for path in root.glob(target+':*'):
        values=tuple((path/key).read_text().strip().lower() for key in
                     ('bInterfaceClass','bInterfaceSubClass','bInterfaceProtocol'))
        if values==('ff','42','01'):interfaces.append(path.name)
    if require_adb and len(interfaces)!=1:raise Failure('adb_interface_not_unique')
    bus=int((device/'busnum').read_text());number=int((device/'devnum').read_text())
    if bus!=int(target.split('-')[0]) or not 1<=number<=127:raise Failure('usb_node_invalid')
    return {'bus':bus,'device':number,'inode':device.stat().st_ino,'interface':interfaces[0] if len(interfaces)==1 else None}


def select_endpoint(current, submit):
    if current == ENDPOINT: return False
    if current != '': raise Conflict('endpoint_changed_outside_service')
    submit()
    return True


def load_module(name):
    path = ROOT/'vendor'/f'{name}.py'
    if not stat.S_ISREG(path.lstat().st_mode) or hashlib.sha256(path.read_bytes()).hexdigest() != PINS[name]:
        raise Failure('reviewed_dependency_hash_mismatch')
    spec = importlib.util.spec_from_file_location('managed_'+name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Runtime:
    def __init__(self, receipt, journal):
        self.receipt = receipt
        self.journal = journal
        self.report = {'stage':'starting','authentication_verified':False,'audible_audio_verified':False}
        self.o = load_module('adb_observer')
        self.e = load_module('endpoint')
        self.v = load_module('verifier')
        self.host = self.e.Host(self.v, self.report, self.save)
        self.host.helper = self.helper_identity
        self.server = None
        self.group = None
        self.leader = None
        self.transport = None
        self.identity = None
        self.forward = False
        self.logs = None
        self.tracker = self.e.SessionTransitions()
        self.endpoint_intent = journal.parent/'endpoint.intent'

    def helper_identity(self, deadline):
        # The shared Bluetooth socket is absent on a wired-only installation.
        # Verify the helper itself through UID, launch path and core ancestry.
        core=self.host.core(deadline)
        matches=[]
        for path in Path('/proc').glob('[0-9]*'):
            try:
                if path.stat().st_uid!=0 or (path/'comm').read_text().strip()!='livi-helperd':continue
                pid=int(path.name);identity=self.v.identity(pid)
                if self.v.first_argument(pid)!=str(self.v.HELPER):continue
                ancestor=pid
                for _ in range(32):
                    if ancestor==core['pid']:break
                    if ancestor<=1:break
                    ancestor=self.v.proc_stat(ancestor)['ppid']
                if ancestor==core['pid'] and self.v.identity(pid)==identity:matches.append(identity)
            except (FileNotFoundError,ProcessLookupError):continue
        if len(matches)!=1:raise Failure('root_helper_not_unique_under_core')
        self.v.checked(self.v.HELPER,self.v.NEW_HELPER)
        return matches[0]

    def save(self, stage):
        self.report['stage'] = stage
        temporary = self.journal.with_suffix('.tmp')
        with temporary.open('w') as out:
            json.dump(self.report, out, indent=2)
            out.write('\n')
            out.flush()
            os.fsync(out.fileno())
        temporary.replace(self.journal)

    def select_usb(self):
        device = Path('/sys/bus/usb/devices')/self.target
        expected = {'idVendor':'05ac','idProduct':'12a8','bNumConfigurations':'4','bcdDevice':'0901'}
        if any((device/name).read_text().strip().lower() != value for name,value in expected.items()):
            raise Failure('usb_device_descriptor_changed')
        raw = (device/'descriptors').read_bytes()
        if not config1_adb_descriptor(raw):
            raise Failure('managed_adb_descriptor_absent')
        before = self.o.usb_identity(require_adb=False)
        node = Path('/dev/bus/usb')/f"{before['bus']:03d}"/f"{before['device']:03d}"
        if (device/'bConfigurationValue').read_text().strip() != '1':
            fd = os.open(node, os.O_RDWR|os.O_CLOEXEC|os.O_NOFOLLOW)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISCHR(info.st_mode) or os.major(info.st_rdev) != 189 or
                        os.minor(info.st_rdev) != (before['bus']-1)*128+before['device']-1 or
                        self.o.usb_identity(require_adb=False) != before or
                        (device/'descriptors').read_bytes() != raw):
                    raise Failure('usb_node_identity_changed')
                fcntl.ioctl(fd, 0x80045505, array.array('I',[1]))
            finally:
                os.close(fd)
        until = time.monotonic()+5
        while time.monotonic() < until:
            try:
                after = self.o.usb_identity()
                if (all(after[k] == before[k] for k in ('bus','device','inode')) and
                        (device/'bConfigurationValue').read_text().strip() == '1'):
                    return after
            except (OSError,self.o.Failure): pass
            time.sleep(.1)
        raise Failure('configuration1_adb_unverified')

    def start(self):
        self.host.pins()
        self.target=find_usb_target()
        self.report['usb_path']=self.target
        # USB controller numbers can change across Pi boots. Keep one verified
        # target per server instance; all later ownership checks use that path.
        self.o.usb_identity=lambda root=Path('/sys/bus/usb/devices'),require_adb=True: target_identity(self.target,root,require_adb)
        select_original=self.o.select_transport
        def select_transport(payload):
            rows=[]
            for line in payload.decode('ascii').splitlines():
                fields=line.split()
                if not any(x in (self.target,'usb:'+self.target) for x in fields[2:]):continue
                fields=[('4-1' if x==self.target else 'usb:4-1' if x=='usb:'+self.target else x) for x in fields]
                rows.append(' '.join(fields))
            return select_original(('\n'.join(rows)+'\n').encode('ascii'))
        self.o.select_transport=select_transport
        self.identity = self.select_usb()
        for path,digest in ((self.o.WRAPPER,self.o.WRAPPER_SHA),(self.o.BINARY,self.o.BINARY_SHA)):
            if not stat.S_ISREG(path.lstat().st_mode) or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise Failure('adb_sdk_hash_mismatch')
        if not self.o.listeners_absent((15037,15000)):
            raise Failure('host_port_already_owned')
        env = os.environ.copy()
        for key in ('ADB_VENDOR_KEYS','ADB_SERVER_SOCKET','ANDROID_SERIAL','ADB_AUTH','ADB_TRACE',
                    'ADB_SERVER_PORT','ANDROID_ADB_SERVER_PORT','ANDROID_ADB_SERVER_ADDRESS'):
            env.pop(key,None)
        env.update(ADB_LIBUSB='1',ADB_MDNS='0',ADB_EMU='0')
        self.server = subprocess.Popen([str(self.o.WRAPPER),'-L','tcp:localhost:15037',
            '--one-device','usb:'+self.target,'server','nodaemon'], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=env,start_new_session=True)
        self.group = self.server.pid
        self.leader = self.o.proc(self.group)
        if self.leader['group'] != self.group or self.leader['session'] != self.group or self.leader['uid'] != os.getuid():
            raise Failure('server_ownership_unverified')
        self.report['server_leader'] = self.leader
        self.save('waiting_for_direct_usb')
        until = time.monotonic()+20
        while not STOP and time.monotonic() < until:
            if self.server.poll() is not None: raise Failure('owned_server_exited')
            try:
                self.o.listener_owner(15037,self.group)
                if self.o.usb_identity() != self.identity: raise Failure('usb_identity_changed')
                with self.o.SmartADB(time.monotonic()+3) as client:
                    self.transport = self.o.select_transport(client.query('host:devices-l'))
                return
            except (OSError,self.o.Failure): time.sleep(.2)
        raise Failure('direct_usb_not_ready')

    def verify_device(self, full=True):
        self.o.verify_target(self.group,self.identity,self.transport,time.monotonic()+4)
        with self.o.SmartADB(time.monotonic()+15) as client:
            payload = client.shell(self.transport,device_check_command(self.receipt,full=full))
        verify_device_response(payload)
        self.o.verify_target(self.group,self.identity,self.transport,time.monotonic()+4)
        if full:
            self.report['device_identities_and_hashes_verified'] = True
            self.save('device_verified')

    def start_forward(self):
        self.forward = True
        with self.o.SmartADB(time.monotonic()+4) as client: client.forward(self.transport)
        self.o.listener_owner(15000,self.group)
        self.o.forward_marker(time.monotonic()+5)
        self.report['provider_protocol_verified'] = True
        self.save('provider_ready')

    def ensure_endpoint(self):
        deadline = time.monotonic()+50
        view = self.await_core(min(deadline,time.monotonic()+30))
        self.logs = self.e.LogCursor()
        prior_intent = self.endpoint_intent.exists()
        if prior_intent:
            info = self.endpoint_intent.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                    stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or
                    self.endpoint_intent.read_text() != self.receipt['host_boot_id']+'\n'):
                raise Conflict('endpoint_intent_invalid')
            if view['endpoint'] != ENDPOINT:
                raise Conflict('previous_endpoint_selection_changed_or_unresolved')
        def record_intent():
            with self.endpoint_intent.open('x') as out:
                out.write(self.receipt['host_boot_id']+'\n')
                out.flush()
                os.fsync(out.fileno())
        if not prior_intent and view['endpoint'] == ENDPOINT:
            record_intent()
        initial_helper = self.host.helper(deadline) if view['endpoint'] == '' else None
        def submit():
            if view['sessions_total'] != 0:
                raise Failure('initial_endpoint_change_requires_idle_core')
            record_intent()
            self.report['endpoint_patch_attempted'] = True
            self.save('selecting_endpoint')
            result = self.e.patch_endpoint_once(self.host.factory,'',ENDPOINT,deadline)
            self.report['endpoint_patch'] = {key:result[key] for key in ('verified','submitted','acknowledged')}
        changed = select_endpoint(view['endpoint'], submit)
        self.report['reattached_existing_endpoint'] = not changed
        self.report['endpoint_persisted'] = True
        if changed:
            self.save('endpoint_saved_waiting_autoapply')
            while not STOP and time.monotonic() < deadline:
                counts = self.logs.read()
                try:
                    helper = self.host.helper(deadline)
                    if helper != initial_helper and counts.get('endpoint_selected', 0) > 0:
                        self.report['endpoint_autoapply_verified'] = True
                        break
                except (OSError,self.e.Failure,self.v.Failure): pass
                time.sleep(.25)
            else:
                raise Failure('endpoint_autoapply_unverified')
        self.save('running')

    def await_core(self, deadline):
        # UI/compositor descendants can appear after the core. Their temporary
        # absence is reported by the verifier's own Failure class, not just the
        # endpoint module's Failure class. Do not discard the healthy forward
        # while normal startup is completing.
        while not STOP and time.monotonic() < deadline:
            try:
                return self.host.view(deadline)
            except (OSError,self.e.Failure,self.v.Failure):
                time.sleep(.2)
        raise Failure('normal_livi_runtime_not_ready')

    def check(self):
        if self.server.poll() is not None: raise Failure('owned_server_exited')
        self.verify_device(full=False)
        self.o.listener_owner(15000,self.group)
        view = self.await_core(time.monotonic()+15)
        if view['endpoint'] != ENDPOINT: raise Conflict('endpoint_changed_outside_service')
        self.tracker.observe(view)
        self.report['observation'] = self.tracker.result()
        self.report['log_counts'] = self.logs.read()
        self.report['authentication_verified'] = self.report['log_counts'].get('phone_auth_accepted',0) > 0
        self.save('running')

    def close(self):
        deadline = time.monotonic()+6
        if self.logs: self.logs.close()
        if self.forward and self.group is not None and self.transport is not None:
            try:
                self.o.listener_owner(15037,self.group)
                with self.o.SmartADB(min(deadline,time.monotonic()+2)) as client:
                    client.forward(self.transport,remove=True)
            except (OSError,self.o.Failure): pass
        if self.group is not None:
            self.report['host_server_stopped'] = self.o.kill_owned(self.group,self.server,deadline,leader=self.leader)
        else:
            self.report['host_server_stopped'] = True
        self.report['host_ports_released'] = self.o.listeners_absent((15037,15000))
        self.report['device_restoration_attempted'] = False
        self.report['endpoint_restoration_attempted'] = False
        self.save('host_stopped_device_preserved')


def serve_once(runtime, stopping, wait):
    try:
        runtime.start()
        runtime.verify_device()
        runtime.start_forward()
        runtime.ensure_endpoint()
        while not stopping():
            runtime.check()
            wait(5)
    finally:
        runtime.close()


def stop_request(_signal,_frame):
    global STOP
    STOP = True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt',type=Path,required=True)
    parser.add_argument('--state-dir',type=Path,default=ROOT/'state')
    args = parser.parse_args(argv)
    if os.getuid() != 1000 or os.geteuid() != 1000:
        raise Failure('service_requires_cruiser_uid')
    os.umask(0o077)
    args.state_dir.mkdir(mode=0o700,exist_ok=True)
    info = args.state_dir.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise Failure('state_directory_invalid')
    lock = (args.state_dir/'service.lock').open('a')
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    receipt = load_receipt(args.receipt)
    runtime = Runtime(receipt,args.state_dir/'result.json')
    for signum in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP): signal.signal(signum,stop_request)
    try:
        serve_once(runtime,lambda:STOP,time.sleep)
        return 0
    except Exception as error:
        runtime.report['error_type'] = type(error).__name__
        if isinstance(error,Failure): runtime.report['error'] = str(error)
        runtime.save('failed_host_cleaned_device_preserved')
        return 78 if isinstance(error,Conflict) else 1


if __name__ == '__main__': raise SystemExit(main())
