#!/usr/bin/env python3
"""Once-only bounded USB ADB observation. Import has no side effects.

Foreground server only; direct smart sockets never auto-start another server.
Requests are fixed shell metadata and provider opcode03; no authentication payloads are logged.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import socket
import stat
import subprocess
import time

ADB_DIR=Path('/home/cruiser/LIVI/tools/adb-34.0.5-20261113-b2d9e0e88072')
WRAPPER=ADB_DIR/'adb'
WRAPPER_SHA='64e4b374dac1a7a3fb4dbd17290bf2c3a71b333aa81f00b2764fe52b3a2a2342'
BINARY=ADB_DIR/'root/usr/lib/android-sdk/platform-tools/adb'
BINARY_SHA='f8a371d07c8c36499f8c89c88c579dabf3411baa70389bdd9199eedb4d7feab5'
STOCK_SHA='19326c5b73c61fd5a604d114ad49035a3730c7d12bfacaef165f7048e8f42e53'
SHELL_COMMAND=("printf 'LIVI_ADB_BEGIN\\n'; uname -r; "
               "sha256sum /mnt/customer/app/libiap_new.so; "
               "for p in $(pidof lylinkapp); do awk '{print \"PID\",$1,$3,$4,$22}' /proc/$p/stat; done; "
               "printf 'LIVI_ADB_END\\n'")
STOP=False
BRIDGE_PROOF=None

class Failure(RuntimeError):
    """Only fixed metadata labels; never retain a remote error or device ID."""

def load_bridge_proof(path,now=None):
    path=Path(path);info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=1000 or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>8192 or info.st_nlink!=1:
        raise Failure('bridge_proof_file_invalid')
    data=json.loads(path.read_text())
    if set(data)!={'watchdog','supervisor','worker','expires_boottime_ms'}:
        raise Failure('bridge_proof_schema_invalid')
    for role,fields in (('watchdog',{'pid','start'}),('supervisor',{'pid','parent','group','start'}),('worker',{'pid','parent','group','start'})):
        row=data[role]
        if not isinstance(row,dict) or set(row)!=fields or any(type(v) is not int or v<=1 for v in row.values()):
            raise Failure('bridge_proof_identity_invalid')
    w,s,c=(data[k] for k in ('watchdog','supervisor','worker'))
    if len({w['pid'],s['pid'],c['pid']})!=3 or s['parent']!=w['pid'] or c['parent']!=s['pid'] or s['group']!=s['pid'] or c['group']!=s['pid']:
        raise Failure('bridge_proof_relationship_invalid')
    if type(data['expires_boottime_ms']) is not int:
        raise Failure('bridge_proof_deadline_invalid')
    if now is None:now=int(time.clock_gettime(time.CLOCK_BOOTTIME)*1000)
    if not 150000<=data['expires_boottime_ms']-now<=300000:
        raise Failure('bridge_proof_window_short')
    return data

def finish_requested(path):
    path=Path(path)
    try:info=path.lstat()
    except FileNotFoundError:return False
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=1000 or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or info.st_size!=5:
        raise Failure('finish_file_invalid')
    if path.read_bytes()!=b'STOP\n':raise Failure('finish_file_invalid')
    return True

def time_left(deadline):
    value=deadline-time.monotonic()
    if value<=0:raise TimeoutError('deadline')
    return value

def select_transport(payload):
    try:lines=payload.decode('ascii').splitlines()
    except UnicodeError:raise Failure('device_list_invalid') from None
    matches=[]
    for line in lines:
        fields=line.split()
        # ADB34 libusb uses bare devpath; Linux native backend uses usb:devpath.
        physical=[x for x in fields[2:] if re.fullmatch(r'(?:usb:)?[0-9]+-[0-9]+(?:\.[0-9]+)*',x)]
        target=[x for x in physical if x in ('4-1','usb:4-1')]
        if not target:continue
        transports=[x for x in fields[2:] if x.startswith('transport_id:')]
        if (len(fields)<3 or fields[1]!='device' or len(physical)!=1 or len(transports)!=1
                or not re.fullmatch(r'transport_id:[1-9][0-9]{0,18}',transports[0])):
            raise Failure('target_not_ready_or_ambiguous')
        matches.append(int(transports[0].split(':')[1]))
    if len(matches)!=1:raise Failure('target_not_ready_or_ambiguous')
    return matches[0]

def usb_identity(root=Path('/sys/bus/usb/devices'),require_adb=True):
    root=Path(root);device=root/'4-1'
    if ((device/'idVendor').read_text().strip()!='05ac' or
            (device/'idProduct').read_text().strip()!='12a8'):
        raise Failure('usb_identity_differs')
    interfaces=[]
    for p in root.glob('4-1:*'):
        values=tuple((p/name).read_text().strip().lower() for name in
                     ('bInterfaceClass','bInterfaceSubClass','bInterfaceProtocol'))
        if values==('ff','42','01'):interfaces.append(p.name)
    if require_adb and len(interfaces)!=1:raise Failure('adb_interface_absent_or_ambiguous')
    bus=int((device/'busnum').read_text());number=int((device/'devnum').read_text())
    if bus!=4 or not 1<=number<=127:raise Failure('usb_node_invalid')
    return {'bus':bus,'device':number,'inode':device.stat().st_ino,'interface':interfaces[0] if len(interfaces)==1 else None}

def parse_shell(payload):
    try:lines=payload.decode('ascii').replace('\r\n','\n').splitlines()
    except UnicodeError:raise Failure('shell_metadata_invalid') from None
    if (len(lines)!=6 or lines[0]!='LIVI_ADB_BEGIN' or lines[-1]!='LIVI_ADB_END'
            or not re.fullmatch(r'[A-Za-z0-9._+~-]{1,100}',lines[1])
            or lines[2]!=STOCK_SHA+'  /mnt/customer/app/libiap_new.so'):
        raise Failure('shell_metadata_invalid')
    rows=[]
    for line in lines[3:5]:
        match=re.fullmatch(r'PID ([1-9][0-9]*) ([RS]) ([1-9][0-9]*) ([1-9][0-9]*)',line)
        if not match:raise Failure('stock_process_metadata_invalid')
        pid,state,parent,start=match.groups()
        rows.append({'pid':int(pid),'state':state,'parent':int(parent),'start':int(start)})
    if BRIDGE_PROOF is None:raise Failure('bridge_proof_missing')
    expected={(BRIDGE_PROOF[role]['pid'],BRIDGE_PROOF[role]['parent'],BRIDGE_PROOF[role]['start']) for role in ('supervisor','worker')}
    if {(row['pid'],row['parent'],row['start']) for row in rows}!=expected:
        raise Failure('stock_process_relationship_invalid')
    return {'kernel_release':lines[1],'stock_library_verified':True,'processes':rows}

class SmartADB:
    def __init__(self,deadline,address=('127.0.0.1',15037)):
        self.deadline=deadline
        self.stream=socket.create_connection(address,timeout=min(2,time_left(deadline)))
    def exact(self,size):
        data=b''
        while len(data)<size:
            self.stream.settimeout(min(2,time_left(self.deadline)))
            chunk=self.stream.recv(size-len(data))
            if not chunk:raise Failure('adb_closed')
            data+=chunk
        return data
    def send(self,service):
        data=service.encode('ascii')
        if len(data)>65535:raise Failure('request_too_large')
        self.stream.settimeout(min(2,time_left(self.deadline)))
        self.stream.sendall(('%04x'%len(data)).encode()+data)
        self.status()
    def status(self):
        if self.exact(4)!=b'OKAY':raise Failure('adb_request_rejected')
    def query(self,service):
        self.send(service)
        raw=self.exact(4)
        if not re.fullmatch(b'[0-9a-fA-F]{4}',raw):raise Failure('adb_length_invalid')
        size=int(raw,16)
        if size>16384:raise Failure('adb_reply_too_large')
        return self.exact(size)
    def shell(self,transport,command):
        self.send('host:transport-id:'+str(transport))
        self.send('shell:'+command)
        data=b''
        while True:
            self.stream.settimeout(min(2,time_left(self.deadline)))
            chunk=self.stream.recv(4096)
            if not chunk:return data
            data+=chunk
            if len(data)>8192:raise Failure('shell_reply_too_large')
    def forward(self,transport,remove=False):
        command='killforward:tcp:15000' if remove else 'forward:norebind:tcp:15000;tcp:15000'
        self.send('host-transport-id:'+str(transport)+':'+command)
        self.status()
    def __enter__(self):return self
    def __exit__(self,*args):self.stream.close()

def proc(pid):
    path=Path('/proc')/str(pid)
    raw=(path/'stat').read_text();fields=raw[raw.rfind(')')+2:].split()
    return {'pid':pid,'state':fields[0],'ppid':int(fields[1]),'group':int(fields[2]),
            'session':int(fields[3]),'start':int(fields[19]),'uid':path.stat().st_uid}

def members(group):
    found=[]
    for path in Path('/proc').iterdir():
        if not path.name.isdigit():continue
        try:item=proc(int(path.name))
        except (OSError,ValueError):continue
        if item['group']==group and item['state'] not in ('Z','X'):found.append(item)
    return found

def listener_owner(port,group):
    inodes=[]
    for file,loopback in (('/proc/net/tcp','0100007F'),('/proc/net/tcp6','00000000000000000000000001000000')):
        for line in Path(file).read_text().splitlines()[1:]:
            fields=line.split();address,value=fields[1].split(':')
            if int(value,16)==port and fields[3]=='0A':
                if address!=loopback or file.endswith('tcp6'):raise Failure('listener_not_ipv4_loopback')
                inodes.append(fields[9])
    if len(inodes)!=1:raise Failure('listener_missing_or_ambiguous')
    owners=[]
    for item in members(group):
        if item['uid']!=1000 or item['session']!=group:raise Failure('server_group_identity_changed')
        try:
            for fd in (Path('/proc')/str(item['pid'])/'fd').iterdir():
                try:target=os.readlink(fd)
                except FileNotFoundError:continue
                if target=='socket:['+inodes[0]+']':owners.append(item);break
        except FileNotFoundError:continue
    if len(owners)!=1:raise Failure('listener_owner_unverified')
    return owners[0]

def port_free(port):
    with socket.socket() as stream:stream.bind(('127.0.0.1',port))

def listeners_absent(ports):
    for path in ('/proc/net/tcp','/proc/net/tcp6'):
        for line in Path(path).read_text().splitlines()[1:]:
            fields=line.split()
            if fields[3]=='0A' and int(fields[1].rsplit(':',1)[1],16) in ports:return False
    return True

def kill_owned(group,process,deadline,leader=None):
    # Session membership is inherited exclusively from our start_new_session child.
    # Never signal by a name, a USB identity, or an unverified arbitrary PID.
    if leader is None:
        try:leader=proc(group)
        except OSError:return not members(group)
    for sig in (signal.SIGTERM,signal.SIGKILL):
        live=members(group)
        if not live:break
        try:current=proc(group)
        except OSError:return False
        if any(current[key]!=leader[key] for key in ('pid','start','group','session','uid')):return False
        if any(p['uid']!=os.getuid() or p['session']!=group for p in live):return False
        try:os.killpg(group,sig)
        except ProcessLookupError:pass
        until=min(deadline,time.monotonic()+(1.5 if sig==signal.SIGTERM else .5))
        while time.monotonic()<until and members(group):time.sleep(.05)
    try:process.wait(timeout=max(.01,min(.5,deadline-time.monotonic())))
    except subprocess.TimeoutExpired:pass
    return not members(group)

def verify_target(group,identity,transport,deadline):
    listener_owner(15037,group)
    if usb_identity()!=identity:raise Failure('usb_target_changed')
    with SmartADB(deadline) as client:
        if select_transport(client.query('host:devices-l'))!=transport:raise Failure('adb_transport_changed')
    if usb_identity()!=identity:raise Failure('usb_target_changed')

def forward_marker(deadline,address=('127.0.0.1',15000)):
    with socket.create_connection(address,timeout=min(2,time_left(deadline))) as stream:
        stream.settimeout(min(2,time_left(deadline)))
        stream.sendall(b'\x03')
        data=b''
        while len(data)<4:
            stream.settimeout(min(2,time_left(deadline)))
            part=stream.recv(4-len(data))
            if not part:raise Failure('provider_metadata_unverified')
            data+=part
        if data!=b'\x00\x00\x01\x03':raise Failure('provider_metadata_unverified')
    return True


def stop_request(_sig,_frame):
    global STOP
    STOP=True

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',action='store_true')
    parser.add_argument('--run-id',required=True)
    parser.add_argument('--forward-check',action='store_true')
    parser.add_argument('--bridge-proof',type=Path,required=True)
    args=parser.parse_args(argv)
    if not args.run or not re.fullmatch('[0-9a-f]{12}',args.run_id):parser.error('explicit run and fresh12hex run id required')
    if os.getuid()!=1000 or os.geteuid()!=1000:raise Failure('wrong_uid')
    global BRIDGE_PROOF
    BRIDGE_PROOF=load_bridge_proof(args.bridge_proof)
    if not args.forward_check:raise Failure('bridge_forward_required')
    os.umask(0o077)
    base=Path('/home/cruiser/LIVI/tools')/('adb-observation-'+args.run_id)
    base.mkdir(mode=0o700) # Once-only journal; never reuse a prior run.
    report={'stage':'preflight','server_started':False,'shell_submitted':False,
            'shell_verified':False,'forward_attempted':False,'forward_verified':False,'cleanup_verified':False}
    def save(stage):
        report['stage']=stage
        tmp=base/'result.tmp'
        with tmp.open('w') as out:json.dump(report,out,indent=2);out.write('\n');out.flush();os.fsync(out.fileno())
        tmp.replace(base/'result.json')
    save('preflight')
    print(json.dumps({'journal':str(base/'result.json'),'stage':'preflight'}),flush=True)
    for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(sig,stop_request)
    started=time.monotonic();deadline=started+165;server=None;group=None;transport=None;leader=None
    log=None;error=None
    try:
        for path,digest in ((WRAPPER,WRAPPER_SHA),(BINARY,BINARY_SHA)):
            if not stat.S_ISREG(path.lstat().st_mode) or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:raise Failure('adb_pin_mismatch')
        if any(os.environ.get(key) for key in ('ADB_VENDOR_KEYS','ADB_SERVER_SOCKET','ANDROID_SERIAL','ADB_AUTH')):
            raise Failure('adb_override_environment_present')
        if b'ADB_LIBUSB' not in BINARY.read_bytes():raise Failure('libusb_support_unverified')
        port_free(15037)
        if args.forward_check:port_free(15000)
        help_result=subprocess.run([str(WRAPPER),'help'],stdin=subprocess.DEVNULL,capture_output=True,timeout=5)
        if help_result.returncode or b'--one-device' not in help_result.stdout:raise Failure('one_device_option_unverified')
        if STOP:raise Failure('stopped_before_start')
        env=os.environ.copy()
        for key in ('ADB_TRACE','ADB_SERVER_PORT','ANDROID_ADB_SERVER_PORT','ANDROID_ADB_SERVER_ADDRESS'):env.pop(key,None)
        env.update(ADB_LIBUSB='1',ADB_MDNS='0',ADB_EMU='0')
        log=(base/'server.log').open('xb')
        def child_limit():resource.setrlimit(resource.RLIMIT_FSIZE,(512*1024,512*1024))
        report['initial_usb']=usb_identity(require_adb=False)
        if STOP:raise Failure('stopped_before_start')
        save('server_launch_submitting')
        server=subprocess.Popen(['/usr/bin/timeout','--signal=TERM','--kill-after=3s','175s',str(WRAPPER),
                '-L','tcp:localhost:15037','--one-device','usb:4-1','server','nodaemon'],
                stdin=subprocess.DEVNULL,stdout=log,stderr=log,env=env,start_new_session=True,preexec_fn=child_limit)
        group=server.pid
        leader=proc(group)
        if leader['group']!=group or leader['session']!=group or leader['uid']!=1000:raise Failure('server_leader_identity_invalid')
        report.update(server_started=True,server_group=group,server_leader=leader,libusb_requested=True)
        save('waiting_for_usb_adb')
        target_deadline=min(deadline,started+80)
        identity=None
        while not STOP and time.monotonic()<target_deadline:
            if server.poll() is not None:raise Failure('server_exited')
            try:
                listener_owner(15037,group)
                candidate=usb_identity()
                node=Path('/dev/bus/usb')/f"{candidate['bus']:03d}"/f"{candidate['device']:03d}"
                if not os.access(node,os.R_OK|os.W_OK):raise Failure('usb_node_access_unavailable')
                with SmartADB(min(target_deadline,time.monotonic()+2)) as client:
                    selected=select_transport(client.query('host:devices-l'))
                if candidate!=usb_identity():raise Failure('usb_target_changed')
                identity,transport=candidate,selected;break
            except (OSError,Failure,ValueError):time.sleep(.2)
        if identity is None:raise Failure('target_deadline_or_stop')
        report.update(usb=identity,transport_id=transport)
        verify_target(group,identity,transport,min(deadline,time.monotonic()+3))
        if STOP:raise Failure('stopped_before_shell')
        report['shell_submitted']=True;save('shell_submitting')
        with SmartADB(min(deadline,time.monotonic()+8)) as client:
            metadata=parse_shell(client.shell(transport,SHELL_COMMAND))
        verify_target(group,identity,transport,min(deadline,time.monotonic()+3))
        report.update(shell_verified=True,stock=metadata);save('shell_verified')
        if args.forward_check and not STOP:
            verify_target(group,identity,transport,min(deadline,time.monotonic()+3))
            if STOP:raise Failure('stopped_before_forward')
            report['forward_attempted']=True;save('forward_submitting')
            with SmartADB(min(deadline,time.monotonic()+3)) as client:client.forward(transport)
            listener_owner(15000,group)
            if STOP:raise Failure('stopped_before_forward_marker')
            forward_marker(min(deadline,time.monotonic()+5))
            verify_target(group,identity,transport,min(deadline,time.monotonic()+3))
            report['forward_verified']=True;save('provider_ready')
            hold_until=min(deadline,time.monotonic()+150,
                           time.monotonic()+max(0,(BRIDGE_PROOF['expires_boottime_ms']-int(time.clock_gettime(time.CLOCK_BOOTTIME)*1000)-15000)/1000))
            while not STOP and time.monotonic()<hold_until:
                if finish_requested(base/'finish'):
                    report['finish_received']=True
                    break
                verify_target(group,identity,transport,min(deadline,time.monotonic()+3))
                listener_owner(15000,group)
                time.sleep(.2)
            else:
                if not STOP:raise Failure('provider_hold_deadline')
    except Exception as exc:
        error=exc;report['error_type']=type(exc).__name__
        if isinstance(exc,Failure):report['error']=str(exc)
        save('observation_failed_no_retry')
    finally:
        cleanup_deadline=time.monotonic()+5
        if report['forward_attempted'] and group is not None and transport is not None:
            try:
                listener_owner(15037,group)
                with SmartADB(min(cleanup_deadline,time.monotonic()+1)) as client:client.forward(transport,remove=True)
                report['forward_removal_acknowledged']=True
            except (OSError,Failure):report['forward_removal_acknowledged']=False
        if group is not None:
            try:report['server_group_stopped']=kill_owned(group,server,cleanup_deadline,leader=leader)
            except (OSError,ValueError):report['server_group_stopped']=False
        else:report['server_group_stopped']=True
        if log:log.close()
        try:
            report['ports_released']=listeners_absent((15037,15000) if args.forward_check else (15037,))
        except OSError:report['ports_released']=False
        report['cleanup_verified']=report['server_group_stopped'] and report['ports_released']
        report['elapsed_seconds']=round(time.monotonic()-started,3)
        report['exit_code']=0 if error is None and report['shell_verified'] and report['cleanup_verified'] else 1
        save('complete' if report['exit_code']==0 else 'failed')
        print(json.dumps(report,sort_keys=True),flush=True)
    return report['exit_code']

if __name__=='__main__':raise SystemExit(main())
