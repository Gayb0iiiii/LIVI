#!/usr/bin/env python3
"""One finite AX520 radio session using an existing, pinned authentication ADB server.

Import is inert. This never starts/stops the ADB server, edits authentication
configuration, flashes firmware or persists files on the dongle.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import struct
import sys
import threading
import time

PORTS = (15038, 15039)
BTAPP_SHA = '29384058090e2faed83a9bf16bd11b927361b1ccd2da07dd75cfbb5615b25879'
STOP = False
HCI_BOUNDS = {'mode':'fresh_pairing_300s','loopback_port':15039,'accept_ms':20000,'relay_ms':300000,
              'worker_ms':330000,'restore_ms':10000,'worker_reap_ms':1000,'restore_reap_ms':1000,
              'resume_each_ms':1000,'pending_io_stall_ms':3000}

class Failure(RuntimeError):
    """Only fixed metadata labels are journaled."""

class StopRequested(Exception):
    """Internal graceful stop before the next mutation."""

class Conflict(Failure):
    """An external change or unresolved outcome must not be automatically retried."""


def validate_manifest(value):
    if not isinstance(value,dict) or set(value)!={'version','seconds','auth_dir','auth_hashes','artifacts'} or type(value['version']) is not int or value['version']!=1:
        raise Failure('manifest_schema_invalid')
    if type(value['seconds']) is not int or not 1<=value['seconds']<=300:
        raise Failure('manifest_duration_invalid')
    root=Path(value['auth_dir'])
    if not root.is_absolute() or '..' in root.parts:raise Failure('manifest_auth_path_invalid')
    hashes=value['auth_hashes']
    if not isinstance(hashes,dict) or set(hashes)!={'service.py','vendor/adb_observer.py','vendor/endpoint.py','vendor/verifier.py'}:
        raise Failure('manifest_auth_pins_invalid')
    if any(not isinstance(v,str) or not re.fullmatch('[0-9a-f]{64}',v) for v in hashes.values()):
        raise Failure('manifest_hash_invalid')
    if not isinstance(value['artifacts'],dict) or set(value['artifacts'])!={'network','bluetooth'}:
        raise Failure('manifest_artifacts_invalid')
    for row in value['artifacts'].values():
        if not isinstance(row,dict) or set(row)!={'path','sha256'} or not isinstance(row['path'],str):
            raise Failure('manifest_artifact_invalid')
        path=Path(row['path'])
        if not path.is_absolute() or '..' in path.parts or not re.fullmatch('[0-9a-f]{64}',row['sha256']):
            raise Failure('manifest_artifact_invalid')
    return value


def read_file(path,limit=2*1024*1024):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as file:
        before=os.fstat(file.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or before.st_nlink!=1 or before.st_size>limit:
            raise Failure('local_file_metadata_invalid')
        data=file.read(limit+1);after=os.fstat(file.fileno())
        if len(data)>limit or (before.st_ino,before.st_mtime_ns,before.st_ctime_ns,before.st_size)!=(after.st_ino,after.st_mtime_ns,after.st_ctime_ns,after.st_size):
            raise Failure('local_file_changed')
        return data


def checked_file(path,digest):
    data=read_file(path)
    if hashlib.sha256(data).hexdigest()!=digest:raise Failure('local_artifact_hash_invalid')
    return data


def save(path,value):
    temporary=path.with_suffix('.next')
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as file:
        json.dump(value,file,indent=2,sort_keys=True);file.write('\n');file.flush();os.fsync(file.fileno())
    temporary.replace(path)


def tap_ready(net=Path('/sys/class/net/ax520cp0'),inet6=Path('/proc/net/if_inet6')):
    try:
        if not int((net/'flags').read_text().strip(),16)&1 or (net/'carrier').read_text().strip()!='1':return False
        for line in inet6.read_text().splitlines():
            p=line.split()
            if len(p)!=6 or p[5]!='ax520cp0' or p[3]!='20':continue
            if int(p[4],16)&(0x40|0x08|0x04):continue
            if ipaddress.IPv6Address(int(p[0],16)).is_link_local:return True
    except (OSError,ValueError):return False
    return False


def parse_forward(payload,serial,port):
    if port not in PORTS:raise Failure('forward_port_invalid')
    found=0;needle='tcp:'+str(port)
    for line in payload.decode('ascii').splitlines():
        fields=line.split()
        if needle not in fields:continue
        if fields!=[serial,needle,needle]:raise Conflict('foreign_radio_forward')
        found+=1
    if found>1:raise Conflict('duplicate_radio_forward')
    return found==1


_STATUS_WORDS = {
    'relay_listening_loopback_only','relay_connected_preflight_failed_no_mutation',
    'stock_pair_all_threads_paused_uart_fd_preserved','paused_controller_baseline_changed_no_mutation',
    'hci_down_unverified','hci_down_verified','hci_user_owned','restore_helper_unreaped',
    'resume_identity_changed_no_signal','worker_release_unverified_no_controller_operation_stock_pair_left_paused',
    'restore_identity_or_topology_changed','restore_helper_release_unverified_stock_pair_left_paused',
    'structural_restore_verified_phone_link_not_verified','structural_restore_unverified',
    'worker_reaped_user_socket_released','worker_reap_failed',
}
_STATUS_ERRORS = {'relay_listen_failed_no_mutation','relay_no_host_no_mutation','pause_supervisor_failed',
    'pause_worker_failed','hci_down_failed','hci_user_bind_failed','read_local_version_failed','controller_restore_failed'}
_RESULTS = {'launch_failed_no_mutation','restoration_unverified_no_retry','relay_no_host_restored',
            'relay_complete_restored','relay_failed_restored'}


def parse_status(text):
    if len(text)>16384:raise Failure('radio_status_limit')
    result={'events':[]}
    patterns=[r'preflight_verified supervisor=\d+/\d+ worker=\d+/\d+ sha256=[0-9a-f]{64} tty_fd=\d+ original_flags=\d+ connections=\d+',
              r'relay_host_connected original_flags=\d+',r'(?:trial_worker|restore_helper)_pid=\d+ start=\d+']
    for line in text.splitlines():
        match=re.fullmatch(r'\d+ (.+)',line)
        if not match:raise Failure('radio_status_invalid')
        item=match[1]
        m=re.fullmatch(r'watchdog_armed pid=([1-9]\d*) start=([1-9]\d*) trial_ms=(\d+) recovery_ms=(\d+)',item)
        if m:
            if 'watchdog' in result:raise Failure('radio_watchdog_ambiguous')
            result['watchdog']={'pid':int(m[1]),'start':int(m[2])};continue
        m=re.fullmatch(r'relay_stop_reason=(\d+) to_controller=(\d+) to_host=(\d+)',item)
        if m:
            if 'counts' in result:raise Failure('radio_counts_ambiguous')
            result['counts']={'reason':int(m[1]),'to_controller':int(m[2]),'to_host':int(m[3])};continue
        if item.startswith('RESULT '):
            value=item.removeprefix('RESULT ')
            if value not in _RESULTS or 'result' in result:raise Failure('radio_result_invalid')
            result['result']=value;continue
        if item in _STATUS_WORDS:result['events'].append(item);continue
        if any(re.fullmatch(re.escape(name)+r' errno=\d+',item) for name in _STATUS_ERRORS):continue
        if any(re.fullmatch(p,item) for p in patterns):continue
        raise Failure('radio_status_unrecognized')
    return result


def wait_guardian_exit(owner,observe,clock=time.monotonic,wait=time.sleep,within=5):
    """Observe only the prior PID/start; never signal a possibly reused PID."""
    if not isinstance(owner,dict) or set(owner)!={'pid','start'} or any(type(v) is not int or v<=1 for v in owner.values()):
        raise Failure('guardian_identity_invalid')
    end=clock()+within
    while True:
        current=observe(owner)
        if current is None:return {'verified':True,'observation':'process_absent'}
        if (not isinstance(current,dict) or set(current)!={'pid','start','state'} or
                current['pid']!=owner['pid'] or type(current['start']) is not int or current['start']<=1 or
                current['state'] not in {'R','S','D','T','t','Z','X','x','I','P','W'}):
            raise Failure('guardian_process_metadata_invalid')
        if current['start']!=owner['start']:return {'verified':True,'observation':'pid_reused'}
        if current['state'] in {'Z','X','x'}:
            # Linux closes its descriptors (including the flock) before zombie
            # notification. Record this separately from parent reaping/absence.
            return {'verified':True,'observation':'exited_zombie' if current['state']=='Z' else 'exited_dead'}
        if clock()>=end:return {'verified':False,'observation':'same_identity_running'}
        wait(min(.2,max(0,end-clock())))


class Session:
    def __init__(self,backend,seconds,journal,stopping=lambda:False,clock=time.monotonic,wait=time.sleep):
        self.b=backend;self.seconds=seconds;self.journal=journal;self.stopping=stopping;self.clock=clock;self.wait=wait
        self.record={'stage':'starting','cleanup_verified':False,'wireless_carplay_verified':False}
        self.forward_intents=[];self.prepared=False;self.network=False;self.bluetooth=False
    def stage(self,value):self.record['stage']=value;self.journal(self.record)
    def checkpoint(self):
        if self.stopping():raise StopRequested()
    def run(self):
        failed=False;errors=[]
        try:
            self.b.verify_ready();self.checkpoint()
            self.prepared=True;self.stage('prepare_intent');self.b.prepare();self.checkpoint()
            self.network=True;self.record['network_intent']=True;self.stage('network_launch_intent');self.b.start_network();self.checkpoint()
            self.forward_intents.append(15038);self.stage('network_forward_intent');self.b.add_forward(15038);self.checkpoint()
            self.bluetooth=True;self.record['bluetooth_intent']=True;self.stage('bluetooth_launch_intent');self.b.start_bluetooth();self.checkpoint()
            self.forward_intents.append(15039);self.stage('bluetooth_forward_intent');self.b.add_forward(15039)
            end=self.clock()+self.seconds;self.stage('running_bounded')
            while not self.stopping() and self.clock()<end:
                ended=self.b.check()
                ready=bool(getattr(self.b,'radio_transports_ready',False))
                if ready!=self.record.get('radio_transports_ready',False):
                    self.record['radio_transports_ready']=ready;self.stage('running_bounded')
                if ended:break
                self.wait(min(2,max(0,end-self.clock())))
        except StopRequested:
            self.record['stop_requested']=True
        except Exception as error:
            failed=True;self.record['error_type']=type(error).__name__
            if isinstance(error,Failure):self.record['error']=str(error)
        finally:
            self.stage('cleanup')
            operations=[('remove_forward_'+str(p),lambda p=p:self.b.remove_forward(p)) for p in reversed(self.forward_intents)]
            if self.bluetooth:operations.append(('stop_bluetooth',self.b.stop_bluetooth))
            if self.network:operations.append(('stop_network',self.b.stop_network))
            for name,operation in operations:
                try:operation()
                except Exception as error:errors.append(name+':'+type(error).__name__)
            if self.prepared:
                try:
                    if not self.b.verify_restored():errors.append('restoration_not_verified')
                except Exception as error:errors.append('verify_restored:'+type(error).__name__)
            if hasattr(self.b,'guardian_exit_verified'):
                self.record['guardian_exit_verified']=self.b.guardian_exit_verified
            self.record['cleanup_errors']=errors
            self.record['cleanup_verified']=self.prepared and not errors
            if errors:self.stage('restoration_unverified_no_retry')
            elif not self.prepared:self.stage('stopped_before_start' if self.record.get('stop_requested') else 'failed_before_start')
            else:self.stage('failed_restored' if failed else 'stopped_verified')
        return self.record


class Backend:
    def __init__(self,manifest,run_dir):
        self.m=manifest;self.dir=run_dir;self.root=Path(manifest['auth_dir'])
        self.remote='/tmp/ax520-radios-'+run_dir.name
        self.native={};self.status={};self.net_text=b'';self.net_error=None;self.net_thread=None;self.net_socket=None
        self.net_ready=threading.Event();self.net_owner=None;self.flags=None;self.hci_before=None;self.started_hci=False
        self.stock_dir_created=False;self.hci_dir_created=False
    def shell(self,command,seconds=8):
        with self.r.o.SmartADB(time.monotonic()+seconds) as c:return c.shell(self.transport,command).decode('ascii').replace('\r\n','\n').strip()
    def verify_ready(self):
        for relative,digest in self.m['auth_hashes'].items():checked_file(self.root/relative,digest)
        spec=importlib.util.spec_from_file_location('radio_verified_auth',self.root/'service.py')
        s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s);self.s=s
        self.receipt=s.load_receipt(self.root/'receipt.json')
        self.r=s.Runtime(self.receipt,self.dir/'unused-auth-journal.json');self.r.host.pins()
        self.leader=json.loads((self.root/'state/result.json').read_text())['server_leader']
        self.target=s.find_usb_target();self.usb=s.target_identity(self.target)
        self.check_server()
        with self.r.o.SmartADB(time.monotonic()+4) as c:raw=c.query('host:devices-l')
        rows=[];serials=[]
        for line in raw.decode('ascii').splitlines():
            fields=line.split()
            if not any(x in (self.target,'usb:'+self.target) for x in fields[2:]):continue
            serials.append(fields[0]);fields=[('4-1' if x==self.target else 'usb:4-1' if x=='usb:'+self.target else x) for x in fields]
            rows.append(' '.join(fields))
        if len(serials)!=1:raise Failure('stock_target_ambiguous')
        self.serial=serials[0];self.transport=self.r.o.select_transport(('\n'.join(rows)+'\n').encode())
        self.verify_auth(full=True)
        if self.shell('id -u')!='0':raise Failure('stock_root_required')
        if Path('/sys/class/net/ax520cp0').exists() or list(Path('/sys/class/bluetooth').glob('hci*')):
            raise Conflict('host_radio_interface_already_present')
        for p in PORTS:
            if self.forwarding(p) or not self.r.o.listeners_absent((p,)):raise Conflict('radio_host_port_busy')
        if self.stock_ports()!='0':raise Conflict('stock_radio_port_busy')
        self.flags=self.shell('cat /sys/class/net/wlan0/flags')
    def check_server(self):
        current=self.r.o.proc(self.leader['pid'])
        if current['start']!=self.leader['start']:raise Conflict('authentication_adb_server_changed')
        state=json.loads((self.root/'state/result.json').read_text())
        if state['stage']!='running' or state['server_leader']['pid']!=self.leader['pid'] or state['server_leader']['start']!=self.leader['start']:
            raise Failure('authentication_service_not_running')
        for p in (15037,15000):self.r.o.listener_owner(p,self.leader['pid'])
        if self.s.target_identity(self.target)!=self.usb:raise Conflict('stock_usb_identity_changed')
    def verify_auth(self,full=False):
        self.check_server()
        with self.r.o.SmartADB(time.monotonic()+18) as c:
            self.s.verify_device_response(c.shell(self.transport,self.s.device_check_command(self.receipt,full=full)))
    def stock_ports(self):
        return self.shell("awk 'NR>1&&$4==\"0A\"{split($2,a,\":\");if(a[2]==\"3ABE\"||a[2]==\"3ABF\")n++}END{print n+0}' /proc/net/tcp /proc/net/tcp6")
    def forwarding(self,p):
        with self.r.o.SmartADB(time.monotonic()+3) as c:return parse_forward(c.query('host:list-forward'),self.serial,p)
    def add_forward(self,p):
        self.check_server()
        if self.forwarding(p) or not self.r.o.listeners_absent((p,)):raise Conflict('radio_forward_not_free')
        with self.r.o.SmartADB(time.monotonic()+4) as c:
            c.send('host-transport-id:'+str(self.transport)+f':forward:norebind:tcp:{p};tcp:{p}');c.status()
        self.r.o.listener_owner(p,self.leader['pid'])
        if not self.forwarding(p):raise Failure('radio_forward_unverified')
    def remove_forward(self,p):
        # Cleanup depends only on the exact ADB owner and mapping. A lost auth
        # endpoint or unplugged USB must not strand this session's host forwards.
        current=self.r.o.proc(self.leader['pid'])
        if current['start']!=self.leader['start']:raise Conflict('authentication_adb_server_changed')
        self.r.o.listener_owner(15037,self.leader['pid'])
        if self.forwarding(p):
            self.r.o.listener_owner(p,self.leader['pid'])
            with self.r.o.SmartADB(time.monotonic()+4) as c:
                c.send('host-transport-id:'+str(self.transport)+f':killforward:tcp:{p}');c.status()
        if self.forwarding(p) or not self.r.o.listeners_absent((p,)):raise Conflict('radio_forward_remains')
    def push(self,data,path):
        # ADB sync v1 on the existing verified smart socket; no CLI auto-start.
        with self.r.o.SmartADB(time.monotonic()+12) as c:
            c.send('host:transport-id:'+str(self.transport));c.send('sync:')
            name=(path+',33216').encode('ascii') # regular file, mode0700
            c.stream.sendall(b'SEND'+struct.pack('<I',len(name))+name)
            for offset in range(0,len(data),65536):
                part=data[offset:offset+65536];c.stream.sendall(b'DATA'+struct.pack('<I',len(part))+part)
            c.stream.sendall(b'DONE'+struct.pack('<I',int(time.time())))
            if c.exact(8)!=b'OKAY\x00\x00\x00\x00':raise Failure('artifact_sync_rejected')
    def prepare(self):
        if self.shell('umask 077; mkdir '+self.remote+' && echo CREATED')!='CREATED':raise Conflict('radio_run_directory_not_new')
        self.stock_dir_created=True
        for role,row in self.m['artifacts'].items():
            data=checked_file(Path(row['path']),row['sha256']);path=self.remote+'/'+role
            self.push(data,path)
            if self.shell('sha256sum '+path).split()[0]!=row['sha256']:raise Failure('staged_artifact_hash_invalid')
            self.native[role]=path
        if json.loads(self.shell(self.native['bluetooth']+' --bounds'))!=HCI_BOUNDS:
            raise Failure('bluetooth_compiled_bounds_invalid')
        # Output is process identity and UART FD numbers only; never bond files.
        command="""set -eu
for p in $(pidof btapp); do
 [ "$(readlink /proc/$p/exe)" = /mnt/customer/app/btapp ] || exit 1
 awk '{print "BT",$1,$3,$4,$5,$22}' /proc/$p/stat
 for f in /proc/$p/fd/*; do [ "$(readlink "$f")" != /dev/ttyS2 ] || echo TTY $p ${f##*/}; done
done
"""
        rows=[];ttys=[]
        for line in self.shell(command).splitlines():
            m=re.fullmatch(r'BT (\d+) ([RS]) (\d+) (\d+) (\d+)',line)
            if m:rows.append({'pid':int(m[1]),'parent':int(m[3]),'group':int(m[4]),'start':int(m[5])});continue
            m=re.fullmatch(r'TTY (\d+) (\d+)',line)
            if m:ttys.append((int(m[1]),int(m[2])));continue
            raise Failure('stock_bluetooth_metadata_invalid')
        sups=[r for r in rows if r['parent']==1]
        if len(rows)!=2 or len(sups)!=1:raise Failure('stock_bluetooth_pair_ambiguous')
        sup=sups[0];workers=[r for r in rows if r['parent']==sup['pid']]
        if len(workers)!=1 or len(ttys)!=1 or ttys[0][0]!=workers[0]['pid']:raise Failure('stock_uart_owner_ambiguous')
        self.bt={'supervisor_pid':sup['pid'],'supervisor_start':sup['start'],'worker_pid':workers[0]['pid'],'worker_start':workers[0]['start'],'tty_fd':ttys[0][1]}
        self.hci_before=self.inspect_hci()
        if self.shell('mkdir '+self.remote+'/hci && chmod 700 '+self.remote+'/hci && echo CREATED')!='CREATED':raise Failure('hci_directory_not_created')
        self.hci_dir_created=True
    def inspect_hci(self):
        b=self.bt
        row=json.loads(self.shell(self.native['bluetooth']+f" --inspect {b['supervisor_pid']} {b['worker_pid']} {b['tty_fd']}"))
        if any(row.get(k)!=v for k,v in b.items()) or row.get('sha256')!=BTAPP_SHA or row.get('hci_id')!=0 or row.get('hci_bus')!=3 or row.get('raw_socket_get_capable') is not True:
            raise Failure('hci_inspection_invalid')
        return row
    def start_network(self):
        path=self.native['network']
        command="printf 'owner %s ' $$; awk '{print $22}' /proc/$$/stat; exec "+path+' --run wlan0 15038 '+str(self.m['seconds'])+' 02:a1:b2:c3:d4:e5'
        def stream():
            try:
                with self.r.o.SmartADB(time.monotonic()+self.m['seconds']+10) as c:
                    self.net_socket=c.stream;c.send('host:transport-id:'+str(self.transport));c.send('shell:'+command)
                    while True:
                        c.stream.settimeout(.5)
                        try:data=c.stream.recv(2048)
                        except socket.timeout:continue
                        if not data:break
                        self.net_text+=data
                        if len(self.net_text)>8192:raise Failure('network_log_limit')
                        if b'relay_ready ' in self.net_text:self.net_ready.set()
            except Exception as error:self.net_error=type(error).__name__
        self.net_thread=threading.Thread(target=stream,daemon=True);self.net_thread.start()
        if not self.net_ready.wait(4):raise Failure('network_relay_not_ready')
        self.network_owner()
    def network_owner(self):
        text=self.net_text.decode('ascii').replace('\r\n','\n')
        matches=re.findall(r'^owner ([1-9]\d*) ([1-9]\d*)$',text,re.M)
        if len(matches)!=1:raise Failure('network_owner_unverified')
        self.net_owner={'pid':int(matches[0][0]),'start':int(matches[0][1])};return self.net_owner
    def hci_status(self):
        path=self.remote+'/hci/status'
        raw=self.shell('[ ! -L '+path+' ] && if [ -f '+path+' ]; then cat '+path+'; fi')
        self.status=parse_status(raw);return self.status
    def start_bluetooth(self):
        self.started_hci=True;b=self.bt
        cmd=self.native['bluetooth']+' --relay-launch '+self.remote+'/hci '+str(b['supervisor_pid'])+' '+str(b['supervisor_start'])+' '+str(b['worker_pid'])+' '+str(b['worker_start'])+' '+BTAPP_SHA+' '+str(b['tty_fd'])
        # Always reconcile this run's status after a lost launch reply; never relaunch.
        launch=json.loads(self.shell(cmd))
        if launch.get('started') is not True:raise Failure('bluetooth_launch_unverified')
        end=time.monotonic()+4
        while time.monotonic()<end:
            state=self.hci_status()
            if state.get('result'):raise Failure('bluetooth_ended_before_forward')
            if 'relay_listening_loopback_only' in state['events']:
                if state.get('watchdog',{}).get('pid')!=launch.get('watchdog_pid'):raise Failure('bluetooth_watchdog_mismatch')
                return
            time.sleep(.1)
        raise Failure('bluetooth_listener_not_ready')
    def check(self):
        self.verify_auth()
        state=self.hci_status()
        save(self.dir/'native-status.json',state)
        if state.get('result')=='restoration_unverified_no_retry':raise Conflict('native_restoration_unverified')
        if state.get('result') and state['result']!='relay_complete_restored':raise Failure('bluetooth_session_ended_without_clean_transport')
        if self.net_error:raise Failure('network_stream_failed')
        self.radio_transports_ready=('hci_user_owned' in state.get('events',[]) and tap_ready()
            and bool(list(Path('/sys/class/bluetooth').glob('hci[0-9]*'))))
        return bool(state.get('result') or (self.net_thread and not self.net_thread.is_alive()))
    def signal_owner(self,owner,role):
        p=owner['pid'];start=owner['start'];exe=self.native[role];sha=self.m['artifacts'][role]['sha256']
        command=f'''set -eu
if [ ! -d /proc/{p} ]; then echo ABSENT; exit; fi
[ "$(awk '{{print $22}}' /proc/{p}/stat)" = {start} ] || exit 1
[ "$(readlink /proc/{p}/exe)" = {exe} ] || exit 1
[ "$(sha256sum /proc/{p}/exe | awk '{{print $1}}')" = {sha} ] || exit 1
kill -TERM {p}
echo SIGNALED'''
        if self.shell(command) not in ('ABSENT','SIGNALED'):raise Conflict('native_signal_owner_unverified')
    def stop_bluetooth(self):
        state=self.hci_status()
        if state.get('result'):return
        owner=state.get('watchdog')
        if not owner:raise Conflict('bluetooth_launch_outcome_unresolved')
        self.signal_owner(owner,'bluetooth')
        end=time.monotonic()+18
        while time.monotonic()<end:
            state=self.hci_status()
            if state.get('result'):return
            time.sleep(.2)
        raise Conflict('bluetooth_restore_timeout')
    def stop_network(self):
        if self.net_thread and self.net_thread.is_alive():
            self.signal_owner(self.network_owner(),'network');self.net_thread.join(timeout=5)
        if self.net_thread and self.net_thread.is_alive():raise Conflict('network_relay_stop_unverified')
    def guardian_process(self,owner):
        p=owner['pid']
        # The fixed guardian executable has a whitespace-free comm. If an
        # unrelated reused PID cannot be parsed, fail closed without signalling.
        command=f"if [ ! -e /proc/{p}/stat ]; then echo ABSENT; elif row=$(awk '{{print $1,$3,$22}}' /proc/{p}/stat 2>/dev/null); then echo \"$row\"; elif [ ! -e /proc/{p}/stat ]; then echo ABSENT; else echo UNREADABLE; fi"
        text=self.shell(command,seconds=2)
        if text=='ABSENT':return None
        match=re.fullmatch(r'([1-9]\d*) ([RSDTtZXxIPW]) ([1-9]\d*)',text)
        if not match:raise Failure('guardian_process_metadata_invalid')
        return {'pid':int(match[1]),'state':match[2],'start':int(match[3])}
    def verify_restored(self):
        self.verify_auth(full=True);self.r.host.pins()
        clean=True
        if self.started_hci:
            state=self.hci_status()
            clean=state.get('result') in {'relay_no_host_restored','relay_complete_restored','relay_failed_restored','launch_failed_no_mutation'}
            exit_state={'verified':False,'observation':'final_receipt_or_identity_missing'}
            if clean and state.get('watchdog'):
                try:exit_state=wait_guardian_exit(state['watchdog'],self.guardian_process)
                except Exception as error:
                    exit_state={'verified':False,'observation':'metadata_unavailable','error_type':type(error).__name__}
            state['guardian_exit']=exit_state
            self.guardian_exit_verified=exit_state['verified']
            clean=clean and self.guardian_exit_verified
            save(self.dir/'native-status.json',state)
            if self.hci_before:
                after=self.inspect_hci()
                clean=clean and (after['hci_flags']&1)==(self.hci_before['hci_flags']&1)
            save(self.dir/'native-status.json',state)
        if self.net_thread:
            text=self.net_text.decode('ascii').replace('\r\n','\n')
            endings=re.findall(r'^relay_end reason=([a-z_]+) errno=(\d+) elapsed_ms=(\d+) to_wifi=(\d+) to_host=(\d+) wifi_filtered=(\d+) host_filtered=(\d+) tx_busy=(\d+)$',text,re.M)
            clean=clean and not self.net_error and len(endings)==1 and endings[0][1]=='0'
            if len(endings)==1:
                m=endings[0];save(self.dir/'network-status.json',{'reason':m[0],'errno':int(m[1]),'elapsed_ms':int(m[2]),'to_wifi':int(m[3]),'to_host':int(m[4]),'wifi_filtered':int(m[5]),'host_filtered':int(m[6]),'tx_busy':int(m[7])})
        if self.flags is not None:clean=clean and self.shell('cat /sys/class/net/wlan0/flags')==self.flags
        clean=clean and self.stock_ports()=='0'
        end=time.monotonic()+8
        while time.monotonic()<end and (Path('/sys/class/net/ax520cp0').exists() or list(Path('/sys/class/bluetooth').glob('hci*'))):time.sleep(.2)
        clean=clean and not Path('/sys/class/net/ax520cp0').exists() and not list(Path('/sys/class/bluetooth').glob('hci*'))
        return clean and all(not self.forwarding(p) and self.r.o.listeners_absent((p,)) for p in PORTS)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest',type=Path,required=True)
    parser.add_argument('--state-dir',type=Path,required=True)
    parser.add_argument('--run-id',required=True)
    args=parser.parse_args(argv)
    if os.getuid()!=1000 or os.geteuid()!=1000:raise Failure('requires_cruiser_user')
    if not re.fullmatch('[0-9a-f]{12}',args.run_id):raise Failure('run_id_invalid')
    os.umask(0o077);manifest=validate_manifest(json.loads(read_file(args.manifest,8192)))
    args.state_dir.mkdir(mode=0o700,parents=True,exist_ok=True)
    with (args.state_dir/'supervisor.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        for previous in args.state_dir.glob('*/result.json'):
            row=json.loads(read_file(previous,16384))
            if row.get('stage') not in ('stopped_verified','failed_restored','failed_before_start','stopped_before_start'):
                raise Conflict('previous_radio_session_unresolved')
        run_dir=args.state_dir/args.run_id;run_dir.mkdir(mode=0o700)
        def stop(_signal,_frame):
            global STOP;STOP=True
        for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(sig,stop)
        session=Session(Backend(manifest,run_dir),manifest['seconds'],lambda r:save(run_dir/'result.json',r),lambda:STOP)
        result=session.run()
        return 0 if result['stage'] in ('stopped_verified','stopped_before_start') else 78 if not result['cleanup_verified'] else 1

if __name__=='__main__':raise SystemExit(main())
