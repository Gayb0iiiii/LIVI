#!/usr/bin/env python3
"""Finite ff575d0 USB endpoint trial; import performs no actions.

Controller writes only one configuration field through the supported core IPC.
No credential messages or full core snapshots are emitted or persisted.
"""
import argparse
import collections
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import struct
import time
import uuid

ENDPOINT = '127.0.0.1:15000'
FIELD = 'carPlayMfiEndpoint'
PROTOCOL = 11
MAX_FRAME = 16 * 1024 * 1024

class Failure(RuntimeError):
    pass

class Conflict(Failure):
    pass

class UncertainMutation(Failure):
    pass

class CoreSession:
    def __init__(self, path, expected_pid, deadline, expected_uid=1000):
        self.deadline = deadline
        self.stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.next_id = 1
        self.initial = None
        try:
            self._timeout()
            self.stream.connect(str(path))
            pid, uid, _gid = struct.unpack('3i', self.stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != expected_uid or pid != expected_pid:
                raise Failure('core IPC peer does not match the verified service')
            self.send({'type':'hello','protocol':PROTOCOL,'client':'bounded-endpoint-trial'})
            self.initial = self._welcome()
        except Exception:
            self.stream.close()
            raise

    def _timeout(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('IPC phase deadline')
        self.stream.settimeout(min(3,remaining))

    def send(self, message):
        body=json.dumps(message,separators=(',',':')).encode()
        if len(body)>MAX_FRAME:
            raise Failure('outgoing frame exceeds limit')
        self._timeout()
        self.stream.sendall(struct.pack('<I',len(body))+body)

    def exact(self, size):
        data=bytearray()
        while len(data)<size:
            self._timeout()
            chunk=self.stream.recv(size-len(data))
            if not chunk:
                raise ConnectionError('core IPC closed')
            data.extend(chunk)
        return bytes(data)

    def receive(self):
        size=struct.unpack('<I',self.exact(4))[0]
        if size>MAX_FRAME:
            raise Failure('incoming frame exceeds limit')
        try:
            message=json.loads(self.exact(size))
        except (ValueError,UnicodeError):
            raise Failure('core IPC returned invalid JSON') from None
        if not isinstance(message,dict):
            raise Failure('core IPC returned an invalid message')
        return message

    def _welcome(self):
        for _ in range(256):
            message=self.receive()
            if message.get('type')=='refused':
                raise Failure('core IPC refused the protocol')
            if message.get('type')!='welcome':
                continue
            if message.get('protocol')!=PROTOCOL:
                raise Failure('core IPC protocol differs')
            state=message.get('state',{})
            if not isinstance(state,dict):raise Failure('core state is not an object')
            config=state.get('config',{})
            sessions=state.get('sessions',{})
            playing=state.get('nowPlaying',{})
            if not all(isinstance(value,dict) for value in (config,sessions,playing)):
                raise Failure('required core state sections are not objects')
            endpoint=config.get(FIELD)
            if sessions.get('active') not in (None,'carplay','androidauto','airplay'):
                raise Failure('session protocol metadata is invalid')
            if not isinstance(endpoint,str) or type(sessions.get('total')) is not int:
                raise Failure('required state fields missing')
            # Discard the broader snapshot immediately. Only allowlisted scalar
            # metadata crosses this boundary; no names, identities or secrets.
            return {'endpoint':endpoint,'sessions_total':sessions['total'],
                    'session_active':sessions.get('active'),
                    'session_video':sessions.get('video') is True,
                    'playing':playing.get('playing') is True}
        raise Failure('welcome not received within bounded frame count')

    def snapshot(self):
        if self.initial is not None:
            result,self.initial=self.initial,None
            return result
        self.send({'type':'resync'})
        return self._welcome()

    def action(self, kind, patch=None):
        action={'kind':kind}
        if patch is not None:
            action['patch']=patch
        request_id=self.next_id
        self.next_id+=1
        self.send({'type':'action','id':request_id,'action':action})
        for _ in range(256):
            message=self.receive()
            if message.get('type')=='reply' and message.get('id')==request_id:
                if message.get('error') is not None:
                    raise Failure('core rejected the requested action')
                return
        raise Failure('reply not received within bounded frame count')

    def close(self):
        self.stream.close()
    def __enter__(self):
        return self
    def __exit__(self,*_args):
        self.close()


def patch_endpoint_once(factory, expected, desired, deadline):
    """One submission, then fresh readback; uncertain ACK never triggers resend."""
    acknowledged=False
    with factory(deadline) as client:
        before=client.snapshot()
        if before['endpoint']==desired:
            return {'verified':True,'submitted':False,'acknowledged':False,'view':before}
        if before['endpoint']!=expected:
            raise Conflict('endpoint changed outside this trial; not overwritten')
        try:
            client.action('setConfig',{FIELD:desired})
            acknowledged=True
        except (OSError,ConnectionError,TimeoutError):
            pass
    try:
        with factory(deadline) as client:
            after=client.snapshot()
    except (OSError,ConnectionError,TimeoutError):
        raise UncertainMutation('patch outcome is unresolved after transport loss') from None
    if after['endpoint']!=desired:
        if after['endpoint']!=expected:
            raise Conflict('endpoint changed during the operation; not overwritten')
        if not acknowledged:
            raise UncertainMutation('unacknowledged patch may still be pending; not retried')
        raise Failure('single patch submission was not observed; not retried')
    return {'verified':True,'submitted':True,'acknowledged':acknowledged,'view':after}


def reconcile_restore(factory, pending_activation, deadline, poll=.25):
    """Resolve late activation before issuing one field-only restoration patch."""
    while time.monotonic()<deadline:
        with factory(deadline) as client:
            view=client.snapshot()
        if view['endpoint']==ENDPOINT:
            return patch_endpoint_once(factory,ENDPOINT,'',deadline)
        if view['endpoint']!='':
            raise Conflict('endpoint changed outside this trial; restoration not overwritten')
        pending=pending_activation() if callable(pending_activation) else pending_activation
        if not pending:
            return {'verified':True,'submitted':False,'acknowledged':False,'view':view}
        time.sleep(min(poll,max(0,deadline-time.monotonic())))
    raise UncertainMutation('late activation remains unresolved; empty readback is not cancellation')


class OnceRecovery:
    """Only a missing core/socket may cause one separately verified restart."""
    def __init__(self, factory, recover):
        self.factory=factory
        self.recover=recover
        self.used=False
    def __call__(self, deadline):
        try:
            return self.factory(deadline)
        except OSError as exc:
            if self.used or exc.errno not in (2,111):
                raise
            self.used=True
            self.recover(deadline)
            return self.factory(deadline)


class SessionTransitions:
    def __init__(self):
        self.connected=False
        self.down=False
        self.reconnected=False
        self.video=False
        self.playing=False
        self.samples=0
    def observe(self, view):
        self.samples+=1
        active=view['session_active']=='carplay' and view['sessions_total']>0
        if active:
            if self.connected and self.down:
                self.reconnected=True
            self.connected=True
        elif self.connected:
            self.down=True
        self.video |= active and view['session_video']
        self.playing |= view['playing']
    def result(self):
        return {'samples':self.samples,'carplay_session_observed':self.connected,
                'session_drop_observed':self.down,'reconnection_observed':self.reconnected,
                'video_flag_observed':self.video,'playing_flag_observed':self.playing,
                'audible_audio_verified':False}

VERIFIER_SHA='6b811f7439c4c4b8cf53fb579c305f0415882a99f8ba5dcd94b6eb2898a2af3a'
BASE=Path('/home/cruiser/LIVI/ax520-auth-trial-20261112-a92b49c1')
CONFIGS=(Path('/home/cruiser/.config/LIVI/config.json'),Path('/home/cruiser/.local/share/LIVI/config.json'))
SHARED_SOCKET=Path('/tmp/livi-shared.sock')
LOG=Path('/home/cruiser/.config/LIVI/log/LIVI.log')


def load_verifier(path):
    path=Path(path)
    if not stat.S_ISREG(path.lstat().st_mode) or hashlib.sha256(path.read_bytes()).hexdigest()!=VERIFIER_SHA:
        raise Failure('reviewed verification module hash does not match')
    spec=importlib.util.spec_from_file_location('reviewed_livi_verifier',str(path))
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LogCursor:
    STAMP=re.compile(r'^\[\d\d:\d\d:\d\d\.\d\d\d\] ')
    WRAPPER=re.compile(r'^\[helper!?\] (?=\[)')
    EVENTS={
        'endpoint_selected':re.compile(r'^\[helper\] MFi endpoint 127\.0\.0\.1:15000: protocol major [23] \(authentication not yet tested\)$'),
        'local_provider_selected':re.compile(r'^\[helper\] (?:opening MFi bus=-?\d+ gpio=-?\d+|MFi from the imported files in .*)$'),
        'phone_auth_accepted':re.compile(r'^\[cp\] wired: MFi auth succeeded$'),
        'identification_accepted':re.compile(r'^\[cp\] wired: identification accepted$'),
        'start_session_sent':re.compile(r'^\[cp\] wired: CarPlayStartSession sent$'),
        'audio_stream_setup':re.compile(r'^\[airplay\] audio '),
        'settings_auto_applied':re.compile(r'^\[core\] settings applied with no phone connected, the helper restarts$'),
        'settings_manual_applied':re.compile(r'^\[core\] applying the settings: helper restart, phones reconnect$'),
    }
    def __init__(self,path=LOG):
        self.path=Path(path)
        self.counts=collections.Counter()
        self.pending=b''
        self.file=None
        self._open(at_end=True)
    def _open(self,at_end=False):
        fd=os.open(self.path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            os.close(fd)
            raise Failure('LIVI log is not a regular file')
        self.file=os.fdopen(fd,'rb')
        self.inode=(info.st_dev,info.st_ino)
        if at_end:self.file.seek(0,os.SEEK_END)
    def _drain(self):
        data=self.file.read(256*1024)
        rows=(self.pending+data).split(b'\n')
        self.pending=rows.pop()
        if len(self.pending)>65536:self.pending=b''
        for raw in rows:
            if len(raw)>65536:continue
            line=self.WRAPPER.sub('',self.STAMP.sub('',raw.decode('utf-8',errors='replace')),count=1)
            for label,pattern in self.EVENTS.items():
                if pattern.search(line):self.counts[label]+=1
    def read(self):
        self._drain()
        try:
            info=self.path.lstat()
        except FileNotFoundError:
            return dict(self.counts)
        if (info.st_dev,info.st_ino)!=self.inode:
            self.file.close()
            self.pending=b''
            self._open()
            self._drain()
        return dict(self.counts)
    def close(self):
        if self.file:self.file.close()


class Host:
    def __init__(self, verifier, report, save):
        self.v=verifier
        self.report=report
        self.save=save
        self.core_id=None
        self.original_core=None
        self.socket_path=None
        self.original_core_gone=False
        self.unit_backup=BASE/'livi-kiosk.original.service'

    def pins(self):
        for path,expected in ((self.v.APPIMAGE,self.v.NEW_APP),(self.v.HELPER,self.v.NEW_HELPER),
                              (self.v.UNIT,self.v.UNIT_SHA),(self.unit_backup,self.v.UNIT_SHA)):
            self.v.checked(path,expected)

    def core(self, deadline):
        state=self.v.state(self.v.SERVICE,deadline)
        if state['active'] in ('inactive','failed') and state['pid']==0:
            raise FileNotFoundError(2,'verified core is absent')
        if not self.v.normal(state):
            raise Failure('core service is not running with the original environment')
        current=self.v.identity(state['pid'])
        if current!=self.core_id:
            self.pins()
            runtime=self.v.runtime_executables(state['pid'])
            if (runtime['livi-core']['pid']!=state['pid'] or
                    {name:item['sha256'] for name,item in runtime.items()}!=self.v.NEW_EXEC):
                raise Failure('core runtime is not the verified installed ff575d0 build')
            self.core_id=current
            self.socket_path=None
            self.report['current_core']=current
            self.report['runtime_hash_source']='launch_path' if not all(x['live_executable_hashes_verified'] for x in runtime.values()) else 'live_executable'
            if self.original_core is not None and current!=self.original_core:
                try:
                    self.original_core_gone=self.v.identity(self.original_core['pid'])!=self.original_core
                except OSError:
                    self.original_core_gone=True
        if self.original_core is None:
            self.original_core=current
        return current

    def factory(self, deadline):
        core=self.core(deadline)
        paths=[Path('/run/user/1000/livi/core.sock'),Path('/tmp/livi-1000/core.sock')]
        if self.socket_path in paths:
            paths.remove(self.socket_path)
            paths.insert(0,self.socket_path)
        for path in paths:
            try:
                client=CoreSession(path,core['pid'],deadline)
            except OSError as exc:
                if exc.errno not in (2,111):raise
                continue
            if self.v.identity(core['pid'])!=core:
                client.close()
                raise Failure('core identity changed while opening IPC')
            self.socket_path=path
            return client
        raise FileNotFoundError(2,'neither verified core socket is available')

    def view(self, deadline, connector=None):
        with (connector or self.factory)(deadline) as client:
            return client.snapshot()

    def helper(self, deadline):
        core=self.core(deadline)
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as stream:
            stream.settimeout(min(2,max(.01,deadline-time.monotonic())))
            stream.connect(str(SHARED_SOCKET))
            pid,uid,_gid=struct.unpack('3i',stream.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        if uid!=0 or Path(f'/proc/{pid}/comm').read_text().strip()!='livi-helperd':
            raise Failure('shared socket peer is not the root helper')
        current=self.v.identity(pid)
        ancestor=pid
        for _ in range(32):
            if ancestor==core['pid']:
                break
            if ancestor<=1:
                raise Failure('root helper is not descended from the verified core')
            ancestor=self.v.proc_stat(ancestor)['ppid']
        else:
            raise Failure('helper ancestry exceeded the bounded depth')
        if self.v.identity(pid)!=current:
            raise Failure('root helper identity changed during verification')
        return current

    def configs_empty(self):
        for path in CONFIGS:
            if not stat.S_ISREG(path.lstat().st_mode):
                raise Failure('configuration path is not a regular file')
            try:
                content=json.loads(path.read_bytes())
            except (ValueError,UnicodeError):
                raise Failure('persisted settings are not valid JSON') from None
            if not isinstance(content,dict) or content.get(FIELD)!='':
                return False
        return True

    def recover(self, deadline):
        # Called only once by OnceRecovery, and only for absence/refusal.
        self.pins()
        if not self.v.switch_idle(deadline):
            raise Failure('a service switch is active; no overlapping recovery')
        state=self.v.state(self.v.SERVICE,deadline)
        previous=self.v.identity(state['pid']) if state['pid']>1 else {'pid':0,'start':0}
        if self.v.normal(state):
            try:
                with self.factory(deadline):
                    return # Socket recovered by itself; no restart is needed.
            except OSError as exc:
                if exc.errno not in (2,111):raise
        elif not (state['pid']==0 and state['active'] in ('inactive','failed')):
            raise Failure('unexpected service state prevents supported recovery')
        self.report['recovery_restart_attempted']=True
        self.save('supported_recovery_submitting')
        self.report['recovery_submit_code']=self.v.install_original_unit(self.unit_backup,deadline)
        while time.monotonic()<deadline:
            try:
                current=self.core(deadline)
                if current!=previous and self.v.switch_idle(deadline):
                    with self.factory(deadline):
                        self.report['recovery_restart_verified']=True
                        self.save('supported_recovery_verified')
                        return
            except (OSError,Failure,self.v.Failure):
                pass
            time.sleep(.25)
        raise Failure('one supported recovery restart was not verified before deadline')


def provider_ready(deadline):
    with socket.create_connection(('127.0.0.1',15000),timeout=min(2,max(.01,deadline-time.monotonic()))) as stream:
        stream.settimeout(min(2,max(.01,deadline-time.monotonic())))
        stream.sendall(b'\x03')
        data=b''
        while len(data)<4:
            chunk=stream.recv(4-len(data))
            if not chunk:raise Failure('provider metadata closed early')
            data+=chunk
        if data not in (b'\x00\x00\x01\x02',b'\x00\x00\x01\x03'):
            raise Failure('provider metadata did not match the reviewed protocol')


def apply_once(host, connector, report, save, deadline):
    report['restore_apply_attempted']=True
    save('restore_apply_submitting')
    try:
        with connector(deadline) as client:
            # Fresh same-field guard before a global apply. Never overwrite or
            # apply a foreign endpoint selection discovered during restoration.
            if client.snapshot()['endpoint']!='':
                raise Conflict('endpoint changed before apply; not forced')
            client.action('applySettings')
        report['restore_apply_acknowledged']=True
    except (OSError,ConnectionError,TimeoutError):
        report['restore_apply_acknowledged']=False
    # No repeat after uncertain acknowledgment; observe actual helper outcome.


def restore_trial(host, logs, report, save, deadline):
    connector=OnceRecovery(host.factory,host.recover)
    before_counts=logs.read()
    try:
        previous_helper=host.helper(deadline)
    except (OSError,Failure):
        previous_helper=None
        report['restore_initial_helper_unverified']=True
    result=reconcile_restore(connector,
        lambda: report.get('activation_pending',False) and not host.original_core_gone,
        deadline)
    report['endpoint_clear']={key:result[key] for key in ('verified','submitted','acknowledged')}
    report['activation_pending']=False
    save('endpoint_clear_verified')
    wait_started=time.monotonic()
    manual_baseline=previous_helper
    manual_baseline_since=wait_started
    stable_helper=None
    stable_since=None
    while time.monotonic()<deadline:
        view=host.view(deadline,connector)
        if view['endpoint']!='':
            raise Conflict('endpoint changed during restoration; not overwritten')
        counts=logs.read()
        helper=None
        try:
            helper=host.helper(deadline)
        except (OSError,Failure):
            pass
        if manual_baseline is None and helper is not None:
            manual_baseline=helper
            manual_baseline_since=time.monotonic()
        newly_local=(helper is not None and helper!=previous_helper and
                     counts.get('local_provider_selected',0)>before_counts.get('local_provider_selected',0))
        if newly_local and host.configs_empty():
            if stable_helper!=helper:
                stable_helper=helper
                stable_since=time.monotonic()
            elif time.monotonic()-stable_since>=2:
                host.pins()
                report['restored_helper']=helper
                report['restored_verified']=True
                report['log_counts']=counts
                save('restored_verified')
                return
        else:
            stable_helper=None
            stable_since=None
        elapsed=time.monotonic()-wait_started
        applied_observed=any(counts.get(key,0)>before_counts.get(key,0)
                             for key in ('settings_auto_applied','settings_manual_applied'))
        if (not report.get('restore_apply_attempted') and not applied_observed
                and helper is not None and helper==manual_baseline
                and time.monotonic()-manual_baseline_since>=2 and elapsed>=2
                and (view['sessions_total']>0 or elapsed>=8)):
            apply_once(host,connector,report,save,deadline)
        time.sleep(.25)
    raise Failure('endpoint application/restoration was not verified before deadline')


stopping=False

def stop_request(_signum,_frame):
    global stopping
    stopping=True


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',action='store_true')
    parser.add_argument('--provider-ready',action='store_true',help='operator verified the independent bounded stock bridge/forwarder')
    parser.add_argument('--verifier-file',required=True)
    parser.add_argument('--seconds',type=int,default=30)
    args=parser.parse_args(argv)
    if not args.run or not args.provider_ready or not 1<=args.seconds<=120:
        parser.error('--run --provider-ready and seconds 1..120 are required')
    if os.getuid()!=1000 or os.geteuid()!=1000:
        raise SystemExit('run as cruiser uid1000')
    invocation=os.environ.get('INVOCATION_ID','')
    if len(invocation)!=32 or any(c not in '0123456789abcdef' for c in invocation):
        raise SystemExit('run in a finite user-systemd service, RuntimeMaxSec=210s TimeoutStopSec=15s')
    os.umask(0o077)
    verifier=load_verifier(args.verifier_file)
    lock=(BASE/'.host-trial.lock').open('a')
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    for kind in (signal.SIGTERM,signal.SIGINT):signal.signal(kind,stop_request)
    signal.signal(signal.SIGHUP,signal.SIG_IGN)
    run_id=uuid.uuid4().hex[:12]
    journal=BASE/('endpoint-trial-ff575d0-usb-'+run_id+'.json')
    report={'run_id':run_id,'mutation_attempted':False,'activation_pending':False,
            'endpoint_selected':False,'restored_verified':False,'audible_audio_verified':False,
            'recovery_restart_attempted':False,'restore_apply_attempted':False}
    def save(stage):
        report['stage']=stage
        temporary=journal.with_suffix('.tmp')
        with temporary.open('w') as file:
            json.dump(report,file,indent=2)
            file.write('\n');file.flush();os.fsync(file.fileno())
        os.replace(temporary,journal)
    save('preflight')
    print('ENDPOINT_TRIAL_JOURNAL='+str(journal),flush=True)
    started=time.monotonic()
    host=Host(verifier,report,save)
    logs=None
    tracker=SessionTransitions()
    error=None
    restore_deadline=started+195
    try:
        host.pins()
        if not verifier.switch_idle(started+25):raise Failure('a kiosk switch is already active')
        view=host.view(started+25)
        if view['endpoint']!='' or view['sessions_total']!=0 or not host.configs_empty():
            raise Failure('initial endpoint must be disabled and phone sessions idle')
        report['original_core']=host.core_id
        report['original_helper']=host.helper(started+25)
        provider_ready(started+25)
        logs=LogCursor()
        if stopping:raise Failure('stop requested before mutation')
        window_end=time.monotonic()+args.seconds
        restore_deadline=min(started+195,window_end+45)
        report['mutation_attempted']=True
        report['activation_pending']=True
        save('endpoint_patch_submitting')
        result=patch_endpoint_once(host.factory,'',ENDPOINT,min(window_end,time.monotonic()+12))
        report['activation_pending']=False
        report['endpoint_patch']={key:result[key] for key in ('verified','submitted','acknowledged')}
        save('endpoint_persisted_waiting_for_autoapply')
        selected_until=min(window_end,time.monotonic()+25)
        while not stopping and time.monotonic()<selected_until:
            counts=logs.read()
            helper=None
            try:helper=host.helper(selected_until)
            except OSError:pass
            if helper is not None and helper!=report['original_helper'] and counts.get('endpoint_selected',0)>0:
                report['trial_helper']=helper
                report['endpoint_selected']=True
                save('endpoint_selected')
                break
            time.sleep(.25)
        if not report['endpoint_selected']:
            raise Failure('idle auto-apply endpoint selection was not verified')
        while not stopping and time.monotonic()<window_end:
            view=host.view(window_end)
            if host.core_id!=host.original_core:raise Failure('core restarted during observation')
            if view['endpoint']!=ENDPOINT:raise Conflict('endpoint changed during trial')
            tracker.observe(view)
            report['observation']=tracker.result()
            report['log_counts']=logs.read()
            report['window_remaining_seconds']=max(0,int(window_end-time.monotonic()))
            save('observing_manual_phone_reconnection')
            time.sleep(min(1,max(0,window_end-time.monotonic())))
    except Exception as exc:
        error=exc
        report['error_type']=type(exc).__name__
        if isinstance(exc,Failure):report['error']=str(exc)
        save('trial_interrupted')
    finally:
        report['observation']=tracker.result()
        if report['mutation_attempted']:
            try:
                save('restoration_started')
                restore_trial(host,logs,report,save,restore_deadline)
            except Exception as exc:
                report['restore_error_type']=type(exc).__name__
                if isinstance(exc,Failure):report['restore_error']=str(exc)
                save('restoration_unverified')
                if error is None:error=exc
        else:
            report['original_unchanged']=True
        if logs:
            report['log_counts']=logs.read()
            logs.close()
        report['elapsed_seconds']=round(time.monotonic()-started,3)
        report['exit_code']=0 if error is None and report['restored_verified'] else 1
        save('complete' if report['exit_code']==0 else 'failed')
        print('ENDPOINT_TRIAL_RESULT='+('RESTORED' if report['restored_verified'] else 'UNVERIFIED'),flush=True)
        print('ENDPOINT_TRIAL_JOURNAL='+str(journal),flush=True)
        lock.close()
    return report['exit_code']


if __name__=='__main__':raise SystemExit(main())
