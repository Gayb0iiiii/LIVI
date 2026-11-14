#!/usr/bin/env python3
"""Finite, local-only Cruiser own-fork update coordinator.

Deploy only after the host and stock trials are independently verified restored.
Run under a finite user-systemd service, never directly in an SSH session:
  systemd-run --user --collect --unit=livi-update-ff575d0-UNIQUE \
    --property=RuntimeMaxSec=480s --property=TimeoutStopSec=20s \
    /usr/bin/python3 THIS_SCRIPT --run --trials-restored
Requires the already functioning cruiser user manager. No firmware operations,
network requests, credential output, or experimental endpoint activation.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import uuid

BASE = Path('/home/cruiser/LIVI/update-ff575d0-6a5f1f6c6b72')
TRIAL_BASE = Path('/home/cruiser/LIVI/ax520-auth-trial-20261112-a92b49c1')
APPIMAGE = Path('/home/cruiser/LIVI/LIVI.AppImage')
STAGED = BASE / 'LIVI.AppImage.new'
HELPER = Path('/home/cruiser/.config/LIVI/driver/livi-helperd')
UNIT = Path('/etc/systemd/system/livi-kiosk.service')
CONFIGS = (Path('/home/cruiser/.config/LIVI/config.json'),
           Path('/home/cruiser/.local/share/LIVI/config.json'))
OLD_APP = '64c595a6de164330e369d8d8c365d8d6e54e3a35a10e4c1717a330d63728a6ec'
NEW_APP = '1bc64f63396aad36b7c615b566780b1509b3b62737c08b4177f50ab58c347872'
NEW_SIZE = 117135880
OLD_HELPER = 'f9e584ce59f80aedc1179f461f6fc5f49ce65afc5f51fd8bc800a29cbb970a84'
NEW_HELPER = '170b11d3c5e9a56e175b800b4c7c54f81078fb9f5e442513b2adf11dfac4d67a'
UNIT_SHA = 'd0bfd5120a4b164f974e47de54f487b3d6383bd271a5d3024ded3e6e1244f3ae'
OLD_EXEC = {
    'livi-core': '1d371aac2e3e10ddd1fa5cd91d28ab60a6c23161208db8d28e9094a167aa52b6',
    'livi-ui': '3954cdf6d53f3595e4ea3d888164315be38e9c850a00e38aa094828ec4cc8a23',
    'livi-compositor': 'fdf619dd382e3969b3a9c0856b3c62fb27990b48f91be8578e15a733d1b06d24',
}
NEW_EXEC = {
    'livi-core': 'a1d62868fac376943c8e0d2fff447a69f6257bbef3b2c6db832bdb0f983751e8',
    'livi-ui': 'c535849141fe3b27433a99d072d2481f3775654000976a5834571179ed83251a',
    'livi-compositor': 'fdf619dd382e3969b3a9c0856b3c62fb27990b48f91be8578e15a733d1b06d24',
}
SERVICE = 'livi-kiosk.service'
SWITCH = 'livi-kiosk-switch.service'
NORMAL_ENV = {'LIVI_KIOSK': '1'}
stopping = False


class Failure(RuntimeError):
    pass


def stop_request(_signum, _frame):
    global stopping
    stopping = True


def file_hash(path, regular=True):
    if regular and not stat.S_ISREG(path.lstat().st_mode):
        raise Failure('non-regular or symlink file rejected')
    h = hashlib.sha256()
    with path.open('rb') as file:
        for block in iter(lambda: file.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def checked(path, expected):
    if file_hash(path) != expected:
        raise Failure('pinned hash mismatch: ' + path.name)


def command(argv, deadline, maximum=5):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise Failure('phase deadline expired')
    return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, text=True, check=False,
                          timeout=min(maximum, remaining))


def state(service, deadline):
    result = command(['/usr/bin/systemctl', 'show', service,
                      '--property=LoadState,ActiveState,SubState,MainPID,Environment'], deadline)
    if result.returncode:
        raise Failure('system service state unavailable')
    fields = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    try:
        env = dict(item.split('=', 1) for item in shlex.split(fields.get('Environment', '')))
        pid = int(fields.get('MainPID', '0'))
    except (ValueError, TypeError):
        raise Failure('malformed service metadata') from None
    return {'load': fields.get('LoadState'), 'active': fields.get('ActiveState'),
            'sub': fields.get('SubState'), 'pid': pid, 'environment': env}


def public_state(value):
    return {key: value[key] for key in ('load', 'active', 'sub', 'pid')}


def normal(value):
    return value['active'] == 'active' and value['pid'] > 1 and value['environment'] == NORMAL_ENV


def switch_idle(deadline):
    value = state(SWITCH, deadline)
    return value['load'] == 'not-found' or value['active'] in ('inactive', 'failed')


def wait_switch_idle(deadline):
    while not switch_idle(deadline):
        if time.monotonic() >= deadline:
            raise Failure('existing switch did not become idle; no overlapping retry')
        time.sleep(.25)


def proc_stat(pid):
    raw = Path(f'/proc/{pid}/stat').read_text()
    fields = raw[raw.rfind(')') + 2:].split()
    return {'ppid': int(fields[1]), 'start': int(fields[19])}


def identity(pid):
    return {'pid': pid, 'start': proc_stat(pid)['start']}


ROLE_PATHS = {
    'livi-core': 'resources/core/livi-core',
    'livi-ui': 'livi-ui',
    'livi-compositor': 'resources/compositor/livi-compositor',
}


def first_argument(pid):
    # Read argv[0] only. Other arguments and process environments are not read.
    value = bytearray()
    with Path(f'/proc/{pid}/cmdline').open('rb', buffering=0) as file:
        for _ in range(4096):
            char = file.read(1)
            if char in (b'', b'\0'):
                break
            value.extend(char)
        else:
            raise Failure('process launch path exceeds the bounded length')
    try:
        return value.decode('utf-8')
    except UnicodeError:
        raise Failure('process launch path is not valid UTF-8') from None


def checked_launch_path(pid, role):
    path = Path(first_argument(pid))
    if (not path.is_absolute() or len(path.parts) < 4 or path.parts[1] != 'tmp'
            or not path.parts[2].startswith('.mount_LIVI.')
            or path.parts[2] == '.mount_LIVI.'):
        raise Failure('process did not launch from the expected AppImage mount layout')
    mount = Path('/tmp') / path.parts[2]
    if path != mount / ROLE_PATHS[role]:
        raise Failure('process launch path does not match its expected role')
    # These exact paths contain no spaces/backslashes, so mountinfo escaping is
    # not needed. Reject any ambiguous/missing or writable mount record.
    entries = []
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        left, separator, right = line.partition(' - ')
        fields, detail = left.split(), right.split()
        if separator and len(fields) > 5 and len(detail) > 2 and fields[4] == str(mount):
            entries.append((fields[5].split(','), detail[0]))
    if len(entries) != 1 or 'ro' not in entries[0][0] or not entries[0][1].startswith('fuse'):
        raise Failure('launch path is not on one verified read-only FUSE mount')
    # This is a file hash at a reviewed launch path, NOT a live executable hash.
    checksum = file_hash(path)
    return path, mount, checksum


def process_evidence(pid, role):
    if Path(f'/proc/{pid}').stat().st_uid != 1000:
        raise Failure('runtime process is not owned by cruiser')
    before = identity(pid)
    if Path(f'/proc/{pid}/comm').read_text().strip() != role:
        raise Failure('runtime comm does not match the expected role')
    launch, mount, launch_sha = checked_launch_path(pid, role)
    exe = Path(f'/proc/{pid}/exe')
    try:
        if Path(os.readlink(exe).removesuffix(' (deleted)')).name != role:
            raise Failure('runtime executable name does not match its role')
        checksum = file_hash(exe, regular=False)
        if checksum != launch_sha:
            raise Failure('live executable differs from its reviewed launch path')
        verified = True
        source = 'live_executable'
    except PermissionError:
        checksum = launch_sha
        verified = False
        source = 'launch_path'
    if identity(pid) != before:
        raise Failure('process identity changed while collecting runtime evidence')
    return {**before, 'sha256': checksum, 'hash_source': source,
            'launch_path': str(launch), 'appimage_mount': str(mount),
            'live_executable_hashes_verified': verified}


def runtime_executables(main_pid):
    # Read process topology, then only names, argv[0], and hashes of known roles.
    # Descendants cover PAM session cgroup migration without exposing argv/env.
    all_procs = {}
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if entry.stat().st_uid == 1000:
                all_procs[int(entry.name)] = proc_stat(int(entry.name))
        except (OSError, ValueError, IndexError):
            pass
    allowed = {main_pid}
    while True:
        extra = {pid for pid, info in all_procs.items() if info['ppid'] in allowed}
        if extra <= allowed:
            break
        allowed |= extra
    found = {}
    for pid in allowed:
        try:
            role = Path(f'/proc/{pid}/comm').read_text().strip()
            if role not in ROLE_PATHS:
                continue
            value = process_evidence(pid, role)
            if role in found:
                raise Failure('multiple runtime processes for a required role')
            found[role] = value
        except (FileNotFoundError, ProcessLookupError):
            continue
    if set(found) != set(NEW_EXEC):
        raise Failure('required runtime processes not all observable as service descendants')
    if len({value['appimage_mount'] for value in found.values()}) != 1:
        raise Failure('runtime roles did not launch from the same AppImage mount')
    return found


def atomic_copy(source, destination, expected, mode):
    checked(source, expected)
    with tempfile.NamedTemporaryFile(dir=destination.parent, prefix='.livi-update-', delete=False) as target:
        temporary = Path(target.name)
        try:
            with source.open('rb') as original:
                shutil.copyfileobj(original, target, 1024 * 1024)
            target.flush()
            os.fchmod(target.fileno(), mode)
            os.fsync(target.fileno())
            checked(temporary, expected)
            os.replace(temporary, destination)
            directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)
    checked(destination, expected)


def config_info(path):
    if not path.exists() and not path.is_symlink():
        return {'exists': False}
    checksum = file_hash(path)
    # Inspect only whether the experimental option is disabled, never record values.
    try:
        value = json.loads(path.read_bytes())
    except (ValueError, UnicodeError):
        raise Failure('config is not valid JSON; do not risk defaulting settings') from None
    if not isinstance(value, dict) or value.get('carPlayMfiEndpoint', '') != '':
        raise Failure('config has an enabled external endpoint or invalid root')
    return {'exists': True, 'sha256': checksum, 'mode': stat.S_IMODE(path.stat().st_mode)}


def snapshot_configs(backup):
    records = []
    for index, path in enumerate(CONFIGS):
        item = config_info(path)
        if item['exists']:
            saved = backup / f'config-{index}.json'
            atomic_copy(path, saved, item['sha256'], 0o600)
        records.append(item)
    return records


def restore_configs(backup, records):
    for index, (path, item) in enumerate(zip(CONFIGS, records)):
        if item['exists']:
            atomic_copy(backup / f'config-{index}.json', path, item['sha256'], item['mode'])
        elif path.exists() or path.is_symlink():
            if not stat.S_ISREG(path.lstat().st_mode):
                raise Failure('new config path is not a regular file; not removed')
            path.unlink()


def configs_match(records):
    return [config_info(path) == item for path, item in zip(CONFIGS, records)]


def install_original_unit(source, deadline):
    checked(source, UNIT_SHA)
    checked(UNIT, UNIT_SHA)
    if file_hash(HELPER) not in (OLD_HELPER, NEW_HELPER):
        raise Failure('installed helper is not a reviewed version')
    if not switch_idle(deadline):
        raise Failure('switch already active; no overlapping restart')
    return command(['/usr/bin/sudo', '-n', str(HELPER), '--install-kiosk-unit', str(source)],
                   deadline, maximum=10).returncode


def await_runtime(previous, expected_exec, expected_helper, deadline, interruptible=True):
    stable_since = None
    stable_snapshot = None
    last_reason = 'service did not restart'
    while time.monotonic() < deadline:
        if interruptible and stopping:
            raise Failure('stop requested during activation')
        try:
            value = state(SERVICE, deadline)
            if not normal(value) or identity(value['pid']) == previous or not switch_idle(deadline):
                raise Failure('fresh normal service and idle switch not yet observed')
            checked(UNIT, UNIT_SHA)
            checked(HELPER, expected_helper)
            if stat.S_IMODE(HELPER.stat().st_mode) != 0o755:
                raise Failure('installed helper is not mode 0755')
            runtime = runtime_executables(value['pid'])
            if runtime['livi-core']['pid'] != value['pid']:
                raise Failure('service MainPID is not the verified core')
            if {name: item['sha256'] for name, item in runtime.items()} != expected_exec:
                raise Failure('running executables do not match the expected version')
            current = {'service': public_state(value), 'identity': identity(value['pid']), 'runtime': runtime,
                       'live_executable_hashes_verified': all(item['live_executable_hashes_verified'] for item in runtime.values())}
            if current != stable_snapshot:
                stable_snapshot = current
                stable_since = time.monotonic()
            elif time.monotonic() - stable_since >= 8:
                return current
        except (Failure, OSError, ValueError) as exc:
            stable_since = None
            stable_snapshot = None
            last_reason = str(exc) if isinstance(exc, Failure) else type(exc).__name__
        time.sleep(.5)
    raise Failure('runtime verification deadline: ' + last_reason)


def stop_verified_core(report, deadline):
    before = state(SERVICE, deadline)
    if before['active'] in ('inactive', 'failed') and before['pid'] == 0:
        return
    if not normal(before):
        raise Failure('cannot stop an unexpected service state for rollback')
    pid = before['pid']
    if Path(f'/proc/{pid}').stat().st_uid != 1000:
        raise Failure('rollback core is not owned by cruiser')
    pinned = identity(pid)
    fd = os.pidfd_open(pid)
    try:
        if identity(pid) != pinned:
            raise Failure('rollback core changed before stop')
        evidence = process_evidence(pid, 'livi-core')
        if evidence['sha256'] not in (NEW_EXEC['livi-core'], report['original_executable_hashes']['livi-core']):
            raise Failure('core launch file is not one of the two reviewed versions')
        current = state(SERVICE, deadline)
        if not normal(current) or current['pid'] != pid or identity(pid) != pinned:
            raise Failure('rollback core/service changed while verifying evidence')
        report['rollback_stop_evidence'] = evidence
        signal.pidfd_send_signal(fd, signal.SIGTERM)
    finally:
        os.close(fd)
    # No SIGKILL fallback: failure leaves immutable backups and reports uncertainty.
    stop_deadline = min(deadline, time.monotonic() + 100)
    while time.monotonic() < stop_deadline:
        value = state(SERVICE, stop_deadline)
        try:
            still_same = identity(pid) == pinned
        except (OSError, ValueError):
            still_same = False
        if not still_same and value['pid'] == 0 and value['active'] in ('inactive', 'failed'):
            return
        time.sleep(.25)
    raise Failure('verified core did not stop; live config files were not overwritten')


def rollback(backup, report, save, deadline):
    # First finish an uncertain activation switch. Never overlap its fixed unit.
    wait_switch_idle(deadline)
    checked(UNIT, UNIT_SHA)
    if file_hash(APPIMAGE) not in (OLD_APP, NEW_APP):
        raise Failure('AppImage changed outside the coordinator; not overwritten')
    if file_hash(HELPER) not in (OLD_HELPER, NEW_HELPER):
        raise Failure('helper changed outside the coordinator; not overwritten')
    stop_verified_core(report, deadline)
    save('rollback_core_stopped')
    atomic_copy(backup / 'LIVI.AppImage.original', APPIMAGE, OLD_APP, 0o755)
    atomic_copy(backup / 'livi-helperd.original', HELPER, OLD_HELPER, 0o755)
    restore_configs(backup, report['configs_before'])
    save('rollback_files_restored')
    report['rollback_submit_code'] = install_original_unit(backup / 'livi-kiosk.original.service', deadline)
    save('rollback_restart_submitted')
    restored = await_runtime({'pid': 0, 'start': 0}, report['original_executable_hashes'],
                             OLD_HELPER, deadline, interruptible=False)
    checked(APPIMAGE, OLD_APP)
    checked(UNIT, UNIT_SHA)
    checked(HELPER, OLD_HELPER)
    report['rollback_runtime'] = restored
    report['configs_after_rollback_match'] = configs_match(report['configs_before'])
    report['rollback_verified'] = all(report['configs_after_rollback_match'])
    save('rollback_verified' if report['rollback_verified'] else 'rollback_runtime_verified_config_changed')
    if not report['rollback_verified']:
        raise Failure('original runtime restored, but exact saved config bytes were not preserved')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--trials-restored', action='store_true', help='operator verified both trials are restored')
    options = parser.parse_args(argv)
    if not options.run or not options.trials_restored:
        parser.error('--run --trials-restored are required')
    if os.getuid() != 1000 or os.geteuid() != 1000:
        raise SystemExit('must run as the verified cruiser account')
    invocation = os.environ.get('INVOCATION_ID', '')
    if len(invocation) != 32 or any(c not in '0123456789abcdef' for c in invocation):
        raise SystemExit('run under the reviewed finite user-systemd coordinator')
    os.umask(0o077)
    for kind in (signal.SIGTERM, signal.SIGINT):
        signal.signal(kind, stop_request)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    lock = (TRIAL_BASE / '.host-trial.lock').open('a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    backup = BASE / ('rollback-' + uuid.uuid4().hex[:12])
    backup.mkdir(mode=0o700)
    journal = backup / 'result.json'
    report = {'stage': 'planned', 'mutation_attempted': False, 'update_verified': False,
              'rollback_verified': False, 'live_executable_hashes_verified': False,
              'backup_directory': str(backup),
              'coordinator': identity(os.getpid())}
    def save(stage):
        report['stage'] = stage
        temporary = backup / 'result.tmp'
        with temporary.open('w') as file:
            json.dump(report, file, indent=2)
            file.write('\n'); file.flush(); os.fsync(file.fileno())
        os.replace(temporary, journal)
    save('planned')
    print('LIVI_UPDATE_JOURNAL=' + str(journal), flush=True)
    start = time.monotonic()
    mutation_start = None
    error = None
    try:
        for path, expected in ((APPIMAGE, OLD_APP), (HELPER, OLD_HELPER), (UNIT, UNIT_SHA), (STAGED, NEW_APP)):
            checked(path, expected)
        if STAGED.stat().st_size != NEW_SIZE:
            raise Failure('staged AppImage size mismatch')
        if shutil.disk_usage(BASE).free < 500 * 1024 * 1024:
            raise Failure('less than 500 MiB free for immutable backups and staging')
        initial = state(SERVICE, start + 30)
        if not normal(initial) or not switch_idle(start + 30):
            raise Failure('original normal service and idle switch required')
        original_runtime = runtime_executables(initial['pid'])
        if {name: item['sha256'] for name, item in original_runtime.items()} != OLD_EXEC:
            raise Failure('original runtime evidence does not match the pinned old executables')
        if original_runtime['livi-core']['pid'] != initial['pid']:
            raise Failure('service MainPID is not the original core; rollback path is not established')
        if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
            raise Failure('pidfd rollback support is unavailable')
        if Path(f"/proc/{initial['pid']}").stat().st_uid != 1000:
            raise Failure('original core is not owned by cruiser')
        pinned_initial = identity(initial['pid'])
        initial_fd = os.pidfd_open(initial['pid'])
        try:
            if identity(initial['pid']) != pinned_initial:
                raise Failure('original core changed during pidfd preflight')
            # Signal 0 checks target access without delivering a signal.
            signal.pidfd_send_signal(initial_fd, 0)
        finally:
            os.close(initial_fd)
        report['original_service'] = public_state(initial)
        report['original_identity'] = identity(initial['pid'])
        report['original_runtime'] = original_runtime
        report['live_executable_hashes_verified'] = all(item['live_executable_hashes_verified'] for item in original_runtime.values())
        report['original_executable_hashes'] = {name: item['sha256'] for name, item in original_runtime.items()}
        report['configs_before'] = snapshot_configs(backup)
        for source, name, checksum in ((APPIMAGE, 'LIVI.AppImage.original', OLD_APP),
                                      (HELPER, 'livi-helperd.original', OLD_HELPER),
                                      (UNIT, 'livi-kiosk.original.service', UNIT_SHA)):
            atomic_copy(source, backup / name, checksum, 0o600)
        # Close the preflight-to-mutation gap; fail closed if another operator acted.
        for path, expected in ((APPIMAGE, OLD_APP), (HELPER, OLD_HELPER), (UNIT, UNIT_SHA)):
            checked(path, expected)
        latest = state(SERVICE, time.monotonic() + 10)
        if not normal(latest) or identity(latest['pid']) != report['original_identity']:
            raise Failure('service changed during backup')
        if not all(configs_match(report['configs_before'])) or stopping:
            raise Failure('config changed during backup or stop was requested')
        save('backups_verified')
        mutation_start = time.monotonic()
        activation_end = mutation_start + 130
        rollback_end = mutation_start + 410
        report['mutation_attempted'] = True
        save('appimage_replace_attempted')
        atomic_copy(STAGED, APPIMAGE, NEW_APP, 0o755)
        report['activation_submit_code'] = install_original_unit(backup / 'livi-kiosk.original.service', activation_end)
        save('activation_restart_submitted')
        report['updated_runtime'] = await_runtime(report['original_identity'], NEW_EXEC, NEW_HELPER, activation_end)
        checked(APPIMAGE, NEW_APP)
        report['live_executable_hashes_verified'] = (report['live_executable_hashes_verified'] and
            report['updated_runtime']['live_executable_hashes_verified'])
        report['configs_after_update_match'] = configs_match(report['configs_before'])
        report['update_verified'] = True
        save('update_verified')
    except Exception as exc:
        error = exc
        report['error_type'] = type(exc).__name__
        if isinstance(exc, Failure):
            report['error'] = str(exc)
        save('activation_failed')
        if report['mutation_attempted']:
            try:
                rollback(backup, report, save, rollback_end)
            except Exception as restore_exc:
                report['rollback_error_type'] = type(restore_exc).__name__
                if isinstance(restore_exc, Failure):
                    report['rollback_error'] = str(restore_exc)
                save('rollback_unverified')
    finally:
        report['elapsed_seconds'] = round(time.monotonic() - start, 3)
        report['exit_code'] = 0 if report['update_verified'] else 1
        save('updated' if report['update_verified'] else 'failed')
        result = 'UPDATED' if report['update_verified'] else ('ROLLED_BACK' if report['rollback_verified'] else 'UNVERIFIED')
        print('LIVI_UPDATE_RESULT=' + result, flush=True)
        print('LIVI_UPDATE_JOURNAL=' + str(journal), flush=True)
        lock.close()
    return report['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
