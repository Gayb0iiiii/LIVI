import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest

import rollback


def receipt():
    return {'version': 1, 'host_boot_id': '12345678-1234-1234-1234-123456789abc',
            'usb_dir': '/tmp/ax520-adb-0123456789ab',
            'bridge_dir': '/tmp/livi-ax520-bridge-0123456789ab',
            'bridge_status': '/tmp/ax520-observer-trial-aB12cD/status',
            'identities': {
                'usb_guard': dict(pid=200, parent=1, group=200, start=111),
                'adbd': dict(pid=202, parent=201, group=202, start=112),
                'bridge_guard': dict(pid=300, parent=1, group=300, start=211),
                'supervisor': dict(pid=301, parent=300, group=301, start=212),
                'worker': dict(pid=302, parent=301, group=301, start=213)}}


class ValidationTests(unittest.TestCase):
    def test_valid_script_has_valid_posix_shell_syntax(self):
        result = subprocess.run(['/bin/sh', '-n'], input=rollback.generate_script(receipt()), text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_shell_injection_and_extra_schema(self):
        for key in ('usb_dir', 'bridge_dir', 'bridge_status', 'host_boot_id'):
            data=receipt(); data[key] += '; touch /tmp/evil'
            with self.subTest(key=key), self.assertRaises(Exception): rollback.generate_script(data)
        data=receipt(); data['credentials']='unacceptable'
        with self.assertRaises(Exception): rollback.generate_script(data)

    def test_rejects_boolean_and_duplicate_process(self):
        for value in (True, 0, -1, '200', 2**64):
            data=receipt(); data['identities']['usb_guard']['pid']=value
            with self.subTest(value=value), self.assertRaises(Exception): rollback.generate_script(data)
        data=receipt(); data['identities']['adbd']['pid']=200
        with self.assertRaises(Exception): rollback.generate_script(data)

    def test_detach_rejects_untrusted_digest(self):
        for value in ('a'*63, 'a'*64+';reboot', ''):
            with self.assertRaises(Exception): rollback.detached_command(receipt(), value)
        command=rollback.detached_command(receipt(), 'a'*64)
        self.assertEqual(subprocess.run(['/bin/sh','-n'],input=command,text=True).returncode,0)


class ExecutionTests(unittest.TestCase):
    def run_fixture(self, scenario='ok'):
        # Same generated script with /proc, /tmp and pinned hashes mapped onto
        # synthetic files. Only kill/sleep are shell stubs: no host signals.
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); proc=root/'proc'; proc.mkdir(); tmp=root/'tmp'; tmp.mkdir()
            data=receipt(); script=rollback.generate_script(data)
            for key in ('usb_dir','bridge_dir'):
                (tmp/data[key].removeprefix('/tmp/')).mkdir()
            status=tmp/data['bridge_status'].removeprefix('/tmp/'); status.parent.mkdir()
            status.write_text('mode managed_device_bridge\nstage armed\nstage original_stopped\nobserver selected\n')
            usb=tmp/data['usb_dir'].removeprefix('/tmp/'); bridge=tmp/data['bridge_dir'].removeprefix('/tmp/')
            (usb/'status').write_text('mode managed_usb\nwatchdog_armed\nadb_usb_ready\n')
            (usb/'guard').write_text('200 111 9223372036854775807\n')
            for role, filename, digest in [('usb_guard',usb/'adb-trial',rollback.USB_SHA),('bridge_guard',bridge/'bridge-trial',rollback.BRIDGE_LAUNCHER_SHA)]:
                filename.write_text(role); fixture_hash=hashlib.sha256(filename.read_bytes()).hexdigest(); script=script.replace(digest, fixture_hash)
                ident=data['identities'][role]; d=proc/str(ident['pid']); d.mkdir()
                fields=[str(ident['pid']), '('+filename.name+')', 'S',str(ident['parent']),str(ident['group'])]+['0']*16+[str(ident['start'])]
                (d/'stat').write_text(' '.join(fields)+'\n'); (d/'comm').write_text(filename.name+'\n'); (d/'exe').symlink_to(filename)
            if scenario=='wrong_start': (proc/'200/stat').write_text((proc/'200/stat').read_text().replace('111\n','999\n'))
            if scenario=='wrong_hash': (usb/'adb-trial').write_text('tampered')
            if scenario=='prior_attempt': (usb/'rollback.status').write_text('previous_attempt\n')
            script=script.replace('/proc/',str(proc)+'/').replace('/tmp/',str(tmp)+'/')
            # Replace mapping overlap created by our own temporary path.
            script=script.replace(str(tmp)+directory[4:]+'/',directory+'/')
            log=root/'signals'
            prelude='''
kill() {
  printf '%s\\n' "$2" >> SIGNAL_LOG
  if [ "$2" = 200 ]; then
    USB_ACTION
  elif [ "$2" = 300 ]; then
    printf 'restored_pid 401\\nresult restored\\n' >> BRIDGE_STATUS
    rm -rf PROC/300
  else return 1; fi
}
sleep() { :; }
mkdir -p PROC/$$
printf '%s (sh) S 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 42\\n' $$ > PROC/$$/stat
'''
            action="printf 'result_restored_device_state\\n' >> USB/status; rm USB/guard; rm -rf PROC/200"
            if scenario=='usb_failure': action="printf 'result_unverified_no_retry\\n' >> USB/status; rm -rf PROC/200"
            if scenario=='usb_alive': action="printf 'result_restored_device_state\\n' >> USB/status; rm USB/guard"
            if scenario=='bridge_changed': action += "; sed -i 's/211$/999/' PROC/300/stat"
            prelude=prelude.replace('USB_ACTION',action).replace('SIGNAL_LOG',str(log)).replace('BRIDGE_STATUS',str(status)).replace('USB',str(usb)).replace('PROC',str(proc))
            if scenario=='unsafe_ancestry': prelude=prelude.replace('(sh) S 1 1','(sh) S 200 1')
            if scenario=='bridge_failure': prelude=prelude.replace('restored_pid 401\\nresult restored', 'result restore_unverified_no_retry')
            if scenario=='bridge_alive': prelude=prelude.replace('rm -rf '+str(proc)+'/300', ':')
            result=subprocess.run(['/bin/sh'],input=prelude+script,text=True,capture_output=True,timeout=5)
            return result, log.read_text().splitlines() if log.exists() else [], (usb/'rollback.status').read_text() if (usb/'rollback.status').exists() else ''

    def test_orders_usb_before_bridge_and_verifies_both(self):
        result,signals,status=self.run_fixture()
        self.assertEqual(result.returncode,0,(result.stderr,status))
        self.assertEqual(signals,['200','300'])
        self.assertEqual(status.splitlines()[-1],'result restored')

    def test_identity_or_hash_mismatch_signals_nothing(self):
        for case in ('wrong_start','wrong_hash','unsafe_ancestry','prior_attempt'):
            result,signals,status=self.run_fixture(case)
            with self.subTest(case=case):
                self.assertNotEqual(result.returncode,0)
                self.assertEqual(signals,[],status)

    def test_usb_failure_or_live_guard_never_signals_bridge(self):
        for case in ('usb_failure','usb_alive'):
            result,signals,status=self.run_fixture(case)
            with self.subTest(case=case):
                self.assertNotEqual(result.returncode,0)
                self.assertEqual(signals,['200'],status)

    def test_bridge_failure_or_live_guard_never_claims_success(self):
        for case in ('bridge_failure','bridge_alive'):
            result,signals,status=self.run_fixture(case)
            with self.subTest(case=case):
                self.assertNotEqual(result.returncode,0)
                self.assertEqual(signals,['200','300'],status)
                self.assertNotEqual(status.splitlines()[-1],'result restored')

    def test_replaced_bridge_identity_is_never_signalled(self):
        result,signals,status=self.run_fixture('bridge_changed')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(signals,['200'],status)

if __name__=='__main__': unittest.main()
