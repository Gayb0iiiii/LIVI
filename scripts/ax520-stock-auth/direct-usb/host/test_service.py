import copy
import importlib.util
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('service', ROOT/'service.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


def receipt():
    return {
        'version': 1,
        'host_boot_id': '11111111-2222-3333-4444-555555555555',
        'usb_dir': '/tmp/ax520-adb-012345abcdef',
        'bridge_dir': '/tmp/livi-ax520-bridge-123456abcdef',
        'bridge_status': '/tmp/ax520-observer-trial-Ab12Cd/status',
        'identities': {
            'usb_guard': {'pid': 100, 'parent': 1, 'group': 100, 'start': 200},
            'adbd': {'pid': 102, 'parent': 101, 'group': 102, 'start': 202},
            'bridge_guard': {'pid': 110, 'parent': 1, 'group': 110, 'start': 210},
            'supervisor': {'pid': 111, 'parent': 110, 'group': 111, 'start': 211},
            'worker': {'pid': 112, 'parent': 111, 'group': 111, 'start': 212},
        },
    }


class Validation(unittest.TestCase):
    def test_usb_target_survives_bus_renumbering_and_excludes_phone(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            descriptor=bytes([9,2,18,0,1,1,0,0x80,50,9,4,0,0,2,0xff,0x42,1,0])
            def device(name,revision):
                p=root/name;p.mkdir()
                for key,value in {'idVendor':'05ac','idProduct':'12a8','bcdDevice':revision,'bNumConfigurations':'4'}.items():(p/key).write_text(value)
                (p/'descriptors').write_bytes(descriptor)
            device('7-1','1801');device('3-1','0901')
            self.assertEqual(s.find_usb_target(root),'3-1')
            device('4-1','0901')
            with self.assertRaises(s.Failure):s.find_usb_target(root)

    def test_receipt_accepts_exact_owned_identities(self):
        data = receipt()
        self.assertEqual(s.validate_receipt(data), data)

    def test_receipt_rejects_injected_path_and_duplicate_owner(self):
        data = receipt()
        data['usb_dir'] += ';reboot'
        with self.assertRaises(s.Failure): s.validate_receipt(data)
        data = receipt()
        data['identities']['worker']['pid'] = data['identities']['supervisor']['pid']
        with self.assertRaises(s.Failure): s.validate_receipt(data)

    def test_remote_command_checks_executable_sdk_and_owners_twice(self):
        command = s.device_check_command(receipt())
        self.assertIn('/proc/102/exe', command)
        self.assertIn(s.STOCK_HASHES['/mnt/customer/app/libiap_new.so'], command)
        self.assertEqual(command.count('check_process 112 '), 2)
        self.assertIn('0100007F:3A98', command)
        self.assertIn('socket:[$inode]', command)
        self.assertNotIn('logcat', command)

    def test_only_exact_verification_marker_is_accepted(self):
        s.verify_device_response(b'AX520_MANAGED_VERIFIED\n')
        for payload in (b'', b'AX520_MANAGED_VERIFIED\nother\n',
                        b'FAIL\nAX520_MANAGED_VERIFIED\n'):
            with self.assertRaises(s.Failure): s.verify_device_response(payload)

    def test_config1_descriptor_must_include_adb(self):
        device = bytes([18,1,0,2,0,0,0,64,0xac,5,0xa8,0x12,1,9,0,0,0,4])
        config = bytes([9,2,18,0,1,1,0,0x80,50])
        adb = bytes([9,4,0,0,2,0xff,0x42,1,0])
        self.assertTrue(s.config1_adb_descriptor(device+config+adb))
        self.assertFalse(s.config1_adb_descriptor(device+config+bytes([9,4,0,0,2,6,1,1,0])))
        self.assertFalse(s.config1_adb_descriptor(device+config+adb[:-1]))

    def test_existing_endpoint_is_read_only_on_reattach(self):
        actions = []
        s.select_endpoint('127.0.0.1:15000', lambda: actions.append('write'))
        self.assertEqual(actions, [])
        s.select_endpoint('', lambda: actions.append('write'))
        self.assertEqual(actions, ['write'])
        with self.assertRaises(s.Failure): s.select_endpoint('other:1234', lambda: actions.append('write'))
        self.assertEqual(actions, ['write'])


class FakeRuntime:
    def __init__(self, fail=False): self.calls=[]; self.fail=fail
    def start(self): self.calls.append('start')
    def verify_device(self):
        self.calls.append('verify')
        if self.fail: raise s.Failure('wrong_device')
    def start_forward(self): self.calls.append('forward')
    def ensure_endpoint(self): self.calls.append('endpoint')
    def check(self): self.calls.append('check')
    def close(self): self.calls.append('host_cleanup')


class Lifetime(unittest.TestCase):
    def test_normal_host_stop_does_not_restore_device_or_endpoint(self):
        runtime = FakeRuntime()
        stopped = iter((False, True))
        s.serve_once(runtime, lambda: next(stopped), lambda _seconds: None)
        self.assertEqual(runtime.calls, ['start','verify','forward','endpoint','check','host_cleanup'])

    def test_wrong_device_never_selects_endpoint_and_cleans_host(self):
        runtime = FakeRuntime(fail=True)
        with self.assertRaises(s.Failure): s.serve_once(runtime, lambda: False, lambda _seconds: None)
        self.assertEqual(runtime.calls, ['start','verify','host_cleanup'])

    def test_startup_waits_for_verifier_and_endpoint_errors(self):
        class EndpointError(Exception): pass
        class VerifierError(Exception): pass
        expected = {'endpoint':s.ENDPOINT,'sessions_total':0}
        responses = iter((VerifierError('runtime roles still starting'),EndpointError('core socket starting'),expected))
        def view(_deadline):
            value = next(responses)
            if isinstance(value,Exception): raise value
            return value
        runtime = s.Runtime.__new__(s.Runtime)
        runtime.e = types.SimpleNamespace(Failure=EndpointError)
        runtime.v = types.SimpleNamespace(Failure=VerifierError)
        runtime.host = types.SimpleNamespace(view=view)
        with patch.object(s.time,'sleep'):
            self.assertEqual(runtime.await_core(s.time.monotonic()+1),expected)

    def test_stored_endpoint_intent_prevents_overwriting_manual_clear(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = s.Runtime.__new__(s.Runtime)
            runtime.receipt = receipt()
            runtime.endpoint_intent = Path(directory)/'endpoint.intent'
            runtime.endpoint_intent.write_text(runtime.receipt['host_boot_id']+'\n')
            runtime.endpoint_intent.chmod(0o600)
            runtime.await_core = lambda _deadline: {'endpoint':'','sessions_total':0}
            runtime.e = types.SimpleNamespace(LogCursor=lambda:None)
            with self.assertRaises(s.Conflict): runtime.ensure_endpoint()


class Capture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import sys
        sys.path.insert(0,str(ROOT))
        import capture_receipt
        cls.capture = capture_receipt

    def settings(self):
        data = receipt()
        return types.SimpleNamespace(**{key:data[key] for key in ('usb_dir','bridge_dir','bridge_status')},bridge_guard_pid=110)

    def capture_text(self):
        return ('USB_FILE 100 200\nADB_FILE 102 202\n'
                'ID usb_guard 100 1 100 200\nID adbd 102 101 102 202\n'
                'ID bridge_guard 110 1 110 210\n'
                'APP 112 111 111 212\nAPP 111 110 111 211\nCAPTURE_DONE\n')

    def test_capture_recognizes_pair_without_order_assumption(self):
        self.assertEqual(self.capture.parse(self.settings(),self.capture_text(),receipt()['host_boot_id']),receipt())

    def test_capture_rejects_process_reuse_or_extra_output(self):
        for raw in (self.capture_text().replace('USB_FILE 100 200','USB_FILE 100 201'),self.capture_text()+'EXTRA\n'):
            with self.assertRaises(self.capture.service.Failure):
                self.capture.parse(self.settings(),raw,receipt()['host_boot_id'])


if __name__ == '__main__': unittest.main()
