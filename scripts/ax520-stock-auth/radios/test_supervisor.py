"""Offline ownership/state-machine tests; no devices, credentials or real ADB."""
import unittest
from supervisor import Conflict, Failure, Session, parse_forward, parse_status, validate_manifest

H='a'*64

def manifest():
    return {'version':1,'seconds':300,'auth_dir':'/home/cruiser/LIVI/ax520-current-boot-service',
            'auth_hashes':{'service.py':H,'vendor/adb_observer.py':H,'vendor/endpoint.py':H,'vendor/verifier.py':H},
            'artifacts':{'network':{'path':'/tmp/network','sha256':H},'bluetooth':{'path':'/tmp/hci','sha256':H}}}

class Fake:
    def __init__(self,fail=None,clean=True):self.events=[];self.fail=fail;self.clean=clean;self.now=0
    def call(self,name):
        self.events.append(name)
        if self.fail==name:raise Failure('injected')
    def verify_ready(self):self.call('verify_ready')
    def prepare(self):self.call('prepare')
    def start_network(self):self.call('start_network')
    def start_bluetooth(self):self.call('start_bluetooth')
    def add_forward(self,p):self.call('add_'+str(p))
    def remove_forward(self,p):self.call('remove_'+str(p))
    def check(self):self.call('check');return self.now>=2
    def stop_bluetooth(self):self.call('stop_bluetooth')
    def stop_network(self):self.call('stop_network')
    def verify_restored(self):self.call('verify_restored');return self.clean
    def time(self):return self.now
    def wait(self,n):self.now+=n

class Lifecycle(unittest.TestCase):
    def run_case(self,fail=None,clean=True,stop=False):
        b=Fake(fail,clean);saved=[]
        result=Session(b,300,lambda r:saved.append(dict(r)),lambda:stop,b.time,b.wait).run()
        return b,result,saved
    def test_full_lifecycle_removes_owned_forwards_before_stopping_relays(self):
        b,r,_=self.run_case();self.assertEqual(r['stage'],'stopped_verified')
        self.assertLess(b.events.index('remove_15039'),b.events.index('stop_bluetooth'))
        self.assertLess(b.events.index('remove_15038'),b.events.index('stop_network'))
        self.assertTrue(r['cleanup_verified']);self.assertFalse(r['wireless_carplay_verified'])
    def test_lost_forward_response_still_attempts_ownership_checked_removal(self):
        b,r,_=self.run_case('add_15039');self.assertIn('remove_15039',b.events)
        self.assertIn('stop_bluetooth',b.events);self.assertEqual(r['stage'],'failed_restored')
    def test_lost_native_launch_response_still_inspects_and_stops_own_run(self):
        b,r,_=self.run_case('start_bluetooth');self.assertIn('stop_bluetooth',b.events)
        self.assertNotIn('add_15039',b.events)
    def test_failed_preflight_does_not_touch_relays_or_forwards(self):
        b,r,_=self.run_case('verify_ready');self.assertEqual(b.events,['verify_ready'])
        self.assertEqual(r['stage'],'failed_before_start')
    def test_failed_prepare_requires_cleanup_verification_but_does_not_signal(self):
        b,r,_=self.run_case('prepare');self.assertNotIn('stop_network',b.events)
        self.assertIn('verify_restored',b.events)
    def test_restore_failure_is_unretryable(self):
        b,r,_=self.run_case(clean=False);self.assertEqual(r['stage'],'restoration_unverified_no_retry')
        self.assertFalse(r['cleanup_verified'])
    def test_cleanup_failure_does_not_skip_other_cleanup(self):
        b,r,_=self.run_case('remove_15039');self.assertIn('stop_network',b.events)
        self.assertIn('verify_restored',b.events);self.assertFalse(r['cleanup_verified'])
    def test_stop_before_start_does_not_launch_any_radio(self):
        b,r,_=self.run_case(stop=True);self.assertEqual(b.events,['verify_ready'])
        self.assertEqual(r['stage'],'stopped_before_start')
    def test_stop_between_relays_cleans_up_without_starting_bluetooth(self):
        b=Fake();r=Session(b,300,lambda _:None,lambda:'start_network' in b.events,b.time,b.wait).run()
        self.assertIn('stop_network',b.events);self.assertNotIn('start_bluetooth',b.events)
        self.assertNotIn('add_15038',b.events);self.assertTrue(r['cleanup_verified'])
    def test_mutation_intent_recorded_before_launch(self):
        _,r,saved=self.run_case('start_network');self.assertTrue(any(x.get('network_intent') for x in saved))

class Parsing(unittest.TestCase):
    def test_manifest_rejects_unbounded_or_unpinned_artifacts(self):
        self.assertEqual(validate_manifest(manifest())['seconds'],300)
        for n in (0,301,True):
            x=manifest();x['seconds']=n
            with self.assertRaises(Failure):validate_manifest(x)
        x=manifest();x['artifacts']['network']['sha256']=''
        with self.assertRaises(Failure):validate_manifest(x)
    def test_forward_matching_does_not_remove_foreign_or_redirected_forward(self):
        self.assertTrue(parse_forward(b'opaque tcp:15038 tcp:15038\n','opaque',15038))
        self.assertFalse(parse_forward(b'opaque tcp:15000 tcp:15000\n','opaque',15038))
        for raw in (b'foreign tcp:15038 tcp:15038\n',b'opaque tcp:15038 tcp:80\n',b'opaque tcp:15038 tcp:15038\n'*2):
            with self.assertRaises(Conflict):parse_forward(raw,'opaque',15038)
    def test_status_requires_unique_guardian_and_final_result(self):
        raw='1 watchdog_armed pid=200 start=300 trial_ms=325000 recovery_ms=10000\n2 RESULT relay_complete_restored\n'
        x=parse_status(raw);self.assertEqual(x['watchdog'],{'pid':200,'start':300})
        self.assertEqual(x['result'],'relay_complete_restored')
        with self.assertRaises(Failure):parse_status(raw+'3 RESULT restoration_unverified_no_retry\n')
        with self.assertRaises(Failure):parse_status('password material\n')
    def test_unknown_status_not_retained(self):
        with self.assertRaises(Failure):parse_status('1 secret=not-a-status-field\n')


class AdapterContracts(unittest.TestCase):
    def test_remove_forward_works_when_auth_checks_are_unavailable(self):
        from supervisor import Backend
        from pathlib import Path
        from types import SimpleNamespace
        from unittest.mock import Mock
        b=Backend(manifest(),Path('/tmp/fixture-run'))
        b.leader={'pid':55,'start':99};b.transport=3;b.serial='opaque'
        messages=[]
        class Socket:
            def __enter__(self):return self
            def __exit__(self,*_):pass
            def send(self,s):messages.append(s)
            def status(self):pass
        o=SimpleNamespace(proc=lambda p:{'pid':p,'start':99},listener_owner=lambda *_:None,
                          SmartADB=lambda _:Socket(),listeners_absent=lambda _:True)
        b.r=SimpleNamespace(o=o);b.check_server=Mock(side_effect=Failure('auth_gone'))
        b.forwarding=Mock(side_effect=[True,False])
        b.remove_forward(15038)
        self.assertEqual(messages,['host-transport-id:3:killforward:tcp:15038'])
        b.check_server.assert_not_called()
    def test_remove_forward_refuses_reused_server_pid(self):
        from supervisor import Backend
        from pathlib import Path
        from types import SimpleNamespace
        b=Backend(manifest(),Path('/tmp/fixture-run'));b.leader={'pid':55,'start':99}
        b.r=SimpleNamespace(o=SimpleNamespace(proc=lambda _: {'start':100}))
        with self.assertRaises(Conflict):b.remove_forward(15038)
    def test_sync_stages_bytes_without_spawning_an_adb_process(self):
        from supervisor import Backend
        from pathlib import Path
        from types import SimpleNamespace
        import struct
        writes=[];services=[]
        class Socket:
            stream=SimpleNamespace(sendall=lambda data:writes.append(data))
            def __enter__(self):return self
            def __exit__(self,*_):pass
            def send(self,s):services.append(s)
            def exact(self,n):return b'OKAY\0\0\0\0'
        b=Backend(manifest(),Path('/tmp/fixture-run'));b.transport=9
        b.r=SimpleNamespace(o=SimpleNamespace(SmartADB=lambda _:Socket()))
        b.push(b'fixture-binary','/tmp/ax520-radios-fixture/network')
        self.assertEqual(services,['host:transport-id:9','sync:'])
        self.assertTrue(writes[0].startswith(b'SEND'))
        self.assertEqual(writes[1],b'DATA'+struct.pack('<I',14)+b'fixture-binary')
        self.assertTrue(writes[-1].startswith(b'DONE'))

    def test_native_failed_restoration_is_not_transport_success(self):
        from supervisor import Backend
        from pathlib import Path
        from unittest.mock import patch
        for label in ('relay_failed_restored','relay_no_host_restored','launch_failed_no_mutation'):
            b=Backend(manifest(),Path('/tmp/fixture-run'))
            b.verify_auth=lambda:None;b.hci_status=lambda:{'result':label}
            with patch('supervisor.save'):
                with self.assertRaises(Failure):b.check()


class GuardianExit(unittest.TestCase):
    def verify(self,sequence):
        from supervisor import wait_guardian_exit
        values=iter(sequence);last=None;now=[0];observed=[]
        def read(owner):
            nonlocal last
            observed.append(dict(owner))
            try:last=next(values)
            except StopIteration:pass
            return last
        result=wait_guardian_exit({'pid':200,'start':300},read,
            clock=lambda:now[0],wait=lambda n:now.__setitem__(0,now[0]+n),within=1)
        return result,observed
    def test_final_receipt_does_not_imply_guardian_exit(self):
        result,seen=self.verify([{'pid':200,'start':300,'state':'S'}])
        self.assertFalse(result['verified']);self.assertEqual(result['observation'],'same_identity_running')
        self.assertGreater(len(seen),1)
    def test_waits_for_exact_guardian_to_disappear(self):
        result,_=self.verify([{'pid':200,'start':300,'state':'R'},None])
        self.assertEqual(result,{'verified':True,'observation':'process_absent'})
    def test_reused_pid_proves_original_exit_without_signalling_replacement(self):
        result,seen=self.verify([{'pid':200,'start':301,'state':'R'}])
        self.assertEqual(result,{'verified':True,'observation':'pid_reused'})
        self.assertEqual(seen,[{'pid':200,'start':300}])
    def test_zombie_is_exited_but_recorded_distinctly_from_absence(self):
        result,_=self.verify([{'pid':200,'start':300,'state':'Z'}])
        self.assertEqual(result,{'verified':True,'observation':'exited_zombie'})
    def test_unexpected_process_metadata_does_not_prove_exit(self):
        with self.assertRaises(Failure):self.verify([{'pid':201,'start':300,'state':'R'}])


class GuardianRestorationIntegration(unittest.TestCase):
    def test_restoration_requires_guardian_exit_after_successful_result(self):
        from supervisor import Backend
        from pathlib import Path
        from types import SimpleNamespace
        from unittest.mock import patch
        for exited in (False,True):
            b=Backend(manifest(),Path('/tmp/fixture-run'));b.started_hci=True
            b.verify_auth=lambda **_:None
            b.r=SimpleNamespace(host=SimpleNamespace(pins=lambda:None),o=SimpleNamespace(listeners_absent=lambda _:True))
            b.hci_status=lambda:{'watchdog':{'pid':200,'start':300},'result':'relay_complete_restored'}
            b.hci_before={'hci_flags':29};b.inspect_hci=lambda:{'hci_flags':29}
            b.stock_ports=lambda:'0';b.forwarding=lambda _:False
            verdict={'verified':exited,'observation':'process_absent' if exited else 'same_identity_running'}
            with patch('supervisor.wait_guardian_exit',return_value=verdict),patch('supervisor.Path.glob',return_value=[]),patch('supervisor.Path.exists',return_value=False),patch('supervisor.save') as saved:
                self.assertEqual(b.verify_restored(),exited)
                self.assertEqual(b.guardian_exit_verified,exited)
                self.assertEqual(saved.call_args.args[1]['guardian_exit'],verdict)

if __name__=='__main__':unittest.main()
