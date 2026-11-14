import json
from pathlib import Path
import tempfile
import unittest
import types
from unittest.mock import patch
import boot
from test_service import receipt

class BootTests(unittest.TestCase):
    def test_idle_helper_refreshes_once_after_provider_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            actions=[];helper=[{'pid':1,'start':10}];counts=[0]
            view={'endpoint':boot.s.ENDPOINT,'sessions_total':0}
            class Client:
                def __enter__(self):return self
                def __exit__(self,*args):pass
                def snapshot(self):return view
                def action(self,name):
                    actions.append(name);helper[0]={'pid':2,'start':20};counts[0]+=1
            r=types.SimpleNamespace(report={'reattached_existing_endpoint':True,'current_core':{'pid':3,'start':30}},receipt=receipt(),journal=Path(directory)/'result.json',await_core=lambda _:view,save=lambda _:None,e=types.SimpleNamespace(Failure=RuntimeError),v=types.SimpleNamespace(Failure=RuntimeError))
            r.host=types.SimpleNamespace(helper=lambda _:helper[0],factory=lambda _:Client())
            r.logs=types.SimpleNamespace(read=lambda:{'endpoint_selected':counts[0]})
            boot.refresh_idle_helper(r);boot.refresh_idle_helper(r)
            self.assertEqual(actions,['applySettings'])
            self.assertTrue(r.report['helper_provider_refreshed'])
            view['sessions_total']=1;helper[0]={'pid':4,'start':40}
            boot.refresh_idle_helper(r);self.assertEqual(actions,['applySettings'])
            view['sessions_total']=0
            p=Path(directory)/'helper-refresh.json';pending=json.loads(p.read_text());pending['state']='pending';p.write_text(json.dumps(pending))
            with self.assertRaises(boot.s.Conflict):boot.refresh_idle_helper(r)
    def test_record_requires_exact_generated_paths(self):
        value=b'AX520_BOOT_V1\n/tmp/ax520-adb-0123456789ab\n/tmp/livi-ax520-bridge-0123456789ab\n/tmp/ax520-observer-trial-aB12cD/status\n300\n'
        self.assertEqual(boot.parse_record(value).bridge_guard_pid,300)
        for bad in (value+b'extra\n',value.replace(b'300\n',b'1\n'),value.replace(b'0123456789ab',b'../etc/passwd')):
            with self.assertRaises(boot.s.Failure):boot.parse_record(bad)
    def test_new_boot_preserves_endpoint_intent_and_archives_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'state').mkdir()
            old=receipt();new=receipt();new['host_boot_id']='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
            boot.write_receipt(root,old)
            intent=root/'state/endpoint.intent';intent.write_text(old['host_boot_id']+'\n')
            boot.write_receipt(root,new)
            self.assertEqual(json.loads((root/'receipt.json').read_text()),new)
            self.assertEqual(intent.read_text(),new['host_boot_id']+'\n')
            self.assertEqual(len(list((root/'history').glob('*'))),1)
            boot.write_receipt(root,new)
            self.assertEqual(len(list((root/'history').glob('*'))),1)
    def test_no_receipt_or_endpoint_written_before_device_validation(self):
        class Fake:
            def start(self):pass
            def verify_device(self):raise boot.s.Failure('owner_changed')
        value=receipt();f=Fake();f.transport=1
        class Client:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def shell(self,*args):return b''
        f.o=type('Observer',(),{'SmartADB':lambda *_:Client()})()
        with patch.object(boot,'parse_record',return_value=None),patch.object(boot.c,'command',return_value=''),patch.object(boot.c,'parse',return_value=value):
            with self.assertRaises(boot.s.Failure):boot.discover(f)

if __name__=='__main__':unittest.main()
