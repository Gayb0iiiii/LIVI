import ctypes
import json
from pathlib import Path
import socket
import subprocess
import time
import unittest

ROOT = Path(__file__).resolve().parent
LIB = ctypes.CDLL(str(ROOT / "relay-policy-test.so"))
class Stats(ctypes.Structure):
    _fields_ = [("to_controller", ctypes.c_uint64), ("to_host", ctypes.c_uint64), ("stop_reason", ctypes.c_uint)]
LIB.relay_pump.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint, ctypes.c_uint, ctypes.POINTER(Stats)]

class BoundTests(unittest.TestCase):
    def test_compiled_production_bounds_are_explicit_and_capped(self):
        proc = subprocess.run([str(ROOT / "bounds-test"), "--bounds"], capture_output=True, text=True, timeout=2)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout), {
            "mode": "fresh_pairing_300s", "loopback_port": 15039,
            "accept_ms": 20000, "relay_ms": 300000, "worker_ms": 330000,
            "restore_ms": 10000, "worker_reap_ms": 1000, "restore_reap_ms": 1000,
            "resume_each_ms": 1000, "pending_io_stall_ms": 3000,
        })

    def pump_closed_peer(self, duration):
        hci, controller = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        tcp, peer = socket.socketpair(); peer.close()
        stats = Stats(); start = time.monotonic()
        try:
            rc = LIB.relay_pump(hci.fileno(), tcp.fileno(), duration, 3000, ctypes.byref(stats))
            self.assertLess(time.monotonic() - start, 0.5)
            self.assertEqual((stats.to_controller, stats.to_host), (0, 0))
            return rc, stats.stop_reason
        finally:
            for s in [hci, controller, tcp]: s.close()

    def test_300_second_session_is_accepted_but_disconnect_still_ends_immediately(self):
        self.assertEqual(self.pump_closed_peer(300000), (0, 1))

    def test_duration_above_300_seconds_is_rejected_without_io(self):
        self.assertEqual(self.pump_closed_peer(300001), (-1, 4))
        self.assertEqual(self.pump_closed_peer(0), (-1, 4))

if __name__ == "__main__": unittest.main(verbosity=2)
