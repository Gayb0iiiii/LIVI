import ctypes
import os
from pathlib import Path
import socket
import threading
import unittest

LIB = ctypes.CDLL(str(Path(__file__).resolve().parent / "relay-policy-test.so"))
PORT = int(os.environ.get("AX520_TEST_RELAY_PORT", "15039"))
class Stats(ctypes.Structure):
    _fields_ = [("to_controller", ctypes.c_uint64), ("to_host", ctypes.c_uint64), ("stop_reason", ctypes.c_uint)]
LIB.relay_packet_allowed.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
LIB.relay_pump.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint, ctypes.c_uint, ctypes.POINTER(Stats)]
LIB.relay_listen.argtypes = []

def command(opcode, params=b""):
    return b"\x01" + opcode.to_bytes(2, "little") + bytes([len(params)]) + params
def event(kind, params): return b"\x04" + bytes([kind, len(params)]) + params
RESET = bytes.fromhex("01 03 0c 00")
RESET_OK = bytes.fromhex("04 0e 04 01 03 0c 00")

def receive_frame(peer):
    prefix = b""
    while len(prefix) < 2: prefix += peer.recv(2 - len(prefix))
    size = int.from_bytes(prefix, "big"); payload = b""
    while len(payload) < size: payload += peer.recv(size - len(payload))
    return payload

def reset_session(peer, controller):
    peer.sendall(len(RESET).to_bytes(2, "big") + RESET)
    if controller.recv(64) != RESET: raise AssertionError("actual Reset was not forwarded")
    controller.send(RESET_OK)
    if receive_frame(peer) != RESET_OK: raise AssertionError("actual successful Reset completion was not forwarded")

class PolicyTests(unittest.TestCase):
    def allowed(self, p, host): return LIB.relay_packet_allowed(p, len(p), host)
    def test_listener_stays_loopback_only_and_exclusive(self):
        fd = LIB.relay_listen(); self.assertGreaterEqual(fd, 0)
        listener = socket.socket(fileno=fd)
        try:
            self.assertEqual(listener.getsockname(), ("127.0.0.1", PORT))
            self.assertLess(LIB.relay_listen(), 0)
        finally: listener.close()
    def test_stored_key_commands_and_entire_vendor_opcode_group_are_blocked(self):
        for opcode in [0x0c0d, 0x0c11, 0x0c12, *range(0xfc00, 0x10000)]:
            with self.subTest(opcode=opcode): self.assertEqual(self.allowed(command(opcode), 1), 0)
    def test_standard_initialization_and_fresh_pairing_commands_are_allowed(self):
        # Real command headers with synthetic payloads only; no device credentials.
        for opcode, params in [(0x1001, b""), (0x1002, b""), (0x0c03, b""), (0x0c24, b"\x04\x04\x20"),
            (0x040b, bytes(22)), (0x040c, bytes(6)), (0x040d, bytes(23)), (0x042b, bytes(9)),
            (0x042c, bytes(6)), (0x2001, bytes(8))]:
            with self.subTest(opcode=opcode): self.assertEqual(self.allowed(command(opcode, params), 1), 1)
    def test_old_key_event_is_blocked_but_fresh_pairing_events_pass(self):
        self.assertEqual(self.allowed(event(0x15, bytes(23)), 0), 0)
        self.assertEqual(self.allowed(event(0x17, bytes(6)), 0), 1)
        self.assertEqual(self.allowed(event(0x18, bytes(23)), 0), 1)
        self.assertEqual(self.allowed(event(0x31, bytes(6)), 0), 1)
        self.assertEqual(self.allowed(event(0x33, bytes(10)), 0), 1)
    def test_queued_blocked_completions_and_vendor_events_cannot_cross(self):
        for opcode in [0x0c0d, 0x0c11, 0x0c12, 0xfc00, 0xffff]:
            complete = event(0x0e, b"\x01" + opcode.to_bytes(2, "little") + b"\x00")
            status = event(0x0f, b"\x00\x01" + opcode.to_bytes(2, "little"))
            self.assertEqual(self.allowed(complete, 0), 0)
            self.assertEqual(self.allowed(status, 0), 0)
        self.assertEqual(self.allowed(event(0xff, bytes(10)), 0), 0)
        self.assertEqual(self.allowed(event(0x0e, b"\x01\x03"), 0), 0)
        self.assertEqual(self.allowed(event(0x0f, b"\x00\x01\x03"), 0), 0)
        self.assertEqual(self.allowed(event(0x0e, bytes.fromhex("01 03 0c 00")), 0), 1)
    def test_acl_and_sco_pass_in_both_directions_with_valid_lengths(self):
        for p in [bytes.fromhex("02 01 00 02 00 aa bb"), bytes.fromhex("03 01 00 02 aa bb")]:
            for host in [0, 1]: self.assertEqual(self.allowed(p, host), 1)
    def test_malformed_packets_and_wrong_directions_remain_blocked(self):
        for p, host in [(b"", 1), (command(0x1001), 0), (event(0x18, bytes(23)), 1), (b"\xff\x00", 0),
                        (bytes.fromhex("01 01 10 01"), 1), (bytes.fromhex("02 01 00 02 00 aa"), 0)]:
            with self.subTest(p=p, host=host): self.assertEqual(self.allowed(p, host), 0)
    def transact(self, packet, host, blocked=False):
        hci, controller = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        tcp, peer = socket.socketpair()
        stats = Stats(); result = []
        controller.settimeout(0.5); peer.settimeout(0.5)
        thread = threading.Thread(target=lambda: result.append(LIB.relay_pump(hci.fileno(), tcp.fileno(), 1000, 200, ctypes.byref(stats))))
        thread.start()
        try:
            reset_session(peer, controller)
            if host: peer.sendall(len(packet).to_bytes(2, "big") + packet)
            else: controller.send(packet)
            target = controller if host else peer
            if blocked:
                thread.join(0.5)
                self.assertEqual(result, [-1]); self.assertEqual(stats.stop_reason, 6)
                target.settimeout(0.03)
                with self.assertRaises(socket.timeout): target.recv(64)
                self.assertEqual((stats.to_controller, stats.to_host), (1, 1))
            else:
                if host: self.assertEqual(controller.recv(4096), packet)
                else:
                    expected = len(packet).to_bytes(2, "big") + packet; got = b""
                    while len(got) < len(expected): got += peer.recv(len(expected) - len(got))
                    self.assertEqual(got, expected)
                peer.shutdown(socket.SHUT_WR)
                thread.join(0.5)
                self.assertEqual(result, [0])
                self.assertEqual((stats.to_controller, stats.to_host), (2, 1) if host else (1, 2))
        finally:
            for s in [hci, controller, tcp, peer]: s.close()
    def test_stored_key_commands_never_reach_controller(self):
        for op in [0x0c0d, 0x0c11, 0x0c12, 0xfc01]:
            with self.subTest(op=op): self.transact(command(op), True, blocked=True)
    def test_returned_old_keys_never_reach_host(self):
        self.transact(event(0x15, bytes(23)), False, blocked=True)
    def test_fresh_pairing_event_is_forwarded_unchanged(self):
        self.transact(event(0x18, bytes(range(23))), False)
    def test_supported_commands_reply_is_not_masked_on_stock_side(self):
        reply = event(0x0e, bytes.fromhex("01 02 10 00") + bytes([255]) * 64)
        self.assertEqual(len(reply), 71)
        self.transact(reply, False)
    def test_standard_command_is_forwarded_unchanged(self):
        self.transact(command(0x0c03), True)
    def test_acl_and_sco_cross_after_real_reset_barrier(self):
        for packet in [bytes.fromhex("02 01 00 02 00 aa bb"), bytes.fromhex("03 01 00 02 aa bb")]:
            for host in [False, True]:
                with self.subTest(packet=packet, host=host): self.transact(packet, host)
    def barrier_block(self, packet, host, send_reset_first=False):
        hci, controller = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        tcp, peer = socket.socketpair()
        controller.settimeout(0.4); peer.settimeout(0.4)
        stats = Stats(); result = []
        thread = threading.Thread(target=lambda: result.append(LIB.relay_pump(hci.fileno(), tcp.fileno(), 1000, 200, ctypes.byref(stats))))
        thread.start()
        try:
            if send_reset_first:
                peer.sendall(len(RESET).to_bytes(2, "big") + RESET)
                self.assertEqual(controller.recv(64), RESET)
            if host: peer.sendall(len(packet).to_bytes(2, "big") + packet)
            else: controller.send(packet)
            thread.join(0.5)
            self.assertEqual(result, [-1]); self.assertEqual(stats.stop_reason, 6)
            self.assertEqual((stats.to_controller, stats.to_host), (1 if send_reset_first else 0, 0))
            target = controller if host else peer
            target.settimeout(0.03)
            with self.assertRaises(socket.timeout): target.recv(64)
        finally:
            for s in [hci, controller, tcp, peer]: s.close()
    def test_first_host_command_must_be_reset(self):
        self.barrier_block(command(0x1001), True)
    def test_queued_key_notification_before_reset_is_not_forwarded(self):
        self.barrier_block(event(0x18, bytes(23)), False)
    def test_reset_sent_without_completion_does_not_unlock_events(self):
        self.barrier_block(event(0x18, bytes(23)), False, send_reset_first=True)
    def test_failed_reset_completion_does_not_unlock_session(self):
        self.barrier_block(event(0x0e, bytes.fromhex("01 03 0c 0c")), False, send_reset_first=True)
    def test_extra_host_command_before_reset_completion_is_blocked(self):
        self.barrier_block(command(0x1001), True, send_reset_first=True)

if __name__ == "__main__": unittest.main(verbosity=2)
