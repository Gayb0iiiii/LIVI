"""Offline relay behavior tests; all packets are synthetic, no hardware access."""
import ctypes
from pathlib import Path
import socket
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parent
LIB = ctypes.CDLL(str(ROOT / "relay-test.so"), use_errno=True)


class Stats(ctypes.Structure):
    _fields_ = [("to_controller", ctypes.c_uint64),
                ("to_host", ctypes.c_uint64), ("stop_reason", ctypes.c_uint)]


LIB.relay_packet_valid.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
LIB.relay_packet_valid.restype = ctypes.c_int
LIB.relay_pump.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint,
                          ctypes.c_uint, ctypes.POINTER(Stats)]
LIB.relay_pump.restype = ctypes.c_int

RESET = bytes.fromhex("01 03 0c 00")
VERSION = bytes.fromhex("01 01 10 00")
EVENT = bytes.fromhex("04 0e 04 01 03 0c 00")
ACL = bytes.fromhex("02 01 00 03 00 61 62 63")
SCO = bytes.fromhex("03 01 00 02 61 62")


def frame(packet):
    return len(packet).to_bytes(2, "big") + packet


def receive_exact(sock, count):
    out = bytearray()
    while len(out) < count:
        part = sock.recv(count - len(out))
        if not part:
            raise EOFError("incomplete synthetic frame")
        out.extend(part)
    return bytes(out)


def receive_frame(sock):
    return receive_exact(sock, int.from_bytes(receive_exact(sock, 2), "big"))


class PacketValidationTests(unittest.TestCase):
    def valid(self, packet, from_host):
        return LIB.relay_packet_valid(packet, len(packet), from_host)

    def test_only_direction_appropriate_h4_packets_are_accepted(self):
        for packet in (RESET, VERSION, ACL, SCO):
            self.assertEqual(self.valid(packet, 1), 1)
        for packet in (EVENT, ACL, SCO):
            self.assertEqual(self.valid(packet, 0), 1)
        self.assertEqual(self.valid(EVENT, 1), 0)
        self.assertEqual(self.valid(RESET, 0), 0)
        for packet in (b"", b"\xff\x00", b"\x05\x00\x00\x00\x00"):
            for direction in (0, 1):
                self.assertEqual(self.valid(packet, direction), 0)

    def test_header_lengths_must_match_the_complete_h4_packet(self):
        for packet, direction in ((RESET, 1), (ACL, 1), (SCO, 1), (EVENT, 0)):
            for n in range(len(packet)):
                self.assertEqual(self.valid(packet[:n], direction), 0)
            self.assertEqual(self.valid(packet + b"\x00", direction), 0)

    def test_controller_and_host_limits_are_enforced_before_forwarding(self):
        # 5-byte ACL header including H4; host kernel accepts at most 1028 total.
        host_max = b"\x02\x01\x00\xff\x03" + b"x" * 1023
        host_large = b"\x02\x01\x00\x00\x04" + b"x" * 1024
        outer_max = b"\x02\x01\x00\xfb\x0f" + b"x" * 4091
        outer_large = b"\x02\x01\x00\xfc\x0f" + b"x" * 4092
        self.assertEqual(self.valid(host_max, 1), 1)
        self.assertEqual(self.valid(host_large, 1), 0)
        self.assertEqual(self.valid(outer_max, 0), 1)
        self.assertEqual(self.valid(outer_large, 0), 0)


class PumpTests(unittest.TestCase):
    def setUp(self):
        self.hci, self.controller = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.tcp, self.host = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.hci.setblocking(False)
        self.tcp.setblocking(False)
        self.controller.settimeout(0.5)
        self.host.settimeout(0.5)
        self.stats = Stats()
        self.result = None
        self.thread = None

    def tearDown(self):
        for sock in (self.hci, self.tcp, self.controller, self.host):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if self.thread:
            self.thread.join(0.2)
        for sock in (self.hci, self.tcp, self.controller, self.host):
            sock.close()

    def start(self, duration=1000, stall=300):
        def run():
            self.result = LIB.relay_pump(self.hci.fileno(), self.tcp.fileno(),
                                         duration, stall, ctypes.byref(self.stats))
        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()

    def finish(self, result, reason, timeout=1.5):
        self.thread.join(timeout)
        self.assertFalse(self.thread.is_alive(), "pump exceeded its bounded test deadline")
        self.assertEqual(self.result, result)
        self.assertEqual(self.stats.stop_reason, reason)

    def test_fragmented_prefix_and_body_never_become_partial_hci_packets(self):
        self.start()
        self.controller.settimeout(0.025)
        self.host.sendall(frame(RESET)[:1])
        with self.assertRaises(socket.timeout):
            self.controller.recv(32)
        self.host.sendall(frame(RESET)[1:4])
        with self.assertRaises(socket.timeout):
            self.controller.recv(32)
        self.host.sendall(frame(RESET)[4:])
        self.controller.settimeout(0.5)
        self.assertEqual(self.controller.recv(32), RESET)
        self.host.shutdown(socket.SHUT_WR)
        self.finish(0, 1)
        self.assertEqual(self.stats.to_controller, 1)

    def test_coalesced_tcp_frames_preserve_atomic_hci_packet_boundaries(self):
        self.start()
        self.host.sendall(frame(RESET) + frame(VERSION) + frame(ACL))
        self.assertEqual(self.controller.recv(4096), RESET)
        self.assertEqual(self.controller.recv(4096), VERSION)
        self.assertEqual(self.controller.recv(4096), ACL)
        self.host.shutdown(socket.SHUT_WR)
        self.finish(0, 1)
        self.assertEqual(self.stats.to_controller, 3)

    def test_both_directions_progress_without_waiting_for_the_other_to_finish(self):
        self.start()
        for _ in range(10):
            self.host.sendall(frame(ACL))
            self.controller.send(EVENT)
            self.assertEqual(receive_frame(self.host), EVENT)
            self.assertEqual(self.controller.recv(4096), ACL)
        self.host.shutdown(socket.SHUT_WR)
        self.finish(0, 1)
        self.assertEqual((self.stats.to_controller, self.stats.to_host), (10, 10))

    def test_zero_length_frame_ends_session_without_touching_controller(self):
        self.start()
        self.host.sendall(b"\x00\x00")
        self.finish(-1, 3)
        self.assertEqual(self.stats.to_controller, 0)

    def test_oversized_frame_is_rejected_from_header_alone(self):
        self.start()
        self.host.sendall(b"\x10\x01")
        self.finish(-1, 3)
        self.assertEqual(self.stats.to_controller, 0)

    def test_wrong_direction_packet_is_rejected_without_forwarding(self):
        self.start()
        self.host.sendall(frame(EVENT))
        self.finish(-1, 3)
        self.assertEqual(self.stats.to_controller, 0)

    def test_eof_mid_prefix_is_malformed_not_clean_disconnect(self):
        self.start()
        self.host.sendall(b"\x00")
        self.host.shutdown(socket.SHUT_WR)
        self.finish(-1, 3)

    def test_eof_mid_body_is_malformed_not_clean_disconnect(self):
        self.start()
        self.host.sendall(frame(RESET)[:-1])
        self.host.shutdown(socket.SHUT_WR)
        self.finish(-1, 3)
        self.assertEqual(self.stats.to_controller, 0)

    def test_truncated_controller_datagram_is_never_forwarded(self):
        self.start()
        packet = b"\x02\x01\x00\xfc\x0f" + b"x" * 4092
        self.controller.send(packet)
        self.finish(-1, 3)
        self.assertEqual(self.stats.to_host, 0)

    def test_idle_session_uses_global_deadline_not_pending_io_stall_timeout(self):
        self.start(duration=100, stall=25)
        self.finish(0, 2, timeout=0.6)

    def test_partial_frame_without_progress_hits_stall_timeout(self):
        self.start(duration=800, stall=60)
        self.host.sendall(b"\x00")
        self.finish(-1, 5, timeout=0.5)

    def test_trickle_progress_cannot_extend_the_absolute_deadline(self):
        self.start(duration=180, stall=80)
        stop = threading.Event()
        def trickle():
            try:
                for byte in frame(b"\x02\x01\x00\xf4\x01" + b"x" * 500):
                    if stop.wait(0.01):
                        return
                    self.host.sendall(bytes([byte]))
            except OSError:
                pass
        sender = threading.Thread(target=trickle, daemon=True)
        sender.start()
        try:
            self.finish(0, 2, timeout=0.65)
            self.assertEqual(self.stats.to_controller, 0)
        finally:
            stop.set()
            sender.join(0.2)

    def test_backpressure_on_tcp_output_is_bounded_by_pending_io_stall(self):
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        self.controller.settimeout(0.02)
        self.start(duration=1500, stall=100)
        stop = threading.Event()
        packet = b"\x02\x01\x00\x9b\x0f" + b"x" * 3995
        def fill():
            while not stop.is_set():
                try:
                    self.controller.send(packet)
                except socket.timeout:
                    continue
                except OSError:
                    return
        sender = threading.Thread(target=fill, daemon=True)
        sender.start()
        try:
            self.finish(-1, 5, timeout=0.8)
        finally:
            stop.set()
            sender.join(0.2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
