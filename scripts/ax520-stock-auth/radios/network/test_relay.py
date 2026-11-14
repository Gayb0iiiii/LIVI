"""Offline relay contract tests; no real interfaces, device probes or credentials.

Run after building librelay.so and relay-host in this directory:
    python3 -m unittest -v test_relay
Framing is a two-byte, network-order Ethernet length followed by that frame.
"""
import ctypes
import errno
from pathlib import Path
import socket
import struct
import subprocess
import threading
import time
import unittest


ROOT = Path(__file__).resolve().parent
U8 = ctypes.c_uint8
PI = bytes.fromhex("02a1b2c3d4e5")
PEER = bytes.fromhex("a4b5c6d7e8f9")
OTHER = bytes.fromhex("a4b5c6d7e801")
BROADCAST = b"\xff" * 6
MDNS4 = bytes.fromhex("01005e0000fb")
MDNS6 = bytes.fromhex("3333000000fb")


def ethernet(destination=PI, source=PEER, kind=0x0800, size=60):
    return destination + source + struct.pack("!H", kind) + bytes(
        (i * 37) & 255 for i in range(size - 14)
    )


def wire(frame):
    return struct.pack("!H", len(frame)) + frame


class LibraryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (ROOT / "librelay.so").is_file():
            raise AssertionError("relay implementation missing: librelay.so")
        cls.lib = ctypes.CDLL(str(ROOT / "librelay.so"), use_errno=True)
        byte_pointer = ctypes.POINTER(U8)
        cls.lib.frame_allowed.argtypes = [byte_pointer, ctypes.c_size_t,
                                         byte_pointer, ctypes.c_int, ctypes.c_int]
        cls.lib.frame_allowed.restype = ctypes.c_int
        cls.lib.read_frame.argtypes = [ctypes.c_int, byte_pointer, ctypes.c_size_t,
                                      ctypes.c_int64]
        cls.lib.read_frame.restype = ctypes.c_int
        cls.lib.write_frame.argtypes = [ctypes.c_int, byte_pointer, ctypes.c_size_t,
                                       ctypes.c_int64]
        cls.lib.write_frame.restype = ctypes.c_int
        cls.lib.now_ms.argtypes = []
        cls.lib.now_ms.restype = ctypes.c_int64
        cls.lib.parse_mac.argtypes = [ctypes.c_char_p, byte_pointer]
        cls.lib.parse_mac.restype = ctypes.c_int

    def sockets(self):
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        return left, right

    def deadline(self, delta=1500):
        return self.lib.now_ms() + delta

    def allowed(self, frame, from_wifi=True, packet_type=0):
        data = (U8 * len(frame)).from_buffer_copy(frame)
        mac = (U8 * 6).from_buffer_copy(PI)
        return self.lib.frame_allowed(data, len(frame), mac,
                                      int(from_wifi), packet_type)

    def read(self, fd, cap=1514, deadline=None):
        buffer = (U8 * max(cap, 1))()
        ctypes.set_errno(0)
        result = self.lib.read_frame(fd, buffer, cap,
                                     self.deadline() if deadline is None else deadline)
        return result, bytes(buffer[:max(0, result)]), ctypes.get_errno()

    def write(self, fd, frame, deadline=None):
        buffer = (U8 * len(frame)).from_buffer_copy(frame)
        ctypes.set_errno(0)
        result = self.lib.write_frame(fd, buffer, len(frame),
                                      self.deadline() if deadline is None else deadline)
        return result, ctypes.get_errno()

    def test_wifi_accepts_only_pi_or_group_destinations(self):
        for destination in (PI, BROADCAST, MDNS4, MDNS6):
            for kind in (0x0800, 0x0806, 0x86DD):
                with self.subTest(destination=destination.hex(), kind=kind):
                    self.assertEqual(self.allowed(ethernet(destination, kind=kind)), 1)
        self.assertEqual(self.allowed(ethernet(OTHER)), 0)
        self.assertEqual(self.allowed(ethernet(b"\x00" * 6)), 0)

    def test_wifi_drops_outgoing_and_own_source_frames(self):
        self.assertEqual(self.allowed(ethernet(), packet_type=4), 0)
        self.assertEqual(self.allowed(ethernet(BROADCAST, PI)), 0)
        self.assertEqual(self.allowed(ethernet(PI, PI)), 0)

    def test_wifi_rejects_nonunicast_and_zero_sources(self):
        for source in (BROADCAST, MDNS4, MDNS6, b"\x00" * 6):
            with self.subTest(source=source.hex()):
                self.assertEqual(self.allowed(ethernet(source=source)), 0)

    def test_host_requires_pi_source_and_nonself_destination(self):
        for destination in (PEER, BROADCAST, MDNS4, MDNS6):
            with self.subTest(destination=destination.hex()):
                self.assertEqual(self.allowed(ethernet(destination, PI), False), 1)
        for source in (PEER, BROADCAST, b"\x00" * 6):
            with self.subTest(source=source.hex()):
                self.assertEqual(self.allowed(ethernet(PEER, source), False), 0)
        for destination in (PI, b"\x00" * 6):
            with self.subTest(destination=destination.hex()):
                self.assertEqual(self.allowed(ethernet(destination, PI), False), 0)

    def test_filter_rejects_eapol_vlan_and_unsupported_ethertypes(self):
        for kind in (0x888E, 0x8100, 0x88A8, 0x0805, 0x0000):
            for from_wifi in (True, False):
                frame = ethernet(PI, PEER, kind) if from_wifi else ethernet(PEER, PI, kind)
                with self.subTest(kind=kind, from_wifi=from_wifi):
                    self.assertEqual(self.allowed(frame, from_wifi), 0)

    def test_filter_checks_ethernet_length_bounds(self):
        for size in (14, 1514):
            self.assertEqual(self.allowed(ethernet(size=size)), 1)
        for frame in (b"", ethernet()[:13], ethernet(size=1515)):
            self.assertEqual(self.allowed(frame), 0)

    def test_mac_parser_accepts_strict_local_unicast_hex(self):
        for text, want in ((b"02:a1:b2:c3:d4:e5", PI),
                           (b"FE:AB:CD:EF:01:23", bytes.fromhex("feabcdef0123"))):
            output = (U8 * 6)()
            self.assertEqual(self.lib.parse_mac(text, output), 0)
            self.assertEqual(bytes(output), want)

    def test_mac_parser_rejects_ambiguous_or_disallowed_addresses(self):
        values = (b"", b"00:00:00:00:00:00", b"00:11:22:33:44:55",
                  b"03:11:22:33:44:55", b"ff:ff:ff:ff:ff:ff",
                  b"2:a1:b2:c3:d4:e5", b"002:a1:b2:c3:d4:e5",
                  b"02-a1-b2-c3-d4-e5", b"02:a1:b2:c3:d4",
                  b"02:a1:b2:c3:d4:e5:00", b"02:a1:b2:c3:d4:gg",
                  b" 02:a1:b2:c3:d4:e5", b"02:a1:b2:c3:d4:e5\n",
                  b"02:a1:b2:c3:d4:e5garbage")
        for text in values:
            with self.subTest(text=text):
                self.assertEqual(self.lib.parse_mac(text, (U8 * 6)()), -1)

    def test_read_reassembles_fragmented_header_and_body(self):
        receiver, sender = self.sockets()
        frame = ethernet(size=1514)
        encoded = wire(frame)
        errors = []

        def send_fragments():
            try:
                for part in (encoded[:1], encoded[1:2], encoded[2:15], encoded[15:]):
                    sender.sendall(part)
                    time.sleep(0.01)
            except Exception as error:
                errors.append(error)

        thread = threading.Thread(target=send_fragments, daemon=True)
        thread.start()
        count, got, _ = self.read(receiver.fileno())
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertFalse(errors)
        self.assertEqual((count, got), (len(frame), frame))

    def test_read_preserves_boundaries_of_coalesced_frames(self):
        receiver, sender = self.sockets()
        first = ethernet(kind=0x0806, size=14)
        second = ethernet(MDNS6, kind=0x86DD, size=1514)
        sender.sendall(wire(first) + wire(second))
        self.assertEqual(self.read(receiver.fileno())[:2], (14, first))
        self.assertEqual(self.read(receiver.fileno())[:2], (1514, second))

    def test_read_rejects_invalid_length_without_waiting_for_body(self):
        for length in (0, 1, 13, 1515, 65535):
            with self.subTest(length=length):
                receiver, sender = self.sockets()
                sender.sendall(struct.pack("!H", length))
                start = time.monotonic()
                result, _, error = self.read(receiver.fileno())
                self.assertEqual(result, -1)
                self.assertNotEqual(error, 0)
                self.assertLess(time.monotonic() - start, 0.75)

    def test_read_rejects_frame_larger_than_callers_buffer(self):
        receiver, sender = self.sockets()
        sender.sendall(wire(ethernet(size=60)))
        result, _, error = self.read(receiver.fileno(), cap=20)
        self.assertEqual(result, -1)
        self.assertNotEqual(error, 0)

    def test_read_reports_eof_at_each_incomplete_boundary(self):
        for prefix in (b"", b"\x00", b"\x00\x3c", wire(ethernet())[:-1]):
            with self.subTest(prefix_length=len(prefix)):
                receiver, sender = self.sockets()
                sender.sendall(prefix)
                sender.shutdown(socket.SHUT_WR)
                result, _, error = self.read(receiver.fileno())
                self.assertEqual(result, -1)
                self.assertNotEqual(error, 0)

    def test_read_deadline_applies_during_header_and_body(self):
        for prefix in (b"", b"\x00", b"\x00\x3c\x02"):
            with self.subTest(prefix_length=len(prefix)):
                receiver, sender = self.sockets()
                sender.sendall(prefix)
                start = time.monotonic()
                result, _, error = self.read(receiver.fileno(), deadline=self.deadline(100))
                self.assertEqual((result, error), (-1, errno.ETIMEDOUT))
                elapsed = time.monotonic() - start
                self.assertGreaterEqual(elapsed, 0.04)
                self.assertLess(elapsed, 0.75)

    def test_write_encodes_lengths_and_handles_backpressure(self):
        sender, receiver = self.sockets()
        sender.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 512)
        sender.setblocking(False)
        receiver.settimeout(3)
        frames = [ethernet(PEER, PI, 0x0800 if i % 2 else 0x86DD,
                           1514 if i % 3 else 14) for i in range(96)]
        expected = b"".join(wire(frame) for frame in frames)
        results = []

        def produce():
            for frame in frames:
                result = self.write(sender.fileno(), frame, self.deadline(2500))
                results.append(result)
                if result[0] != 0:
                    break

        thread = threading.Thread(target=produce, daemon=True)
        thread.start()
        time.sleep(0.03)
        got = bytearray()
        try:
            while len(got) < len(expected):
                chunk = receiver.recv(min(31, len(expected) - len(got)))
                if not chunk:
                    break
                got.extend(chunk)
        except socket.timeout:
            self.fail(f"write_frame stalled after {len(got)} of {len(expected)} bytes")
        thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual([r[0] for r in results], [0] * len(frames))
        self.assertEqual(bytes(got), expected)

    def test_write_rejects_invalid_frame_lengths(self):
        for frame in (b"", b"x" * 13, b"x" * 1515):
            with self.subTest(length=len(frame)):
                sender, receiver = self.sockets()
                result, error = self.write(sender.fileno(), frame)
                self.assertEqual(result, -1)
                self.assertNotEqual(error, 0)
                receiver.setblocking(False)
                with self.assertRaises(BlockingIOError):
                    receiver.recv(1)

    def test_write_times_out_when_peer_does_not_drain(self):
        sender, _receiver = self.sockets()
        sender.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 512)
        sender.setblocking(False)
        while True:
            try:
                sender.send(b"x" * 4096)
            except BlockingIOError:
                break
        start = time.monotonic()
        result, error = self.write(sender.fileno(), ethernet(PEER, PI), self.deadline(100))
        self.assertEqual((result, error), (-1, errno.ETIMEDOUT))
        self.assertLess(time.monotonic() - start, 0.75)


class MalformedCliTests(unittest.TestCase):
    def test_bad_arguments_are_rejected_before_any_device_operation(self):
        executable = ROOT / "relay-host"
        self.assertTrue(executable.is_file(), "relay implementation missing: relay-host")
        base = ["--run", "wlan0", "15101", "30", "02:a1:b2:c3:d4:e5"]
        invalid = [[], ["--unknown"], ["--probe"], ["--probe", "wlan0", "extra"],
                   base[:-1], base + ["extra"]]
        for value in ("0", "301", "-1", "1.5", "1junk", "99999999999999999999"):
            args = base.copy()
            args[3] = value
            invalid.append(args)
        for value in ("0", "-1", "65536", "15101junk", ""):
            args = base.copy()
            args[2] = value
            invalid.append(args)
        for value in ("", "03:a1:b2:c3:d4:e5", "00:a1:b2:c3:d4:e5",
                      "02:a1:b2:c3:d4:e5junk"):
            args = base.copy()
            args[4] = value
            invalid.append(args)
        for args in invalid:
            with self.subTest(args=args):
                result = subprocess.run([str(executable), *args], stdin=subprocess.DEVNULL,
                                        capture_output=True, timeout=2, check=False)
                self.assertEqual(result.returncode, 2, result.stderr.decode(errors="replace"))


if __name__ == "__main__":
    unittest.main()
