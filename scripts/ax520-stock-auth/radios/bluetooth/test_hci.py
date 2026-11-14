import ctypes
import hashlib
from pathlib import Path
import socket
import threading
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
LIB = ctypes.CDLL(str(ROOT / "hci-test.so"), use_errno=True)

class Version(ctypes.Structure):
    _fields_ = [("status", ctypes.c_uint), ("hci_version", ctypes.c_uint), ("lmp_version", ctypes.c_uint)]

LIB.decode_version.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(Version)]
LIB.hw_read_version.argtypes = [ctypes.c_int, ctypes.POINTER(Version)]
LIB.sha256_file.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
COMPLETE = bytes.fromhex("04 0e 0c 01 01 10 00 09 34 12 09 0a 00 78 56")

class HciTests(unittest.TestCase):
    def decode(self, packet):
        v = Version(255, 255, 255)
        return LIB.decode_version(packet, len(packet), ctypes.byref(v)), v

    def test_complete_returns_only_status_and_version_fields(self):
        rc, v = self.decode(COMPLETE)
        self.assertEqual(rc, 1)
        self.assertEqual((v.status, v.hci_version, v.lmp_version), (0, 9, 9))

    def test_truncated_or_inconsistent_event_is_not_success(self):
        for packet in [b"", b"\x04", COMPLETE[:6], COMPLETE[:-1], COMPLETE + b"\x00", bytes.fromhex("04 0e 04 01 01 10 00")]:
            with self.subTest(packet=packet):
                self.assertLess(self.decode(packet)[0], 0)

    def test_unrelated_opcode_and_events_are_ignored(self):
        packet = bytearray(COMPLETE)
        packet[4] = 2
        self.assertEqual(self.decode(bytes(packet))[0], 0)
        self.assertEqual(self.decode(bytes.fromhex("04 10 01 00"))[0], 0)

    def test_command_status_error_cannot_be_reported_as_proof(self):
        rc, v = self.decode(bytes.fromhex("04 0f 04 0c 01 01 10"))
        self.assertEqual(rc, 1)
        self.assertEqual(v.status, 12)
        self.assertEqual(self.decode(bytes.fromhex("04 0f 04 00 01 01 10"))[0], 0)

    def test_real_socket_sends_only_read_local_version_then_parses_response(self):
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        seen = []
        def controller():
            seen.append(b.recv(64))
            b.send(bytes.fromhex("04 10 01 00"))
            b.send(COMPLETE)
        t = threading.Thread(target=controller)
        t.start()
        try:
            v = Version()
            self.assertEqual(LIB.hw_read_version(a.fileno(), ctypes.byref(v)), 0)
            t.join(2)
            self.assertFalse(t.is_alive())
            self.assertEqual(seen, [bytes.fromhex("01 01 10 00")])
            self.assertEqual(v.status, 0)
            b.settimeout(0.05)
            with self.assertRaises(socket.timeout): b.recv(64)
        finally: a.close(); b.close()

    def test_controller_silence_is_bounded_and_fails(self):
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            v = Version()
            self.assertLess(LIB.hw_read_version(a.fileno(), ctypes.byref(v)), 0)
        finally: a.close(); b.close()

    def test_binary_pin_hash_matches_independent_implementation_at_padding_boundaries(self):
        with tempfile.NamedTemporaryFile() as f:
            for size in [0, 3, 55, 56, 63, 64, 65, 119, 120, 4097, 149692]:
                with self.subTest(size=size):
                    data = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
                    f.seek(0); f.truncate(); f.write(data); f.flush()
                    out = ctypes.create_string_buffer(65)
                    self.assertEqual(LIB.sha256_file(f.name.encode(), out), 0)
                    self.assertEqual(out.value.decode(), hashlib.sha256(data).hexdigest())

if __name__ == "__main__": unittest.main(verbosity=2)
