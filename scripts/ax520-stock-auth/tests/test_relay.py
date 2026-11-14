# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise the isolated byte relay against synthetic local TCP peers only."""
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import unittest


class RelayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="ax520-relay-test-")
        cls.exe = Path(cls.temp.name) / "relay"
        source = Path(__file__).resolve().parents[1] / "relay.c"
        cls.build = subprocess.run(
            ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
             str(source), "-o", str(cls.exe)], capture_output=True, text=True
        )

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def relay(self, args=(), **kwargs):
        self.assertEqual(self.build.returncode, 0, self.build.stderr)
        env = os.environ.copy()
        env.pop("AX520_RELAY_PORT", None)
        env["AX520_RELAY_IDLE_MS"] = "1500"
        env.update(kwargs.pop("env", {}))
        return subprocess.run([str(self.exe), *map(str, args)], env=env,
                              capture_output=True, timeout=5, **kwargs)

    def peer(self, handler):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(4)
        errors = []
        def serve():
            try:
                with listener:
                    conn, _ = listener.accept()
                    with conn:
                        conn.settimeout(4)
                        handler(conn)
            except Exception as exc:
                errors.append(exc)
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        return listener.getsockname()[1], thread, errors

    @staticmethod
    def receive_all(conn):
        chunks = []
        while True:
            data = conn.recv(4096)
            if not data:
                return b"".join(chunks)
            chunks.append(data)

    def test_preserves_bytes_and_stdin_half_close_before_response(self):
        # Catches line-oriented forwarding, truncation, and missing SHUT_WR.
        sent = bytes(range(256)) * 512
        received = []
        def handler(conn):
            received.append(self.receive_all(conn))
            conn.sendall(b"\x00reply\xff\n" * 1024)
        port, thread, errors = self.peer(handler)
        result = self.relay([port], input=sent)
        thread.join(4)
        self.assertEqual(errors, [])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(received, [sent])
        self.assertEqual(result.stdout, b"\x00reply\xff\n" * 1024)
        self.assertEqual(result.stderr, b"")

    def test_peer_half_close_does_not_discard_pending_stdin(self):
        # Catches treating a peer write-half close as a full disconnect.
        received = []
        sent = b"after-peer-eof\x00\xff" * 32768
        def handler(conn):
            conn.sendall(b"hello\x00\xff")
            conn.shutdown(socket.SHUT_WR)
            received.append(self.receive_all(conn))
        port, thread, errors = self.peer(handler)
        result = self.relay([], input=sent, env={"AX520_RELAY_PORT": str(port)})
        thread.join(4)
        self.assertEqual(errors, [])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(received, [sent])
        self.assertEqual(result.stdout, b"hello\x00\xff")

    def test_simultaneous_large_duplex_flow(self):
        # Catches deadlock when both directions exceed socket/pipe buffers.
        sent = bytes(range(256)) * 4096
        received = []
        def handler(conn):
            writer = threading.Thread(target=conn.sendall, args=(sent[::-1],))
            writer.start()
            received.append(self.receive_all(conn))
            writer.join(3)
            if writer.is_alive():
                raise AssertionError("peer writer stuck")
        port, thread, errors = self.peer(handler)
        result = self.relay([port], input=sent)
        thread.join(4)
        self.assertEqual(errors, [])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(received, [sent])
        self.assertEqual(result.stdout, sent[::-1])

    def test_rejects_invalid_configuration_without_stdout(self):
        # Catches permissive numeric parsing and accidentally accepting a host.
        cases = [["0"], ["-1"], ["65536"], [" 15"], ["15x"], [""],
                 ["127.0.0.2", "15000"], ["1", "2"]]
        for args in cases:
            with self.subTest(args=args):
                result = self.relay(args, input=b"")
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b"")
        for env in ({"AX520_RELAY_PORT": "0"},
                    {"AX520_RELAY_IDLE_MS": "0"},
                    {"AX520_RELAY_IDLE_MS": "60001"}):
            with self.subTest(env=env):
                result = self.relay([], input=b"", env=env)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b"")

    def test_idle_peer_is_bounded_and_logs_no_content(self):
        # Catches an unbounded read after stdin EOF and payload diagnostics.
        secret = b"synthetic-payload-not-for-logs"
        closed = []
        def handler(conn):
            self.receive_all(conn)
            # Peer deliberately keeps its response half open past the bound.
            closed.append(conn.recv(1))
            time.sleep(0.4)
        port, thread, errors = self.peer(handler)
        started = time.monotonic()
        result = self.relay([port], input=secret,
                            env={"AX520_RELAY_IDLE_MS": "150"})
        elapsed = time.monotonic() - started
        thread.join(4)
        self.assertEqual(errors, [])
        self.assertEqual(result.returncode, 1)
        self.assertLess(elapsed, 2)
        self.assertGreater(elapsed, 0.08)
        self.assertEqual(result.stdout, b"")
        self.assertNotIn(secret, result.stderr)

    def test_blocked_stdout_obeys_idle_deadline(self):
        # Catches a blocking write that escapes the poll idle deadline.
        def handler(conn):
            try:
                conn.sendall(b"x" * (4 * 1024 * 1024))
            except (BrokenPipeError, ConnectionResetError):
                pass
        port, thread, errors = self.peer(handler)
        self.assertEqual(self.build.returncode, 0, self.build.stderr)
        env = os.environ.copy()
        env["AX520_RELAY_IDLE_MS"] = "150"
        proc = subprocess.Popen([str(self.exe), str(port)], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        try:
            self.assertEqual(proc.wait(timeout=3), 1)
            self.assertNotIn(b"x" * 32, proc.stderr.read())
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            proc.stdout.close()
            proc.stderr.close()
        thread.join(4)
        self.assertEqual(errors, [])

    def test_closed_stdout_returns_error_without_sigpipe(self):
        # Catches process death from SIGPIPE instead of a controlled I/O error.
        port, thread, errors = self.peer(lambda conn: conn.sendall(b"synthetic-output"))
        self.assertEqual(self.build.returncode, 0, self.build.stderr)
        read_fd, write_fd = os.pipe()
        os.close(read_fd)
        try:
            result = subprocess.run([str(self.exe), str(port)], stdin=subprocess.DEVNULL,
                                    stdout=write_fd, stderr=subprocess.PIPE, timeout=3)
        finally:
            os.close(write_fd)
        thread.join(4)
        self.assertEqual(errors, [])
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(b"synthetic-output", result.stderr)

    def test_connection_refusal_fails_without_stdout(self):
        # Catches silently reporting success on a failed connect.
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            result = self.relay([reserved.getsockname()[1]], input=b"synthetic")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"")
        self.assertNotIn(b"synthetic", result.stderr)


if __name__ == "__main__":
    unittest.main()
