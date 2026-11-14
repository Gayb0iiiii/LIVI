# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise the real forwarder against local synthetic shell/relay peers."""
import concurrent.futures
import importlib.util
from pathlib import Path
import shlex
import socket
import subprocess
import sys
import threading
import time
import unittest

SOURCE = Path(__file__).resolve().parent.parent / "host_forward.py"
MODULE = None
if SOURCE.exists():
    spec = importlib.util.spec_from_file_location("ax520_host_forward", SOURCE)
    MODULE = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(MODULE)


def line(sock):
    result = b""
    while not result.endswith(b"\n"):
        data = sock.recv(1)
        if not data:
            raise EOFError("missing synthetic shell command")
        result += data
    return result


def drained(sock):
    result = b""
    while True:
        data = sock.recv(8192)
        if not data:
            return result
        result += data


class HostForwardTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(MODULE, "host forwarding implementation is missing")
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=5)
        self.addCleanup(self.pool.shutdown, wait=True, cancel_futures=True)
        self.upstream = socket.socket()
        self.upstream.bind(("127.0.0.1", 0))
        self.upstream.listen(8)
        self.upstream.settimeout(2)
        self.addCleanup(self.upstream.close)
        self.servers = []
        self.addCleanup(self.stop_servers)

    def stop_servers(self):
        for server, worker in self.servers:
            server.stop()
            worker.join(timeout=2)
            self.assertFalse(worker.is_alive(), "forwarder shutdown was not bounded")

    def start(self, path="/tmp/ax520-relay", **kwargs):
        server = MODULE.Forwarder(path, bind=("127.0.0.1", 0),
                                  upstream=self.upstream.getsockname(), **kwargs)
        worker = threading.Thread(target=server.serve)
        worker.start()
        self.servers.append((server, worker))
        client = socket.create_connection(server.address, timeout=2)
        client.settimeout(2)
        self.addCleanup(client.close)
        return server, client

    def peer(self, callback):
        def run():
            connection, _ = self.upstream.accept()
            with connection:
                connection.settimeout(2)
                return callback(connection)
        return self.pool.submit(run)

    def test_waits_for_whole_marker_and_preserves_coalesced_protocol_bytes(self):
        # Forwarding early would inject binary bytes into the shell; reading
        # beyond the marker would discard the first two reply bytes.
        def peer(connection):
            command = line(connection).decode()
            lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
            lexer.whitespace_split = True
            self.assertEqual(list(lexer), ["printf", "AX520-RELAY-READY\\n", ";", "exec", "/tmp/relay'$(false)"])
            connection.settimeout(.12)
            with self.assertRaises(socket.timeout):
                connection.recv(1)
            connection.sendall(b"AX520-RELAY-")
            with self.assertRaises(socket.timeout):
                connection.recv(1)
            connection.settimeout(2)
            connection.sendall(b"READY\n\x00\x00")
            self.assertEqual(connection.recv(1), b"\x03")
            connection.sendall(b"\x01\x03")
        task = self.peer(peer)
        _, client = self.start("/tmp/relay'$(false)")
        client.sendall(b"\x03")
        self.assertEqual(drained(client), b"\x00\x00\x01\x03")
        task.result(timeout=3)

    def test_client_half_close_allows_final_reply(self):
        def peer(connection):
            line(connection)
            connection.sendall(b"AX520-RELAY-READY\n")
            self.assertEqual(drained(connection), b"request")
            connection.sendall(b"final response")
        task = self.peer(peer)
        _, client = self.start()
        client.sendall(b"request")
        client.shutdown(socket.SHUT_WR)
        self.assertEqual(drained(client), b"final response")
        task.result(timeout=3)

    def test_peer_half_close_keeps_client_to_peer_direction_open(self):
        def peer(connection):
            line(connection)
            connection.sendall(b"AX520-RELAY-READY\nreply")
            connection.shutdown(socket.SHUT_WR)
            self.assertEqual(drained(connection), b"sent after peer EOF")
        task = self.peer(peer)
        _, client = self.start()
        self.assertEqual(drained(client), b"reply")
        client.sendall(b"sent after peer EOF")
        client.shutdown(socket.SHUT_WR)
        task.result(timeout=3)

    def test_wrong_marker_closes_without_forwarding_pending_client_payload(self):
        def peer(connection):
            line(connection)
            connection.sendall(b"WRONG\n")
            try:
                self.assertEqual(connection.recv(1), b"")
            except ConnectionResetError:
                pass  # Rejecting unread bytes can close with a TCP reset.
        task = self.peer(peer)
        _, client = self.start()
        client.sendall(b"must not reach the shell")
        try:
            self.assertEqual(client.recv(1), b"")
        except ConnectionResetError:
            pass
        task.result(timeout=3)

    def test_slow_marker_cannot_extend_readiness_deadline(self):
        def peer(connection):
            line(connection)
            try:
                for byte in b"AX520-RELAY-READY\n":
                    connection.sendall(bytes([byte]))
                    time.sleep(.08)
            except (BrokenPipeError, ConnectionResetError):
                pass
        task = self.peer(peer)
        _, client = self.start(handshake_timeout=.18)
        client.settimeout(.8)
        self.assertEqual(client.recv(1), b"")
        task.result(timeout=3)

    def test_stop_closes_pending_handshake(self):
        received_command = threading.Event()
        def peer(connection):
            line(connection)
            received_command.set()
            self.assertEqual(connection.recv(1), b"")
        task = self.peer(peer)
        server, client = self.start()
        self.assertTrue(received_command.wait(2))
        server.stop()
        self.assertEqual(client.recv(1), b"")
        task.result(timeout=3)

    def test_stop_closes_established_duplex_stream(self):
        def peer(connection):
            line(connection)
            connection.sendall(b"AX520-RELAY-READY\nreply")
            self.assertEqual(connection.recv(1), b"")
        task = self.peer(peer)
        server, client = self.start()
        self.assertEqual(client.recv(5), b"reply")
        server.stop()
        self.assertEqual(client.recv(1), b"")
        task.result(timeout=3)

    def test_stop_between_accept_and_tracking_is_normal_shutdown(self):
        server = MODULE.Forwarder("/tmp/relay", bind=("127.0.0.1", 0),
                                  upstream=self.upstream.getsockname())
        track = server._track
        def stop_before_tracking(sock):
            server.stop()
            track(sock)
        server._track = stop_before_tracking
        serving = self.pool.submit(server.serve)
        try:
            with socket.create_connection(server.address, timeout=2) as client:
                self.assertEqual(client.recv(1), b"")
            serving.result(timeout=2)
        finally:
            server.stop()

    def test_idle_established_stream_has_a_finite_deadline(self):
        def peer(connection):
            line(connection)
            connection.sendall(b"AX520-RELAY-READY\nreply")
            self.assertEqual(connection.recv(1), b"")
        task = self.peer(peer)
        _, client = self.start(idle_timeout=.15)
        client.settimeout(.8)
        self.assertEqual(drained(client), b"reply")
        task.result(timeout=2)

    def test_overall_lifetime_closes_even_an_incomplete_handshake(self):
        def peer(connection):
            line(connection)
            self.assertEqual(connection.recv(1), b"")
        task = self.peer(peer)
        _, client = self.start(seconds=.2)
        client.settimeout(1)
        self.assertEqual(client.recv(1), b"")
        task.result(timeout=2)

    def test_connection_limit_includes_pending_handshakes(self):
        server, first = self.start()
        clients = [first]
        peers = []
        for index in range(4):
            if index:
                client = socket.create_connection(server.address, timeout=2)
                clients.append(client)
                self.addCleanup(client.close)
            connection, _ = self.upstream.accept()
            connection.settimeout(2)
            peers.append(connection)
            self.addCleanup(connection.close)
            line(connection)
        with socket.create_connection(server.address, timeout=2) as extra:
            self.assertEqual(extra.recv(1), b"")
        self.upstream.settimeout(.15)
        with self.assertRaises(socket.timeout):
            self.upstream.accept()
        server.stop()
        for connection in peers:
            self.assertEqual(connection.recv(1), b"")

    def test_path_and_network_scope_validation_precedes_listening(self):
        for path in ["relative", "/tmp", "/tmp/.", "/tmp//", "/tmp/../bin/sh", "/etc/relay", "/tmp/a\ncommand", "/tmp/a\0b"]:
            with self.subTest(path=path), self.assertRaises(ValueError):
                MODULE.Forwarder(path, bind=("127.0.0.1", 0))
        for override in [{"bind": ("0.0.0.0", 0)}, {"upstream": ("192.168.50.100", 2323)}, {"seconds": 901}]:
            with self.subTest(override=override), self.assertRaises(ValueError):
                MODULE.Forwarder("/tmp/relay", **override)

    def test_cli_rejects_extra_destination_options_and_unbounded_lifetime(self):
        for arguments in [["/tmp/relay", "--upstream", "192.168.50.100:2323"],
                          ["/tmp/relay", "--seconds", "901"], ["/tmp/relay", "--seconds", "0"]]:
            checked = subprocess.run([sys.executable, str(SOURCE)] + arguments,
                                     capture_output=True, text=True, timeout=2)
            self.assertEqual(checked.returncode, 2)


if __name__ == "__main__":
    unittest.main()
