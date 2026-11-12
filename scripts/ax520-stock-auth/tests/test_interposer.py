# SPDX-License-Identifier: GPL-3.0-or-later
"""Run real preload/network behavior against an explicitly synthetic provider.

These tests catch missing child/provider gates, provider forcing, loss of shared
serialization, oversized frames, provider failures and accidental real-device
enablement. No stock binary, certificate, private key or signature is used.
"""
import concurrent.futures
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent


def build(command):
    subprocess.run(command, check=True)


def exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("truncated synthetic response")
        data += chunk
    return data


class App:
    def __init__(self, artifacts, library="bridge.so", extra=None, observer=False, full=False,
                 oversized_observer=False):
        with socket.socket() as candidate:
            candidate.bind(("127.0.0.1", 0))
            self.port = candidate.getsockname()[1]
        env = os.environ.copy()
        env.update(AX520_AUTH_PORT=str(self.port), LD_LIBRARY_PATH=str(artifacts))
        preload = artifacts / library
        env["LD_PRELOAD"] = str(preload)
        if extra:
            env.update(extra)
        self.observer_read = None
        inherited = ()
        if observer:
            reader, writer = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
            self.observer_read = reader
            inherited = (reader, writer)
            env["AX520_OBSERVER_FDS"] = f"{reader}:{writer}"
            if oversized_observer:
                env["AX520_OBSERVER_FDS"] = f"{reader + 2**32}:{writer}"
            if full:
                while True:
                    try:
                        os.write(writer, b"x" * 4096)
                    except BlockingIOError:
                        break
        self.process = subprocess.Popen(
            [str(artifacts / "mock-app")], env=env, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            start_new_session=True, pass_fds=inherited,
        )
        if observer:
            os.close(writer)
        if self.read() != "ready":
            raise AssertionError("mock application did not start")

    def read(self):
        if not select.select([self.process.stdout], [], [], 4)[0]:
            raise AssertionError("mock application timed out")
        value = self.process.stdout.readline().strip()
        if not value:
            raise AssertionError("mock application exited: " + self.process.stderr.read())
        return value

    def command(self, value):
        self.process.stdin.write(value + "\n")
        self.process.stdin.flush()
        return self.read()

    def connect(self):
        return socket.create_connection(("127.0.0.1", self.port), timeout=2)

    def ready(self):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                with self.connect():
                    return
            except OSError:
                time.sleep(.01)
        raise AssertionError("selected child never opened synthetic broker")

    def request(self, request):
        with self.connect() as stream:
            stream.sendall(request)
            status, size = struct.unpack("!BH", exact(stream, 3))
            return status, exact(stream, size)

    def counts(self):
        return tuple(map(int, self.command("counts").split()))

    def events(self):
        if not select.select([self.observer_read], [], [], 1)[0]:
            raise AssertionError("no fixed observer event arrived")
        data = os.read(self.observer_read, 4096)
        if len(data) % 12:
            raise AssertionError("observer emitted a partial event")
        events = []
        for offset in range(0, len(data), 12):
            magic, version, flags, reserved, pid = struct.unpack("!4sBBHI", data[offset:offset + 12])
            if (magic, version, reserved) != (b"AXOB", 1, 0):
                raise AssertionError("invalid observer event")
            events.append((flags, pid))
        return events

    def close(self):
        try:
            os.killpg(self.process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        self.process.communicate(timeout=4)
        if self.observer_read is not None:
            os.close(self.observer_read)


class InterposerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="ax520-mock-")
        cls.artifacts = Path(cls.temporary.name)
        common = ["cc", "-std=c11", "-D_POSIX_C_SOURCE=200809L", "-D_FORTIFY_SOURCE=2", "-Wall", "-Wextra", "-Werror", "-O1", "-g", "-pthread"]
        build(common + ["-shared", "-fPIC", str(HERE / "mock_vendor.c"),
              "-Wl,--version-script=" + str(HERE / "mock_vendor.map"),
              "-o", str(cls.artifacts / "libmock.so")])
        build(common + [str(HERE / "mock_app.c"), "-L" + str(cls.artifacts),
              "-lmock", "-o", str(cls.artifacts / "mock-app")])
        (cls.artifacts / "no-marker").mkdir()
        build(common + ["-DMOCK_WITHOUT_MARKER", "-shared", "-fPIC", str(HERE / "mock_vendor.c"),
              "-Wl,--version-script=" + str(HERE / "mock_vendor.map"),
              "-o", str(cls.artifacts / "no-marker" / "libmock.so")])
        build(common + ["-shared", "-fPIC", str(HERE / "mock_marker.c"),
              "-o", str(cls.artifacts / "unrelated-marker.so")])
        for target, flags in [("bridge.so", ["-DAX520_SYNTHETIC_TEST"]), ("observe.so", [])]:
            build(common + flags + ["-shared", "-fPIC", str(SOURCE / "interposer.c"),
                  "-Wl,--version-script=" + str(SOURCE / "interposer.map"),
                  "-ldl", "-o", str(cls.artifacts / target)])

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def start(self, **kwargs):
        app = App(self.artifacts, **kwargs)
        self.addCleanup(app.close)
        return app

    def selected(self):
        app = self.start()
        self.assertEqual(app.command("select"), "selected 0")
        app.ready()
        return app

    def assert_closed(self, app):
        with self.assertRaises(OSError):
            with app.connect():
                pass

    def test_no_listener_or_provider_forcing_before_stock_selection(self):
        app = self.start()
        self.assert_closed(app)
        self.assertEqual(app.counts(), (0, 0, 0, 0))

    def test_normal_setter_is_forwarded_and_opens_synthetic_child_only(self):
        app = self.selected()
        self.assertEqual(app.counts(), (1, 0, 0, 0))
        self.assertEqual(app.request(b"\x03"), (0, b"\x03"))
        self.assertEqual(app.counts(), (1, 0, 0, 0))

    def test_supervisor_does_not_start_listener(self):
        app = self.start(extra={"MOCK_NO_FORK": "1"})
        self.assertEqual(app.command("select"), "selected 0")
        self.assert_closed(app)

    def test_fork_does_not_inherit_readiness(self):
        app = self.start(extra={"MOCK_SELECT_BEFORE_FORK": "1"})
        self.assert_closed(app)
        self.assertEqual(app.counts()[0], 1)
        app.command("select")
        app.ready()
        self.assertEqual(app.request(b"\x03"), (0, b"\x03"))

    def test_default_build_never_exposes_provider(self):
        app = self.start(library="observe.so")
        app.command("select")
        self.assert_closed(app)

    def test_test_build_cannot_enable_a_provider_without_synthetic_marker(self):
        app = self.start(extra={"LD_LIBRARY_PATH": str(self.artifacts / "no-marker")})
        self.assertEqual(app.command("select"), "selected 0")
        self.assert_closed(app)

    def test_failed_setter_is_forwarded_without_readiness(self):
        app = self.start()
        self.assertEqual(app.command("bad"), "bad -71")
        self.assert_closed(app)
        self.assertEqual(app.counts(), (1, 0, 0, 0))

    def test_unrelated_marker_cannot_enable_a_different_provider(self):
        app = self.start(extra={
            "LD_LIBRARY_PATH": str(self.artifacts / "no-marker"),
            "LD_PRELOAD": str(self.artifacts / "bridge.so") + ":" + str(self.artifacts / "unrelated-marker.so"),
        })
        self.assertEqual(app.command("select"), "selected 0")
        self.assert_closed(app)

    def test_mode_change_revokes_an_open_session(self):
        app = self.selected()
        with app.connect() as stream:
            stream.sendall(b"\x03")
            self.assertEqual(exact(stream, 4), b"\x00\x00\x01\x03")
            app.command("hardware")
            # Closing readiness must also stop a previously connected client.
            stream.settimeout(.3)
            try:
                data = stream.recv(1)
            except TimeoutError:
                self.fail("mode change left an authenticated broker connection open")
            self.assertEqual(data, b"")

    def test_refork_closes_child_copies_without_shutdown_of_parent_listener(self):
        app = self.selected()
        with socket.socket() as candidate:
            candidate.bind(("127.0.0.1", 0))
            child_port = candidate.getsockname()[1]
        self.assertEqual(app.command("refork " + str(child_port)), "reforked")
        self.assertEqual(app.request(b"\x03"), (0, b"\x03"))
        app.port = child_port
        self.assert_closed(app)
        app.command("select")
        app.ready()
        self.assertEqual(app.request(b"\x03"), (0, b"\x03"))

    def test_synthetic_certificate_and_signature_wire_frames(self):
        app = self.selected()
        with app.connect() as stream:
            stream.sendall(b"\x03\x01\x02\x00\x20" + b" " * 32)
            self.assertEqual(exact(stream, 4), b"\x00\x00\x01\x03")
            self.assertEqual(exact(stream, 17), b"\x00\x00\x0eSYNTHETIC-CERT")
            self.assertEqual(exact(stream, 67), b"\x00\x00\x40" + b"z" * 64)

    def test_mode_change_fails_closed_without_changing_stock_arguments(self):
        app = self.selected()
        self.assertEqual(app.command("hardware"), "hardware 23")
        for request in (b"\x01", b"\x03", b"\x02\x00\x20" + b" " * 32):
            self.assertEqual(app.request(request), (1, b""))
        self.assertEqual(app.counts(), (2, 0, 0, 0))
        app.command("select")
        self.assertEqual(app.request(b"\x03"), (0, b"\x03"))

    def test_invalid_sign_lengths_reject_without_calling_provider(self):
        app = self.selected()
        for size in (0, 1, 31, 33, 65535):
            with app.connect() as stream:
                stream.sendall(b"\x02" + struct.pack("!H", size))
                self.assertEqual(exact(stream, 3), b"\x01\x00\x00")
                self.assertEqual(stream.recv(1), b"")
        self.assertEqual(app.counts(), (1, 0, 0, 0))

    def test_provider_oversized_null_and_error_outputs_fail_closed(self):
        app = self.selected()
        app.command("fault 1")
        self.assertEqual(app.request(b"\x01"), (1, b""))
        for fault in (2, 3, 4):
            app.command("fault " + str(fault))
            self.assertEqual(app.request(b"\x02\x00\x20" + b" " * 32), (1, b""))

    def test_stock_and_broker_calls_share_serialization(self):
        app = self.selected()
        app.command("work")
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            replies = list(pool.map(lambda _: app.request(b"\x02\x00\x20" + b" " * 32), range(8)))
        self.assertEqual(replies, [(0, b"z" * 64)] * 8)
        self.assertEqual(app.command("join"), "joined")
        setters, calls, certs, peak = app.counts()
        self.assertEqual((setters, calls, certs, peak), (1, 104, 0, 1))

    def test_truncated_request_times_out_without_signing(self):
        app = self.selected()
        with app.connect() as stream:
            stream.sendall(b"\x02\x00\x20x")
            stream.settimeout(4)
            self.assertEqual(stream.recv(1), b"")
        self.assertEqual(app.counts(), (1, 0, 0, 0))
        self.assertEqual(app.request(b"\x03"), (0, b"\x03"))

    def test_busy_provider_does_not_execute_an_expired_broker_request(self):
        app = self.selected()
        app.command("fault 5")
        app.command("work")
        deadline = time.monotonic() + 1
        while app.counts()[1] == 0 and time.monotonic() < deadline:
            time.sleep(.005)
        self.assertEqual(app.counts()[1], 1)
        with app.connect() as stream:
            stream.settimeout(2.7)
            stream.sendall(b"\x02\x00\x20" + b" " * 32)
            try:
                response = exact(stream, 3)
            except TimeoutError:
                self.fail("broker waited past its deadline for the stock provider")
            self.assertEqual(response, b"\x01\x00\x00")
        self.assertEqual(app.counts()[1], 1)

    def test_observer_reports_only_fixed_flags_and_pid_without_provider_calls(self):
        app = self.start(library="observe.so", observer=True)
        self.assertEqual(app.events(), [(0, app.process.pid)])
        self.assertEqual(app.command("select"), "selected 0")
        events = app.events()
        self.assertEqual(len(events), 1)
        flags, pid = events[0]
        self.assertEqual(flags, 7)
        self.assertGreater(pid, 0)
        self.assertNotEqual(pid, app.process.pid)
        self.assertEqual(app.counts(), (1, 0, 0, 0))
        self.assert_closed(app)
        app.command("hardware")
        self.assertEqual(app.events(), [(13, pid)])

    def test_full_observer_pipe_cannot_stall_stock_setter(self):
        app = self.start(library="observe.so", observer=True, full=True)
        start = time.monotonic()
        self.assertEqual(app.command("select"), "selected 0")
        self.assertLess(time.monotonic() - start, .5)
        self.assertEqual(app.counts(), (1, 0, 0, 0))

    def test_closed_observer_collector_cannot_signal_stock_process(self):
        app = self.start(library="observe.so", observer=True)
        os.close(app.observer_read)
        app.observer_read = None
        self.assertEqual(app.command("select"), "selected 0")
        self.assertEqual(app.counts(), (1, 0, 0, 0))

    def test_overlarge_observer_fd_is_rejected_without_wrapping(self):
        # On ARM32, unchecked multiplication could wrap this onto the real fd.
        app = self.start(library="observe.so", observer=True, oversized_observer=True)
        self.assertEqual(app.command("select"), "selected 0")
        self.assertFalse(select.select([app.observer_read], [], [], .05)[0])

    def test_unknown_operation_closes_without_calling_provider(self):
        app = self.selected()
        with app.connect() as stream:
            stream.sendall(b"\xff")
            self.assertEqual(stream.recv(1), b"")
        self.assertEqual(app.counts(), (1, 0, 0, 0))

    def test_invalid_configured_port_stays_closed(self):
        for port in ("0", "-1", "65536", "123x", " 123", ""):
            with self.subTest(port=port):
                app = self.start(extra={"AX520_AUTH_PORT": port})
                app.command("select")
                self.assert_closed(app)


if __name__ == "__main__":
    unittest.main()
