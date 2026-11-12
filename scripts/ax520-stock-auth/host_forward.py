#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Optional finite dev forwarder through the existing private stock-shell tunnel.

No payload logging or storage. This starts no service unless invoked explicitly.
The CLI fixes both addresses to IPv4 loopback; the dongle relay stays in /tmp.
"""
import argparse
import math
from pathlib import PurePosixPath
import select
import shlex
import signal
import socket
import threading
import time

MARKER = b"AX520-RELAY-READY\n"


class Forwarder:
    def __init__(self, relay_path, seconds=180, *, bind=("127.0.0.1", 15000),
                 upstream=("127.0.0.1", 12323), connect_timeout=2,
                 handshake_timeout=2, io_timeout=2, idle_timeout=10):
        if (not isinstance(relay_path, str) or not relay_path.startswith("/tmp/")
                or len(PurePosixPath(relay_path).parts) < 3
                or ".." in PurePosixPath(relay_path).parts
                or any(char in relay_path for char in "\0\r\n")):
            raise ValueError("relay path must be an absolute file path beneath /tmp")
        if bind[0] != "127.0.0.1" or upstream[0] != "127.0.0.1":
            raise ValueError("only IPv4 loopback is permitted")
        if not math.isfinite(seconds) or not 0 < seconds <= 900:
            raise ValueError("lifetime must be greater than zero and at most 900 seconds")
        for limit in (connect_timeout, handshake_timeout, io_timeout, idle_timeout):
            if not math.isfinite(limit) or not 0 < limit <= 60:
                raise ValueError("timeouts must be finite, positive and at most 60 seconds")
        self.command = ("printf 'AX520-RELAY-READY\\n'; exec " + shlex.quote(relay_path) + "\n").encode()
        self.upstream = upstream
        self.seconds = seconds
        self.connect_timeout = connect_timeout
        self.handshake_timeout = handshake_timeout
        self.io_timeout = io_timeout
        self.idle_timeout = idle_timeout
        self.stopping = threading.Event()
        self.lock = threading.Lock()
        self.sockets = set()
        self.workers = set()
        self.slots = threading.BoundedSemaphore(4)
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listener.bind(bind)
            self.listener.listen(8)
            self.listener.settimeout(.1)
        except BaseException:
            self.listener.close()
            raise
        self.address = self.listener.getsockname()

    def stop(self):
        # Safe for a signal handler: the serving thread owns socket cleanup.
        self.stopping.set()

    @staticmethod
    def _close(sock):
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()

    def _track(self, sock):
        with self.lock:
            if self.stopping.is_set():
                raise ConnectionAbortedError("forwarder stopping")
            self.sockets.add(sock)

    def _ready(self, upstream):
        # Connect, shell command and the complete marker share one deadline;
        # a slow-drip marker cannot restart the timeout for every byte.
        deadline = time.monotonic() + self.handshake_timeout
        upstream.settimeout(min(self.connect_timeout, self.handshake_timeout))
        upstream.connect(self.upstream)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("readiness timeout")
        upstream.settimeout(min(self.io_timeout, remaining))
        upstream.sendall(self.command)
        for expected in MARKER:
            remaining = deadline - time.monotonic()
            if self.stopping.is_set() or remaining <= 0:
                raise TimeoutError("readiness timeout")
            upstream.settimeout(min(self.io_timeout, remaining))
            # Read exactly the marker: a coalesced protocol byte must remain
            # in the socket, not be discarded by readiness parsing.
            if upstream.recv(1) != bytes([expected]):
                raise ConnectionError("readiness failed")

    def _pump(self, client, upstream):
        client.settimeout(self.io_timeout)
        upstream.settimeout(self.io_timeout)
        readers = {client: upstream, upstream: client}
        deadline = time.monotonic() + self.idle_timeout
        while readers and not self.stopping.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("idle timeout")
            ready, _, _ = select.select(list(readers), [], [], min(.1, remaining))
            for source in ready:
                target = readers[source]
                data = source.recv(8192)
                if not data:
                    target.shutdown(socket.SHUT_WR)
                    del readers[source]
                    continue
                target.sendall(data)
                deadline = time.monotonic() + self.idle_timeout

    def _handle(self, client):
        upstream = None
        try:
            upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._track(upstream)
            self._ready(upstream)
            # Do not read even one client byte until the shell has consumed the
            # command and emitted the complete readiness marker.
            self._pump(client, upstream)
        except (OSError, ValueError):
            # Fixed behavior only: close the failed stream. Never print marker,
            # protocol bytes, shell output or an exception carrying those bytes.
            pass
        finally:
            for sock in (client, upstream):
                if sock is not None:
                    with self.lock:
                        self.sockets.discard(sock)
                    self._close(sock)
            with self.lock:
                self.workers.discard(threading.current_thread())
            self.slots.release()

    def serve(self):
        deadline = time.monotonic() + self.seconds
        try:
            while not self.stopping.is_set() and time.monotonic() < deadline:
                try:
                    client, _ = self.listener.accept()
                except socket.timeout:
                    continue
                if not self.slots.acquire(blocking=False):
                    self._close(client)
                    continue
                try:
                    self._track(client)
                    worker = threading.Thread(target=self._handle, args=(client,), daemon=True)
                    with self.lock:
                        self.workers.add(worker)
                    worker.start()
                except BaseException as error:
                    with self.lock:
                        self.sockets.discard(client)
                    self._close(client)
                    self.slots.release()
                    if self.stopping.is_set() and isinstance(error, ConnectionAbortedError):
                        break
                    raise
        finally:
            self.stop()
            self.listener.close()
            with self.lock:
                sockets = list(self.sockets)
                workers = list(self.workers)
            for sock in sockets:
                self._close(sock)
            # Socket shutdown interrupts pending handshakes and sendall calls.
            end = time.monotonic() + max(self.connect_timeout, self.io_timeout) + .5
            for worker in workers:
                if worker.ident is not None:
                    worker.join(max(0, end - time.monotonic()))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("relay_path", help="reviewed dongle relay executable beneath /tmp")
    parser.add_argument("--seconds", type=int, default=180, help="finite lifetime, 1..900 seconds")
    options = parser.parse_args(argv)
    try:
        forwarder = Forwarder(options.relay_path, seconds=options.seconds)
    except ValueError as error:
        parser.error(str(error))
    except OSError:
        parser.exit(1, "host-forward: listener unavailable\n")
    previous = {kind: signal.getsignal(kind) for kind in (signal.SIGINT, signal.SIGTERM)}
    try:
        for kind in previous:
            signal.signal(kind, lambda _kind, _frame: forwarder.stop())
        print("host-forward: ready on 127.0.0.1:15000", flush=True)
        forwarder.serve()
    finally:
        for kind, handler in previous.items():
            signal.signal(kind, handler)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
