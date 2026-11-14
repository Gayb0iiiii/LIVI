import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parent
PORT = int(os.environ.get("AX520_TEST_RELAY_PORT", "55339"))
BIN = ROOT / "radio-test"
FIXTURE = ROOT / "btapp-fixture"

def identity(pid):
    text = Path(f"/proc/{pid}/stat").read_text()
    fields = text[text.rindex(")") + 2:].split()
    return fields[0], int(fields[19])

class WatchdogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ax520-hci-")
        self.dir = Path(self.temp.name)
        self.state = self.dir / "radio-state"
        self.state.write_bytes(struct.pack("ii", 1, 0))
        self.events = self.dir / "events"
        self.env = dict(os.environ, RADIO_STATE=str(self.state), RADIO_EVENTS=str(self.events))
        self.fixture = subprocess.Popen([str(FIXTURE)], stdout=subprocess.PIPE, text=True)
        self.sup, self.worker = map(int, self.fixture.stdout.readline().split())
        self.ss = identity(self.sup)[1]
        self.ws = identity(self.worker)[1]
        self.sha = hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
        self.guard = None

    def tearDown(self):
        if self.guard:
            try: os.kill(self.guard, signal.SIGTERM)
            except ProcessLookupError: pass
        blocked_file = self.dir / "radio-state.blocked"
        if blocked_file.exists():
            try: os.kill(int(blocked_file.read_text()), signal.SIGKILL)
            except ProcessLookupError: pass
        try: os.killpg(self.sup, signal.SIGKILL)
        except ProcessLookupError: pass
        self.fixture.wait(timeout=3)
        self.fixture.stdout.close()
        self.temp.cleanup()

    def pins(self, start=None, sha=None):
        return [str(self.sup), str(self.ss), str(self.worker), str(self.ws if start is None else start), self.sha if sha is None else sha, "13"]

    def launch(self, failure=None, start=None, sha=None):
        if failure: self.env["RADIO_FAIL"] = failure
        run = self.dir / "run"
        run.mkdir(mode=0o700)
        result = subprocess.run([str(BIN), "--launch", str(run), *self.pins(start, sha)], env=self.env, capture_output=True, text=True, timeout=5)
        if result.returncode:
            return result, ""
        self.guard = json.loads(result.stdout)["watchdog_pid"]
        deadline = time.monotonic() + 8
        log = ""
        while time.monotonic() < deadline:
            log = (run / "status").read_text()
            if "RESULT " in log:
                self.wait_guard_exit()
                return result, log
            time.sleep(0.02)
        self.fail(f"watchdog did not finish: {log}")

    def wait_guard_exit(self):
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            try:
                if identity(self.guard)[0] == "Z": return
            except FileNotFoundError: return
            time.sleep(0.005)
        self.fail("watchdog did not exit after recording its final result")

    def assert_restored(self, want_up=1):
        self.assertNotIn(identity(self.sup)[0], "TtZ")
        self.assertNotIn(identity(self.worker)[0], "TtZ")
        self.assertEqual(identity(self.sup)[1], self.ss)
        self.assertEqual(identity(self.worker)[1], self.ws)
        self.assertEqual(os.readlink(f"/proc/{self.worker}/fd/13"), "/dev/null")
        self.assertEqual(struct.unpack("ii", self.state.read_bytes()), (want_up, 0))

    def test_inspect_never_pauses_processes_or_mutates_controller(self):
        result = subprocess.run([str(BIN), "--inspect", str(self.sup), str(self.worker), "13"], env=self.env, capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)
        info = json.loads(result.stdout)
        self.assertEqual(info["worker_start"], self.ws)
        self.assertEqual(info["sha256"], self.sha)
        self.assertEqual(info["hci_up"], True)
        self.assertFalse(self.events.exists())
        self.assert_restored()

    def test_success_restores_up_and_same_processes_after_worker_exits(self):
        result, log = self.launch()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("RESULT proof_ok_restored", log)
        self.assertEqual(self.events.read_text().splitlines(), ["DOWN", "USER", "VERSION", "UP"])
        self.assert_restored()

    def test_originally_down_stays_down(self):
        self.state.write_bytes(struct.pack("ii", 0, 0))
        _, log = self.launch()
        self.assertIn("RESULT proof_ok_restored", log)
        self.assertNotIn("UP", self.events.read_text().splitlines())
        self.assert_restored(0)

    def test_pid_reuse_pin_mismatch_blocks_all_mutations(self):
        result, _ = self.launch(start=self.ws + 1)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.events.exists())
        self.assert_restored()

    def test_binary_hash_mismatch_blocks_all_mutations(self):
        result, _ = self.launch(sha="0" * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.events.exists())
        self.assert_restored()

    def test_already_stopped_stock_process_is_not_resumed(self):
        os.kill(self.worker, signal.SIGSTOP)
        for _ in range(100):
            if identity(self.worker)[0] == "T": break
            time.sleep(0.005)
        result, _ = self.launch()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(identity(self.worker)[0], "T")
        self.assertFalse(self.events.exists())
        os.kill(self.worker, signal.SIGCONT)

    def test_every_hardware_failure_restores_and_reports_failure(self):
        for failure in ["down_error", "bind_error", "command_error", "crash", "timeout"]:
            with self.subTest(failure=failure):
                run = self.dir / "run"
                if run.exists():
                    import shutil
                    shutil.rmtree(run)
                self.events.unlink(missing_ok=True)
                _, log = self.launch(failure)
                self.assertIn("RESULT proof_failed_restored", log)
                self.assert_restored()

    def test_restore_error_never_claims_success_and_resumes_stock(self):
        _, log = self.launch("up_error")
        self.assertIn("RESULT restoration_unverified_no_retry", log)
        self.assertNotIn(identity(self.sup)[0], "TtZ")
        self.assertNotIn(identity(self.worker)[0], "TtZ")

    def test_cancelling_detached_watchdog_still_restores_stock(self):
        self.env["RADIO_FAIL"] = "timeout"
        run = self.dir / "run"
        run.mkdir(mode=0o700)
        result = subprocess.run([str(BIN), "--launch", str(run), *self.pins()], env=self.env, capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.guard = json.loads(result.stdout)["watchdog_pid"]
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if self.events.exists() and "VERSION" in self.events.read_text(): break
            time.sleep(0.005)
        self.assertEqual(identity(self.worker)[0], "T")
        os.kill(self.guard, signal.SIGHUP)  # Detached ADB shell loss must not kill recovery.
        os.kill(self.guard, signal.SIGTERM)  # Explicit cancellation requests cleanup.
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            log = (run / "status").read_text()
            if "RESULT " in log: break
            time.sleep(0.01)
        self.assertIn("RESULT proof_failed_restored", log)
        self.assert_restored()

    def test_changed_uart_fd_blocks_hardware_mutations(self):
        bad_pins = self.pins()
        bad_pins[-1] = "12"
        run = self.dir / "run"
        run.mkdir(mode=0o700)
        result = subprocess.run([str(BIN), "--launch", str(run), *bad_pins], env=self.env, capture_output=True, text=True, timeout=3)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.events.exists())
        self.assert_restored()

    def test_unreaped_hci_owner_does_not_resume_stock_or_restore_controller_concurrently(self):
        _, log = self.launch("unreaped_main")
        self.assertIn("RESULT restoration_unverified_no_retry", log)
        self.assertEqual(identity(self.sup)[0], "T")
        self.assertEqual(identity(self.worker)[0], "T")
        self.assertNotIn("UP", self.events.read_text().splitlines())

    def test_unreaped_restore_helper_does_not_resume_stock_concurrently(self):
        _, log = self.launch("unreaped_restore")
        self.assertIn("RESULT restoration_unverified_no_retry", log)
        self.assertEqual(identity(self.sup)[0], "T")
        self.assertEqual(identity(self.worker)[0], "T")

    def start_relay(self):
        self.env["RADIO_RELAY"] = "1"
        run = self.dir / "run"
        run.mkdir(mode=0o700)
        result = subprocess.run([str(BIN), "--relay-launch", str(run), *self.pins()], env=self.env, capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.guard = json.loads(result.stdout)["watchdog_pid"]
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            log = (run / "status").read_text()
            if "relay_listening" in log: return run
            if "RESULT " in log: self.fail(log)
            time.sleep(0.005)
        self.fail("relay never listened")

    def finish_relay(self, run):
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            log = (run / "status").read_text()
            if "RESULT " in log:
                self.wait_guard_exit()
                return log
            time.sleep(0.01)
        self.fail("relay did not finish")

    def test_relay_wait_without_host_never_pauses_or_changes_radio(self):
        run = self.start_relay()
        time.sleep(0.05)
        self.assertNotIn(identity(self.worker)[0], "TtZ")
        self.assertFalse(self.events.exists())
        log = self.finish_relay(run)
        self.assertIn("RESULT relay_no_host_restored", log)
        self.assertFalse(self.events.exists())
        self.assert_restored()

    def test_relay_waits_for_host_then_disconnect_restores_without_probe(self):
        run = self.start_relay()
        self.assertFalse(self.events.exists())
        client = socket.create_connection(("127.0.0.1", PORT), timeout=1)
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            if self.events.exists() and "USER" in self.events.read_text(): break
            time.sleep(0.005)
        self.assertEqual(identity(self.worker)[0], "T")
        client.close()
        log = self.finish_relay(run)
        self.assertIn("RESULT relay_complete_restored", log)
        self.assertEqual(self.events.read_text().splitlines(), ["DOWN", "USER", "UP"])
        self.assert_restored()

    def test_relay_idle_deadline_restores_without_waiting_for_peer_close(self):
        run = self.start_relay()
        client = socket.create_connection(("127.0.0.1", PORT), timeout=1)
        try:
            log = self.finish_relay(run)
            self.assertIn("RESULT relay_complete_restored", log)
            self.assertIn("relay_stop_reason=2", log)
            self.assert_restored()
        finally: client.close()

if __name__ == "__main__": unittest.main(verbosity=2)
