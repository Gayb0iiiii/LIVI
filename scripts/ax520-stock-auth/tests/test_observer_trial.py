# SPDX-License-Identifier: GPL-3.0-or-later
"""Lifecycle tests use only a dedicated synthetic supervisor and its worker."""
import ctypes
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent


class ObserverTrialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Adopt only this test process's orphaned fixture descendants so that
        # PID1 in minimal CI containers is not left hundreds of zombies.
        cls.libc = ctypes.CDLL(None, use_errno=True)
        cls.was_subreaper = ctypes.c_int()
        if cls.libc.prctl(37, ctypes.byref(cls.was_subreaper), 0, 0, 0) or cls.libc.prctl(36, 1, 0, 0, 0):
            raise RuntimeError("could not enable synthetic child cleanup")
        cls.directory = tempfile.TemporaryDirectory(prefix="ax520-trial-test-")
        cls.artifacts = Path(cls.directory.name)
        cls.console = cls.artifacts / "console"
        cls.console.touch()
        cls.stock = cls.artifacts / "mock-stock"
        cls.shim = cls.artifacts / "observer.so"
        cls.launcher = cls.artifacts / "observer-trial"
        cls.bridge_launcher = cls.artifacts / "bridge-trial"
        cls.interrupted_launcher = cls.artifacts / "interrupted-trial"
        common = ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O1", "-g", "-pthread"]
        commands = [
            common + ["-shared", "-fPIC", str(HERE / "mock_vendor.c"),
                      "-Wl,--version-script=" + str(HERE / "mock_vendor.map"), "-o", str(cls.artifacts / "libmock.so")],
            common + [str(HERE / "mock_supervisor.c"), "-L" + str(cls.artifacts), "-lmock", "-o", str(cls.stock)],
            common + ["-shared", "-fPIC", str(SOURCE / "interposer.c"), "-ldl",
                      "-Wl,--version-script=" + str(SOURCE / "interposer.map"), "-o", str(cls.shim)],
            common + ["-DAX520_LAUNCHER_TEST", '-DAX520_TEST_STOCK="' + str(cls.stock) + '"',
                      '-DAX520_TEST_CONSOLE="' + str(cls.console) + '"',
                      str(SOURCE / "observer_trial.c"), "-o", str(cls.launcher)],
            common + ["-DAX520_LAUNCHER_TEST", "-DAX520_LAUNCHER_ENABLE_BRIDGE",
                      '-DAX520_TEST_STOCK="' + str(cls.stock) + '"',
                      '-DAX520_TEST_CONSOLE="' + str(cls.console) + '"',
                      str(SOURCE / "observer_trial.c"), "-o", str(cls.bridge_launcher)],
            common + ["-DAX520_LAUNCHER_TEST", "-DAX520_LAUNCHER_ENABLE_BRIDGE",
                      '-DAX520_TEST_STOCK="' + str(cls.stock) + '"',
                      '-DAX520_TEST_CONSOLE="' + str(cls.console) + '"',
                      str(HERE / "exec_interruption.c"), "-o", str(cls.interrupted_launcher)],
            common + [str(HERE / "task_visibility.c"), "-o", str(cls.artifacts / "task-visibility")],
            common + [str(HERE / "exiting_process.c"), "-o", str(cls.artifacts / "exiting-process")],
        ]
        cls.build_failure = None
        for command in commands:
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode:
                cls.build_failure = result.stderr
                break

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()
        cls.libc.prctl(36, cls.was_subreaper.value, 0, 0, 0)

    def setUp(self):
        self.assertIsNone(self.build_failure, self.build_failure)
        self.case = tempfile.TemporaryDirectory(prefix="case-", dir=self.artifacts)
        self.addCleanup(self.case.cleanup)
        self.log = Path(self.case.name) / "events"
        self.env = os.environ.copy()
        self.env.pop("LD_PRELOAD", None)
        self.env.pop("AX520_OBSERVER_FDS", None)
        self.env.update(LD_LIBRARY_PATH=str(self.artifacts), WORKDIR=str(self.artifacts),
                        LY_PLATFORM="synthetic", LY_MFI_I2C_BUS="2", LY_ENCRYPT_I2C_BUS="1",
                        AX520_TEST_EVENTS=str(self.log))
        self.processes = []
        self.watchdogs = []
        self.addCleanup(self.cleanup_processes)

    def events(self):
        return [line.split() for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def cleanup_processes(self):
        for pid in self.watchdogs:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        for event in self.events():
            for index in (1, 2):
                pid = int(event[index])
                if pid > 1:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
        for process in self.processes:
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if not pid:
                time.sleep(.01)

    def original(self, ignore_term=False):
        env = self.env.copy()
        if ignore_term:
            env["AX520_TEST_IGNORE_TERM"] = "1"
            self.env["AX520_TEST_IGNORE_TERM"] = "1"
        with open(os.devnull, "rb") as stdin, self.console.open("ab") as console:
            process = subprocess.Popen([str(self.stock), "-w"], cwd="/", env=env,
                                       stdin=stdin, stdout=console, stderr=console,
                                       start_new_session=True, umask=0o022)
        self.processes.append(process)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            children = [int(row[2]) for row in self.events() if row[0] == "child" and int(row[1]) == process.pid]
            workers = [int(row[1]) for row in self.events() if row[0] == "worker"]
            if children and children[-1] in workers:
                return process.pid, children[-1]
            time.sleep(.01)
        self.fail("synthetic supervisor never forked")

    def remember_watchdog(self, result):
        if result.returncode == 0:
            fields = dict(field.split("=", 1) for field in result.stdout.strip().split())
            self.watchdogs.append(int(fields["watchdog"]))
        return result

    def launch(self, supervisor, worker, env=None, shim=None):
        return self.remember_watchdog(subprocess.run([str(self.launcher), str(supervisor), str(worker), str(shim or self.shim)],
                              cwd="/", env=env or self.env, capture_output=True, text=True, timeout=4))

    def launch_bridge(self, supervisor, worker, seconds="1", launcher=None, env=None):
        return self.remember_watchdog(subprocess.run([str(launcher or self.bridge_launcher), "--device-bridge", seconds,
                               str(supervisor), str(worker), str(self.shim)],
                              cwd="/", env=env or self.env, capture_output=True, text=True, timeout=4))

    def finish(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)
        fields = dict(field.split("=", 1) for field in result.stdout.strip().split())
        watchdog = int(fields["watchdog"])
        status = Path(fields["status"])
        self.addCleanup(lambda: self.remove_status(status))
        deadline = time.monotonic() + 7
        while time.monotonic() < deadline:
            data = status.read_text()
            if "result " in data:
                return watchdog, data
            time.sleep(.02)
        self.fail("detached watchdog did not finish: " + status.read_text())

    @staticmethod
    def remove_status(status):
        status.unlink(missing_ok=True)
        status.parent.rmdir()

    def test_trial_restores_once_without_preload_and_reports_only_metadata(self):
        supervisor, worker = self.original()
        _, status = self.finish(self.launch(supervisor, worker))
        self.assertIn("result restored", status)
        self.assertIn("observer selected", status)
        starts = [row for row in self.events() if row[0] == "start"]
        self.assertEqual([row[3] for row in starts], ["0", "1", "0"])
        self.assertEqual([row[4] for row in starts], ["0", "0", "0"])
        self.assertNotIn("SYNTHETIC-CERT", status)

    def test_explicit_bridge_trial_enables_only_trial_and_restores_once(self):
        self.env["AX520_AUTH_PORT"] = "15999"
        self.env["AX520_SYNTHETIC_TEST"] = "1"
        supervisor, worker = self.original()
        _, status = self.finish(self.launch_bridge(supervisor, worker))
        self.assertIn("mode device_bridge", status)
        self.assertIn("result restored", status)
        self.assertIn("observer selected", status)
        settings = [row[3:] for row in self.events() if row[0] == "settings"]
        self.assertEqual(settings, [["0", "0", "0", "0", "1", "1"],
                                    ["1", "1", "1", "1", "0", "1"],
                                    ["0", "0", "0", "0", "0", "0"]])

    def test_bridge_trial_sigterm_restores_before_its_deadline(self):
        supervisor, worker = self.original()
        started = time.monotonic()
        result = self.launch_bridge(supervisor, worker, seconds="5")
        self.assertEqual(result.returncode, 0, result.stderr)
        fields = dict(field.split("=", 1) for field in result.stdout.strip().split())
        status_path = Path(fields["status"])
        deadline = time.monotonic() + 2
        while "observer selected" not in status_path.read_text() and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertIn("observer selected", status_path.read_text())
        os.kill(int(fields["watchdog"]), signal.SIGTERM)
        _, status = self.finish(result)
        self.assertIn("result restored", status)
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual(len([row for row in self.events() if row[0] == "start"]), 3)

    def test_stop_during_exec_handshake_waits_for_session_then_restores(self):
        self.env["AX520_TEST_INTERRUPT_EXEC"] = str(Path(self.case.name) / "interrupted")
        supervisor, worker = self.original()
        _, status = self.finish(self.launch_bridge(supervisor, worker, launcher=self.interrupted_launcher))
        self.assertIn("result restored", status)
        # Exec can complete before the new program reaches main; cleanup may
        # then terminate it before the synthetic fixture records its start.
        starts = [row[3] for row in self.events() if row[0] == "start"]
        self.assertIn(starts, [["0", "0"], ["0", "1", "0"]])

    def test_default_launcher_rejects_bridge_mode_before_signalling(self):
        supervisor, worker = self.original()
        result = self.launch_bridge(supervisor, worker, launcher=self.launcher)
        self.assertNotEqual(result.returncode, 0)
        os.kill(supervisor, 0)
        os.kill(worker, 0)
        self.assertEqual(len([row for row in self.events() if row[0] == "start"]), 1)

    def test_bridge_duration_must_be_strict_decimal_between_one_and_300(self):
        supervisor, worker = self.original()
        for value in ("0", "301", "-1", "1.5", " 1", "+1", "1x", "", "999999999999"):
            with self.subTest(value=value):
                result = self.launch_bridge(supervisor, worker, seconds=value)
                self.assertNotEqual(result.returncode, 0)
        os.kill(supervisor, 0)
        os.kill(worker, 0)
        self.assertEqual(len([row for row in self.events() if row[0] == "start"]), 1)

    def test_worker_ignoring_term_is_bounded_and_stock_is_restored(self):
        supervisor, worker = self.original(ignore_term=True)
        _, status = self.finish(self.launch(supervisor, worker))
        self.assertIn("result restored", status)

    def test_early_trial_exit_still_restores_stock_once(self):
        self.env["AX520_TEST_TRIAL_EXIT"] = "1"
        supervisor, worker = self.original()
        _, status = self.finish(self.launch(supervisor, worker))
        self.assertIn("result restored", status)
        self.assertIn("observer no_selection_observed", status)
        self.assertEqual(len([row for row in self.events() if row[0] == "start"]), 3)

    def test_failed_restore_is_reported_without_repeated_relaunch(self):
        self.env["AX520_TEST_RESTORE_EXIT"] = "1"
        supervisor, worker = self.original()
        _, status = self.finish(self.launch(supervisor, worker))
        self.assertIn("result restore_unverified_no_retry", status)
        self.assertEqual(len([row for row in self.events() if row[0] == "start"]), 3)

    def test_device_bridge_toggle_is_rejected_before_signalling(self):
        supervisor, worker = self.original()
        enabled = self.env.copy()
        enabled["AX520_DEVICE_BRIDGE"] = "1"
        result = self.launch(supervisor, worker, env=enabled)
        self.assertNotEqual(result.returncode, 0)
        os.kill(supervisor, 0)
        os.kill(worker, 0)

    def test_escaped_trial_worker_blocks_duplicate_restore_without_being_killed(self):
        self.env["AX520_TEST_ESCAPE_TRIAL"] = "1"
        supervisor, worker = self.original()
        _, status = self.finish(self.launch(supervisor, worker))
        self.assertIn("result rollback_blocked_existing_stock", status)
        starts = [row for row in self.events() if row[0] == "start"]
        self.assertEqual([row[3] for row in starts], ["0", "1"])
        escaped = [int(row[1]) for row in self.events() if row[0] == "worker" and row[3] == "1"]
        self.assertEqual(len(escaped), 1)
        os.kill(escaped[0], 0)

    @staticmethod
    def live_tasks(pid):
        try:
            tasks = list(Path(f"/proc/{pid}/task").iterdir())
        except FileNotFoundError:
            return []
        states = []
        for task in tasks:
            try:
                state = (task / "stat").read_text().rsplit(")", 1)[1].split()[0]
                if state not in ("Z", "X"):
                    states.append(state)
            except FileNotFoundError:
                pass
        return states

    def test_original_zombie_leader_with_live_sibling_is_killed_before_trial(self):
        self.env["AX520_TEST_ZOMBIE_ON_TERM"] = "original"
        supervisor, worker = self.original()
        _, status = self.finish(self.launch(supervisor, worker))
        self.assertIn("result restored", status)
        self.assertTrue(any(row[0] == "leader_exit" and int(row[1]) == worker for row in self.events()))
        self.assertEqual(self.live_tasks(worker), [], "original sibling survived cleanup")

    def test_trial_zombie_leader_with_live_sibling_is_killed_before_restore(self):
        self.env["AX520_TEST_ZOMBIE_ON_TERM"] = "trial"
        supervisor, worker = self.original()
        _, status = self.finish(self.launch(supervisor, worker))
        self.assertIn("result restored", status)
        exits = [int(row[1]) for row in self.events() if row[0] == "leader_exit" and row[3] == "1"]
        self.assertEqual(len(exits), 1)
        self.assertEqual(self.live_tasks(exits[0]), [], "trial sibling survived cleanup")

    def test_escaped_zombie_leader_live_sibling_blocks_duplicate_restore(self):
        self.env["AX520_TEST_ESCAPE_TRIAL"] = "1"
        self.env["AX520_TEST_ZOMBIE_START"] = "1"
        supervisor, worker = self.original()
        _, status = self.finish(self.launch(supervisor, worker))
        self.assertIn("result rollback_blocked_existing_stock", status)
        exits = [int(row[1]) for row in self.events() if row[0] == "leader_exit" and row[3] == "1"]
        self.assertEqual(len(exits), 1)
        self.assertTrue(self.live_tasks(exits[0]), "untracked sibling should remain untouched")
        state = Path(f"/proc/{exits[0]}/stat").read_text().rsplit(")", 1)[1].split()[0]
        self.assertEqual(state, "Z")
        self.assertEqual(len([row for row in self.events() if row[0] == "start"]), 2)

    def test_exit_during_identity_read_waits_for_death_and_uncertainty_never_signals(self):
        result = subprocess.run([str(self.artifacts / "exiting-process")],
                                capture_output=True, text=True, timeout=4)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "transition=0 uncertain=-1 waited=1 signal=-1 untouched=1\n")

    def test_unavailable_zombie_task_directory_is_uncertain_not_dead(self):
        empty = Path(self.case.name) / "empty"
        empty.mkdir()
        result = subprocess.run([str(self.artifacts / "task-visibility"), str(empty)],
                                capture_output=True, text=True, timeout=4)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "missing=-1 empty=-1\n")

    def test_watchdog_survives_hangup_after_launcher_exits(self):
        supervisor, worker = self.original()
        result = self.launch(supervisor, worker)
        self.assertEqual(result.returncode, 0, result.stderr)
        fields = dict(field.split("=", 1) for field in result.stdout.strip().split())
        os.kill(int(fields["watchdog"]), signal.SIGHUP)
        _, status = self.finish(result)
        self.assertIn("result restored", status)

    def test_environment_mismatch_aborts_before_signalling_original(self):
        supervisor, worker = self.original()
        wrong = self.env.copy()
        wrong["LY_PLATFORM"] = "different"
        result = self.launch(supervisor, worker, env=wrong)
        self.assertNotEqual(result.returncode, 0)
        os.kill(supervisor, 0)
        os.kill(worker, 0)
        self.assertEqual(len([e for e in self.events() if e[0] == "start"]), 1)

    def test_wrong_worker_relationship_aborts_before_signalling(self):
        supervisor, worker = self.original()
        result = self.launch(supervisor, supervisor)
        self.assertNotEqual(result.returncode, 0)
        os.kill(supervisor, 0)
        os.kill(worker, 0)

    def test_missing_shim_aborts_before_signalling(self):
        supervisor, worker = self.original()
        result = self.launch(supervisor, worker, shim=self.artifacts / "missing.so")
        self.assertNotEqual(result.returncode, 0)
        os.kill(supervisor, 0)
        os.kill(worker, 0)


if __name__ == "__main__":
    unittest.main()
