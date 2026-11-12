# SPDX-FileCopyrightText: 2026 LIVI contributors
# SPDX-License-Identifier: GPL-3.0-or-later
# Additional terms: see NOTICE

"""Check that inherited CLA automation cannot mutate fork repositories."""
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("cla.sh")


class ClaScopeTests(unittest.TestCase):
    def run_cla(self, repository, command):
        with tempfile.TemporaryDirectory() as directory:
            # A regression must fail safely, without network or repository writes.
            calls = Path(directory) / "external-calls"
            for command_name in ("git", "gh"):
                stub = Path(directory) / command_name
                stub.write_text('#!/bin/sh\necho called >> "$CALL_LOG"\nexit 97\n')
                stub.chmod(0o755)
            env = {"PATH": directory + ":/usr/bin:/bin", "HOME": directory,
                   "CALL_LOG": str(calls), "CLA_STORE": str(Path(directory) / "store")}
            if repository is not None:
                env["GITHUB_REPOSITORY"] = repository
            result = subprocess.run(["sh", str(SCRIPT), command], env=env,
                                    capture_output=True, text=True)
            self.assertFalse(calls.exists(), "CLA invoked an external mutation tool")
            self.assertFalse(Path(directory, "store").exists())
            return result

    def test_fork_commands_are_noops_without_credentials(self):
        for command in ("sign", "check", "stale"):
            with self.subTest(command=command):
                result = self.run_cla("Gayb0iiiii/LIVI", command)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("not applicable", result.stdout)

    def test_other_forks_are_also_excluded(self):
        result = self.run_cla("someone/LIVI", "check")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_upstream_is_not_silently_skipped(self):
        result = self.run_cla("f-io/LIVI", "unknown")
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("not applicable", result.stdout)

    def test_missing_repository_fails_closed(self):
        result = self.run_cla(None, "check")
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
