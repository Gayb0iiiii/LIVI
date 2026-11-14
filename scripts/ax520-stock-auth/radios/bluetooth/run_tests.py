#!/usr/bin/env python3
"""Run synthetic radio tests in an isolated temporary directory; no dongle access."""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
WARNINGS = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default=os.environ.get("CC", "cc"), help="native Linux C compiler executable")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="ax520-hci-tests-") as temp:
        work = Path(temp)
        for pattern in ("*.c", "*.h", "test_*.py"):
            for source in ROOT.glob(pattern):
                shutil.copyfile(source, work / source.name)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", AX520_TEST_RELAY_PORT=str(port))

        def compile_c(*arguments):
            subprocess.run([args.cc, *WARNINGS, *arguments], cwd=work, env=env, check=True)

        def suite(name):
            subprocess.run([sys.executable, name], cwd=work, env=env, check=True)

        compile_c("fixture.c", "-o", "btapp-fixture")
        compile_c(
            "-DSTOCK_EXE=" + json.dumps(str(work / "btapp-fixture")),
            '-DSTOCK_TTY="/dev/null"',
            "-DLOCK_PATH=" + json.dumps(str(work / "test.lock")),
            "-DTRIAL_MS=500", "-DRESTORE_MS=500", f"-DRELAY_PORT={port}",
            "-DRELAY_WAIT_MS=700", "-DRELAY_LIVE_MS=400", "-DRELAY_STALL_MS=100",
            "-DRELAY_TRIAL_MS=2000", "-Wl,--wrap=kill",
            "tool.c", "sha256.c", "fake_hci.c", "relay.c", "-o", "radio-test",
        )
        suite("test_radio.py")
        compile_c("-fPIC", "-shared", "-DCOMMAND_MS=150", "hci_probe.c", "sha256.c", "-o", "hci-test.so")
        suite("test_hci.py")
        compile_c("-fPIC", "-shared", "-DRELAY_ALLOW_UNRESTRICTED_TEST_TRANSPORT", "relay.c", "-o", "relay-test.so")
        suite("test_relay.py")
        compile_c("-fPIC", "-shared", f"-DRELAY_PORT={port}", "relay.c", "-o", "relay-policy-test.so")
        suite("test_policy.py")
        compile_c("tool.c", "sha256.c", "hci_get.c", "hci_probe.c", "relay.c", "-o", "bounds-test")
        suite("test_bounds.py")


if __name__ == "__main__":
    main()
