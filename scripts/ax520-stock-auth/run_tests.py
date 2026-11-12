#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Native synthetic tests only; does not access or execute stock firmware."""
from pathlib import Path
import unittest

suite = unittest.defaultTestLoader.discover(str(Path(__file__).parent / "tests"))
result = unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(not result.wasSuccessful())
