#!/usr/bin/env python3
"""Build the frozen static ARMv7 relay without a vendor SDK or device access."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
SOURCES = ["tool.c", "sha256.c", "hci_get.c", "hci_probe.c", "relay.c"]
FLAGS = [
    "-mcpu=cortex-a7", "-mfpu=neon", "-mfloat-abi=hard", "-std=c11", "-Os",
    "-static", "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections",
    "-Wall", "-Wextra", "-Werror",
]


def verify_elf(data):
    if len(data) < 52 or data[:6] != b"\x7fELF\x01\x01":
        raise ValueError("output is not a little-endian ELF32 executable")
    if struct.unpack_from("<HH", data, 16) != (2, 40):
        raise ValueError("output is not an ARM executable")
    offset = struct.unpack_from("<I", data, 28)[0]
    entry_size, count = struct.unpack_from("<HH", data, 42)
    if entry_size < 32 or offset + entry_size * count > len(data):
        raise ValueError("invalid ELF program headers")
    if any(struct.unpack_from("<I", data, offset + i * entry_size)[0] in (2, 3) for i in range(count)):
        raise ValueError("output requires dynamic linking or a program interpreter")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default=os.environ.get("ARM_MUSL_CC"), help="ARM hard-float musl compiler executable")
    parser.add_argument("--output", required=True, type=Path, help="new artifact path; existing files are never overwritten")
    parser.add_argument("--verify-frozen", action="store_true", help="require the reviewed V4 artifact SHA256")
    args = parser.parse_args()
    if not args.cc:
        parser.error("provide --cc or ARM_MUSL_CC; no compiler is downloaded automatically")
    output = args.output.expanduser().resolve()
    if output.exists():
        parser.error("output path already exists")
    if not output.parent.is_dir():
        parser.error("output parent directory does not exist")
    manifest = json.loads((ROOT / "source-manifest.json").read_text())
    with tempfile.TemporaryDirectory(prefix="ax520-hci-build-", dir=output.parent) as temp:
        generated = Path(temp) / "relay"
        subprocess.run([args.cc, *FLAGS, *SOURCES, "-o", str(generated)], cwd=ROOT, check=True)
        data = generated.read_bytes()
        verify_elf(data)
        digest = hashlib.sha256(data).hexdigest()
        matches = digest == manifest["sha256"]
        if args.verify_frozen and not matches:
            raise SystemExit(f"frozen artifact mismatch: expected {manifest['sha256']}, got {digest}")
        with output.open("xb") as target:
            target.write(data)
        output.chmod(0o700)
    print(json.dumps({"artifact": str(output), "sha256": digest, "matches_frozen": matches}, sort_keys=True))


if __name__ == "__main__":
    main()
