#!/usr/bin/env python3
"""Verify Python SDK source parity between libsa/sibna/ and sibna-protc/sdks/python/sibna/.

This script compares the Python SDK source files between the two repositories
to ensure they remain in sync. It should be run from CI or manually with the
path to the sibna-protc repository's sdks/python directory.

Usage:
    python scripts/check_pq_sync.py /path/to/sibna-protc/sdks/python

Exit codes:
    0 - All files match
    1 - Files differ or are missing
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

# Files that must exist and match exactly between the two repositories
SDK_FILES = [
    "__init__.py",
    "client.py",
    "constants.py",
    "crypto.py",
    "envelope.py",
    "errors.py",
    "group.py",
    "p2p.py",
    "padding.py",
    "py.typed",
    "ratchet.py",
    "safety_number.py",
    "session.py",
    "storage.py",
    "x3dh.py",
]


def file_hash(path: Path) -> str:
    """Return SHA-256 hash of a file."""
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def check_parity(sibna_protc_sdk_dir: Path) -> bool:
    """Check that libsa/sibna/ matches sibna-protc/sdks/python/sibna/.

    Args:
        sibna_protc_sdk_dir: Path to the sibna-protc/sdks/python directory.

    Returns:
        True if all files match, False otherwise.
    """
    libsa_sibna_dir = Path(__file__).resolve().parent.parent / "sibna"
    sibna_protc_sibna_dir = sibna_protc_sdk_dir / "sibna"

    all_match = True

    for fname in SDK_FILES:
        libsa_file = libsa_sibna_dir / fname
        sp_file = sibna_protc_sibna_dir / fname

        if not libsa_file.exists():
            print(f"MISSING: libsa/sibna/{fname}")
            all_match = False
            continue

        if not sp_file.exists():
            print(f"MISSING: sibna-protc/sdks/python/sibna/{fname}")
            all_match = False
            continue

        h1 = file_hash(libsa_file)
        h2 = file_hash(sp_file)

        if h1 != h2:
            print(f"DIFFER: sibna/{fname} != sibna-protc/sdks/python/sibna/{fname}")
            all_match = False
        else:
            print(f"OK: sibna/{fname} matches sibna-protc/sdks/python/sibna/{fname}")

    return all_match


def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <path-to-sibna-protc/sdks/python>")
        return 1

    sdk_python_dir = Path(sys.argv[1]).resolve()

    if not sdk_python_dir.is_dir():
        print(f"Error: {sibna_protc_sdk_dir} is not a directory")
        return 1

    sibna_dir = sdk_python_dir / "sibna"
    if not sibna_dir.is_dir():
        print(f"Error: {sibna_dir} is not a directory")
        return 1

    all_match = check_parity(sdk_python_dir)

    if all_match:
        print("\nAll SDK source files match between libsa/sibna/ and sibna-protc/sdks/python/sibna/")
        return 0
    else:
        print("\nDIFFERENCES FOUND - libsa/sibna/ and sibna-protc/sdks/python/sibna/ are out of sync")
        return 1


if __name__ == "__main__":
    sys.exit(main())
