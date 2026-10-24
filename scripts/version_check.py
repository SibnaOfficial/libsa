#!/usr/bin/env python3
"""
Sibna Python SDK — version consistency check.

Verifies that the package version, __version__, and protocol constants
are all in sync. Exits non-zero with actionable errors on any mismatch.

Protocol-affecting changes MUST update these together.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

ERRORS = []


def fail(msg: str) -> None:
    ERRORS.append(msg)


def read_pyproject_version() -> str:
    pyproject = REPO_ROOT / "pyproject.toml"
    text = pyproject.read_text()
    m = re.search(r'^version\s*=\s*"([^"]+)"\s*$', text, re.MULTILINE)
    if not m:
        fail("pyproject.toml: project version not found")
        return "0.0.0"
    return m.group(1)


def read_sibna_version() -> str:
    init = REPO_ROOT / "sibna" / "__init__.py"
    text = init.read_text()
    m = re.search(r'^__version__\s*=\s*"([^"]+)"\s*$', text, re.MULTILINE)
    if not m:
        fail("sibna/__init__.py: __version__ not found")
        return "0.0.0"
    return m.group(1)


def read_protocol_version_string() -> str:
    constants = REPO_ROOT / "sibna" / "constants.py"
    text = constants.read_text()
    m = re.search(r'^PROTOCOL_VERSION_STRING\s*=\s*"([^"]+)"\s*$', text, re.MULTILINE)
    if not m:
        fail("sibna/constants.py: PROTOCOL_VERSION_STRING not found")
        return "0.0.0"
    return m.group(1)


def read_constants_wire_version() -> int:
    constants = REPO_ROOT / "sibna" / "constants.py"
    text = constants.read_text()
    m = re.search(r'^PROTOCOL_VERSION_WIRE\s*=\s*(\d+)\s*$', text, re.MULTILINE)
    if not m:
        fail("sibna/constants.py: PROTOCOL_VERSION_WIRE not found")
        return -1
    return int(m.group(1))


def main() -> int:
    py_ver = read_pyproject_version()
    init_ver = read_sibna_version()
    proto_ver_str = read_protocol_version_string()
    const_wire = read_constants_wire_version()

    print(f"Python package version   : {py_ver}")
    print(f"Python __version__       : {init_ver}")
    print(f"Python version string    : {proto_ver_str}")
    print(f"Python constants wire    : {const_wire}")

    # Package versions must all agree.
    if py_ver != init_ver:
        fail(f"version mismatch: pyproject {py_ver} != __init__ {init_ver}")
    if py_ver != proto_ver_str:
        fail(f"version mismatch: pyproject {py_ver} != PROTOCOL_VERSION_STRING {proto_ver_str}")

    if ERRORS:
        print("\nVERSION CONSISTENCY CHECK FAILED:")
        for e in ERRORS:
            print(f"  - {e}")
        return 1

    print("\nVersion consistency check passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
