#!/usr/bin/env python3
"""Verify Python SDK source parity between libsa/sibna/ and sibna-protc/sdks/python/sibna/.

This script compares the Python SDK runtime source files between the two
repositories to ensure they remain in sync. It is run from CI (and can be run
manually) with the path to the sibna-protc repository's sdks/python directory.

The upstream source (sibna-protc/sdks/python/sibna/) is authoritative for the
runtime implementation. libsa/sibna/ must contain the same intended runtime
files with identical contents.

Packaging metadata (e.g. the ``__version__`` string in ``__init__.py``) is
repository-specific configuration kept in libsa and is intentionally excluded
from the strict byte comparison.

Usage:
    python scripts/check_pq_sync.py /path/to/sibna-protc/sdks/python

Exit codes:
    0 - All intended runtime files match
    1 - Files differ, are missing, or unexpected modules are present
"""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

# Files that are packaging / repository configuration rather than portable
# runtime implementation. These live in libsa/sibna/ but are not compared
# byte-for-byte against upstream because they carry libsa-specific values.
PACKAGING_FILES = {"__init__.py"}

# Within __init__.py, the version line is libsa packaging metadata.
VERSION_LINE_RE = re.compile(r"^__version__\s*=\s*.*$", re.MULTILINE)


def runtime_files(sibna_dir: Path) -> set[str]:
    """Return the set of intended runtime file names in a sibna/ package dir.

    Intended runtime files are every ``*.py`` module plus ``py.typed``.
    This is discovered dynamically so future modules cannot be silently missed.
    """
    files = {p.name for p in sibna_dir.glob("*.py")}
    if (sibna_dir / "py.typed").exists():
        files.add("py.typed")
    return files


def read_normalized(path: Path) -> bytes:
    """Read a file and normalize line endings to LF (matching .gitattributes)."""
    return path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def file_hash(path: Path) -> str:
    """Return SHA-256 hash of a file (line-ending normalized)."""
    return hashlib.sha256(read_normalized(path)).hexdigest()


def normalize_init_py(path: Path) -> str:
    """Strip the libsa-specific __version__ line before comparing __init__.py."""
    text = read_normalized(path).decode("utf-8-sig")
    return VERSION_LINE_RE.sub('__version__ = "<PACKAGING>"', text)


def check_parity(sibna_protc_sdk_dir: Path) -> bool:
    """Check that libsa/sibna/ matches sibna-protc/sdks/python/sibna/.

    Args:
        sibna_protc_sdk_dir: Path to the sibna-protc/sdks/python directory.

    Returns:
        True if all intended runtime files match, False otherwise.
    """
    libsa_sibna_dir = Path(__file__).resolve().parent.parent / "sibna"
    sibna_protc_sibna_dir = sibna_protc_sdk_dir / "sibna"

    if not libsa_sibna_dir.is_dir():
        print(f"Error: {libsa_sibna_dir} is not a directory")
        return False
    if not sibna_protc_sibna_dir.is_dir():
        print(f"Error: {sibna_protc_sibna_dir} is not a directory")
        return False

    libsa_files = runtime_files(libsa_sibna_dir)
    sp_files = runtime_files(sibna_protc_sibna_dir)

    all_match = True

    # Files present in libsa but missing upstream (unexpected in libsa).
    for fname in sorted(libsa_files - sp_files):
        print(f"UNEXPECTED (libsa only): sibna/{fname}")
        all_match = False

    # Files present upstream but missing in libsa.
    for fname in sorted(sp_files - libsa_files):
        print(f"MISSING: libsa/sibna/{fname}")
        all_match = False

    # Compare the shared intended runtime files.
    for fname in sorted(libsa_files & sp_files):
        libsa_file = libsa_sibna_dir / fname
        sp_file = sibna_protc_sibna_dir / fname

        if fname in PACKAGING_FILES:
            # Packaging metadata: compare content ignoring the __version__ line.
            h1 = hashlib.sha256(normalize_init_py(libsa_file).encode()).hexdigest()
            h2 = hashlib.sha256(normalize_init_py(sp_file).encode()).hexdigest()
        else:
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
        print(f"Error: {sdk_python_dir} is not a directory")
        return 1

    sibna_dir = sdk_python_dir / "sibna"
    if not sibna_dir.is_dir():
        print(f"Error: {sibna_dir} is not a directory")
        return 1

    all_match = check_parity(sdk_python_dir)

    if all_match:
        print(
            "\nAll SDK source files match between libsa/sibna/ and sibna-protc/sdks/python/sibna/"
        )
        return 0
    else:
        print(
            "\nDIFFERENCES FOUND - libsa/sibna/ and sibna-protc/sdks/python/sibna/ are out of sync"
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
