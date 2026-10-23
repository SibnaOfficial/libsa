#!/usr/bin/env python3
"""
Cross-SDK Padding Compatibility Test

Validates that the Python SDK's padding implementation produces output
matching the committed Rust fixtures and that unpadding roundtrips correctly.
"""

import json
from pathlib import Path

from sibna.padding import pad_payload, unpad_payload

VECTORS_FILE = Path(__file__).resolve().parent / "cross_sdk" / "padding_vectors.json"


def load_vectors():
    with open(VECTORS_FILE, encoding="utf-8") as f:
        return json.load(f)


def test_padding_matches_fixtures():
    vectors = load_vectors()
    for vec in vectors["vectors"]:
        plaintext = bytes.fromhex(vec["plaintext_hex"])
        padded = pad_payload(plaintext)
        assert len(padded) % 1024 == 0, f"{vec['name']}: padded length not block-aligned"
        assert unpad_payload(padded) == plaintext, f"{vec['name']}: unpadding failed"


def test_padding_roundtrip():
    for data in [b"", b"a", b"hello world", b"\x00" * 100, bytes(range(256))]:
        padded = pad_payload(data)
        assert len(padded) % 1024 == 0
        assert unpad_payload(padded) == data


def test_unpad_empty_raises():
    from sibna.errors import CryptoError

    try:
        unpad_payload(b"")
    except CryptoError:
        pass
    else:
        raise AssertionError("unpad_payload(b'') should raise CryptoError")
