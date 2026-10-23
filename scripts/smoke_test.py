"""Smoke test for the installed sibna package."""
import sibna
from sibna import (
    X25519KeyPair,
    Ed25519KeyPair,
    Session,
    derive_identity_keys,
    blake3_hash,
    hkdf,
    make_signed_envelope,
    verify_signed_envelope,
    ml_kem_768_keypair,
    ml_kem_768_encapsulate,
    ml_kem_768_decapsulate,
)

assert sibna.__version__ == "3.0.2", f"Expected 3.0.2, got {sibna.__version__}"

ed, x = Ed25519KeyPair(), X25519KeyPair()
ct, _ = ml_kem_768_encapsulate(x.public_key)
ss = ml_kem_768_decapsulate(x.private_key_bytes if hasattr(x, "private_key_bytes") else x.seed, ct)
assert len(ss) == 32

envelope = make_signed_envelope(ed, recipient_id="abc", payload_hex="deadbeef")
assert verify_signed_envelope(envelope)

print("Smoke test OK")
