"""
Sibna Protocol — Python SDK v3.0.2 (sole official SDK).

Pure-Python implementation of the Sibna Protocol (X3DH handshake, Double
Ratchet session encryption, sender-key group messaging, safety numbers,
envelope signing, encrypted storage, and the relay HTTP/WebSocket client).

No Rust core, FFI, or native library required. All cryptography is provided by
maintained libraries (`cryptography`, `blake3`, `pqcrypto`).

Wire formats, domain-separation strings, KDF constructions, and limits match
the retained Rust core (`core/`) and `PROTOCOL_SPECIFICATION.md`.

Install:
    pip install sibna
"""

from __future__ import annotations

__version__ = "3.0.2"
__author__ = "Sibna Security Team"
__license__ = "Apache-2.0 OR MIT"

# ── Constants ────────────────────────────────────────────────────────────────
# ── Relay client ─────────────────────────────────────────────────────────────
from .client import (
    AsyncSibnaClient,
    Identity,
    SibnaClient,
)
from .constants import (  # noqa: F401
    ED25519_PUBLIC_KEY_LENGTH,
    GROUP_CHAIN_KEY_INFO,
    GROUP_KEY_DISTRIBUTE_INFO,
    GROUP_MESSAGE_KEY_INFO,
    KEY_LENGTH,
    MAX_AD_LEN,
    MAX_CHAIN_MESSAGES,
    MAX_EXTRA_BLOCKS,
    MAX_GROUP_MESSAGE_SIZE,
    MAX_GROUP_SIZE,
    MAX_MESSAGE_AGE_SECS,
    MAX_MESSAGE_NUMBER,
    MAX_MESSAGE_SIZE,
    MAX_PADDING_BYTES,
    MAX_PASSWORD_LEN,
    MAX_SESSION_ID_LEN,
    MAX_SKIPPED_MESSAGES,
    MIN_COMPATIBLE_VERSION,
    ML_KEM_768_CIPHERTEXT_LENGTH,
    ML_KEM_768_PUBLIC_KEY_LENGTH,
    ML_KEM_768_SECRET_KEY_LENGTH,
    NONCE_LENGTH,
    PADDING_BLOCK_STANDARD,
    PROTOCOL_VERSION_STRING,
    PROTOCOL_VERSION_WIRE,
    SAFETY_NUMBER_DIGIT_COUNT,
    TAG_LENGTH,
    X25519_PUBLIC_KEY_LENGTH,
)

# ── Cryptographic primitives ─────────────────────────────────────────────────
from .crypto import (  # noqa: F401
    C,
    Ed25519KeyPair,
    X25519KeyPair,
    blake3_hash,
    chacha20_poly1305_decrypt,
    chacha20_poly1305_encrypt,
    derive_identity_keys,
    hkdf,
    hkdf_expand,
    hkdf_extract,
    hmac_sha256,
    ml_kem_768_decapsulate,
    ml_kem_768_encapsulate,
    ml_kem_768_keypair,
    random_bytes,
    sha256,
    sha512,
)

# ── Envelope ─────────────────────────────────────────────────────────────────
from .envelope import (  # noqa: F401
    ENVELOPE_MAX_AGE_SECS as _ENVELOPE_MAX_AGE_SECS,
)
from .envelope import (
    make_signed_envelope,
    verify_signed_envelope,
)

# ── Errors ───────────────────────────────────────────────────────────────────
from .errors import (
    AuthError,
    CryptoError,
    KeyNotFoundError,
    NetworkError,
    ProtocolError,
    SessionNotFoundError,
    SibnaError,
    StorageError,
    ValidationError,
)
from .group import (
    MAX_GROUP_MESSAGE_SIZE as _MAX_GROUP_MESSAGE_SIZE,  # noqa: F401
)
from .group import (
    MAX_GROUP_SIZE as _MAX_GROUP_SIZE,  # noqa: F401
)

# ── Group messaging ──────────────────────────────────────────────────────────
from .group import (
    GroupMessage,
    GroupSession,
    SenderKey,
    SenderKeyMessage,
)

# ── Padding ──────────────────────────────────────────────────────────────────
from .padding import (
    PaddingMode,
    pad_message,
    pad_payload,
    unpad_message,
    unpad_payload,
)

# ── Double Ratchet ──────────────────────────────────────────────────────────
from .ratchet import (
    HEADER_SIZE,
    ChainKey,
    DoubleRatchet,
)
from .safety_number import (
    SAFETY_NUMBER_DIGIT_COUNT as _SAFETY_NUMBER_DIGIT_COUNT,  # noqa: F401
)
from .safety_number import (
    SAFETY_NUMBER_VERSION as _SAFETY_NUMBER_VERSION,  # noqa: F401
)

# ── Safety numbers ───────────────────────────────────────────────────────────
from .safety_number import (
    SafetyNumber,
)

# ── Session ──────────────────────────────────────────────────────────────────
from .session import (
    Session,
    SessionConfig,
)
from .storage import (
    STORAGE_FORMAT_VERSION as _STORAGE_FORMAT_VERSION,  # noqa: F401
)

# ── Storage ──────────────────────────────────────────────────────────────────
from .storage import (
    SecureStorage,
)

# ── X3DH ─────────────────────────────────────────────────────────────────────
from .x3dh import (
    PreKeyBundle,
    X3DHResult,
    generate_peer_bundle,
    x3dh_initiator,
    x3dh_responder,
)

__all__ = [
    "ED25519_PUBLIC_KEY_LENGTH",
    "HEADER_SIZE",
    # Constants
    "KEY_LENGTH",
    "MAX_AD_LEN",
    "MAX_CHAIN_MESSAGES",
    "MAX_EXTRA_BLOCKS",
    "MAX_GROUP_MESSAGE_SIZE",
    "MAX_GROUP_SIZE",
    "MAX_MESSAGE_AGE_SECS",
    "MAX_MESSAGE_NUMBER",
    "MAX_MESSAGE_SIZE",
    "MAX_PADDING_BYTES",
    "MAX_PASSWORD_LEN",
    "MAX_SESSION_ID_LEN",
    "MAX_SKIPPED_MESSAGES",
    "MIN_COMPATIBLE_VERSION",
    "ML_KEM_768_CIPHERTEXT_LENGTH",
    "ML_KEM_768_PUBLIC_KEY_LENGTH",
    "ML_KEM_768_SECRET_KEY_LENGTH",
    "NONCE_LENGTH",
    "PADDING_BLOCK_STANDARD",
    "PROTOCOL_VERSION_STRING",
    "PROTOCOL_VERSION_WIRE",
    "SAFETY_NUMBER_DIGIT_COUNT",
    "TAG_LENGTH",
    "X25519_PUBLIC_KEY_LENGTH",
    "AsyncSibnaClient",
    "AuthError",
    # Double Ratchet
    "ChainKey",
    "CryptoError",
    "DoubleRatchet",
    "Ed25519KeyPair",
    "GroupMessage",
    "GroupSession",
    # Relay client
    "Identity",
    "KeyNotFoundError",
    "NetworkError",
    # Padding
    "PaddingMode",
    # X3DH
    "PreKeyBundle",
    "ProtocolError",
    # Safety Numbers
    "SafetyNumber",
    # Storage
    "SecureStorage",
    # Group
    "SenderKey",
    "SenderKeyMessage",
    # Session
    "Session",
    "SessionConfig",
    "SessionNotFoundError",
    "SibnaClient",
    # Errors
    "SibnaError",
    "StorageError",
    "ValidationError",
    "X3DHResult",
    # Crypto
    "X25519KeyPair",
    # Version
    "__version__",
    "blake3_hash",
    "chacha20_poly1305_decrypt",
    "chacha20_poly1305_encrypt",
    "derive_identity_keys",
    "generate_peer_bundle",
    "hkdf",
    "hkdf_expand",
    "hkdf_extract",
    "hmac_sha256",
    # Envelope
    "make_signed_envelope",
    "ml_kem_768_decapsulate",
    "ml_kem_768_encapsulate",
    "ml_kem_768_keypair",
    "pad_message",
    "pad_payload",
    "random_bytes",
    "sha256",
    "sha512",
    "unpad_message",
    "unpad_payload",
    "verify_signed_envelope",
    "x3dh_initiator",
    "x3dh_responder",
]
