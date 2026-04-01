"""
Sibna Protocol — Python SDK
============================

Python wrapper for the Sibna Rust core via FFI (ctypes).
No external dependencies — uses only Python stdlib + the compiled Rust library.

Requirements:
    - Python 3.8+
    - The compiled native library from sibna-protc/core:
        Windows : sibna_core.dll
        Linux   : libsibna_core.so
        macOS   : libsibna_core.dylib

    Build it:
        cd sibna-protc/core
        cargo build --release --features ffi

    Then place the file next to this sibna/ folder.

Quick start:
    import sibna

    if not sibna.is_available():
        raise RuntimeError("Native library not found")

    key = sibna.generate_key()
    ct  = sibna.encrypt(key, b"Hello")
    pt  = sibna.decrypt(key, ct)
    assert pt == b"Hello"
"""

__version__ = "1.0.0"
__author__  = "Sibna Security Team"
__license__ = "Apache-2.0"

import ctypes
import os
import platform
from typing import Optional, Tuple

# ── Library loading ────────────────────────────────────────────────────────────

def _find_library() -> Optional[str]:
    system = platform.system()
    if system == "Linux":
        names = ["libsibna_core.so"]
    elif system == "Darwin":
        names = ["libsibna_core.dylib"]
    elif system == "Windows":
        names = ["sibna_core.dll"]
    else:
        return None

    search_paths = [
        os.path.dirname(os.path.dirname(__file__)),   # parent of sibna/
        os.path.dirname(__file__),                     # sibna/ itself
        os.path.join(os.path.dirname(__file__),
                     "..", "..", "core", "target", "release"),
    ]
    for folder in search_paths:
        for name in names:
            candidate = os.path.normpath(os.path.join(folder, name))
            if os.path.isfile(candidate):
                return candidate
    return None


def _configure(lib: ctypes.CDLL) -> None:
    lib.sibna_generate_key.restype  = ctypes.c_int
    lib.sibna_generate_key.argtypes = [ctypes.c_char_p]

    lib.sibna_random_bytes.restype  = ctypes.c_int
    lib.sibna_random_bytes.argtypes = [ctypes.c_size_t, ctypes.c_char_p]

    lib.sibna_encrypt.restype  = ctypes.c_int
    lib.sibna_encrypt.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p,
    ]
    lib.sibna_decrypt.restype  = ctypes.c_int
    lib.sibna_decrypt.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p,
    ]
    lib.sibna_free_buffer.restype  = None
    lib.sibna_free_buffer.argtypes = [ctypes.c_void_p]

    lib.sibna_version.restype  = ctypes.c_int
    lib.sibna_version.argtypes = [ctypes.c_char_p, ctypes.c_size_t]

    lib.sibna_context_create.restype  = ctypes.c_int
    lib.sibna_context_create.argtypes = [
        ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_void_p),
    ]
    lib.sibna_context_destroy.restype  = None
    lib.sibna_context_destroy.argtypes = [ctypes.c_void_p]

    lib.sibna_generate_identity.restype  = ctypes.c_int
    lib.sibna_generate_identity.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
    ]
    lib.sibna_generate_prekey_bundle.restype  = ctypes.c_int
    lib.sibna_generate_prekey_bundle.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

    lib.sibna_perform_handshake.restype  = ctypes.c_int
    lib.sibna_perform_handshake.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_uint8,
    ]
    lib.sibna_session_encrypt.restype  = ctypes.c_int
    lib.sibna_session_encrypt.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_void_p,
    ]
    lib.sibna_session_decrypt.restype  = ctypes.c_int
    lib.sibna_session_decrypt.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_void_p,
    ]


def _load() -> Optional[ctypes.CDLL]:
    path = _find_library()
    if not path:
        return None
    try:
        lib = ctypes.CDLL(path)
        _configure(lib)
        return lib
    except OSError:
        return None


_lib: Optional[ctypes.CDLL] = _load()


def is_available() -> bool:
    """True if the native Rust library is loaded and ready."""
    return _lib is not None


def library_path() -> Optional[str]:
    """Full path of the loaded library, or None."""
    return _find_library()


# ── ByteBuffer — mirrors Rust FFI struct ──────────────────────────────────────

class _ByteBuffer(ctypes.Structure):
    _fields_ = [
        ("data",     ctypes.POINTER(ctypes.c_uint8)),
        ("len",      ctypes.c_size_t),
        ("capacity", ctypes.c_size_t),
    ]

    def to_bytes(self) -> bytes:
        if not self.data or self.len == 0:
            return b""
        return bytes((ctypes.c_uint8 * self.len).from_address(
            ctypes.addressof(self.data.contents)
        ))

    def free(self) -> None:
        if _lib and self.data:
            _lib.sibna_free_buffer(ctypes.byref(self))


# ── Errors ────────────────────────────────────────────────────────────────────

_ERRORS = {
    1: "Invalid argument", 2: "Invalid key", 3: "Encryption failed",
    4: "Decryption failed", 5: "Out of memory", 6: "Invalid state",
    7: "Session not found", 8: "Key not found", 9: "Rate limit exceeded",
    10: "Internal error", 11: "Buffer too small", 12: "Invalid ciphertext",
    13: "Authentication failed",
}


class SibnaError(Exception):
    """Error from the native library."""
    def __init__(self, code: int):
        self.code = code
        super().__init__(f"SibnaError({code}): {_ERRORS.get(code, f'Unknown ({code})')}")


class LibraryNotFoundError(RuntimeError):
    """
    Raised when a function requires the native library and it is not found.

    Fix:
        cd sibna-protc/core
        cargo build --release --features ffi
    Then place sibna_core.dll / libsibna_core.so / .dylib
    next to the sibna/ package folder.
    """
    def __init__(self):
        super().__init__(
            "Native library not found.\n"
            "Build it from sibna-protc:\n"
            "    cd sibna-protc/core\n"
            "    cargo build --release --features ffi\n"
            "Then place the output file next to this SDK."
        )


def _require() -> ctypes.CDLL:
    if _lib is None:
        raise LibraryNotFoundError()
    return _lib


def _check(code: int) -> None:
    if code != 0:
        raise SibnaError(code)


# ── Standalone crypto ─────────────────────────────────────────────────────────

def version() -> str:
    """Protocol version string from the native library."""
    lib = _require()
    buf = ctypes.create_string_buffer(32)
    _check(lib.sibna_version(buf, 32))
    return buf.value.decode()


def generate_key() -> bytes:
    """
    Generate a cryptographically secure random 32-byte encryption key.

    Returns:
        bytes: 32-byte key for use with encrypt() / decrypt().
    """
    lib = _require()
    buf = ctypes.create_string_buffer(32)
    _check(lib.sibna_generate_key(buf))
    return buf.raw


def random_bytes(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes.

    Args:
        length: Number of bytes (must be > 0).
    """
    if length <= 0:
        raise ValueError("length must be > 0")
    lib = _require()
    buf = ctypes.create_string_buffer(length)
    _check(lib.sibna_random_bytes(length, buf))
    return buf.raw


def encrypt(
    key: bytes,
    plaintext: bytes,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """
    Encrypt data with ChaCha20-Poly1305.

    Args:
        key:             32-byte key from generate_key().
        plaintext:       Data to encrypt (must be non-empty).
        associated_data: Optional authenticated-but-not-encrypted context.
                         Must pass the same value to decrypt().

    Returns:
        bytes: nonce (12) + ciphertext + tag (16).

    Raises:
        ValueError:          Wrong key size or empty plaintext.
        SibnaError(3):       Encryption failed.
        LibraryNotFoundError if library not loaded.
    """
    lib = _require()
    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes (got {len(key)})")
    if not plaintext:
        raise ValueError("plaintext must not be empty")
    out = _ByteBuffer()
    _check(lib.sibna_encrypt(
        key, plaintext, len(plaintext),
        associated_data, len(associated_data) if associated_data else 0,
        ctypes.byref(out),
    ))
    try:
        return out.to_bytes()
    finally:
        out.free()


def decrypt(
    key: bytes,
    ciphertext: bytes,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """
    Decrypt data with ChaCha20-Poly1305.

    Args:
        key:             Same 32-byte key used in encrypt().
        ciphertext:      Output of encrypt().
        associated_data: Same value passed to encrypt() (if any).

    Returns:
        bytes: Original plaintext.

    Raises:
        SibnaError(13): Data tampered or wrong key (Authentication failed).
        SibnaError(12): Ciphertext is invalid/truncated.
        LibraryNotFoundError if library not loaded.
    """
    lib = _require()
    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes (got {len(key)})")
    if not ciphertext:
        raise ValueError("ciphertext must not be empty")
    out = _ByteBuffer()
    _check(lib.sibna_decrypt(
        key, ciphertext, len(ciphertext),
        associated_data, len(associated_data) if associated_data else 0,
        ctypes.byref(out),
    ))
    try:
        return out.to_bytes()
    finally:
        out.free()


# ── Context ────────────────────────────────────────────────────────────────────

class Context:
    """
    Manages identity keypairs and Double Ratchet sessions.

    Password rules (enforced by Rust core):
        Must contain uppercase + lowercase + digit, minimum 8 characters.

    Usage:
        ctx = Context(password=b"MyPass1!")
        ed_pub, x_pub = ctx.generate_identity()
        bundle = ctx.generate_prekey_bundle()

        # After exchanging bundles with a peer:
        ctx.perform_handshake(peer_id=peer_ed_pub, peer_bundle=peer_bundle, initiator=True)
        ct = ctx.session_encrypt(peer_ed_pub, b"Hello!")
        pt = ctx.session_decrypt(peer_ed_pub, ct)

        ctx.close()
    """

    def __init__(self, password: Optional[bytes] = None):
        """
        Args:
            password: Optional master password for the local keystore.
                      If None, a random storage key is generated.

        Raises:
            SibnaError(10): Password too weak.
            LibraryNotFoundError: Library not loaded.
        """
        lib = _require()
        handle = ctypes.c_void_p()
        _check(lib.sibna_context_create(
            password, len(password) if password else 0,
            ctypes.byref(handle),
        ))
        self._handle = handle
        self._lib    = lib
        self._closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def generate_identity(self) -> Tuple[bytes, bytes]:
        """
        Generate an Ed25519 + X25519 identity keypair stored in the keystore.

        Returns:
            (ed25519_public_key, x25519_public_key) — both 32 bytes.
            - ed25519_public_key: for signing / identity verification
            - x25519_public_key:  for X3DH key agreement

        Raises:
            SibnaError: on failure.
        """
        self._check_open()
        ed_buf = ctypes.create_string_buffer(32)
        x_buf  = ctypes.create_string_buffer(32)
        _check(self._lib.sibna_generate_identity(self._handle, ed_buf, x_buf))
        return ed_buf.raw, x_buf.raw

    def generate_prekey_bundle(self) -> bytes:
        """
        Generate a PreKey Bundle to upload to the prekey server.

        Must call generate_identity() first.

        Returns:
            bytes: Serialized bundle — pass directly to your server
                   or to SibnaClient.upload_prekey(bundle.hex()).

        Raises:
            SibnaError(8): No identity generated yet (Key not found).
        """
        self._check_open()
        out = _ByteBuffer()
        _check(self._lib.sibna_generate_prekey_bundle(
            self._handle, ctypes.byref(out),
        ))
        try:
            return out.to_bytes()
        finally:
            out.free()

    def perform_handshake(
        self,
        peer_id: bytes,
        peer_bundle: bytes,
        initiator: bool,
    ) -> None:
        """
        Run X3DH handshake and create a Double Ratchet session.

        After success, use session_encrypt() / session_decrypt() with peer_id.

        Args:
            peer_id:     Peer's Ed25519 public key (used as session identifier).
            peer_bundle: Peer's PreKey Bundle bytes (from prekey server).
            initiator:   True if you start the conversation, False if responding.

        Raises:
            SibnaError(2): Invalid bundle or bad signature.
            SibnaError(6): Context in invalid state.
        """
        self._check_open()
        if not peer_id:
            raise ValueError("peer_id must not be empty")
        if not peer_bundle:
            raise ValueError("peer_bundle must not be empty")
        _check(self._lib.sibna_perform_handshake(
            self._handle,
            peer_bundle, len(peer_bundle),
            peer_id,     len(peer_id),
            1 if initiator else 0,
        ))

    def session_encrypt(
        self,
        peer_id: bytes,
        plaintext: bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """
        Encrypt a message over an existing Double Ratchet session.

        The ratchet key advances with every message — forward secrecy
        is automatic.

        Args:
            peer_id:         Same bytes used in perform_handshake().
            plaintext:       Message to encrypt (non-empty).
            associated_data: Optional authenticated context (e.g. message ID).

        Returns:
            bytes: Encrypted message. Pass to peer's session_decrypt().

        Raises:
            SibnaError(7): No session for this peer. Call perform_handshake() first.
            SibnaError(9): Rate limit exceeded.
        """
        self._check_open()
        if not peer_id:
            raise ValueError("peer_id must not be empty")
        if not plaintext:
            raise ValueError("plaintext must not be empty")
        out = _ByteBuffer()
        _check(self._lib.sibna_session_encrypt(
            self._handle,
            peer_id,   len(peer_id),
            plaintext, len(plaintext),
            associated_data, len(associated_data) if associated_data else 0,
            ctypes.byref(out),
        ))
        try:
            return out.to_bytes()
        finally:
            out.free()

    def session_decrypt(
        self,
        peer_id: bytes,
        ciphertext: bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """
        Decrypt a message from a Double Ratchet session.

        Args:
            peer_id:         Peer identifier (same as used in perform_handshake).
            ciphertext:      Encrypted message from the peer's session_encrypt().
            associated_data: Same value passed during encryption (if any).

        Returns:
            bytes: Original plaintext.

        Raises:
            SibnaError(13): Message tampered or wrong session.
            SibnaError(7):  Session not found.
            SibnaError(12): Ciphertext too short / corrupted.
        """
        self._check_open()
        if not peer_id:
            raise ValueError("peer_id must not be empty")
        if not ciphertext:
            raise ValueError("ciphertext must not be empty")
        out = _ByteBuffer()
        _check(self._lib.sibna_session_decrypt(
            self._handle,
            peer_id,    len(peer_id),
            ciphertext, len(ciphertext),
            associated_data, len(associated_data) if associated_data else 0,
            ctypes.byref(out),
        ))
        try:
            return out.to_bytes()
        finally:
            out.free()

    def close(self) -> None:
        """Free native memory and zero all keys. Call when done."""
        if not self._closed and self._handle:
            self._lib.sibna_context_destroy(self._handle)
            self._closed = True

    def _check_open(self) -> None:
        if self._closed:
            raise SibnaError(6)  # invalid state

    def __del__(self):
        self.close()

    def __repr__(self) -> str:
        return f"<sibna.Context closed={self._closed}>"


# ── Exports ────────────────────────────────────────────────────────────────────

__all__ = [
    "is_available", "library_path", "version",
    "SibnaError", "LibraryNotFoundError",
    "generate_key", "random_bytes", "encrypt", "decrypt",
    "Context",
    "__version__",
]
