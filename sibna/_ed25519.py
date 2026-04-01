"""
Pure Python Ed25519 — no external dependencies.

Implements RFC 8032 (Edwards-Curve Digital Signature Algorithm).
Uses only Python stdlib: hashlib, os.

This is used for server authentication (signing challenge responses).
The Rust core handles all other cryptography (encryption, ratchet, X3DH).

Performance: ~5ms per sign operation (acceptable for auth flows).
"""

import hashlib
import os

# ── Field arithmetic over GF(2^255 - 19) ──────────────────────────────────────

_q  = 2**255 - 19
_q2 = 2**252 + 27742317777372353535851937790883648493  # curve order


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _modinv(x: int) -> int:
    """Modular inverse in GF(q) via Fermat's little theorem."""
    return pow(x, _q - 2, _q)


_d = -121665 * _modinv(121666) % _q


def _recover_x(y: int, sign: int):
    if y >= _q:
        return None
    x2 = (y * y - 1) * _modinv(_d * y * y + 1)
    if x2 == 0:
        return 0 if sign == 0 else None
    x = pow(x2, (_q + 3) // 8, _q)
    if (x * x - x2) % _q != 0:
        x = x * pow(2, (_q - 1) // 4, _q) % _q
    if (x * x - x2) % _q != 0:
        return None
    if x & 1 != sign:
        x = _q - x
    return x


# Base point G in extended coordinates (X:Y:Z:T)
_Gy = 4 * _modinv(5) % _q
_Gx = _recover_x(_Gy, 0)
_G  = (_Gx, _Gy, 1, _Gx * _Gy % _q)


def _point_add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % _q
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % _q
    C = 2 * P[3] * Q[3] * _d % _q
    D = 2 * P[2] * Q[2] % _q
    E, F, G_, H = B - A, D - C, D + C, B + A
    return (E * F % _q, H * G_ % _q, F * G_ % _q, E * H % _q)


def _point_mul(s: int, P):
    Q = (0, 1, 1, 0)  # identity point
    while s > 0:
        if s & 1:
            Q = _point_add(Q, P)
        P = _point_add(P, P)
        s >>= 1
    return Q


def _compress(P) -> bytes:
    zinv = _modinv(P[2])
    x = P[0] * zinv % _q
    y = P[1] * zinv % _q
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(s: bytes):
    if len(s) != 32:
        raise ValueError("Invalid point: expected 32 bytes")
    y    = int.from_bytes(s, "little")
    sign = y >> 255
    y   &= (1 << 255) - 1
    x    = _recover_x(y, sign)
    if x is None:
        raise ValueError("Invalid point: cannot recover x")
    return (x, y, 1, x * y % _q)


def _secret_expand(seed: bytes):
    if len(seed) != 32:
        raise ValueError("Seed must be 32 bytes")
    h = _sha512(seed)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= (1 << 254)
    return a, h[32:]


# ── Public API ─────────────────────────────────────────────────────────────────

def generate_keypair() -> tuple:
    """
    Generate a random Ed25519 keypair.

    Returns:
        (private_key_bytes, public_key_bytes) — both 32 bytes.
        private_key_bytes is the seed (keep secret).
        public_key_bytes is the public point.
    """
    seed = os.urandom(32)
    pub  = _compress(_point_mul(_secret_expand(seed)[0], _G))
    return seed, pub


def public_key(seed: bytes) -> bytes:
    """Derive the 32-byte public key from a 32-byte seed."""
    a, _ = _secret_expand(seed)
    return _compress(_point_mul(a, _G))


def sign(seed: bytes, message: bytes) -> bytes:
    """
    Sign a message with a 32-byte seed.

    Returns a 64-byte signature.
    """
    a, prefix = _secret_expand(seed)
    A = _compress(_point_mul(a, _G))
    r = int.from_bytes(_sha512(prefix + message), "little") % _q2
    R = _compress(_point_mul(r, _G))
    h = int.from_bytes(_sha512(R + A + message), "little") % _q2
    S = (r + h * a) % _q2
    return R + int.to_bytes(S, 32, "little")


def verify(pub: bytes, message: bytes, signature: bytes) -> bool:
    """
    Verify an Ed25519 signature.

    Returns True if valid, False otherwise. Never raises.
    """
    try:
        if len(pub) != 32 or len(signature) != 64:
            return False
        A   = _decompress(pub)
        Rs  = signature[:32]
        R   = _decompress(Rs)
        s   = int.from_bytes(signature[32:], "little")
        if s >= _q2:
            return False
        h   = int.from_bytes(_sha512(Rs + pub + message), "little") % _q2
        sB  = _point_mul(s, _G)
        hA  = _point_mul(h, A)
        # negate hA to check sB == R + hA  ↔  sB - hA == R
        neg = (_q - hA[0]) % _q, hA[1], hA[2], (_q - hA[3]) % _q
        return _compress(_point_add(sB, neg)) == Rs
    except Exception:
        return False
