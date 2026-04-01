"""
Sibna Protocol — HTTP + WebSocket Client
==========================================

يتعامل مع الشبكة: التسجيل، المصادقة، إرسال الرسائل، استقبالها.

هذا الملف يعتمد على مكتبات خارجية — ليس "Zero Dependencies":
    pip install requests aiohttp cryptography

مثال استخدام (Sync):
    from sibna.client import SibnaClient, Identity

    client = SibnaClient(server="http://localhost:8080")
    client.generate_identity()
    client.authenticate()

    bundle = ...  # من sibna.Context.generate_prekey_bundle()
    client.upload_prekey(bundle.hex())

    client.send_message(recipient_id="<hex>", payload_hex="<hex>")

    messages = client.fetch_inbox()

مثال استخدام (Async WebSocket):
    import asyncio
    from sibna.client import AsyncSibnaClient

    async def main():
        client = AsyncSibnaClient(server="http://localhost:8080")
        client.generate_identity()
        await client.authenticate()
        await client.connect(on_message=lambda env: print(env))

    asyncio.run(main())

المتطلبات:
    - requests  (للـ HTTP sync)
    - aiohttp   (للـ async + WebSocket)
    - cryptography (لـ Ed25519)

ملاحظة: هذا الـ client يتعامل فقط مع النقل (transport).
التشفير الفعلي يتم في sibna.Context (FFI → Rust Core).
"""

__version__ = "1.0.0"
__author__  = "Sibna Security Team"
__license__ = "Apache-2.0"

import hashlib
import json
import os
import secrets
import struct
import time
import uuid
from typing import Any, Callable, Dict, List, Optional

# ─── تحقق من المكتبات الاختيارية ──────────────────────────────────────────────
# هذه المكتبات ليست مدمجة — يجب تثبيتها يدوياً

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat, PrivateFormat, NoEncryption,
    )
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False

try:
    import requests as _requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

try:
    import aiohttp as _aiohttp
    _AIOHTTP_AVAILABLE = True
except ImportError:
    _AIOHTTP_AVAILABLE = False


# ─── الأخطاء ──────────────────────────────────────────────────────────────────

class SibnaClientError(Exception):
    """خطأ عام في الـ client."""
    def __init__(self, message: str, status_code: int = 0):
        self.status_code = status_code
        super().__init__(message)

class AuthError(SibnaClientError):
    """فشل المصادقة مع السيرفر."""

class NetworkError(SibnaClientError):
    """خطأ في الشبكة أو السيرفر."""

class MissingDependencyError(SibnaClientError):
    """مكتبة مطلوبة غير مثبتة."""


# ─── Identity (Ed25519) ────────────────────────────────────────────────────────

class Identity:
    """
    زوج مفاتيح Ed25519 للمصادقة مع السيرفر.

    هذا غير مرتبط بمفاتيح التشفير في sibna.Context —
    هذا فقط للـ authentication flow مع السيرفر.

    يتطلب: pip install cryptography
    """

    def __init__(self, private_key_bytes: Optional[bytes] = None):
        if not _CRYPTO_AVAILABLE:
            raise MissingDependencyError(
                "مكتبة cryptography غير مثبتة.\n"
                "ثبّتها بـ: pip install cryptography"
            )
        if private_key_bytes:
            self._private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        else:
            self._private_key = Ed25519PrivateKey.generate()

        self._public_key = self._private_key.public_key()

    @property
    def public_key_bytes(self) -> bytes:
        """المفتاح العام — 32 بايت."""
        return self._public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    @property
    def public_key_hex(self) -> str:
        """المفتاح العام بصيغة hex."""
        return self.public_key_bytes.hex()

    @property
    def private_key_bytes(self) -> bytes:
        """المفتاح الخاص — 32 بايت. احتفظ به سراً."""
        return self._private_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )

    def sign(self, data: bytes) -> bytes:
        """يوقّع البيانات ويعيد توقيع 64 بايت."""
        return self._private_key.sign(data)

    def sign_hex(self, data: bytes) -> str:
        """يوقّع البيانات ويعيد التوقيع بصيغة hex."""
        return self.sign(data).hex()

    def save(self, path: str) -> None:
        """يحفظ المفتاح الخاص في ملف (صلاحيات 600)."""
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "wb") as f:
            f.write(self.private_key_bytes)
        os.chmod(path, 0o600)

    @classmethod
    def load(cls, path: str) -> "Identity":
        """يحمّل هوية من ملف مفتاح خاص محفوظ مسبقاً."""
        with open(path, "rb") as f:
            return cls(private_key_bytes=f.read())

    def __repr__(self) -> str:
        return f"<Identity pub={self.public_key_hex[:16]}...>"


# ─── Message Padding (لتقليل تسريب حجم الرسائل) ─────────────────────────────

_PADDING_BLOCK = 1024


def pad_payload(data: bytes) -> bytes:
    """
    يُحشي البيانات لأقرب مضاعف لـ 1024 بايت.
    يجعل حجم جميع الرسائل متماثلاً للمراقب السلبي.
    """
    unpadded_len  = len(data) + 1
    remainder     = unpadded_len % _PADDING_BLOCK
    padding_needed = (_PADDING_BLOCK - remainder) % _PADDING_BLOCK or _PADDING_BLOCK
    indicator     = padding_needed % 256
    return bytes([indicator]) + data + secrets.token_bytes(padding_needed)


def unpad_payload(padded: bytes) -> bytes:
    """يُزيل الحشو من payload مستقبَل."""
    if not padded:
        raise ValueError("payload فارغ")
    indicator    = padded[0]
    total_len    = len(padded)
    padding_needed = total_len % _PADDING_BLOCK
    actual_padding = indicator if padding_needed == 0 else padding_needed
    return padded[1 : total_len - actual_padding]


# ─── Envelope (غلاف الرسالة الموقّع) ─────────────────────────────────────────

def make_signed_envelope(
    identity: Identity,
    recipient_id: str,
    payload_hex: str,
) -> Dict[str, Any]:
    """
    ينشئ غلافاً موقّعاً للإرسال عبر السيرفر.

    السيرفر لا يرى محتوى الرسالة (payload_hex مشفر مسبقاً من sibna.Context).
    التوقيع يضمن أن المُرسِل هو من يدّعي.

    Args:
        identity:     هوية المُرسِل.
        recipient_id: معرّف المستقبِل (hex).
        payload_hex:  الرسالة المشفرة مسبقاً (hex).

    Returns:
        dict: الغلاف الجاهز للإرسال كـ JSON.
    """
    message_id = str(uuid.uuid4())
    timestamp  = int(time.time())

    h = hashlib.sha512()
    h.update(recipient_id.encode())
    h.update(payload_hex.encode())
    h.update(struct.pack("<q", timestamp))
    h.update(message_id.encode())

    return {
        "recipient_id": recipient_id,
        "payload_hex":  payload_hex,
        "sender_id":    identity.public_key_hex,
        "timestamp":    timestamp,
        "message_id":   message_id,
        "signature_hex": identity.sign_hex(h.digest()),
    }


def verify_signed_envelope(envelope: Dict[str, Any]) -> bool:
    """
    يتحقق من توقيع غلاف مستقبَل.

    يجب استدعاؤه قبل معالجة أي رسالة واردة.

    Returns:
        True إذا كان التوقيع صحيحاً والرسالة حديثة (أقل من 5 دقائق).
        False في أي حالة أخرى.
    """
    if not _CRYPTO_AVAILABLE:
        raise MissingDependencyError("pip install cryptography")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature

        key_bytes = bytes.fromhex(envelope["sender_id"])
        sig_bytes = bytes.fromhex(envelope["signature_hex"])

        h = hashlib.sha512()
        h.update(envelope["recipient_id"].encode())
        h.update(envelope["payload_hex"].encode())
        h.update(struct.pack("<q", envelope["timestamp"]))
        h.update(envelope["message_id"].encode())

        Ed25519PublicKey.from_public_bytes(key_bytes).verify(sig_bytes, h.digest())

        # الرسالة لا يجب أن تكون أقدم من 5 دقائق
        if abs(int(time.time()) - envelope["timestamp"]) > 300:
            return False

        return True
    except Exception:
        return False


# ─── HTTP Sync Client ──────────────────────────────────────────────────────────

class SibnaClient:
    """
    Sync HTTP client للتعامل مع سيرفر Sibna.

    يتطلب: pip install requests cryptography

    هذا الـ client يتولى:
    - المصادقة (Ed25519 challenge-response → JWT)
    - رفع PreKey Bundle
    - إرسال رسائل مشفرة عبر REST
    - استقبال رسائل offline

    التشفير الفعلي يتم خارج هذا الـ client في sibna.Context.
    """

    def __init__(self, server: str = "http://localhost:8080"):
        if not _REQUESTS_AVAILABLE:
            raise MissingDependencyError(
                "مكتبة requests غير مثبتة.\n"
                "ثبّتها بـ: pip install requests"
            )
        self.server    = server.rstrip("/")
        self.identity: Optional[Identity] = None
        self.jwt_token: Optional[str]     = None
        self._session  = _requests.Session()

    def generate_identity(self, private_key_bytes: Optional[bytes] = None) -> Identity:
        """
        يولّد (أو يحمّل) هوية Ed25519 للمصادقة مع السيرفر.

        Args:
            private_key_bytes: مفتاح خاص محفوظ مسبقاً (اختياري).
                               إذا لم يُمرَّر، يُولَّد مفتاح جديد.
        """
        if not _CRYPTO_AVAILABLE:
            raise MissingDependencyError("pip install cryptography")
        self.identity = Identity(private_key_bytes)
        return self.identity

    def authenticate(self) -> str:
        """
        يُصادق مع السيرفر عبر Ed25519 challenge-response ويحصل على JWT.

        الخطوات:
        1. يطلب تحدياً (challenge) من السيرفر
        2. يوقّع التحدي بمفتاحه الخاص
        3. يُرسل التوقيع للسيرفر ليحصل على JWT

        Returns:
            str: JWT token (صالح لـ 24 ساعة عادةً).

        Raises:
            AuthError: إذا لم تُولَّد هوية أولاً أو فشلت المصادقة.
        """
        if not self.identity:
            raise AuthError("استدعِ generate_identity() أولاً")

        r = self._session.post(f"{self.server}/v1/auth/challenge", json={
            "identity_key_hex": self.identity.public_key_hex
        })
        self._check_response(r, "auth/challenge")
        challenge_hex = r.json()["challenge_hex"]

        r = self._session.post(f"{self.server}/v1/auth/prove", json={
            "identity_key_hex": self.identity.public_key_hex,
            "challenge_hex":    challenge_hex,
            "signature_hex":    self.identity.sign_hex(bytes.fromhex(challenge_hex)),
        })
        self._check_response(r, "auth/prove")
        self.jwt_token = r.json()["token"]
        return self.jwt_token

    def upload_prekey(self, bundle_hex: str) -> None:
        """
        يرفع PreKey Bundle إلى السيرفر.

        bundle_hex يُولَّد من: sibna.Context.generate_prekey_bundle().hex()

        يجب المصادقة أولاً (authenticate()).
        """
        self._require_auth()
        r = self._session.post(f"{self.server}/v1/prekeys/upload", json={
            "bundle_hex": bundle_hex
        }, headers=self._auth_headers())
        self._check_response(r, "prekeys/upload")

    def fetch_prekeys(self, identity_key_hex: str) -> List[str]:
        """
        يجلب PreKey Bundles لـ peer من السيرفر.

        Args:
            identity_key_hex: المفتاح العام للـ peer (hex).

        Returns:
            List[str]: قائمة bundles بصيغة hex.
                       تُمرَّر إلى sibna.Context.perform_handshake()

        ملاحظة: كل bundle يُحذف من السيرفر بعد الجلب (لمنع إعادة الاستخدام).
        """
        r = self._session.get(f"{self.server}/v1/prekeys/{identity_key_hex}")
        self._check_response(r, "prekeys/fetch")
        return r.json()["bundles_hex"]

    def send_message(
        self,
        recipient_id: str,
        payload_hex: str,
        sign: bool = True,
    ) -> int:
        """
        يُرسل رسالة مشفرة عبر REST (HTTP fallback).

        payload_hex هو ناتج sibna.Context.session_encrypt().hex()
        السيرفر لا يرى محتوى الرسالة.

        Args:
            recipient_id: معرّف المستقبِل (hex).
            payload_hex:  الرسالة المشفرة (hex).
            sign:         True لإضافة توقيع Ed25519 (موصى به).

        Returns:
            int: HTTP status code.
                 200 = وصلت مباشرة، 202 = في قائمة الانتظار (offline)

        Raises:
            AuthError: إذا لم تُولَّد هوية موقّعة عند sign=True.
        """
        if sign and self.identity:
            body = make_signed_envelope(self.identity, recipient_id, payload_hex)
        else:
            body = {"recipient_id": recipient_id, "payload_hex": payload_hex}

        r = self._session.post(
            f"{self.server}/v1/messages/send",
            json=body,
            headers=self._auth_headers(),
        )
        self._check_response(r, "messages/send")
        return r.status_code

    def fetch_inbox(self) -> List[Dict[str, Any]]:
        """
        يجلب الرسائل المنتظرة من الـ inbox.

        يتحقق تلقائياً من توقيع كل رسالة ويُسقط الرسائل ذات التوقيع الخاطئ.
        الرسائل تُحذف من السيرفر بعد الجلب.

        Returns:
            List[dict]: قائمة الغلافات الموثوقة.
                        payload_hex في كل غلاف يجب فك تشفيره بـ:
                        sibna.Context.session_decrypt(peer_id, bytes.fromhex(envelope["payload_hex"]))

        Raises:
            AuthError: إذا لم تتم المصادقة.
        """
        self._require_auth()
        r = self._session.get(
            f"{self.server}/v1/messages/inbox",
            params={
                "identity_key_hex": self.identity.public_key_hex,
                "token":            self.jwt_token,
            },
        )
        self._check_response(r, "messages/inbox")

        verified = []
        for msg in r.json().get("messages", []):
            if verify_signed_envelope(msg):
                verified.append(msg)
            else:
                print(f"⚠ رسالة بتوقيع خاطئ، تم تجاهلها: {msg.get('message_id')}")
        return verified

    def health(self) -> Dict[str, Any]:
        """يتحقق من حالة السيرفر."""
        r = self._session.get(f"{self.server}/health")
        self._check_response(r, "health")
        return r.json()

    # ── دوال مساعدة داخلية ────────────────────────────────────────────────────

    def _require_auth(self) -> None:
        if not self.identity or not self.jwt_token:
            raise AuthError("استدعِ authenticate() أولاً")

    def _auth_headers(self) -> Dict[str, str]:
        if self.jwt_token:
            return {"Authorization": f"Bearer {self.jwt_token}"}
        return {}

    def _check_response(self, r: Any, endpoint: str) -> None:
        if r.status_code == 429:
            raise NetworkError(f"Rate limit على {endpoint}", 429)
        if r.status_code == 401:
            raise AuthError(f"Unauthorized على {endpoint}", 401)
        if r.status_code >= 400:
            raise NetworkError(
                f"{endpoint} فشل: HTTP {r.status_code} — {r.text[:200]}",
                r.status_code,
            )

    def __repr__(self) -> str:
        pub = self.identity.public_key_hex[:16] if self.identity else "None"
        return f"<SibnaClient server={self.server} identity={pub}...>"


# ─── Async WebSocket Client ────────────────────────────────────────────────────

class AsyncSibnaClient:
    """
    Async client مع WebSocket للرسائل الفورية.

    يتطلب: pip install aiohttp cryptography

    مثال:
        client = AsyncSibnaClient(server="http://localhost:8080")
        client.generate_identity()
        await client.authenticate()
        await client.connect(on_message=my_handler)
        await client.send(recipient_id="<hex>", payload_hex="<hex>")
    """

    def __init__(self, server: str = "http://localhost:8080"):
        self.server     = server.rstrip("/")
        self.ws_server  = server.replace("http://", "ws://").replace("https://", "wss://")
        self.identity:  Optional[Identity] = None
        self.jwt_token: Optional[str]      = None
        self._ws        = None

    def generate_identity(self, private_key_bytes: Optional[bytes] = None) -> Identity:
        """يولّد أو يحمّل هوية Ed25519."""
        if not _CRYPTO_AVAILABLE:
            raise MissingDependencyError("pip install cryptography")
        self.identity = Identity(private_key_bytes)
        return self.identity

    async def authenticate(self) -> str:
        """
        يُصادق مع السيرفر بشكل async.

        Returns:
            str: JWT token.
        """
        if not _AIOHTTP_AVAILABLE:
            raise MissingDependencyError("pip install aiohttp")
        if not self.identity:
            raise AuthError("استدعِ generate_identity() أولاً")

        async with _aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.server}/v1/auth/challenge",
                json={"identity_key_hex": self.identity.public_key_hex},
            ) as r:
                if r.status != 200:
                    raise AuthError(f"Challenge فشل: {r.status}")
                challenge_hex = (await r.json())["challenge_hex"]

            async with session.post(
                f"{self.server}/v1/auth/prove",
                json={
                    "identity_key_hex": self.identity.public_key_hex,
                    "challenge_hex":    challenge_hex,
                    "signature_hex":    self.identity.sign_hex(bytes.fromhex(challenge_hex)),
                },
            ) as r:
                if r.status != 200:
                    raise AuthError(f"Prove فشل: {r.status}")
                self.jwt_token = (await r.json())["token"]
                return self.jwt_token

    async def connect(self, on_message: Optional[Callable] = None) -> None:
        """
        يتصل بـ WebSocket ويبقى مستمعاً للرسائل.

        يتحقق تلقائياً من توقيع كل رسالة واردة.

        Args:
            on_message: دالة async تُستدعى مع كل رسالة موثوقة (اختياري).
                        Signature: async def handler(envelope: dict) -> None
        """
        if not _AIOHTTP_AVAILABLE:
            raise MissingDependencyError("pip install aiohttp")
        if not self.jwt_token:
            raise AuthError("استدعِ authenticate() أولاً")

        ws_url = f"{self.ws_server}/ws?token={self.jwt_token}"

        async with _aiohttp.ClientSession() as session:
            async with session.ws_connect(ws_url) as ws:
                self._ws = ws
                async for msg in ws:
                    if msg.type == _aiohttp.WSMsgType.BINARY:
                        try:
                            envelope = json.loads(msg.data)
                            if verify_signed_envelope(envelope):
                                if on_message:
                                    await on_message(envelope)
                            else:
                                print(f"⚠ توقيع خاطئ: {envelope.get('message_id')}")
                        except Exception as e:
                            print(f"⚠ خطأ في تحليل الرسالة: {e}")
                    elif msg.type == _aiohttp.WSMsgType.ERROR:
                        raise NetworkError(f"WebSocket error: {ws.exception()}")

    async def send(
        self,
        recipient_id: str,
        payload_hex: str,
        sign: bool = True,
    ) -> None:
        """
        يُرسل رسالة مشفرة عبر WebSocket.

        Args:
            recipient_id: معرّف المستقبِل (hex).
            payload_hex:  الرسالة المشفرة (hex) من sibna.Context.session_encrypt().
            sign:         True لإضافة توقيع Ed25519.
        """
        if not self._ws:
            raise NetworkError("غير متصل — استدعِ connect() أولاً")

        if sign and self.identity:
            envelope = make_signed_envelope(self.identity, recipient_id, payload_hex)
        else:
            envelope = {
                "recipient_id": recipient_id,
                "payload_hex":  payload_hex,
                "message_id":   str(uuid.uuid4()),
                "timestamp":    int(time.time()),
            }

        await self._ws.send_bytes(json.dumps(envelope).encode())

    def __repr__(self) -> str:
        pub = self.identity.public_key_hex[:16] if self.identity else "None"
        return f"<AsyncSibnaClient server={self.server} identity={pub}...>"


# ─── Exports ───────────────────────────────────────────────────────────────────

__all__ = [
    "Identity",
    "SibnaClient",
    "AsyncSibnaClient",
    "SibnaClientError",
    "AuthError",
    "NetworkError",
    "MissingDependencyError",
    "pad_payload",
    "unpad_payload",
    "make_signed_envelope",
    "verify_signed_envelope",
    "__version__",
]
