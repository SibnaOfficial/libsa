"""
Sibna Protocol — Python SDK
============================

Python wrapper للـ Sibna Rust Core عبر FFI (ctypes).

ما يفعله هذا الـ SDK:
- تشفير وفك تشفير البيانات (ChaCha20-Poly1305)
- توليد مفاتيح عشوائية آمنة
- إنشاء هوية (Ed25519 + X25519)
- إنشاء جلسة Double Ratchet مع peer (بعد X3DH handshake)
- تشفير وفك تشفير رسائل الجلسة

ما لا يفعله هذا الـ SDK:
- لا يتصل بأي سيرفر (هذا دور client.py)
- لا يدير الشبكة أو WebSocket
- لا يعمل بدون ملف المكتبة المُجمَّعة (.dll / .so / .dylib)

المتطلبات:
- Python 3.8+
- ملف المكتبة المُجمَّعة من مشروع sibna-protc (Rust)
  - Windows : sibna_core.dll
  - Linux   : libsibna_core.so
  - macOS   : libsibna_core.dylib

لبناء المكتبة بنفسك:
    cd sibna-protc/core
    cargo build --release --features ffi
    # النتيجة في: target/release/

مثال استخدام أساسي:
    import sibna

    # تحقق أن المكتبة محملة
    if not sibna.is_available():
        raise RuntimeError("المكتبة غير موجودة — ابنها من sibna-protc أولاً")

    # توليد مفتاح وتشفير
    key = sibna.generate_key()
    ct  = sibna.encrypt(key, b"Hello")
    pt  = sibna.decrypt(key, ct)
    assert pt == b"Hello"

    # جلسة مشفرة (تحتاج handshake مسبق)
    ctx = sibna.Context()
    ctx.generate_identity()
    # ... (راجع README لخطوات X3DH الكاملة)
"""

__version__ = "1.0.0"
__author__  = "Sibna Security Team"
__license__ = "Apache-2.0"

import ctypes
import os
import platform
from typing import Optional, Tuple

# ─── تحميل المكتبة ────────────────────────────────────────────────────────────

def _find_library() -> Optional[str]:
    """
    يبحث عن ملف المكتبة المُجمَّعة في المسارات المعتادة.
    يعيد المسار إذا وجده، أو None إذا لم يجده.
    """
    system = platform.system()

    if system == "Linux":
        names = ["libsibna_core.so"]
    elif system == "Darwin":
        names = ["libsibna_core.dylib"]
    elif system == "Windows":
        names = ["sibna_core.dll"]
    else:
        return None

    # المسارات التي نبحث فيها بالترتيب
    search_paths = [
        os.path.dirname(__file__),                          # نفس مجلد هذا الملف
        os.path.join(os.path.dirname(__file__), ".."),      # مجلد فوقه
        os.path.join(os.path.dirname(__file__), "..", "..", "..", "core", "target", "release"),
    ]

    for folder in search_paths:
        for name in names:
            candidate = os.path.normpath(os.path.join(folder, name))
            if os.path.isfile(candidate):
                return candidate

    return None


def _load_library() -> Optional[ctypes.CDLL]:
    path = _find_library()
    if path is None:
        return None
    try:
        lib = ctypes.CDLL(path)
        _configure_signatures(lib)
        return lib
    except OSError:
        return None


def _configure_signatures(lib: ctypes.CDLL) -> None:
    """يحدد أنواع المعاملات والقيم المُعادة لكل دالة FFI."""

    # ByteBuffer هو struct بثلاثة حقول: data*, len, capacity
    # نستخدمه كـ output buffer في encrypt/decrypt

    # sibna_generate_key(key: *mut u8) -> i32
    lib.sibna_generate_key.restype  = ctypes.c_int
    lib.sibna_generate_key.argtypes = [ctypes.c_char_p]

    # sibna_random_bytes(len: usize, output: *mut u8) -> i32
    lib.sibna_random_bytes.restype  = ctypes.c_int
    lib.sibna_random_bytes.argtypes = [ctypes.c_size_t, ctypes.c_char_p]

    # sibna_encrypt(key, pt, pt_len, ad, ad_len, out: *mut ByteBuffer) -> i32
    lib.sibna_encrypt.restype  = ctypes.c_int
    lib.sibna_encrypt.argtypes = [
        ctypes.c_char_p,   # key
        ctypes.c_char_p,   # plaintext
        ctypes.c_size_t,   # plaintext_len
        ctypes.c_char_p,   # associated_data (nullable)
        ctypes.c_size_t,   # ad_len
        ctypes.c_void_p,   # *mut ByteBuffer
    ]

    # sibna_decrypt(key, ct, ct_len, ad, ad_len, out: *mut ByteBuffer) -> i32
    lib.sibna_decrypt.restype  = ctypes.c_int
    lib.sibna_decrypt.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
    ]

    # sibna_free_buffer(buf: *mut ByteBuffer) -> void
    lib.sibna_free_buffer.restype  = None
    lib.sibna_free_buffer.argtypes = [ctypes.c_void_p]

    # sibna_version(out: *mut c_char, len: usize) -> i32
    lib.sibna_version.restype  = ctypes.c_int
    lib.sibna_version.argtypes = [ctypes.c_char_p, ctypes.c_size_t]

    # sibna_context_create(password, password_len, *mut *mut ctx) -> i32
    lib.sibna_context_create.restype  = ctypes.c_int
    lib.sibna_context_create.argtypes = [
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_void_p),
    ]

    # sibna_context_destroy(ctx) -> void
    lib.sibna_context_destroy.restype  = None
    lib.sibna_context_destroy.argtypes = [ctypes.c_void_p]

    # sibna_generate_identity(ctx, ed25519_pub_out *mut u8, x25519_pub_out *mut u8) -> i32
    lib.sibna_generate_identity.restype  = ctypes.c_int
    lib.sibna_generate_identity.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,  # ed25519_pub (32 bytes output)
        ctypes.c_char_p,  # x25519_pub  (32 bytes output)
    ]

    # sibna_perform_handshake(ctx, bundle, bundle_len, peer_id, peer_id_len, initiator) -> i32
    lib.sibna_perform_handshake.restype  = ctypes.c_int
    lib.sibna_perform_handshake.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_uint8,
    ]

    # sibna_session_encrypt(ctx, session_id, sid_len, pt, pt_len, ad, ad_len, out) -> i32
    lib.sibna_session_encrypt.restype  = ctypes.c_int
    lib.sibna_session_encrypt.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_void_p,
    ]

    # sibna_session_decrypt(ctx, session_id, sid_len, ct, ct_len, ad, ad_len, out) -> i32
    lib.sibna_session_decrypt.restype  = ctypes.c_int
    lib.sibna_session_decrypt.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_void_p,
    ]

    # sibna_generate_prekey_bundle(ctx, out: *mut ByteBuffer) -> i32
    lib.sibna_generate_prekey_bundle.restype  = ctypes.c_int
    lib.sibna_generate_prekey_bundle.argtypes = [ctypes.c_void_p, ctypes.c_void_p]


_lib: Optional[ctypes.CDLL] = _load_library()


def is_available() -> bool:
    """يعيد True إذا كانت المكتبة المُجمَّعة محملة وجاهزة للاستخدام."""
    return _lib is not None


def library_path() -> Optional[str]:
    """يعيد المسار الكامل للمكتبة المحملة، أو None إذا لم تُحمَّل."""
    return _find_library()


# ─── ByteBuffer (struct مشترك مع Rust) ────────────────────────────────────────

class _ByteBuffer(ctypes.Structure):
    """
    يطابق تعريف ByteBuffer في Rust FFI:
        pub struct ByteBuffer { data: *mut u8, len: usize, capacity: usize }
    """
    _fields_ = [
        ("data",     ctypes.POINTER(ctypes.c_uint8)),
        ("len",      ctypes.c_size_t),
        ("capacity", ctypes.c_size_t),
    ]

    def to_bytes(self) -> bytes:
        if not self.data or self.len == 0:
            return b""
        arr_type = ctypes.c_uint8 * self.len
        return bytes(ctypes.cast(self.data, ctypes.POINTER(arr_type)).contents)

    def free(self) -> None:
        if _lib is not None and self.data:
            _lib.sibna_free_buffer(ctypes.byref(self))


# ─── الأخطاء ──────────────────────────────────────────────────────────────────

_ERROR_MESSAGES = {
    0:  "Success",
    1:  "Invalid argument",
    2:  "Invalid key",
    3:  "Encryption failed",
    4:  "Decryption failed",
    5:  "Out of memory",
    6:  "Invalid state",
    7:  "Session not found",
    8:  "Key not found",
    9:  "Rate limit exceeded",
    10: "Internal error",
    11: "Buffer too small",
    12: "Invalid ciphertext",
    13: "Authentication failed",
}


class SibnaError(Exception):
    """خطأ من المكتبة. يحتوي على كود الخطأ ورسالة توضيحية."""

    def __init__(self, code: int):
        self.code = code
        message = _ERROR_MESSAGES.get(code, f"Unknown error (code={code})")
        super().__init__(f"SibnaError({code}): {message}")


class LibraryNotFoundError(RuntimeError):
    """
    تُرفع عند محاولة استخدام أي دالة تحتاج المكتبة وهي غير موجودة.

    الحل: ابنِ المكتبة من مشروع sibna-protc:
        cd sibna-protc/core
        cargo build --release --features ffi
    ثم انسخ الملف الناتج إلى نفس مجلد هذا الملف.
    """

    def __init__(self):
        super().__init__(
            "المكتبة المُجمَّلة غير موجودة.\n"
            "ابنِها من sibna-protc:\n"
            "    cd sibna-protc/core\n"
            "    cargo build --release --features ffi\n"
            "ثم انسخ الملف الناتج (sibna_core.dll / libsibna_core.so / .dylib) "
            "إلى نفس مجلد هذا الملف."
        )


def _require_lib() -> ctypes.CDLL:
    if _lib is None:
        raise LibraryNotFoundError()
    return _lib


def _check(code: int) -> None:
    if code != 0:
        raise SibnaError(code)


# ─── دوال مساعدة عامة ─────────────────────────────────────────────────────────

def version() -> str:
    """يعيد رقم إصدار بروتوكول Sibna من المكتبة."""
    lib = _require_lib()
    buf = ctypes.create_string_buffer(32)
    _check(lib.sibna_version(buf, 32))
    return buf.value.decode("utf-8")


def generate_key() -> bytes:
    """
    يولّد مفتاح تشفير عشوائي بحجم 32 بايت (256 بت).

    Returns:
        bytes: مفتاح 32 بايت صالح للاستخدام مع encrypt() و decrypt().
    """
    lib = _require_lib()
    key = ctypes.create_string_buffer(32)
    _check(lib.sibna_generate_key(key))
    return key.raw


def random_bytes(length: int) -> bytes:
    """
    يولّد عدداً عشوائياً من البايتات باستخدام المولّد الآمن في المكتبة.

    Args:
        length: عدد البايتات المطلوبة (يجب أن يكون أكبر من 0).

    Returns:
        bytes: بايتات عشوائية.
    """
    if length <= 0:
        raise ValueError("length يجب أن يكون أكبر من 0")
    lib = _require_lib()
    buf = ctypes.create_string_buffer(length)
    _check(lib.sibna_random_bytes(length, buf))
    return buf.raw


def encrypt(
    key: bytes,
    plaintext: bytes,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """
    يشفّر البيانات باستخدام ChaCha20-Poly1305.

    Args:
        key:             مفتاح 32 بايت (من generate_key() أو مفتاح خاص بك).
        plaintext:       البيانات المراد تشفيرها.
        associated_data: بيانات إضافية مُصادَق عليها لكن غير مشفرة (اختياري).
                         يجب تمريرها بنفس القيمة عند فك التشفير.

    Returns:
        bytes: البيانات المشفرة. تحتوي على nonce + ciphertext + tag.

    Raises:
        ValueError:    إذا كان المفتاح ليس 32 بايت أو plaintext فارغة.
        SibnaError:    إذا فشل التشفير.
        LibraryNotFoundError: إذا لم تُحمَّل المكتبة.
    """
    lib = _require_lib()
    if len(key) != 32:
        raise ValueError(f"المفتاح يجب أن يكون 32 بايت، وصل {len(key)}")
    if not plaintext:
        raise ValueError("plaintext لا يمكن أن تكون فارغة")

    ad_ptr = associated_data or None
    ad_len = len(associated_data) if associated_data else 0

    out = _ByteBuffer()
    _check(lib.sibna_encrypt(key, plaintext, len(plaintext), ad_ptr, ad_len, ctypes.byref(out)))
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
    يفك تشفير البيانات باستخدام ChaCha20-Poly1305.

    Args:
        key:             نفس المفتاح 32 بايت المستخدم في encrypt().
        ciphertext:      البيانات المشفرة الصادرة من encrypt().
        associated_data: نفس associated_data المستخدمة في encrypt() (إذا كانت موجودة).

    Returns:
        bytes: البيانات الأصلية.

    Raises:
        SibnaError(13): إذا كانت البيانات منقحة أو المفتاح خاطئ (Authentication failed).
        SibnaError(12): إذا كان ciphertext غير صالح.
        LibraryNotFoundError: إذا لم تُحمَّل المكتبة.
    """
    lib = _require_lib()
    if len(key) != 32:
        raise ValueError(f"المفتاح يجب أن يكون 32 بايت، وصل {len(key)}")
    if not ciphertext:
        raise ValueError("ciphertext لا يمكن أن تكون فارغة")

    ad_ptr = associated_data or None
    ad_len = len(associated_data) if associated_data else 0

    out = _ByteBuffer()
    _check(lib.sibna_decrypt(key, ciphertext, len(ciphertext), ad_ptr, ad_len, ctypes.byref(out)))
    try:
        return out.to_bytes()
    finally:
        out.free()


# ─── Context — إدارة الهوية والجلسات ─────────────────────────────────────────

class Context:
    """
    السياق الرئيسي للبروتوكول. يدير:
    - مفاتيح الهوية (Ed25519 + X25519)
    - جلسات Double Ratchet مع peers
    - Keystore مشفر بكلمة مرور اختيارية

    ملاحظة حول كلمة المرور:
        إذا استخدمت كلمة مرور، يجب أن تحتوي على:
        - حرف كبير واحد على الأقل
        - حرف صغير واحد على الأقل
        - رقم واحد على الأقل
        - طول 8 أحرف على الأقل
        (هذه قواعد المكتبة الداخلية وليست اختياراتنا)
    """

    def __init__(self, password: Optional[bytes] = None):
        """
        Args:
            password: كلمة مرور لتشفير الـ keystore (اختياري).
                      إذا لم تُمرَّر، يُولَّد مفتاح عشوائي.

        Raises:
            SibnaError(10): إذا كانت كلمة المرور ضعيفة جداً.
            LibraryNotFoundError: إذا لم تُحمَّل المكتبة.
        """
        lib = _require_lib()
        handle = ctypes.c_void_p()
        pwd_ptr = password or None
        pwd_len = len(password) if password else 0
        _check(lib.sibna_context_create(pwd_ptr, pwd_len, ctypes.byref(handle)))
        self._handle = handle
        self._lib = lib

    def __del__(self):
        if hasattr(self, "_handle") and self._handle and hasattr(self, "_lib"):
            self._lib.sibna_context_destroy(self._handle)
            self._handle = None

    def generate_identity(self) -> Tuple[bytes, bytes]:
        """
        يولّد زوج مفاتيح هوية جديد ويحفظه في الـ keystore.

        Returns:
            Tuple[bytes, bytes]: (ed25519_public_key, x25519_public_key)
            كلاهما 32 بايت.
            - ed25519_public_key: للتوقيع والتحقق من الهوية
            - x25519_public_key:  للـ X3DH key agreement

        Raises:
            SibnaError: إذا فشل التوليد.
        """
        ed_pub = ctypes.create_string_buffer(32)
        x_pub  = ctypes.create_string_buffer(32)
        _check(self._lib.sibna_generate_identity(self._handle, ed_pub, x_pub))
        return ed_pub.raw, x_pub.raw

    def generate_prekey_bundle(self) -> bytes:
        """
        يولّد PreKey Bundle لرفعه إلى سيرفر المفاتيح (Prekey Server).

        يجب استدعاء generate_identity() أولاً.

        PreKey Bundle يحتوي على:
        - مفتاح الهوية (identity key)
        - Signed PreKey مع توقيعه
        - OneTime PreKey اختياري

        Returns:
            bytes: البيانات المسلسلة للـ PreKey Bundle.
                   يمكن رفعها مباشرة عبر SibnaClient.upload_prekey()

        Raises:
            SibnaError(8): إذا لم تُولَّد الهوية بعد (Key not found).
            SibnaError: لأسباب أخرى.
        """
        out = _ByteBuffer()
        _check(self._lib.sibna_generate_prekey_bundle(self._handle, ctypes.byref(out)))
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
        ينفّذ X3DH Handshake مع peer ويُنشئ جلسة Double Ratchet.

        بعد نجاح هذه الدالة يمكن استخدام session_encrypt() / session_decrypt()
        مع نفس peer_id.

        Args:
            peer_id:     معرّف الـ peer (بايتات). يُستخدم كـ session ID لاحقاً.
            peer_bundle: PreKey Bundle الخاص بالـ peer (من سيرفر المفاتيح).
            initiator:   True إذا كنت أنت من يبدأ الاتصال، False إذا كنت المستقبِل.

        Raises:
            SibnaError(2): إذا كان bundle غير صالح أو التوقيع خاطئ.
            SibnaError(6): إذا كانت الحالة غير صالحة.
            SibnaError: لأسباب أخرى.
        """
        _check(self._lib.sibna_perform_handshake(
            self._handle,
            peer_bundle, len(peer_bundle),
            peer_id,     len(peer_id),
            ctypes.c_uint8(1 if initiator else 0),
        ))

    def session_encrypt(
        self,
        peer_id: bytes,
        plaintext: bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """
        يشفّر رسالة عبر جلسة Double Ratchet موجودة.

        يجب استدعاء perform_handshake() مع نفس peer_id أولاً.

        المفتاح يتغير تلقائياً مع كل رسالة (Double Ratchet).

        Args:
            peer_id:         معرّف الـ peer (نفسه المستخدم في perform_handshake).
            plaintext:       الرسالة المراد تشفيرها.
            associated_data: بيانات إضافية مُصادَق عليها (اختياري).

        Returns:
            bytes: الرسالة المشفرة.

        Raises:
            SibnaError(7): إذا لم تُنشأ جلسة مع هذا الـ peer.
            SibnaError(9): إذا تجاوزت حد الرسائل (Rate limit).
            LibraryNotFoundError: إذا لم تُحمَّل المكتبة.
        """
        ad_ptr = associated_data or None
        ad_len = len(associated_data) if associated_data else 0

        out = _ByteBuffer()
        _check(self._lib.sibna_session_encrypt(
            self._handle,
            peer_id,   len(peer_id),
            plaintext, len(plaintext),
            ad_ptr,    ad_len,
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
        يفك تشفير رسالة عبر جلسة Double Ratchet موجودة.

        Args:
            peer_id:         معرّف الـ peer.
            ciphertext:      الرسالة المشفرة (من session_encrypt() على الطرف الآخر).
            associated_data: نفس associated_data المستخدمة عند التشفير.

        Returns:
            bytes: الرسالة الأصلية.

        Raises:
            SibnaError(13): إذا كانت الرسالة منقحة (Authentication failed).
            SibnaError(7):  إذا لم تُنشأ جلسة مع هذا الـ peer.
            SibnaError(12): إذا كان ciphertext تالفاً.
        """
        ad_ptr = associated_data or None
        ad_len = len(associated_data) if associated_data else 0

        out = _ByteBuffer()
        _check(self._lib.sibna_session_decrypt(
            self._handle,
            peer_id,    len(peer_id),
            ciphertext, len(ciphertext),
            ad_ptr,     ad_len,
            ctypes.byref(out),
        ))
        try:
            return out.to_bytes()
        finally:
            out.free()


# ─── Exports ───────────────────────────────────────────────────────────────────

__all__ = [
    # الحالة
    "is_available",
    "library_path",
    "version",
    # الأخطاء
    "SibnaError",
    "LibraryNotFoundError",
    # دوال التشفير
    "generate_key",
    "random_bytes",
    "encrypt",
    "decrypt",
    # الـ Context (هوية + جلسات)
    "Context",
    # الإصدار
    "__version__",
]
