# Sibna Protocol — Python SDK

Python SDK للتعامل مع بروتوكول Sibna المشفر.

---

## قبل كل شيء — ماذا تحتاج؟

هذا الـ SDK **لا يعمل وحده**. يحتاج إلى ملف مكتبة مُجمَّعة من مشروع `sibna-protc`:

| النظام  | الملف المطلوب        |
|---------|----------------------|
| Windows | `sibna_core.dll`     |
| Linux   | `libsibna_core.so`   |
| macOS   | `libsibna_core.dylib`|

**لبناء المكتبة:**
```bash
cd sibna-protc/core
cargo build --release --features ffi
# الملف الناتج في: target/release/
```
ثم انسخ الملف الناتج إلى نفس مجلد `sibna/` في هذا الـ SDK.

---

## التثبيت

```bash
# المكتبات الخارجية المطلوبة (ليست zero-dependencies)
pip install cryptography          # للـ Identity + التحقق من التوقيعات
pip install requests              # للـ HTTP sync client
pip install aiohttp               # للـ async + WebSocket
```

---

## ما الذي يفعله هذا الـ SDK؟

### `sibna` (الـ core — يحتاج المكتبة المُجمَّعة)

| الدالة / الكلاس | ما يفعله |
|-----------------|----------|
| `is_available()` | يتحقق إن كانت المكتبة محملة |
| `generate_key()` | يولّد مفتاح 32 بايت عشوائي |
| `encrypt(key, data)` | يشفّر البيانات (ChaCha20-Poly1305) |
| `decrypt(key, data)` | يفك التشفير |
| `random_bytes(n)` | يولّد بايتات عشوائية |
| `Context()` | يدير الهوية والجلسات المشفرة |
| `Context.generate_identity()` | يولّد مفتاحي هوية (Ed25519 + X25519) |
| `Context.generate_prekey_bundle()` | يولّد bundle للرفع على السيرفر |
| `Context.perform_handshake(...)` | ينفّذ X3DH ويُنشئ جلسة Double Ratchet |
| `Context.session_encrypt(...)` | يشفّر رسالة عبر جلسة موجودة |
| `Context.session_decrypt(...)` | يفك تشفير رسالة |

### `sibna.client` (الشبكة — يحتاج `requests` / `aiohttp`)

| الكلاس | ما يفعله |
|--------|----------|
| `Identity` | مفتاح Ed25519 للمصادقة مع السيرفر |
| `SibnaClient` | HTTP sync client |
| `AsyncSibnaClient` | Async + WebSocket client |

---

## مثال أساسي — تشفير بسيط

```python
import sibna

# تحقق أن المكتبة موجودة
if not sibna.is_available():
    raise RuntimeError(f"المكتبة غير موجودة في: {sibna.library_path()}")

# تشفير وفك تشفير
key = sibna.generate_key()          # 32 بايت عشوائي
ct  = sibna.encrypt(key, b"مرحبا")
pt  = sibna.decrypt(key, ct)
assert pt == "مرحبا".encode()

# مع associated_data (بيانات إضافية مُصادَق عليها)
ct  = sibna.encrypt(key, b"سري", associated_data=b"context-header")
pt  = sibna.decrypt(key, ct, associated_data=b"context-header")
```

---

## مثال متقدم — جلسة Double Ratchet

```python
import sibna

# على جهاز Alice
alice_ctx = sibna.Context(password=b"AlicePass1!")
alice_ed, alice_x = alice_ctx.generate_identity()
alice_bundle = alice_ctx.generate_prekey_bundle()

# على جهاز Bob
bob_ctx = sibna.Context(password=b"BobPass1!")
bob_ed, bob_x = bob_ctx.generate_identity()
bob_bundle = bob_ctx.generate_prekey_bundle()

# Alice تبدأ الاتصال مع Bob
alice_ctx.perform_handshake(
    peer_id=bob_ed,          # معرّف Bob
    peer_bundle=bob_bundle,  # bundle Bob (من السيرفر)
    initiator=True,
)

# Bob يستقبل الاتصال من Alice
bob_ctx.perform_handshake(
    peer_id=alice_ed,
    peer_bundle=alice_bundle,
    initiator=False,
)

# Alice تشفّر
ciphertext = alice_ctx.session_encrypt(bob_ed, b"مرحبا يا Bob!")

# Bob يفك التشفير
plaintext = bob_ctx.session_decrypt(alice_ed, ciphertext)
```

---

## مثال — HTTP Client

```python
from sibna.client import SibnaClient
import sibna

# إعداد الـ context والهوية
ctx = sibna.Context()
ctx.generate_identity()
bundle = ctx.generate_prekey_bundle()

# الاتصال بالسيرفر
client = SibnaClient(server="http://localhost:8080")
client.generate_identity()   # هوية منفصلة للمصادقة
client.authenticate()         # JWT challenge-response
client.upload_prekey(bundle.hex())

# إرسال رسالة (payload مشفر مسبقاً)
ciphertext = ctx.session_encrypt(b"peer_id_here", b"Hello!")
client.send_message(
    recipient_id="peer_identity_hex",
    payload_hex=ciphertext.hex(),
)

# استقبال رسائل
messages = client.fetch_inbox()
for msg in messages:
    pt = ctx.session_decrypt(
        bytes.fromhex(msg["sender_id"]),
        bytes.fromhex(msg["payload_hex"]),
    )
    print(pt.decode())
```

---

## الأخطاء الشائعة

| الخطأ | السبب | الحل |
|-------|-------|------|
| `LibraryNotFoundError` | المكتبة غير موجودة | ابنِ `sibna-protc` بـ Rust |
| `SibnaError(13)` | بيانات منقحة أو مفتاح خاطئ | تحقق من المفتاح و associated_data |
| `SibnaError(7)` | جلسة غير موجودة | استدعِ `perform_handshake()` أولاً |
| `SibnaError(10)` | كلمة مرور ضعيفة | استخدم كلمة مرور بحروف كبيرة وصغيرة وأرقام |
| `MissingDependencyError` | مكتبة Python غير مثبتة | `pip install cryptography requests aiohttp` |

---

## ملاحظة حول "Zero Dependencies"

هذا الـ SDK **ليس** zero-dependencies:
- `__init__.py` يحتاج المكتبة المُجمَّعة (Rust)
- `client.py` يحتاج `cryptography`, `requests`, `aiohttp`

الـ Rust Core نفسه لا يحتاج أي شيء إضافي بعد البناء.

---

## الترخيص

Apache-2.0
