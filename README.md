# Sibna Protocol — Python SDK

Python SDK for the Sibna encrypted communication protocol.

---

## Before You Start — What You Need

This SDK **does not work standalone**. It requires a compiled native library built from the `sibna-protc` Rust project:

| OS      | Required File          |
|---------|------------------------|
| Windows | `sibna_core.dll`       |
| Linux   | `libsibna_core.so`     |
| macOS   | `libsibna_core.dylib`  |

**To build the library:**
```bash
cd sibna-protc/core
cargo build --release --features ffi
# Output is in: target/release/
```
Then copy the resulting file into the same `sibna/` folder as this SDK.

---

## Installation

```bash
# External dependencies (this SDK is NOT zero-dependencies)
pip install cryptography          # For Identity + signature verification
pip install requests              # For the sync HTTP client
pip install aiohttp               # For async + WebSocket
```

---

## What This SDK Does

### `sibna` (core — requires the compiled native library)

| Function / Class | What it does |
|------------------|--------------|
| `is_available()` | Checks if the native library is loaded |
| `generate_key()` | Generates a random 32-byte key |
| `encrypt(key, data)` | Encrypts data (ChaCha20-Poly1305) |
| `decrypt(key, data)` | Decrypts data |
| `random_bytes(n)` | Generates cryptographically secure random bytes |
| `Context()` | Manages identity and encrypted sessions |
| `Context.generate_identity()` | Generates an identity keypair (Ed25519 + X25519) |
| `Context.generate_prekey_bundle()` | Generates a bundle to upload to the prekey server |
| `Context.perform_handshake(...)` | Runs X3DH and creates a Double Ratchet session |
| `Context.session_encrypt(...)` | Encrypts a message over an existing session |
| `Context.session_decrypt(...)` | Decrypts a message |

### `sibna.client` (networking — requires `requests` / `aiohttp`)

| Class | What it does |
|-------|--------------|
| `Identity` | Ed25519 keypair for server authentication |
| `SibnaClient` | Synchronous HTTP client |
| `AsyncSibnaClient` | Async + WebSocket client |

---

## Basic Example — Simple Encryption

```python
import sibna

# Check the library is available
if not sibna.is_available():
    raise RuntimeError("Native library not found. Build it from sibna-protc first.")

# Encrypt and decrypt
key = sibna.generate_key()          # Random 32-byte key
ct  = sibna.encrypt(key, b"Hello")
pt  = sibna.decrypt(key, ct)
assert pt == b"Hello"

# With associated data (authenticated but not encrypted)
ct  = sibna.encrypt(key, b"Secret", associated_data=b"context-header")
pt  = sibna.decrypt(key, ct, associated_data=b"context-header")
```

---

## Advanced Example — Double Ratchet Session

```python
import sibna

# On Alice's device
alice_ctx = sibna.Context(password=b"AlicePass1!")
alice_ed, alice_x = alice_ctx.generate_identity()
alice_bundle = alice_ctx.generate_prekey_bundle()

# On Bob's device
bob_ctx = sibna.Context(password=b"BobPass1!")
bob_ed, bob_x = bob_ctx.generate_identity()
bob_bundle = bob_ctx.generate_prekey_bundle()

# Alice initiates the handshake with Bob
alice_ctx.perform_handshake(
    peer_id=bob_ed,          # Bob's identity key (used as session ID)
    peer_bundle=bob_bundle,  # Bob's bundle (fetched from prekey server)
    initiator=True,
)

# Bob accepts the handshake from Alice
bob_ctx.perform_handshake(
    peer_id=alice_ed,
    peer_bundle=alice_bundle,
    initiator=False,
)

# Alice encrypts
ciphertext = alice_ctx.session_encrypt(bob_ed, b"Hello Bob!")

# Bob decrypts
plaintext = bob_ctx.session_decrypt(alice_ed, ciphertext)
assert plaintext == b"Hello Bob!"
```

---

## Example — HTTP Client

```python
from sibna.client import SibnaClient
import sibna

# Set up encryption context
ctx = sibna.Context()
ctx.generate_identity()
bundle = ctx.generate_prekey_bundle()

# Connect to server
client = SibnaClient(server="http://localhost:8080")
client.generate_identity()   # Separate identity for server auth
client.authenticate()         # JWT challenge-response flow
client.upload_prekey(bundle.hex())

# Send an encrypted message (payload is pre-encrypted by Context)
ciphertext = ctx.session_encrypt(b"peer_id_here", b"Hello!")
client.send_message(
    recipient_id="peer_identity_hex",
    payload_hex=ciphertext.hex(),
)

# Receive messages
messages = client.fetch_inbox()
for msg in messages:
    plaintext = ctx.session_decrypt(
        bytes.fromhex(msg["sender_id"]),
        bytes.fromhex(msg["payload_hex"]),
    )
    print(plaintext.decode())
```

---

## Common Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `LibraryNotFoundError` | Native library not found | Build `sibna-protc` with Rust |
| `SibnaError(13)` | Tampered data or wrong key | Check key and `associated_data` |
| `SibnaError(7)` | Session does not exist | Call `perform_handshake()` first |
| `SibnaError(10)` | Weak password | Use a password with uppercase, lowercase, and digits |
| `MissingDependencyError` | Python package not installed | `pip install cryptography requests aiohttp` |

---

## A Note on Dependencies

This SDK is **not** zero-dependencies:
- `__init__.py` requires the compiled Rust native library
- `client.py` requires `cryptography`, `requests`, and `aiohttp`

The Rust core itself has no runtime dependencies once compiled.

---

## License

Apache-2.0
