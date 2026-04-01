# Sibna Protocol — Python SDK (Standalone)

Python SDK for the Sibna Protocol. **Zero external dependencies.**

---

## What "standalone" means

| Component | Implementation | External package? |
|-----------|---------------|-------------------|
| ChaCha20-Poly1305 encryption | Rust core (FFI) | ❌ none |
| X3DH + Double Ratchet sessions | Rust core (FFI) | ❌ none |
| Ed25519 signing (server auth) | `_ed25519.py` — pure Python RFC 8032 | ❌ none |
| HTTP client | Python stdlib `urllib` | ❌ none |
| WebSocket client | `_websocket.py` — pure Python RFC 6455 | ❌ none |

The **only** thing you need that isn't pure Python is the compiled Rust library
(`sibna_core.dll` / `libsibna_core.so` / `.dylib`) — because Python has no
native ChaCha20 or Double Ratchet in stdlib.

---

## Requirements

- Python 3.8+
- The compiled Rust library from `sibna-protc/core`

**Nothing else. No `pip install`.**

---

## Build the native library

```bash
cd sibna-protc/core
cargo build --release --features ffi
```

Then place the output file next to the `sibna/` folder:

| OS      | File                   | Location      |
|---------|------------------------|---------------|
| Windows | `sibna_core.dll`       | next to `sibna/` |
| Linux   | `libsibna_core.so`     | next to `sibna/` |
| macOS   | `libsibna_core.dylib`  | next to `sibna/` |

---

## Package structure

```
sibna/
  __init__.py    — FFI wrapper (encrypt, decrypt, Context)
  client.py      — HTTP + WebSocket client (SibnaClient, AsyncSibnaClient)
  _ed25519.py    — Pure Python Ed25519 (RFC 8032) — server auth signing
  _websocket.py  — Pure Python WebSocket (RFC 6455) — real-time transport
```

`_ed25519.py` and `_websocket.py` are internal modules (prefixed with `_`).
They are bundled inside the SDK — not installed via pip.

---

## Quick start

```python
import sibna

if not sibna.is_available():
    raise RuntimeError("Build the Rust library first — see README")

# Encrypt / decrypt
key = sibna.generate_key()
ct  = sibna.encrypt(key, b"Hello!")
pt  = sibna.decrypt(key, ct)
assert pt == b"Hello!"
```

---

## E2EE session (X3DH + Double Ratchet)

```python
import sibna

# Alice
alice = sibna.Context(password=b"AlicePass1!")
alice_ed, alice_x = alice.generate_identity()
alice_bundle = alice.generate_prekey_bundle()

# Bob
bob = sibna.Context(password=b"BobPass1!")
bob_ed, bob_x = bob.generate_identity()
bob_bundle = bob.generate_prekey_bundle()

# Handshake (bundles are normally exchanged via prekey server)
alice.perform_handshake(peer_id=bob_ed, peer_bundle=bob_bundle, initiator=True)
bob.perform_handshake(peer_id=alice_ed, peer_bundle=alice_bundle, initiator=False)

# Alice sends
ct = alice.session_encrypt(bob_ed, b"Hello Bob!")

# Bob receives
pt = bob.session_decrypt(alice_ed, ct)
assert pt == b"Hello Bob!"

alice.close()
bob.close()
```

---

## HTTP client (no pip install)

```python
from sibna.client import SibnaClient
import sibna

# Set up encryption
ctx = sibna.Context()
ctx.generate_identity()
bundle = ctx.generate_prekey_bundle()

# Connect to server
client = SibnaClient(server="http://localhost:8080")
client.generate_identity()   # Ed25519 identity for server auth
client.authenticate()         # challenge-response → JWT (uses urllib, no requests)
client.upload_prekey(bundle.hex())

# Send
ct = ctx.session_encrypt(b"peer_id", b"Hello!")
client.send_message(recipient_id="peer_hex", payload_hex=ct.hex())

# Receive
for msg in client.fetch_inbox():
    pt = ctx.session_decrypt(
        bytes.fromhex(msg["sender_id"]),
        bytes.fromhex(msg["payload_hex"]),
    )
    print(pt.decode())
```

---

## Async + WebSocket (no pip install)

```python
import asyncio
from sibna.client import AsyncSibnaClient

async def on_message(envelope):
    print("Received:", envelope["payload_hex"])

async def main():
    client = AsyncSibnaClient(server="http://localhost:8080")
    client.generate_identity()
    await client.authenticate()   # uses asyncio + urllib, no aiohttp
    await client.connect(on_message=on_message)   # pure Python WebSocket

asyncio.run(main())
```

---

## Error reference

| Error | Code | Meaning |
|-------|------|---------|
| `SibnaError(13)` | 13 | Tampered data or wrong key |
| `SibnaError(7)`  |  7 | No session — call `perform_handshake()` first |
| `SibnaError(8)`  |  8 | No identity — call `generate_identity()` first |
| `SibnaError(10)` | 10 | Weak password |
| `SibnaError(6)`  |  6 | Context already closed |
| `LibraryNotFoundError` | — | Rust library not found |
| `AuthError` | — | Server auth failed |
| `NetworkError` | — | HTTP / WebSocket failure |

---

## License

Apache-2.0
