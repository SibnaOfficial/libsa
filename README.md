#  Sibna Protocol — Python SDK

<div align="center">

[![PyPI Version](https://img.shields.io/pypi/v/sibna.svg?color=blue&label=PyPI)](https://pypi.org/project/sibna/)
[![Python Versions](https://img.shields.io/pypi/pyversions/sibna.svg)](https://pypi.org/project/sibna/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](https://github.com/SibnaOfficial/libsa/blob/main/LICENSE)
[![Downloads](https://img.shields.io/pypi/dm/sibna.svg)](https://pypi.org/project/sibna/)

**Sibna Protocol** is a standalone, ultra-secure communication framework with **zero external dependencies**. This SDK provides a seamless Python interface to the hardened **Sibna Rust Core** — delivering military-grade cryptography at native speed.

</div>

---

##  Key Features

| Feature | Details |
|---|---|
|  **Military-Grade Security** | X3DH + Double Ratchet protocol (Signal-compatible) |
|  **Native Performance** | Pre-compiled Rust core — no build step required |
|  **Zero Dependencies** | Completely standalone, no Rust toolchain needed |
|  **Perfect Forward Secrecy** | Automatic key rotation per message |
|  **Cross-Platform** | Windows, Linux, macOS — all supported |
|  **ChaCha20-Poly1305** | AEAD encryption with authenticated data support |

---

##  Installation

```bash
pip install sibna
```

Requires **Python 3.8+**. No other system dependencies needed.

---

##  Quick Start

### Symmetric Encryption

```python
import sibna

# 1. Generate a secure 32-byte key
key = sibna.generate_key()

# 2. Encrypt your message
plaintext = b"Top secret data"
ciphertext = sibna.encrypt(key, plaintext)

# 3. Decrypt and recover
decrypted = sibna.decrypt(key, ciphertext)
print(decrypted.decode())  # "Top secret data"
```

### Authenticated Encryption (with AAD)

```python
import sibna

key = sibna.generate_key()
plaintext = b"Sensitive payload"
aad = b"context-header"  # Additional Authenticated Data

ciphertext = sibna.encrypt(key, plaintext, associated_data=aad)
decrypted = sibna.decrypt(key, ciphertext, associated_data=aad)
```

### Secure Session (X3DH + Double Ratchet)

```python
import sibna

# Create a secure context with master password protection
ctx = sibna.Context(password=b"your-master-password")

# Initialize a secure session with a peer
session = ctx.create_session(b"peer_public_identity_key")

# Encrypt — automatic ratcheting every message
encrypted = session.encrypt(b"Hello, Secure World!")
```

---

##  Architecture

Sibna uses a layered security approach:

```
┌─────────────────────────────────┐
│        Your Application         │
├─────────────────────────────────┤
│      Sibna Python SDK (this)    │  ← pip install sibna
├─────────────────────────────────┤
│   Sibna Rust Core (pre-built)   │  ← bundled .dll / .so / .dylib
├─────────────────────────────────┤
│  ChaCha20-Poly1305 · Ed25519    │
│  X3DH · Double Ratchet          │
└─────────────────────────────────┘
```

1. **Transport Layer**: Agnostic — works over WebSocket, HTTP, MQTT, or raw TCP.
2. **Messaging Layer**: Sealed envelopes with metadata resistance.
3. **Cryptographic Core**: Hardened Rust implementation — constant-time, memory-safe.

---

##  Security

- All cryptographic operations are performed in the native Rust core
- Memory is zeroed after use (no key material left in heap)
- Side-channel resistant implementations
- Security issues: please email **security@sibna.dev**

---

##  License

Licensed under the **Apache License 2.0**.  
See [LICENSE](https://github.com/SibnaOfficial/libsa/blob/main/LICENSE) for full details.

---

##  Contributing

Issues and pull requests are welcome at [github.com/SibnaOfficial/libsa](https://github.com/SibnaOfficial/libsa).

---

*Developed with ❤️ by the **Sibna Security Team**.*
