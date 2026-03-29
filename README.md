# 🛡️ Sibna Protocol - Python SDK

[![PyPI Version](https://img.shields.io/pypi/v/sibna.svg)](https://pypi.org/project/sibna/)
[![License](https://img.shields.io/badge/license-Apache%202.0%2FMIT-blue.svg)](https://github.com/SibnaOfficial/libs/blob/main/LICENSE)
[![Python Versions](https://img.shields.io/pypi/pyversions/sibna.svg)](https://pypi.org/project/sibna/)

**Sibna Protocol** is a standalone, ultra-secure communication framework designed for high-performance end-to-end encrypted applications. This SDK provides a seamless Python interface to the hardened **Sibna Rust Core**.

---

## ✨ Key Features

- 🔒 **Military-Grade Security**: Built-in support for **X3DH** (Extended Triple Diffie-Hellman) and the **Double Ratchet** protocol.
- 🚀 **Native Performance**: Powered by a pre-compiled Rust core for blazing-fast cryptographic operations.
- 📦 **Zero Dependencies**: Completely standalone – no need to install Rust or complex system libraries.
- 🛡️ **Perfect Forward Secrecy**: Automatic key rotation for every message sent.
- 💻 **Cross-Platform**: Full support for Windows, Linux, and macOS.

---

## 🚀 Quick Start

### Installation

```bash
pip install sibna
```

### Basic Encryption

```python
import sibna

# 1. Generate a secure 32-byte key
key = sibna.generate_key()

# 2. Encrypt your message
plaintext = b"Top secret data from the deep sea"
ciphertext = sibna.encrypt(key, plaintext)

# 3. Decrypt and recover
decrypted = sibna.decrypt(key, ciphertext)
print(decrypted.decode()) # "Top secret data from the deep sea"
```

### Advanced Session Management

```python
import sibna

# Create a secure context with master password protection
ctx = sibna.Context(password=b"your-secret-password")

# Initialize a secure session with a peer's identity
session = ctx.create_session(b"peer_public_identity_key")

# Encrypt data within the session (includes automatic ratcheting)
encrypted_payload = session.encrypt(b"Hello, Secure World!")
```

---

## 🏗️ Architecture

Sibna Protocol uses a layered approach to security:
1.  **Transport Layer**: Agnostic (works over WebSocket, HTTP, or MQTT).
2.  **Messaging Layer**: Sealed envelopes with metadata resistance.
3.  **Cryptographic Core**: Hardened Rust implementation of ChaCha20-Poly1305 and Ed25519.

---

## 📜 License

This project is dual-licensed under the **Apache License 2.0** and the **MIT License**.

---

## 🤝 Contributing

Contributions are welcome! Please check our [GitHub Repository](https://github.com/SibnaOfficial/libs) for issues and pull request guidelines.

---
*Developed with ❤️ by the Sibna Security Team.*
