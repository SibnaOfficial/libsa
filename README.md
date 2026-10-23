# Sibna Protocol — Python SDK

Pure-Python implementation of the Sibna Protocol (X3DH handshake, Double
Ratchet session encryption, sender-key group messaging, safety numbers,
envelope signing, encrypted storage, and the relay HTTP/WebSocket client).

No Rust core, FFI, or native library is required. All cryptography is provided
by maintained libraries (`cryptography`, `blake3`, `pqcrypto`).

Wire formats, domain-separation strings, KDF constructions, and limits match
the retained Rust core (`sibna-protc/core/`) and
`PROTOCOL_SPECIFICATION.md`.

Install:

    pip install sibna

## Capabilities

| Capability | Modules |
|---|---|
| Cryptographic primitives | `sibna.crypto` |
| X25519 / Ed25519 keys | `sibna.crypto.X25519KeyPair`, `Ed25519KeyPair` |
| ML-KEM-768 hybrid KEM | `sibna.crypto.ml_kem_768_*` |
| X3DH handshake | `sibna.x3dh` |
| Double Ratchet sessions | `sibna.ratchet`, `sibna.session` |
| Sender-key group messaging | `sibna.group` |
| Safety numbers | `sibna.safety_number` |
| Signed envelopes | `sibna.envelope` |
| Protocol padding | `sibna.padding` |
| Encrypted storage | `sibna.storage` |
| Synchronous HTTP relay client | `sibna.client.SibnaClient` |
| Asynchronous WebSocket relay client | `sibna.client.AsyncSibnaClient` |

## Quick start

```python
from sibna import (
    X25519KeyPair, Ed25519KeyPair, Session,
    generate_peer_bundle, make_signed_envelope,
    verify_signed_envelope,
)
from sibna.crypto import ml_kem_768_keypair, derive_identity_keys
from sibna.client import SibnaClient

# Create an identity
ed, x = Ed25519KeyPair(), X25519KeyPair()

# Perform X3DH with a peer bundle
alice_session = Session()
ephemeral_pub = alice_session.initiate_as_initiator(
    identity=x,
    ephemeral=X25519KeyPair(),
    peer_bundle=peer_bundle,
)

# Encrypt and send
ciphertext = alice_session.encrypt(b"Hello", associated_data=b"v3.0.2")

# Verify a signed envelope
envelope = make_signed_envelope(ed, recipient_id="abc...", payload_hex=ciphertext.hex())
assert verify_signed_envelope(envelope)
```

The package works offline for all cryptographic operations. The relay client
(`SibnaClient`, `AsyncSibnaClient`) requires a running Sibna relay server
(see `sibna-protc/server/`) and a valid JWT obtained through the Ed25519
challenge-response flow.

## Installation

```bash
pip install sibna
```

Supported: Python 3.9+ on Linux, macOS, and Windows.

Runtime dependencies: `cryptography`, `blake3`, `pqcrypto`, `requests`,
`aiohttp`.

## Development

```bash
pip install -e ".[dev]"
pytest tests/
black --check sibna tests
mypy sibna
```

## Security

This SDK implements the Sibna Protocol v3.0.2. It has not received an
independent cryptographic audit. Do not describe it as formally verified or
production-ready without supporting evidence. See `SECURITY.md` and
`THREAT_MODEL.md` in `sibna-protc`.

License: Apache-2.0 OR MIT.
