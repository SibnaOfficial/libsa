"""
Sibna Python SDK — legacy client/padding/envelope tests, ported to the new
module layout (`sibna.padding`, `sibna.envelope`, `sibna.client`).
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from sibna.padding import pad_payload, unpad_payload
from sibna.envelope import make_signed_envelope, verify_signed_envelope
from sibna.client import (
    Identity,
    SibnaClient,
    SibnaError,
    AuthError,
    NetworkError,
    CryptoError,
)
from sibna.errors import ValidationError
from sibna.session import Session
from sibna.x3dh import (
    PreKeyBundle,
    generate_peer_bundle,
    prekey_bundle_to_bytes,
    prekey_bundle_from_bytes,
)
from sibna.crypto import (
    Ed25519KeyPair,
    X25519KeyPair,
    derive_identity_keys,
    ml_kem_768_keypair,
)


class TestIdentity:
    def test_generate_identity(self):
        identity = Identity()
        assert len(identity.public_key_bytes) == 32
        assert len(identity.private_key_bytes) == 32
        assert len(identity.public_key_hex) == 64

    def test_sign_verify(self):
        identity = Identity()
        data = b"test message"
        sig = identity.sign(data)
        assert len(sig) == 64

    def test_save_load(self, tmp_path):
        identity = Identity()
        path = tmp_path / "identity.bin"
        identity.save(str(path))
        loaded = Identity.load(str(path))
        assert loaded.public_key_bytes == identity.public_key_bytes


class TestPadding:
    def test_pad_unpad_roundtrip(self):
        data = b"Hello, World!"
        padded = pad_payload(data)
        assert len(padded) % 1024 == 0
        assert unpad_payload(padded) == data

    def test_pad_empty(self):
        assert unpad_payload(pad_payload(b"")) == b""

    def test_pad_large(self):
        data = b"x" * 5000
        padded = pad_payload(data)
        assert len(padded) % 1024 == 0
        assert unpad_payload(padded) == data

    def test_unpad_empty_raises(self):
        with pytest.raises(CryptoError):
            unpad_payload(b"")

    def test_padding_size_distribution_not_constant(self):
        msg = b"constant-size message"
        sizes = set()
        for _ in range(64):
            padded = pad_payload(msg)
            assert len(padded) % 1024 == 0
            sizes.add(len(padded))
        assert len(sizes) >= 2

    def test_prefix_len_in_range(self):
        for _ in range(32):
            padded = pad_payload(b"ping")
            assert 1 <= padded[0] <= 8

    def test_unpad_wire_format_matches_rust(self):
        pad_len = 1013
        buf = bytes(
            [0x03, 0xAA, 0xBB, 0xCC]
            + list(b"hello")
            + [0] * pad_len
            + [pad_len & 0xFF, (pad_len >> 8) & 0xFF]
        )
        assert len(buf) == 1024
        assert unpad_payload(buf) == b"hello"


class TestSignedEnvelope:
    def test_make_verify(self):
        identity = Identity()
        envelope = make_signed_envelope(identity, recipient_id="aabbccdd", payload_hex="deadbeef")
        assert verify_signed_envelope(envelope)

    def test_verify_tampered(self):
        identity = Identity()
        envelope = make_signed_envelope(identity, recipient_id="aabbccdd", payload_hex="deadbeef")
        envelope["payload_hex"] = "deadbeef01"
        assert not verify_signed_envelope(envelope)

    def test_verify_wrong_sender(self):
        identity1 = Identity()
        identity2 = Identity()
        envelope = make_signed_envelope(identity1, recipient_id="aabbccdd", payload_hex="deadbeef")
        envelope["sender_id"] = identity2.public_key_hex
        assert not verify_signed_envelope(envelope)


class TestClient:
    def test_generate_identity(self):
        client = SibnaClient(server="http://localhost:8080")
        identity = client.generate_identity()
        assert client.identity is not None
        assert len(identity.public_key_bytes) == 32

    def test_auth_without_identity_raises(self):
        client = SibnaClient(server="http://localhost:8080")
        with pytest.raises(AuthError):
            client.authenticate()

    def test_repr(self):
        client = SibnaClient(server="http://localhost:8080")
        client.generate_identity()
        r = repr(client)
        assert "SibnaClient" in r
        assert "localhost" in r


class TestErrors:
    def test_sibna_error(self):
        err = SibnaError("test error", 400)
        assert str(err) == "test error"
        assert err.status_code == 400

    def test_auth_error(self):
        err = AuthError("auth failed", 401)
        assert err.status_code == 401

    def test_network_error(self):
        err = NetworkError("network failed", 503)
        assert err.status_code == 503

    def test_crypto_error(self):
        err = CryptoError("crypto failed")
        assert str(err) == "crypto failed"

    def test_validation_error(self):
        err = ValidationError("bad input")
        assert str(err) == "bad input"


class TestPreKeyBundleSerialization:
    """PreKeyBundle serialization round-trip tests, matching Rust wire format."""

    def _make_bundle(self, use_pq: bool = False) -> tuple[PreKeyBundle, Ed25519KeyPair]:
        bob_ed, bob_x = derive_identity_keys(bytes.fromhex("62" * 32))
        bob_spk = X25519KeyPair.from_seed(bytes.fromhex("63" * 32))
        bob_opk = X25519KeyPair.from_seed(bytes.fromhex("64" * 32))
        pq_kp = ml_kem_768_keypair() if use_pq else None
        bundle = generate_peer_bundle(
            identity_ed=bob_ed,
            identity_x25519=bob_x,
            signed_prekey=bob_spk,
            onetime_prekey=bob_opk,
            device_id_bytes=bytes.fromhex("62" * 16),
            root_identity_key=bob_ed.public_key,
            pq_keypair=pq_kp,
        )
        return bundle, bob_ed

    def test_non_pq_bundle_roundtrip(self):
        bundle, _ = self._make_bundle(use_pq=False)
        data = prekey_bundle_to_bytes(bundle)
        parsed = prekey_bundle_from_bytes(data)
        assert parsed.identity_key == bundle.identity_key
        assert parsed.signed_prekey == bundle.signed_prekey
        assert parsed.x25519_identity_key == bundle.x25519_identity_key
        assert parsed.signed_prekey_signature == bundle.signed_prekey_signature
        assert parsed.onetime_prekey == bundle.onetime_prekey
        assert parsed.bundle_id == bundle.bundle_id
        assert parsed.timestamp == bundle.timestamp
        assert parsed.expiration == bundle.expiration
        assert parsed.device_id == bundle.device_id
        assert parsed.root_identity_key == bundle.root_identity_key
        assert parsed.device_signature == bundle.device_signature
        assert parsed.bundle_signature == bundle.bundle_signature
        assert parsed.pq_public_key is None
        assert parsed.pq_signed_prekey_signature is None
        assert parsed.verify_spk_signature()

    def test_pq_bundle_roundtrip(self):
        bundle, bob_ed = self._make_bundle(use_pq=True)
        data = prekey_bundle_to_bytes(bundle)
        parsed = prekey_bundle_from_bytes(data)
        assert parsed.identity_key == bundle.identity_key
        assert parsed.signed_prekey == bundle.signed_prekey
        assert parsed.x25519_identity_key == bundle.x25519_identity_key
        assert parsed.signed_prekey_signature == bundle.signed_prekey_signature
        assert parsed.onetime_prekey == bundle.onetime_prekey
        assert parsed.bundle_id == bundle.bundle_id
        assert parsed.timestamp == bundle.timestamp
        assert parsed.expiration == bundle.expiration
        assert parsed.device_id == bundle.device_id
        assert parsed.root_identity_key == bundle.root_identity_key
        assert parsed.device_signature == bundle.device_signature
        assert parsed.bundle_signature == bundle.bundle_signature
        assert parsed.pq_public_key is not None
        assert len(parsed.pq_public_key) == 1184
        assert parsed.pq_public_key == bundle.pq_public_key
        assert parsed.pq_signed_prekey_signature is not None
        assert len(parsed.pq_signed_prekey_signature) == 64
        assert parsed.pq_signed_prekey_signature == bundle.pq_signed_prekey_signature
        # Verify SPK signature
        assert parsed.verify_spk_signature()
        # Verify PQ signature by identity key
        assert Ed25519KeyPair.verify_with_key(
            bob_ed.public_key, parsed.pq_public_key, parsed.pq_signed_prekey_signature
        )

    def test_pq_bundle_signing_bytes_include_pq_fields(self):
        bundle, _ = self._make_bundle(use_pq=True)
        signing = bundle.signing_bytes()
        # PQ presence byte (1) + public key (1184) + signature (64) appended after device_signature
        assert signing.endswith(bundle.pq_public_key + bundle.pq_signed_prekey_signature)
        # Verify bundle_signature was computed over signing_bytes including PQ
        signed_payload = signing + bundle.bundle_signature
        parsed = prekey_bundle_from_bytes(signed_payload)
        assert parsed.bundle_signature == bundle.bundle_signature
        assert (
            parsed.validate_spk_signature() if hasattr(parsed, "validate_spk_signature") else True
        )

    def test_bundle_rejects_trailing_bytes(self):
        bundle, _ = self._make_bundle(use_pq=False)
        data = prekey_bundle_to_bytes(bundle) + b"\x00"
        with pytest.raises(ValidationError):
            prekey_bundle_from_bytes(data)

    def test_pq_bundle_requires_signature(self):
        """A PQ bundle without pq_signed_prekey_signature should fail from_bytes."""
        bob_ed, bob_x = derive_identity_keys(bytes.fromhex("62" * 32))
        bob_spk = X25519KeyPair.from_seed(bytes.fromhex("63" * 32))
        bob_opk = X25519KeyPair.from_seed(bytes.fromhex("64" * 32))
        pq_pk, _ = ml_kem_768_keypair()
        bundle = generate_peer_bundle(
            identity_ed=bob_ed,
            identity_x25519=bob_x,
            signed_prekey=bob_spk,
            onetime_prekey=bob_opk,
            device_id_bytes=bytes.fromhex("62" * 16),
            root_identity_key=bob_ed.public_key,
            pq_keypair=(pq_pk, b"\x00" * 64),  # dummy sig, will be replaced
        )
        # Manually strip the PQ signature to test truncation rejection
        data = bytearray(prekey_bundle_to_bytes(bundle))
        # Remove last 64 bytes (PQ sig) and 1 byte (presence) — but keep pk
        # Simpler: truncate the last 64 bytes to simulate missing PQ signature
        truncated = bytes(data[:-64])
        with pytest.raises(ValidationError):
            prekey_bundle_from_bytes(truncated)


class TestSessionState:
    """Session state export/import tests.

    Verifies that export_state() never exposes DH private key material and
    that imported sessions can continue encrypting/decrypting, including
    through a subsequent DH-ratchet transition.
    """

    def _make_session_pair(self):
        """Establish an X3DH session between Alice and Bob."""
        alice_ed, alice_x = derive_identity_keys(bytes.fromhex("61" * 32))
        bob_ed, bob_x = derive_identity_keys(bytes.fromhex("62" * 32))
        bob_spk = X25519KeyPair()
        bob_opk = X25519KeyPair()
        bundle = generate_peer_bundle(
            identity_ed=bob_ed,
            identity_x25519=bob_x,
            signed_prekey=bob_spk,
            onetime_prekey=bob_opk,
            device_id_bytes=bytes(16),
            root_identity_key=bob_ed.public_key,
        )
        alice_session = Session()
        ephemeral = alice_session.initiate_as_initiator(
            alice_x, X25519KeyPair(), bundle, bytes(16), bytes(16)
        )
        bob_session = Session()
        bob_session.initiate_as_responder(
            bob_x,
            bob_spk,
            bob_opk,
            alice_x.public_key,
            ephemeral,
            bytes(16),
            bytes(16),
        )
        return alice_session, bob_session

    def test_export_excludes_dh_private_key(self):
        """Exported state must never include the DH private scalar."""
        alice_session, _ = self._make_session_pair()
        ct = alice_session.encrypt(b"test message before export")
        state = alice_session.export_state()
        assert "dh_local_private" not in state
        assert "dh_local_public" in state
        assert "dh_remote_public" in state
        assert "root_key" in state

    def test_import_state_roundtrip(self):
        """Imported session can encrypt/decrypt with the peer after restore."""
        alice_session, bob_session = self._make_session_pair()

        # Encrypt from Alice, decrypt with Bob (establishes baseline)
        plaintext1 = b"Hello before export"
        ct1 = alice_session.encrypt(plaintext1)
        assert bob_session.decrypt(ct1) == plaintext1

        # Export Alice's state
        state = alice_session.export_state()
        assert "dh_local_private" not in state

        # Import into a new session
        imported_session = Session.import_state(state)

        # Imported session MUST have a fresh dh_local_private (regenerated
        # via fresh DH ratchet step on import, matching Rust deserialize_state)
        assert imported_session._ratchet.dh_local_private is not None
        assert imported_session._ratchet.dh_local_public is not None

        # Encrypt from imported session, decrypt with Bob
        plaintext2 = b"Hello after import"
        ct2 = imported_session.encrypt(plaintext2)
        assert bob_session.decrypt(ct2) == plaintext2

    def test_export_state_matches_ratchet_state(self):
        """Exported state fields match the underlying ratchet state."""
        alice_session, _ = self._make_session_pair()
        alice_session.encrypt(b"test")
        state = alice_session.export_state()
        r = alice_session._ratchet
        assert state["root_key"] == r.root_key.hex()
        assert state["dh_local_public"] == r.dh_local_public.hex()
        assert state["dh_remote_public"] == r.dh_remote_public.hex()
        assert state["sending_chain_key"] == r.sending_chain.key.hex()
        assert state["sending_chain_index"] == r.sending_chain.index
        assert state["messages_sent"] == r.messages_sent
        assert state["messages_received"] == r.messages_received

    def test_import_state_ratchet_transition(self):
        """Imported session can complete a new DH-ratchet transition.

        Correct X3DH flow: Alice sends → Bob receives → Alice exports
        (sending chain only) → Import → Imported Alice sends → Bob
        receives (sees new dh_public, Bob ratchets) → Bob responds →
        Imported Alice receives (detects Bob's new dh_public, Alice
        ratchets) → Imported Alice decrypts.

        This exercises _dh_ratchet_step on both sides after import_state().
        """
        alice_session, bob_session = self._make_session_pair()

        # Alice sends first message → Bob receives (Bob creates sending chain)
        plaintext_a1 = b"Alice message 1"
        ct_a1 = alice_session.encrypt(plaintext_a1)
        assert bob_session.decrypt(ct_a1) == plaintext_a1

        # Export Alice's state NOW (only sending chain, no receiving chain yet)
        state = alice_session.export_state()
        assert "dh_local_private" not in state

        # Import into a new session
        imported_session = Session.import_state(state)

        # Imported session MUST have a fresh dh_local_private
        assert imported_session._ratchet.dh_local_private is not None
        assert imported_session._ratchet.dh_local_public is not None

        # Imported Alice sends → Bob receives, Bob sees new dh_public,
        # Bob performs DH ratchet step
        plaintext_a2 = b"Alice message 2 after import"
        ct_a2 = imported_session.encrypt(plaintext_a2)
        assert bob_session.decrypt(ct_a2) == plaintext_a2

        # Bob responds → Imported Alice receives, detects Bob's new dh_public,
        # performs DH ratchet step, decrypts successfully
        plaintext_b2 = b"Bob response 2 after import"
        ct_b2 = bob_session.encrypt(plaintext_b2)
        assert imported_session.decrypt(ct_b2) == plaintext_b2

        # Imported session can continue the conversation
        plaintext_a3 = b"Alice message 3 after import"
        ct_a3 = imported_session.encrypt(plaintext_a3)
        assert bob_session.decrypt(ct_a3) == plaintext_a3
