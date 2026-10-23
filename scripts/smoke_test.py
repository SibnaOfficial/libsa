"""Smoke test: verify the installed sibna package works correctly."""
import sibna
from sibna import (
    X25519KeyPair,
    Ed25519KeyPair,
    Session,
    generate_peer_bundle,
    make_signed_envelope,
    verify_signed_envelope,
)

assert sibna.__version__ == "3.0.2", f"Expected 3.0.2, got {sibna.__version__}"

# Alice creates her identity
alice_ed = Ed25519KeyPair()
alice_x = X25519KeyPair()

# Bob creates his identity and prekey bundle
bob_ed = Ed25519KeyPair()
bob_x = X25519KeyPair()
bob_spk = X25519KeyPair()
bob_opk = X25519KeyPair()

bob_bundle = generate_peer_bundle(
    identity_ed=bob_ed,
    identity_x25519=bob_x,
    signed_prekey=bob_spk,
    onetime_prekey=bob_opk,
    device_id_bytes=b"bob-device-01000",
    root_identity_key=bob_ed.public_key,
)

# Alice performs X3DH as initiator
alice_session = Session()
ephemeral_pub = alice_session.initiate_as_initiator(
    identity=alice_x,
    ephemeral=X25519KeyPair(),
    peer_bundle=bob_bundle,
    our_device_id=b"alice-device-010",
    peer_device_id=b"bob-device-01000",
)

# Alice encrypts a message
plaintext = b"Hello Bob from Alice via Sibna Protocol v3.0.2!"
ciphertext = alice_session.encrypt(plaintext, associated_data=b"v3.0.2")

# Alice creates a signed envelope
envelope = make_signed_envelope(
    alice_ed,
    recipient_id=bob_ed.public_key.hex(),
    payload_hex=ciphertext.hex(),
)
assert verify_signed_envelope(envelope)

# Bob establishes his side of the session and decrypts
bob_session = Session()
bob_session.initiate_as_responder(
    identity=bob_x,
    signed_prekey=bob_spk,
    onetime_prekey=bob_opk,
    peer_identity=alice_x.public_key,
    peer_ephemeral=ephemeral_pub,
    our_device_id=b"bob-device-01000",
    peer_device_id=b"alice-device-010",
)
decrypted = bob_session.decrypt(ciphertext, associated_data=b"v3.0.2")
assert decrypted == plaintext

print("Smoke test OK")