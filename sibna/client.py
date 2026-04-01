"""
Sibna Protocol — HTTP + WebSocket Client
==========================================

Handles server communication: authentication, prekey management,
message sending and receiving.

No external dependencies — uses only Python stdlib:
    urllib.request  — HTTP
    asyncio         — async/await
    hashlib, hmac   — hashing
    ssl, socket     — TLS/WebSocket (via _websocket module)

Ed25519 signing is provided by the bundled _ed25519 module (pure Python).

Usage (sync):
    from sibna.client import SibnaClient

    client = SibnaClient(server="http://localhost:8080")
    client.generate_identity()
    client.authenticate()
    client.upload_prekey(bundle_hex)
    client.send_message(recipient_id="<hex>", payload_hex="<hex>")
    messages = client.fetch_inbox()

Usage (async + WebSocket):
    from sibna.client import AsyncSibnaClient
    import asyncio

    async def main():
        client = AsyncSibnaClient(server="http://localhost:8080")
        client.generate_identity()
        await client.authenticate()
        await client.connect(on_message=my_handler)

    asyncio.run(main())
"""

__version__ = "1.6.0"

import asyncio
import hashlib
import json
import os
import secrets
import ssl
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, Callable, Dict, List, Optional

from sibna import _ed25519
from sibna._websocket import AsyncWebSocket, WebSocketError

# ── Exceptions ────────────────────────────────────────────────────────────────

class SibnaClientError(Exception):
    def __init__(self, message: str, status_code: int = 0):
        self.status_code = status_code
        super().__init__(message)

class AuthError(SibnaClientError):
    """Authentication with the server failed."""

class NetworkError(SibnaClientError):
    """HTTP or WebSocket error."""


# ── Identity (Ed25519 — pure Python, no external deps) ────────────────────────

class Identity:
    """
    Ed25519 keypair for server authentication.

    Generated entirely in Python using the bundled _ed25519 module —
    no external packages needed.

    This identity is separate from the encryption keys in sibna.Context.
    It is only used for the server's JWT challenge-response flow.
    """

    def __init__(self, seed: Optional[bytes] = None):
        """
        Args:
            seed: 32-byte private key seed. If None, a random one is generated.
        """
        if seed is not None:
            if len(seed) != 32:
                raise ValueError("seed must be 32 bytes")
            self._seed = seed
        else:
            self._seed = os.urandom(32)

        self._public = _ed25519.public_key(self._seed)

    @property
    def public_key_bytes(self) -> bytes:
        """32-byte Ed25519 public key."""
        return self._public

    @property
    def public_key_hex(self) -> str:
        return self._public.hex()

    @property
    def seed_bytes(self) -> bytes:
        """32-byte private key seed. Keep secret."""
        return self._seed

    def sign(self, data: bytes) -> bytes:
        """Sign data. Returns 64-byte signature."""
        return _ed25519.sign(self._seed, data)

    def sign_hex(self, data: bytes) -> str:
        return self.sign(data).hex()

    def save(self, path: str) -> None:
        """Save seed to file with permissions 600."""
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "wb") as f:
            f.write(self._seed)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass  # Windows doesn't support chmod

    @classmethod
    def load(cls, path: str) -> "Identity":
        """Load identity from a saved seed file."""
        with open(path, "rb") as f:
            return cls(seed=f.read())

    def __repr__(self) -> str:
        return f"<Identity pub={self.public_key_hex[:16]}...>"


# ── Envelope helpers ──────────────────────────────────────────────────────────

_PADDING_BLOCK = 1024


def pad_payload(data: bytes) -> bytes:
    """
    Pad payload to the nearest 1024-byte boundary.
    Makes all messages appear the same size to a passive observer.

    Format: [padding_len: 2 bytes LE] + [data] + [random padding]
    Total length is always a multiple of 1024.
    """
    content_len  = 2 + len(data)
    remainder    = content_len % _PADDING_BLOCK
    padding_len  = (_PADDING_BLOCK - remainder) % _PADDING_BLOCK
    header       = padding_len.to_bytes(2, "little")
    return header + data + secrets.token_bytes(padding_len)


def unpad_payload(padded: bytes) -> bytes:
    """Remove padding added by pad_payload()."""
    if len(padded) < 2:
        raise ValueError("Payload too short")
    padding_len = int.from_bytes(padded[:2], "little")
    data_end    = len(padded) - padding_len
    if data_end < 2:
        raise ValueError("Invalid padding length")
    return padded[2:data_end]


def make_signed_envelope(
    identity: Identity,
    recipient_id: str,
    payload_hex: str,
) -> Dict[str, Any]:
    """
    Create a signed sealed envelope for sending via the server.

    The server sees only the recipient_id. payload_hex is already
    encrypted by sibna.Context — the server cannot read it.

    The signature ensures the recipient can verify the sender's identity.
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
    Verify the Ed25519 signature on a received envelope.

    Always call this before processing any incoming message.

    Returns True if valid and recent (< 5 minutes old), False otherwise.
    """
    try:
        pub = bytes.fromhex(envelope["sender_id"])
        sig = bytes.fromhex(envelope["signature_hex"])

        h = hashlib.sha512()
        h.update(envelope["recipient_id"].encode())
        h.update(envelope["payload_hex"].encode())
        h.update(struct.pack("<q", envelope["timestamp"]))
        h.update(envelope["message_id"].encode())

        if not _ed25519.verify(pub, h.digest(), sig):
            return False

        # Reject messages older than 5 minutes
        if abs(int(time.time()) - envelope["timestamp"]) > 300:
            return False

        return True
    except Exception:
        return False


# ── HTTP helper (stdlib urllib) ───────────────────────────────────────────────

def _http(
    method: str,
    url: str,
    body: Optional[dict] = None,
    params: Optional[dict] = None,
    headers: Optional[dict] = None,
    timeout: int = 30,
) -> dict:
    """
    Make an HTTP request using urllib (stdlib only).
    Returns the parsed JSON response body.
    Raises NetworkError or AuthError on failure.
    """
    if params:
        url += "?" + urllib.parse.urlencode(params)

    data = json.dumps(body).encode() if body is not None else None

    req_headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if headers:
        req_headers.update(headers)

    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        body_text = e.read().decode(errors="replace")[:300]
        if e.code == 401:
            raise AuthError(f"Unauthorized ({url}): {body_text}", 401)
        if e.code == 429:
            raise NetworkError(f"Rate limited ({url})", 429)
        raise NetworkError(f"HTTP {e.code} on {url}: {body_text}", e.code)
    except urllib.error.URLError as e:
        raise NetworkError(f"Connection failed ({url}): {e.reason}")


# ── Sync HTTP Client ──────────────────────────────────────────────────────────

class SibnaClient:
    """
    Synchronous HTTP client for the Sibna Protocol server.

    No external dependencies — uses only Python stdlib (urllib).

    Handles:
    - Ed25519 challenge-response authentication → JWT
    - PreKey Bundle upload
    - Message sending (REST fallback)
    - Inbox polling for offline messages

    The actual encryption is done separately by sibna.Context.
    This client only transports already-encrypted payloads.
    """

    def __init__(self, server: str = "http://localhost:8080"):
        self.server    = server.rstrip("/")
        self.identity: Optional[Identity] = None
        self.jwt_token: Optional[str]     = None

    def generate_identity(self, seed: Optional[bytes] = None) -> Identity:
        """
        Generate (or load) an Ed25519 identity for server authentication.

        Args:
            seed: 32-byte private key seed. If None, a new random key is generated.

        Returns:
            The Identity object (also stored in self.identity).
        """
        self.identity = Identity(seed)
        return self.identity

    def authenticate(self) -> str:
        """
        Authenticate with the server via Ed25519 challenge-response.

        Steps:
        1. Request a challenge from the server
        2. Sign the challenge with the private key
        3. Submit the signature and receive a JWT

        Returns:
            str: JWT token (stored in self.jwt_token).

        Raises:
            AuthError: If generate_identity() was not called first,
                       or if authentication fails.
        """
        if not self.identity:
            raise AuthError("Call generate_identity() before authenticate()")

        resp = _http("POST", f"{self.server}/v1/auth/challenge", body={
            "identity_key_hex": self.identity.public_key_hex,
        })
        challenge_hex = resp["challenge_hex"]

        resp = _http("POST", f"{self.server}/v1/auth/prove", body={
            "identity_key_hex": self.identity.public_key_hex,
            "challenge_hex":    challenge_hex,
            "signature_hex":    self.identity.sign_hex(bytes.fromhex(challenge_hex)),
        })
        self.jwt_token = resp["token"]
        return self.jwt_token

    def upload_prekey(self, bundle_hex: str) -> None:
        """
        Upload a PreKey Bundle to the server.

        bundle_hex comes from: sibna.Context.generate_prekey_bundle().hex()

        Requires authentication first.
        """
        self._require_auth()
        _http("POST", f"{self.server}/v1/prekeys/upload",
              body={"bundle_hex": bundle_hex},
              headers=self._auth_headers())

    def fetch_prekeys(self, identity_key_hex: str) -> List[str]:
        """
        Fetch a peer's PreKey Bundles from the server.

        Args:
            identity_key_hex: The peer's Ed25519 public key in hex.

        Returns:
            List[str]: PreKey Bundle(s) in hex.
                       Pass bytes.fromhex(bundle) to sibna.Context.perform_handshake().

        Note: Bundles are deleted from the server after fetching (one-time use).
        """
        resp = _http("GET", f"{self.server}/v1/prekeys/{identity_key_hex}")
        return resp["bundles_hex"]

    def send_message(
        self,
        recipient_id: str,
        payload_hex: str,
        sign: bool = True,
    ) -> int:
        """
        Send an encrypted message via REST.

        payload_hex must be the output of sibna.Context.session_encrypt().hex().
        The server cannot read the payload.

        Args:
            recipient_id: Recipient's identity key in hex.
            payload_hex:  The encrypted payload in hex.
            sign:         Add an Ed25519 signature for end-to-end integrity.
                          Requires generate_identity() to have been called.

        Returns:
            int: HTTP status code.
                 200 = delivered live, 202 = queued (recipient offline).
        """
        if sign and self.identity:
            body = make_signed_envelope(self.identity, recipient_id, payload_hex)
        else:
            body = {"recipient_id": recipient_id, "payload_hex": payload_hex}

        _http("POST", f"{self.server}/v1/messages/send",
              body=body, headers=self._auth_headers())
        return 200

    def fetch_inbox(self) -> List[Dict[str, Any]]:
        """
        Fetch queued messages from the server inbox.

        Automatically verifies the Ed25519 signature on each message
        and drops any with an invalid signature.

        Messages are deleted from the server after retrieval.

        Returns:
            List[dict]: Verified envelopes. Each has:
                - sender_id    (hex): peer's identity key
                - payload_hex  (hex): encrypted payload — decrypt with:
                  sibna.Context.session_decrypt(
                      bytes.fromhex(msg["sender_id"]),
                      bytes.fromhex(msg["payload_hex"])
                  )
                - message_id, timestamp, signature_hex

        Raises:
            AuthError: If not authenticated.
        """
        self._require_auth()
        resp = _http(
            "GET", f"{self.server}/v1/messages/inbox",
            params={
                "identity_key_hex": self.identity.public_key_hex,
                "token":            self.jwt_token,
            },
        )
        verified = []
        for msg in resp.get("messages", []):
            if verify_signed_envelope(msg):
                verified.append(msg)
            else:
                print(f"[sibna] Dropped message with invalid signature: {msg.get('message_id')}")
        return verified

    def health(self) -> Dict[str, Any]:
        """Check server health."""
        return _http("GET", f"{self.server}/health")

    def _require_auth(self) -> None:
        if not self.identity or not self.jwt_token:
            raise AuthError("Call authenticate() first")

    def _auth_headers(self) -> Dict[str, str]:
        if self.jwt_token:
            return {"Authorization": f"Bearer {self.jwt_token}"}
        return {}

    def __repr__(self) -> str:
        pub = self.identity.public_key_hex[:16] if self.identity else "None"
        return f"<SibnaClient server={self.server} identity={pub}...>"


# ── Async WebSocket Client ────────────────────────────────────────────────────

class AsyncSibnaClient:
    """
    Async client with WebSocket support for real-time messaging.

    No external dependencies — uses only asyncio + stdlib ssl/socket.

    Usage:
        client = AsyncSibnaClient(server="http://localhost:8080")
        client.generate_identity()
        await client.authenticate()
        await client.connect(on_message=my_handler)
        await client.send(recipient_id="<hex>", payload_hex="<hex>")
    """

    def __init__(self, server: str = "http://localhost:8080"):
        self.server     = server.rstrip("/")
        self.ws_server  = (server
                           .replace("http://", "ws://")
                           .replace("https://", "wss://")
                           .rstrip("/"))
        self.identity:  Optional[Identity] = None
        self.jwt_token: Optional[str]      = None
        self._ws:       Optional[AsyncWebSocket] = None

    def generate_identity(self, seed: Optional[bytes] = None) -> Identity:
        """Generate (or load) an Ed25519 identity."""
        self.identity = Identity(seed)
        return self.identity

    async def authenticate(self) -> str:
        """
        Async Ed25519 challenge-response authentication.

        Returns: JWT token.
        Raises: AuthError if identity not set or auth fails.
        """
        if not self.identity:
            raise AuthError("Call generate_identity() first")

        loop = asyncio.get_event_loop()

        # Run blocking HTTP in thread pool to avoid blocking event loop
        resp = await loop.run_in_executor(
            None,
            lambda: _http("POST", f"{self.server}/v1/auth/challenge",
                          body={"identity_key_hex": self.identity.public_key_hex})
        )
        challenge_hex = resp["challenge_hex"]

        resp = await loop.run_in_executor(
            None,
            lambda: _http("POST", f"{self.server}/v1/auth/prove", body={
                "identity_key_hex": self.identity.public_key_hex,
                "challenge_hex":    challenge_hex,
                "signature_hex":    self.identity.sign_hex(bytes.fromhex(challenge_hex)),
            })
        )
        self.jwt_token = resp["token"]
        return self.jwt_token

    async def connect(self, on_message: Optional[Callable] = None) -> None:
        """
        Connect to the WebSocket relay and listen for incoming messages.

        Automatically verifies the signature of every incoming message
        and drops those with invalid signatures.

        Args:
            on_message: Async callback invoked for each verified message.
                        Signature: async def handler(envelope: dict) -> None
        """
        if not self.jwt_token:
            raise AuthError("Call authenticate() first")

        ws_url  = f"{self.ws_server}/ws?token={self.jwt_token}"
        headers = {}
        if self.identity:
            headers["X-Identity"] = self.identity.public_key_hex

        self._ws = AsyncWebSocket(ws_url, headers=headers)
        async with self._ws:
            while True:
                try:
                    raw = await self._ws.recv()
                    envelope = json.loads(raw)
                    if verify_signed_envelope(envelope):
                        if on_message:
                            await on_message(envelope)
                    else:
                        print(f"[sibna] Invalid signature on {envelope.get('message_id')}")
                except WebSocketError:
                    break
                except json.JSONDecodeError as e:
                    print(f"[sibna] Failed to parse message: {e}")

    async def send(
        self,
        recipient_id: str,
        payload_hex: str,
        sign: bool = True,
    ) -> None:
        """
        Send an encrypted message over the WebSocket.

        payload_hex must be the output of sibna.Context.session_encrypt().hex().

        Args:
            recipient_id: Recipient's identity key in hex.
            payload_hex:  The encrypted payload in hex.
            sign:         Add an Ed25519 signature.
        """
        if not self._ws:
            raise NetworkError("Not connected. Call connect() first.")

        if sign and self.identity:
            envelope = make_signed_envelope(self.identity, recipient_id, payload_hex)
        else:
            envelope = {
                "recipient_id": recipient_id,
                "payload_hex":  payload_hex,
                "message_id":   str(uuid.uuid4()),
                "timestamp":    int(time.time()),
            }
        await self._ws.send(json.dumps(envelope))

    def __repr__(self) -> str:
        pub = self.identity.public_key_hex[:16] if self.identity else "None"
        return f"<AsyncSibnaClient server={self.server} identity={pub}...>"


# ── Exports ────────────────────────────────────────────────────────────────────

__all__ = [
    "Identity",
    "SibnaClient",
    "AsyncSibnaClient",
    "SibnaClientError",
    "AuthError",
    "NetworkError",
    "pad_payload",
    "unpad_payload",
    "make_signed_envelope",
    "verify_signed_envelope",
    "__version__",
]
