"""
Minimal WebSocket client — stdlib only (socket, ssl, base64, hashlib).

Implements RFC 6455. Supports:
- ws:// and wss:// (TLS)
- Sending and receiving text and binary frames
- Synchronous blocking API
- Async API via asyncio

Used by SibnaClient for real-time message delivery.
"""

import asyncio
import base64
import hashlib
import json
import os
import socket
import ssl
import struct
from typing import Callable, Optional
from urllib.parse import urlparse

_WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# WebSocket opcodes
_OP_TEXT   = 0x1
_OP_BINARY = 0x2
_OP_CLOSE  = 0x8
_OP_PING   = 0x9
_OP_PONG   = 0xA


def _make_key() -> str:
    return base64.b64encode(os.urandom(16)).decode()


def _expected_accept(key: str) -> str:
    return base64.b64encode(
        hashlib.sha1((key + _WS_MAGIC).encode()).digest()
    ).decode()


def _encode_frame(opcode: int, payload: bytes, mask: bool = True) -> bytes:
    """Encode a single WebSocket frame."""
    length = len(payload)
    header = bytearray()
    header.append(0x80 | opcode)  # FIN + opcode

    if length < 126:
        header.append((0x80 if mask else 0) | length)
    elif length < 65536:
        header.append((0x80 if mask else 0) | 126)
        header.extend(struct.pack(">H", length))
    else:
        header.append((0x80 if mask else 0) | 127)
        header.extend(struct.pack(">Q", length))

    if mask:
        mask_key = os.urandom(4)
        header.extend(mask_key)
        masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
        return bytes(header) + masked
    return bytes(header) + payload


def _decode_frame(data: bytes) -> tuple:
    """
    Decode one WebSocket frame.
    Returns (opcode, payload, bytes_consumed) or raises if incomplete.
    """
    if len(data) < 2:
        raise ValueError("Incomplete frame header")

    opcode  = data[0] & 0x0F
    masked  = bool(data[1] & 0x80)
    length  = data[1] & 0x7F
    offset  = 2

    if length == 126:
        if len(data) < 4:
            raise ValueError("Incomplete extended length")
        length = struct.unpack(">H", data[2:4])[0]
        offset = 4
    elif length == 127:
        if len(data) < 10:
            raise ValueError("Incomplete 64-bit length")
        length = struct.unpack(">Q", data[2:10])[0]
        offset = 10

    if masked:
        if len(data) < offset + 4 + length:
            raise ValueError("Incomplete masked payload")
        mask_key = data[offset:offset + 4]
        offset  += 4
        payload  = bytes(b ^ mask_key[i % 4]
                         for i, b in enumerate(data[offset:offset + length]))
    else:
        if len(data) < offset + length:
            raise ValueError("Incomplete payload")
        payload = data[offset:offset + length]

    return opcode, payload, offset + length


class WebSocketError(OSError):
    pass


class SyncWebSocket:
    """
    Synchronous WebSocket connection using stdlib socket + ssl.
    Used for blocking calls in SibnaClient (non-async contexts).
    """

    def __init__(self, url: str, headers: Optional[dict] = None):
        self._url     = url
        self._headers = headers or {}
        self._sock    = None
        self._buf     = b""

    def connect(self) -> None:
        parsed  = urlparse(self._url)
        scheme  = parsed.scheme
        host    = parsed.hostname
        port    = parsed.port or (443 if scheme == "wss" else 80)
        path    = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        raw = socket.create_connection((host, port), timeout=30)

        if scheme == "wss":
            ctx  = ssl.create_default_context()
            self._sock = ctx.wrap_socket(raw, server_hostname=host)
        else:
            self._sock = raw

        # HTTP Upgrade handshake
        key = _make_key()
        request_lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {host}:{port}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {key}",
            "Sec-WebSocket-Version: 13",
        ]
        for k, v in self._headers.items():
            request_lines.append(f"{k}: {v}")
        request_lines += ["", ""]
        self._sock.sendall("\r\n".join(request_lines).encode())

        # Read response headers
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise WebSocketError("Connection closed during handshake")
            response += chunk

        status_line = response.split(b"\r\n")[0].decode()
        if "101" not in status_line:
            raise WebSocketError(f"WebSocket upgrade failed: {status_line}")

        accept = _expected_accept(key)
        if accept.encode() not in response:
            raise WebSocketError("Invalid Sec-WebSocket-Accept")

    def send(self, data) -> None:
        if isinstance(data, str):
            frame = _encode_frame(_OP_TEXT, data.encode())
        else:
            frame = _encode_frame(_OP_BINARY, data)
        self._sock.sendall(frame)

    def recv(self) -> bytes:
        """Receive one complete frame. Blocks until data arrives."""
        while True:
            try:
                opcode, payload, _ = _decode_frame(self._buf)
                self._buf = b""  # simple: one frame at a time
                if opcode == _OP_CLOSE:
                    self.close()
                    raise WebSocketError("Server closed the connection")
                if opcode == _OP_PING:
                    self._sock.sendall(_encode_frame(_OP_PONG, payload))
                    continue
                return payload
            except ValueError:
                chunk = self._sock.recv(65536)
                if not chunk:
                    raise WebSocketError("Connection closed")
                self._buf += chunk

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.sendall(_encode_frame(_OP_CLOSE, b""))
                self._sock.close()
            except OSError:
                pass
            finally:
                self._sock = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_):
        self.close()


class AsyncWebSocket:
    """
    Async WebSocket using asyncio streams.
    Used in AsyncSibnaClient for real-time messaging.
    """

    def __init__(self, url: str, headers: Optional[dict] = None):
        self._url     = url
        self._headers = headers or {}
        self._reader: Optional[asyncio.StreamReader]  = None
        self._writer: Optional[asyncio.StreamWriter]  = None
        self._buf     = b""

    async def connect(self) -> None:
        parsed = urlparse(self._url)
        scheme = parsed.scheme
        host   = parsed.hostname
        port   = parsed.port or (443 if scheme == "wss" else 80)
        path   = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        if scheme == "wss":
            ssl_ctx = ssl.create_default_context()
            self._reader, self._writer = await asyncio.open_connection(
                host, port, ssl=ssl_ctx
            )
        else:
            self._reader, self._writer = await asyncio.open_connection(host, port)

        key = _make_key()
        lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {host}:{port}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {key}",
            "Sec-WebSocket-Version: 13",
        ]
        for k, v in self._headers.items():
            lines.append(f"{k}: {v}")
        lines += ["", ""]
        self._writer.write("\r\n".join(lines).encode())
        await self._writer.drain()

        response = b""
        while b"\r\n\r\n" not in response:
            chunk = await self._reader.read(4096)
            if not chunk:
                raise WebSocketError("Connection closed during handshake")
            response += chunk

        status_line = response.split(b"\r\n")[0].decode()
        if "101" not in status_line:
            raise WebSocketError(f"WebSocket upgrade failed: {status_line}")

        if _expected_accept(key).encode() not in response:
            raise WebSocketError("Invalid Sec-WebSocket-Accept")

    async def send(self, data) -> None:
        if isinstance(data, str):
            frame = _encode_frame(_OP_TEXT, data.encode())
        else:
            frame = _encode_frame(_OP_BINARY, data)
        self._writer.write(frame)
        await self._writer.drain()

    async def recv(self) -> bytes:
        while True:
            try:
                opcode, payload, consumed = _decode_frame(self._buf)
                self._buf = self._buf[consumed:]
                if opcode == _OP_CLOSE:
                    await self.close()
                    raise WebSocketError("Server closed the connection")
                if opcode == _OP_PING:
                    self._writer.write(_encode_frame(_OP_PONG, payload))
                    await self._writer.drain()
                    continue
                return payload
            except ValueError:
                chunk = await self._reader.read(65536)
                if not chunk:
                    raise WebSocketError("Connection closed")
                self._buf += chunk

    async def close(self) -> None:
        if self._writer:
            try:
                self._writer.write(_encode_frame(_OP_CLOSE, b""))
                await self._writer.drain()
                self._writer.close()
                await self._writer.wait_closed()
            except OSError:
                pass
            finally:
                self._writer = None
                self._reader = None

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, *_):
        await self.close()
