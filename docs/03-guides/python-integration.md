# Python Integration Guide

This guide details how to integrate the Opela Nexus Protocol (ONP) in Python applications using the native C FFI library (`onp_ffi`) and the standard library `ctypes` module.

---

## 1. Prerequisites

Compile the native dynamic library from the `rust/` workspace:

```bash
cd rust
cargo build --release -p onp-ffi
```

Locate the output dynamic library:
- Windows: `rust/target/release/onp_ffi.dll`
- Linux: `rust/target/release/libonp_ffi.so`
- macOS: `rust/target/release/libonp_ffi.dylib`

No third-party Python packages are required; `ctypes` is part of standard Python.

---

## 2. Python ctypes Wrapper (`onp.py`)

Save the following module as `onp.py`:

```python
"""
Opela Nexus Protocol (ONP) Python Native Wrapper.
Binds to onp_ffi via ctypes.
"""

import ctypes
import os
import sys
from typing import Tuple, Optional

# Protocol Constants
ONP_OK = 0
ONP_ERR_NULL_PTR = -1
ONP_ERR_BUFFER_TOO_SMALL = -2
ONP_ERR_INVALID_STATE = -3
ONP_ERR_CRYPTO_FAILED = -4
ONP_ERR_REPLAY_DETECTED = -5
ONP_ERR_UNKNOWN_OPCODE = -6
ONP_ERR_FRAME_CORRUPT = -7
ONP_ERR_SEQUENCE_EXHAUSTED = -8
ONP_ERR_FRAME_TOO_LARGE = -9

# Standard Logical Opcodes
OPCODE_SYS_PING = 0x0001
OPCODE_SYS_PONG = 0x0002
OPCODE_SYS_DISCONNECT = 0x0003
OPCODE_AUTH_TOKEN = 0x0010
OPCODE_AUTH_RESULT = 0x0011
OPCODE_LOBBY_JOIN = 0x0020
OPCODE_LOBBY_STATE = 0x0021
OPCODE_CLOUD_SAVE_PUT = 0x0030
OPCODE_CLOUD_SAVE_GET = 0x0031
OPCODE_RPC_CALL = 0x0050
OPCODE_RPC_REPLY = 0x0051


def _load_library(lib_path: Optional[str] = None) -> ctypes.CDLL:
    if lib_path is None:
        if sys.platform == "win32":
            lib_name = "onp_ffi.dll"
        elif sys.platform == "darwin":
            lib_name = "libonp_ffi.dylib"
        else:
            lib_name = "libonp_ffi.so"

        candidates = [
            os.path.join(os.path.dirname(__file__), lib_name),
            os.path.join(os.path.dirname(__file__), "../../rust/target/release", lib_name),
            lib_name,
        ]
        for c in candidates:
            if os.path.exists(c):
                lib_path = c
                break
        if lib_path is None:
            lib_path = lib_name

    return ctypes.CDLL(lib_path)


_lib = _load_library()

# Function Signatures
_lib.onp_version.restype = ctypes.c_uint32
_lib.onp_max_payload_size.restype = ctypes.c_size_t
_lib.onp_overhead_size.restype = ctypes.c_size_t

_lib.onp_session_new_client.restype = ctypes.c_void_p
_lib.onp_session_new_server.restype = ctypes.c_void_p
_lib.onp_session_is_established.argtypes = [ctypes.c_void_p]
_lib.onp_session_is_established.restype = ctypes.c_int32

_lib.onp_session_destroy.argtypes = [ctypes.c_void_p]
_lib.onp_session_destroy.restype = None

_lib.onp_session_create_handshake_syn.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
_lib.onp_session_create_handshake_syn.restype = ctypes.c_int32

_lib.onp_session_process_handshake_syn.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
_lib.onp_session_process_handshake_syn.restype = ctypes.c_int32

_lib.onp_session_process_handshake_ack.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
]
_lib.onp_session_process_handshake_ack.restype = ctypes.c_int32

_lib.onp_session_encrypt.argtypes = [
    ctypes.c_void_p,
    ctypes.c_uint16,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
_lib.onp_session_encrypt.restype = ctypes.c_int32

_lib.onp_session_decrypt.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint16),
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
_lib.onp_session_decrypt.restype = ctypes.c_int32


class OnpError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(f"{message} (code: {code})")
        self.code = code


class OnpSession:
    def __init__(self, is_client: bool = True):
        self.is_client = is_client
        if is_client:
            self._ptr = _lib.onp_session_new_client()
        else:
            self._ptr = _lib.onp_session_new_server()

        if not self._ptr:
            raise MemoryError("Failed to allocate native ONP session")

    def __del__(self):
        self.destroy()

    def destroy(self):
        if hasattr(self, "_ptr") and self._ptr:
            _lib.onp_session_destroy(self._ptr)
            self._ptr = None

    @property
    def is_established(self) -> bool:
        return bool(_lib.onp_session_is_established(self._ptr) == 1)

    def create_handshake_syn(self) -> bytes:
        buf = (ctypes.c_uint8 * 256)()
        out_len = ctypes.c_size_t(0)
        rc = _lib.onp_session_create_handshake_syn(
            self._ptr, buf, len(buf), ctypes.byref(out_len)
        )
        if rc != ONP_OK:
            raise OnpError(rc, "Failed to create HANDSHAKE_SYN")
        return bytes(buf[: out_len.value])

    def process_handshake_syn(self, syn_bytes: bytes) -> bytes:
        in_buf = (ctypes.c_uint8 * len(syn_bytes)).from_buffer_copy(syn_bytes)
        out_buf = (ctypes.c_uint8 * 256)()
        out_len = ctypes.c_size_t(0)
        rc = _lib.onp_session_process_handshake_syn(
            self._ptr, in_buf, len(syn_bytes), out_buf, len(out_buf), ctypes.byref(out_len)
        )
        if rc != ONP_OK:
            raise OnpError(rc, "Failed to process HANDSHAKE_SYN")
        return bytes(out_buf[: out_len.value])

    def process_handshake_ack(self, ack_bytes: bytes) -> None:
        in_buf = (ctypes.c_uint8 * len(ack_bytes)).from_buffer_copy(ack_bytes)
        rc = _lib.onp_session_process_handshake_ack(self._ptr, in_buf, len(ack_bytes))
        if rc != ONP_OK:
            raise OnpError(rc, "Failed to process HANDSHAKE_ACK")

    def encrypt(self, opcode: int, data: bytes) -> bytes:
        overhead = _lib.onp_overhead_size()
        cap = len(data) + overhead
        payload_buf = (ctypes.c_uint8 * len(data)).from_buffer_copy(data) if data else None
        out_buf = (ctypes.c_uint8 * cap)()
        out_len = ctypes.c_size_t(0)

        rc = _lib.onp_session_encrypt(
            self._ptr,
            ctypes.c_uint16(opcode),
            payload_buf,
            len(data),
            out_buf,
            cap,
            ctypes.byref(out_len),
        )
        if rc != ONP_OK:
            raise OnpError(rc, "Encryption failed")
        return bytes(out_buf[: out_len.value])

    def decrypt(self, frame_bytes: bytes) -> Tuple[int, bytes]:
        frame_buf = (ctypes.c_uint8 * len(frame_bytes)).from_buffer_copy(frame_bytes)
        out_buf = (ctypes.c_uint8 * len(frame_bytes))()
        out_len = ctypes.c_size_t(0)
        out_opcode = ctypes.c_uint16(0)

        rc = _lib.onp_session_decrypt(
            self._ptr,
            frame_buf,
            len(frame_bytes),
            ctypes.byref(out_opcode),
            out_buf,
            len(out_buf),
            ctypes.byref(out_len),
        )
        if rc != ONP_OK:
            raise OnpError(rc, "Decryption failed")

        return out_opcode.value, bytes(out_buf[: out_len.value])
```

---

## 3. End-to-End Test and Verification

Run the following script to verify encryption and anti-replay protection:

```python
from onp import OnpSession, OPCODE_LOBBY_JOIN, ONP_ERR_REPLAY_DETECTED, OnpError

def test_session():
    client = OnpSession(is_client=True)
    server = OnpSession(is_client=False)

    # Handshake
    syn = client.create_handshake_syn()
    ack = server.process_handshake_syn(syn)
    client.process_handshake_ack(ack)

    assert client.is_established
    assert server.is_established

    # Encrypt
    payload = b"Hello from Python client"
    frame = client.encrypt(OPCODE_LOBBY_JOIN, payload)

    # Decrypt
    opcode, data = server.decrypt(frame)
    assert opcode == OPCODE_LOBBY_JOIN
    assert data == payload

    # Test Anti-Replay Sliding Window
    try:
        server.decrypt(frame)
        assert False, "Expected anti-replay exception"
    except OnpError as e:
        assert e.code == ONP_ERR_REPLAY_DETECTED
        print("Sliding window anti-replay blocked duplicated frame successfully.")

    client.destroy()
    server.destroy()
    print("Test passed successfully.")

if __name__ == "__main__":
    test_session()
```

---

## 4. Asyncio TCP Client Example

```python
import asyncio
import struct
from onp import OnpSession, OPCODE_SYS_PING

async def onp_stream_client(host: str, port: int):
    reader, writer = await asyncio.open_connection(host, port)
    session = OnpSession(is_client=True)

    # 1. Send Handshake SYN
    syn = session.create_handshake_syn()
    writer.write(syn)
    await writer.drain()

    # 2. Receive Handshake ACK
    header = await reader.readexactly(8)
    _, _, _, payload_len = struct.unpack("<2sBB I", header)
    ack_payload = await reader.readexactly(payload_len)
    session.process_handshake_ack(header + ack_payload)

    # 3. Send Encrypted Application Packet
    encrypted_frame = session.encrypt(OPCODE_SYS_PING, b"Ping from Asyncio")
    writer.write(encrypted_frame)
    await writer.drain()

    # 4. Read Response
    resp_header = await reader.readexactly(8)
    _, _, _, resp_len = struct.unpack("<2sBB I", resp_header)
    resp_payload = await reader.readexactly(resp_len)
    opcode, data = session.decrypt(resp_header + resp_payload)

    print(f"Received Opcode: {hex(opcode)}, Data: {data.decode()}")

    session.destroy()
    writer.close()
    await writer.wait_closed()
```
