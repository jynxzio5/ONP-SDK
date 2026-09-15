# ONP Protocol Specification (RFC v1.0.0)

## Overview

The Opela Nexus Protocol (ONP) is a high-performance binary transport protocol engineered for uncompromising wire confidentiality, sub-millisecond serialization, and automated replay defense.

ONP operates directly on top of byte streams (TCP) or message transports (WebSocket binary frames, QUIC datagrams).

---

## 1. Packet Binary Layout

Every ONP frame is serialized as a packed contiguous byte sequence without memory padding:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Magic (0x4F, 0x4E)      |    Ver (0x01) |   Flags (1B)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Payload Length (32-bit LE)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Nonce / Sequence (96 bits / 12B)            |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Encrypted Ciphertext                       |
|           [ Dynamic Opcode (2B) + Payload (N Bytes) ]         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Poly1305 Authentication Tag (16B)             |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

---

## 2. Header Fields Definition

| Field | Offset | Size (Bytes) | Data Type | Description |
| :--- | :--- | :--- | :--- | :--- |
| **Magic** | `0x00` | 2 | `[u8; 2]` | Fixed ASCII value `ON` (`0x4F`, `0x4E`). Frames with mismatched magic are dropped immediately without processing. |
| **Version** | `0x02` | 1 | `u8` | Protocol version (`0x01`). Prevents cross-version decoding collisions. |
| **Flags** | `0x03` | 1 | `u8` (Bitmask) | Bitfield controlling frame processing semantics. |
| **Payload Length** | `0x04` | 4 | `u32` (LE) | Little-endian integer indicating length of subsequent ciphertext (excluding 16-byte MAC tag). |
| **Nonce** | `0x08` | 12 | `[u8; 12]` | 96-bit monotonic sequence identifier used for ChaCha20-Poly1305 AEAD and replay window validation. |
| **Ciphertext** | `0x14` | Variable ($N$) | `[u8; N]` | Authenticated encrypted body. First 2 bytes are the encrypted polymorphic rolling opcode; remainder is application data. |
| **Poly1305 Tag** | $0x14 + N$ | 16 | `[u8; 16]` | Authenticator tag over Additional Authenticated Data (AAD) + Ciphertext. |

---

## 3. Protocol Flags Bitmask

```rust
pub mod flags {
    pub const HANDSHAKE_SYN: u8 = 0x01; // Client initiating ephemeral key exchange
    pub const HANDSHAKE_ACK: u8 = 0x02; // Server acknowledging handshake with server public key
    pub const ENCRYPTED: u8     = 0x04; // Payload is encrypted with session key
    pub const COMPRESSED: u8    = 0x08; // Payload is compressed (Zstandard)
    pub const HEARTBEAT: u8     = 0x10; // Ping / Pong keepalive frame
    pub const ERROR: u8         = 0x20; // Protocol error response
    pub const TERMINATE: u8     = 0x80; // Graceful connection teardown notification
}
```

---

## 4. Size Limits & Constraints

- **Minimum Header Size**: 8 bytes (`Magic` + `Version` + `Flags` + `PayloadLength`).
- **Maximum Frame Payload**: 16 MiB (`16,777,216` bytes). Frames advertising larger lengths trigger immediate connection termination to prevent memory exhaustion DoS attacks.
- **Envelope Overhead**: 8 bytes header + 12 bytes nonce + 16 bytes MAC tag = 36 bytes total overhead.
