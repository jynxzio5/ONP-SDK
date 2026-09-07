# Opela Nexus Protocol (ONP) Specification
**Version:** 1.0.0-RFC  
**Author:** Opela Nexus Architecture Group  
**Status:** Standards Track / Proprietary Implementation  

---

## 1. Abstract & Motivation

The **Opela Nexus Protocol (ONP)** is a high-performance, low-latency, zero-knowledge binary communication protocol designed to eliminate the overhead, predictability, and attack surface of standard web protocols (HTTP/REST, GraphQL, plaintext JSON). 

ONP delivers:
1. **Total Wire Confidentiality**: Every byte beyond the 8-byte framing envelope is cryptographically indistinguishable from pure white noise.
2. **Polymorphic Rolling Opcodes**: Prevents static command identification and packet signature matching by permuting all command identifiers on a per-session basis using cryptographic seeds.
3. **Hardware-Accelerated AEAD**: Authenticated Encryption with Associated Data via **ChaCha20-Poly1305** ensuring sub-microsecond encryption/decryption with zero plaintext tampering tolerance.
4. **Perfect Forward Secrecy (PFS)**: Ephemeral Curve25519 (X25519) key exchange per connection; compromising long-term credentials never exposes past or future sessions.
5. **Replay & Injection Immunity**: 96-bit monotonic nonce sequences guarded by a sliding window bitmap filter.

---

## 2. Protocol Architecture

ONP operates directly on top of reliable byte streams (TCP) or message transports (WebSocket binary frames, QUIC datagrams).

```text
+-------------------------------------------------------------+
|               Application Layer (Opela Engine)              |
+-------------------------------------------------------------+
|             Polymorphic Opcode Mapping (Seed-Based)         |
+-------------------------------------------------------------+
|          ChaCha20-Poly1305 Authenticated Encryption         |
+-------------------------------------------------------------+
|                 ONP Binary Framing & Codec                  |
+-------------------------------------------------------------+
|              Transport Layer (TCP / WebSocket)              |
+-------------------------------------------------------------+
```

---

## 3. Packet Binary Layout

Every ONP packet is serialized as a contiguous binary sequence without memory alignment padding:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Magic (0x4F, 0x4E)      |    Ver (0x01) |   Flags (1B)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Payload Length (32-bit LE)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                   Nonce / Sequence (96 bits / 12B)            |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                    Encrypted Ciphertext                       |
|           [ Dynamic Opcode (2B) + Payload (N Bytes) ]         |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                  Poly1305 MAC Tag (128 bits / 16B)            |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 3.1 Field Definitions

| Field | Size | Encoding | Description |
| :--- | :--- | :--- | :--- |
| **Magic** | 2 Bytes | ASCII `ON` (`0x4F4E`) | Protocol identifier. Stream resets if invalid. |
| **Version** | 1 Byte | `0x01` | Protocol major version. |
| **Flags** | 1 Byte | Bitfield | Control bits (see §3.2). |
| **Payload Length** | 4 Bytes | uint32 (LE) | Size of `Ciphertext` + 16 (MAC Tag length). |
| **Nonce / Sequence** | 12 Bytes | Binary | Unique 96-bit IV. High 32-bit = epoch, Low 64-bit = counter. |
| **Ciphertext** | N Bytes | Encrypted | Polymorphic Opcode (2B LE) followed by Application Data. |
| **MAC Tag** | 16 Bytes | Binary | ChaCha20-Poly1305 authentication tag. |

### 3.2 Flag Bitmasks

- `0x01` - **FLAG_HANDSHAKE_SYN**: Initiates ephemeral key negotiation.
- `0x02` - **FLAG_HANDSHAKE_ACK**: Server response containing ephemeral public key.
- `0x04` - **FLAG_COMPRESSED**: Ciphertext payload is compressed via LZ4/Zstd prior to encryption.
- `0x08` - **FLAG_ENCRYPTED**: Packet contains encrypted payload and MAC tag.
- `0x10` - **FLAG_HEARTBEAT**: Zero-data ping/pong keepalive packet.
- `0x20` - **FLAG_ERROR**: Out-of-band error alert.
- `0x80` - **FLAG_TERMINATE**: Graceful session closure.

---

## 4. Cryptographic Handshake & Key Derivation

ONP mandates zero long-term static session keys. Each session negotiates a fresh ephemeral keypair:

### 4.1 3-Step Handshake Diagram

```text
Client                                                   Server
  |                                                        |
  | -------- 1. SYN (Client_Pk [32B], Client_Nonce [16B]) -> |
  |                                                        | (Generates Ephemeral Key)
  |                                                        | (Computes Shared Secret)
  |                                                        | (Derives Session Keys & Seed)
  | <- 2. ACK (Server_Pk [32B], Server_Nonce [16B], MAC) - |
  |                                                        |
(Computes Shared Secret)                                   |
(Derives Session Keys & Seed)                              |
(Instantiates Opcode Permutation Map)                      |
  |                                                        |
  | ------ 3. ENCRYPTED CONFIRM (Encrypted Hello Pong) ---> |
  |                                                        | (Instantiates Map)
  |                                                        | [SESSION READY]
```

### 4.2 Key Derivation Function (HKDF-SHA256)

1. Compute Diffie-Hellman Shared Secret:
   $$\text{SharedSecret} = \text{X25519}(\text{PrivateKey}_{\text{local}}, \text{PublicKey}_{\text{remote}})$$
2. Salt construction:
   $$\text{Salt} = \text{ClientNonce} \parallel \text{ServerNonce}$$
3. Extract and Expand using HKDF-SHA256:
   $$\text{PRK} = \text{HKDF-Extract}(\text{Salt}, \text{SharedSecret})$$
   $$\text{KeyMaterial} = \text{HKDF-Expand}(\text{PRK}, \text{"ONP-v1-SESSION-KEYS"}, 96)$$
4. Split `KeyMaterial`:
   - `ClientWriteKey` (Bytes 0..31): 32 Bytes for Client-to-Server AEAD
   - `ServerWriteKey` (Bytes 32..63): 32 Bytes for Server-to-Client AEAD
   - `SessionOpcodeSeed` (Bytes 64..95): 32 Bytes for Polymorphic Opcode Permutation

---

## 5. Polymorphic Rolling Opcode Engine

Traditional protocols use static IDs (e.g. `0x0001 = LOGIN`, `0x0002 = HEARTBEAT`). Network analyzers can easily map these. ONP solves this by generating a session-specific opcode permutation.

### 5.1 Permutation Function

For any standard Logical Opcode $L \in [0, 65535]$:

$$\text{PhysicalOpcode} = (\text{HMAC-SHA256}(\text{SessionOpcodeSeed}, L)_{0..1}) \pmod{65535} + 1$$

- Collision resolution is performed deterministically using Robin Hood linear probing.
- Both endpoints generate the identical lookup tables in $O(1)$ memory lookup time upon handshake completion.
- To a network snooper, packet opcodes look like completely random 16-bit integers with zero recurring patterns across sessions.

---

## 6. Anti-Replay & Sequence Security

Each packet transmission increments the 64-bit sequence counter inside the 96-bit Nonce.
Endpoints maintain a sliding window of size $W = 64$:
1. If $\text{Seq} > \text{MaxSeq}$: the window advances and the bit is set.
2. If $\text{Seq} \le \text{MaxSeq} - W$: the packet is dropped immediately as expired.
3. If $\text{Seq}$ was already received in the current window: the packet is rejected as a duplicate replay attack.

---

## 7. Standard Logical Command Table

| Logical ID | Name | Direction | Payload Description |
| :--- | :--- | :--- | :--- |
| `0x0001` | `SYS_PING` | Bi-directional | 8-byte monotonic timestamp. |
| `0x0002` | `SYS_PONG` | Bi-directional | 8-byte echo timestamp. |
| `0x0003` | `SYS_DISCONNECT`| Bi-directional | 2-byte reason code + UTF-8 message. |
| `0x0010` | `AUTH_TOKEN` | Client -> Server | Ephemeral auth ticket / JWT bytes. |
| `0x0011` | `AUTH_RESULT`| Server -> Client | 1-byte status + 8-byte session ID. |
| `0x0020` | `LOBBY_JOIN` | Client -> Server | 8-byte Lobby ID + 16-byte Passcode. |
| `0x0021` | `LOBBY_STATE`| Server -> Client | Compact binary lobby snapshot. |
| `0x0030` | `CLOUD_SAVE_PUT`| Client -> Server | 4-byte Game ID + binary save blob. |
| `0x0031` | `CLOUD_SAVE_GET`| Client -> Server | 4-byte Game ID + 8-byte version. |
| `0x0050` | `RPC_CALL` | Client -> Server | 4-byte method hash + args buffer. |
| `0x0051` | `RPC_REPLY`| Server -> Client | 4-byte correlation ID + result. |

*(All logical IDs are translated into dynamic Physical Opcodes on the wire)*.
