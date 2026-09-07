# Opela Nexus Protocol (ONP) Architecture & Design

## 1. Design Philosophy

Modern internet communication is overwhelmed by excessive protocol abstraction. A standard HTTP/JSON request transmits between 400 and 800 bytes of repetitive ASCII headers (`Host`, `User-Agent`, `Accept`, `Content-Type`, `Cookie`), followed by verbose string-serialized JSON. 

ONP is built on three core pillars:
1. **Zero Text on the Wire**: Strings are replaced with compact numeric tokens or raw binary slices.
2. **Deterministic Cryptographic Privacy**: The protocol reveals neither the action being performed nor the user performing it to intermediate network observers.
3. **Zero-Allocation Deserialization**: In Rust, incoming frames can be mapped directly onto typed structs without dynamic memory allocations (`no_std` capable).

---

## 2. Threat Model & Mitigations

| Threat Vector | Standard Web (HTTPS/REST) | ONP Defense |
| :--- | :--- | :--- |
| **Deep Packet Inspection (DPI)** | Reveals hostnames (SNI), URL paths, request sizes, and timing signatures. | Fixed envelope sizes with optional random jitter padding; completely opaque wire entropy. |
| **Static Opcode Fingerprinting** | Attackers map API actions to HTTP routes or static RPC method IDs. | **Polymorphic Rolling Opcodes**: Command IDs change randomly every session based on cryptographically hashed seeds. |
| **Replay Attacks** | Mitigated via cookies or server-side nonces requiring database lookups. | **Monotonic 96-bit Nonces & 64-bit Sliding Window**: Duplicate sequence numbers are dropped in $O(1)$ CPU cycles at the socket level. |
| **Man-in-the-Middle (MITM)** | Vulnerable to rogue CA certificates or TLS termination proxies (e.g. corporate proxies, Fiddler). | **End-to-End Ephemeral Curve25519**: Keys exist only in RAM during the connection lifetime and are erased immediately upon disconnection. |
| **Denial of Service (CPU Exhaustion)** | Parsing large JSON payloads requires recursive string tokenization. | **Direct Memory Bounds Checking**: Frame header validated in 8 bytes; unauthenticated packets are dropped before decrypting payload. |

---

## 3. Polymorphic Rolling Opcode Flow

The following diagram illustrates how logical operations are shielded:

```text
[ Developer Code ]
     |
     v
  Logical Action: LOBBY_JOIN (0x0020)
     |
     v
[ ONP Opcode Table ] <--- Input: SessionOpcodeSeed (32B)
     |
     v
  Physical Opcode on Wire: 0xD83F (Changes every connection)
     |
     v
[ ChaCha20-Poly1305 Encrypt ]
     |
     v
[ Wire: Indistinguishable High-Entropy Binary ]
     |
     v
[ ChaCha20-Poly1305 Decrypt ]
     |
     v
[ ONP Inverse Opcode Table ]
     |
     v
  Resolved: LOBBY_JOIN (0x0020)
```

---

## 4. Cross-Platform Reusability

ONP is packaged as two independent, production-grade SDKs:

1. **`onp-core` (Rust)**:
   - Zero-copy deserialization using `bytes` and `zerocopy`.
   - Async network runtime using `tokio` and `tokio-util`.
   - Suitable for game engines, desktop companions, high-throughput microservices, and embedded clients.
2. **`onp-ts` (TypeScript / Node.js)**:
   - Works seamlessly in modern browsers via native `crypto.subtle` / WebCrypto and in Node.js via `node:crypto`.
   - Implements identical wire framing and rolling opcode permutations.
   - Suitable for Electron / Tauri frontends, Express/Fastify servers, and web bots.
