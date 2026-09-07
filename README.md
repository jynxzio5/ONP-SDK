# 🛡️ Opela Nexus Protocol (ONP)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Protocol Version: 1.0](https://img.shields.io/badge/ONP-v1.0.0-emerald.svg)](SPECIFICATION.md)
[![Rust: 2021 Edition](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](rust/)
[![TypeScript: 5.x](https://img.shields.io/badge/TypeScript-5.x-blue.svg)](typescript/)

**Opela Nexus Protocol (ONP)** is a high-performance, proprietary binary transport protocol designed for uncompromising wire confidentiality, sub-millisecond latency, and automated replay protection.

Unlike standard web protocols (HTTP/REST, JSON, WebSockets with text payloads), ONP replaces human-readable headers and static command identifiers with **ephemeral Curve25519 key agreements**, **authenticated ChaCha20-Poly1305 encryption**, and **polymorphic rolling opcodes** that mutate on every session.

---

## ⚡ Key Highlights

- **Zero-Knowledge Wire Footprint**: Wireshark, ISPs, and proxies see only random pseudorandom binary noise.
- **Polymorphic Rolling Opcodes**: Command IDs change dynamically per session; static packet pattern matching is impossible.
- **Microsecond Deserialization**: Binary framing processed directly in memory without string parsing or recursive JSON parsing.
- **Anti-Replay Sliding Window**: 96-bit monotonic nonce sequence dropping out-of-order or duplicate packets in $O(1)$ CPU time.
- **Multi-Language Architecture**: Standalone implementations in **Rust** (`crates/onp-core`) and **TypeScript / Node.js** (`typescript/`) ready to drop into any project.

---

## 📂 Repository Layout

```text
Opela Nexus Protocol ONP/
├── SPECIFICATION.md       # Formal RFC-grade binary wire protocol specification
├── ARCHITECTURE.md        # Threat model, security boundaries & state machine diagrams
├── rust/                  # Rust workspace & production libraries
│   ├── Cargo.toml
│   ├── onp-core/          # Protocol framing, crypto, session state & polymorphic opcodes
│   ├── onp-transport/     # Tokio-based TCP framing client & server streams
│   └── examples/          # Benchmarking echo server & client ping
└── typescript/            # TypeScript / Node.js / Browser SDK
    ├── package.json
    ├── tsconfig.json
    ├── src/               # Complete wire framing, WebCrypto/Node crypto & opcode mapping
    └── examples/          # Client & server integration examples
```

---

## 🚀 Quick Start (Rust)

```rust
use onp_core::{OnpSession, LogicalOpcode, Packet};

// 1. Establish session with dynamic opcode seed
let mut session = OnpSession::new_client();
let syn_packet = session.create_handshake_syn()?;

// 2. Transmit packet over wire...
// After handshake:
let ping_payload = b"PING_TIMESTAMP_12345678";
let encrypted_frame = session.encrypt_packet(LogicalOpcode::SysPing, ping_payload)?;

// 3. Receiver decrypts & automatically maps polymorphic opcode
let (opcode, data) = server_session.decrypt_packet(&encrypted_frame)?;
assert_eq!(opcode, LogicalOpcode::SysPing);
```

---

## 🚀 Quick Start (TypeScript / Node.js)

```typescript
import { OnpClientSession, LogicalOpcode } from './src';

// 1. Initialize client session
const client = new OnpClientSession();
const synPacket = client.createHandshakeSyn();

// 2. Encrypt application message with dynamic polymorphic opcode
const payload = new TextEncoder().encode("Hello Opela Core");
const frame = client.encrypt(LogicalOpcode.LobbyJoin, payload);

// 3. Send over TCP / WebSocket
socket.write(frame);
```

---

## 🔒 Cryptographic Primitives

- **Key Agreement**: `Curve25519` (X25519 ECDH)
- **Key Derivation**: `HKDF-SHA256` (RFC 5869)
- **Authenticated Encryption**: `ChaCha20-Poly1305` (RFC 8439)
- **Polymorphic Opcode Hash**: `HMAC-SHA256`

---

## 📄 License
MIT License. Built with pride for Opela Nexus and high-performance privacy-centric applications.
