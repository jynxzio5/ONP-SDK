# ONP Documentation Index

Welcome to the official technical documentation for the Opela Nexus Protocol (ONP).

---

## Documentation Directory

### 1. Protocol Architecture
- [Protocol Specification](01-architecture/protocol-specification.md): Byte-level binary framing layout, header fields, flags, and size limits.
- [Handshake Flow](01-architecture/handshake-flow.md): Ephemeral Curve25519 (X25519) Diffie-Hellman exchange, HKDF key derivation, and transcript signing.
- [State Machine](01-architecture/state-machine.md): Session lifecycle states (`DISCONNECTED`, `HANDSHAKING`, `ACTIVE`, `TERMINATED`) and memory zeroization.

### 2. Security & Cryptography
- [Threat Model & Mitigations](02-security-and-crypto/threat-model.md): Deep Packet Inspection (DPI) evasion, MITM prevention, DoS resistance, and forward secrecy.
- [Cryptographic Primitives](02-security-and-crypto/cryptographic-primitives.md): RFC standards compliance (RFC 7748, RFC 8439, RFC 8032, RFC 5869).
- [Polymorphic Rolling Opcodes](02-security-and-crypto/polymorphic-opcodes.md): Mathematical explanation of seed-based opcode permutation and anti-fingerprinting.
- [Anti-Replay Sliding Window](02-security-and-crypto/anti-replay-window.md): Monotonic 96-bit sequence validation and 64-packet bitmap mechanics.

### 3. Implementation Guides
- [Getting Started with TypeScript](03-guides/getting-started-typescript.md): Node.js, WebViews (Tauri/Electron), and browser client/server usage.
- [Getting Started with Rust](03-guides/getting-started-rust.md): Low-level in-memory framing and Tokio TCP server examples.
- [Universal ONP Wire Tunnel](03-guides/universal-wire-tunnel.md): Routing standard HTTP/REST endpoints through encrypted binary WebSocket frames.
- [Error Handling & Resilience](03-guides/error-handling.md): Protocol error codes, automatic reconnection, and frame verification failures.

### 4. Benchmarks & Comparisons
- [Performance & Overhead Comparison](04-benchmarks/performance-comparison.md): Microbenchmarks, memory allocations, and comparison against HTTPS/REST and plain WebSockets.

### 5. Frequently Asked Questions
- [FAQ](05-faq.md): Common questions regarding DPI, WireGuard/QUIC comparisons, and commercial licensing.
