<p align="center">
  <img src="assets/onp-logo.png" alt="Opela Nexus Protocol (ONP) Logo" width="280" />
</p>

<h1 align="center">Opela Nexus Protocol (ONP)</h1>

<p align="center">
  <strong>Next-Generation Zero-Knowledge Polymorphic Binary Transport Protocol</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT" /></a>
  <a href="SPECIFICATION.md"><img src="https://img.shields.io/badge/ONP-v1.0.0-emerald.svg" alt="Protocol Version: 1.0" /></a>
  <a href="rust/"><img src="https://img.shields.io/badge/Rust-1.75%2B-orange.svg" alt="Rust: 2021 Edition" /></a>
  <a href="typescript/"><img src="https://img.shields.io/badge/TypeScript-5.x-blue.svg" alt="TypeScript: 5.x" /></a>
  <a href="https://www.npmjs.com/package/@opela-team/onp"><img src="https://img.shields.io/npm/v/@opela-team/onp.svg?color=crimson" alt="npm package" /></a>
  <a href="docs/"><img src="https://img.shields.io/badge/Documentation-Complete-purple.svg" alt="Documentation" /></a>
</p>

---

## Documentation Index

Comprehensive technical guides and RFC specifications are available in the [`docs/`](docs/) directory:

- [Protocol Specification (RFC v1.0.0)](docs/01-architecture/protocol-specification.md)
- [Cryptographic Handshake & Key Derivation](docs/01-architecture/handshake-flow.md)
- [Session State Machine & Memory Zeroization](docs/01-architecture/state-machine.md)
- [Threat Model & DPI Defense](docs/02-security-and-crypto/threat-model.md)
- [Cryptographic Primitives Reference](docs/02-security-and-crypto/cryptographic-primitives.md)
- [Polymorphic Rolling Opcodes Guide](docs/02-security-and-crypto/polymorphic-opcodes.md)
- [Anti-Replay Sliding Window Filter](docs/02-security-and-crypto/anti-replay-window.md)
- [ONP vs. HTTPS: Security & Trade-Offs](docs/02-security-and-crypto/onp-vs-https.md)
- [C and C++ Integration Guide](docs/03-guides/cpp-integration.md)
- [Mobile Integration Guide (Android, iOS, Flutter, React Native)](docs/03-guides/mobile-integration.md)
- [Rust Integration Guide](docs/03-guides/getting-started-rust.md)
- [TypeScript & JavaScript Guide](docs/03-guides/getting-started-typescript.md)
- [Python Integration Guide](docs/03-guides/python-integration.md)
- [C# / .NET & Unity Guide](docs/03-guides/csharp-dotnet.md)
- [Go Integration Guide](docs/03-guides/golang-integration.md)
- [Multi-Platform Deployment Guide](docs/03-guides/platforms.md)
- [Universal ONP Wire Tunnel Guide](docs/03-guides/universal-wire-tunnel.md)
- [Error Handling & Resilience](docs/03-guides/error-handling.md)
- [Performance & Overhead Benchmarks](docs/04-benchmarks/performance-comparison.md)
- [Frequently Asked Questions (FAQ)](docs/05-faq.md)

---

## Overview

Opela Nexus Protocol (ONP) is a high-throughput, low-latency, zero-knowledge binary communication protocol designed to eliminate the metadata leakage, performance overhead, and predictable attack surface of standard application-layer protocols such as HTTP/REST, GraphQL, and plaintext WebSockets.

Modern internet traffic is vulnerable to Deep Packet Inspection (DPI), heuristic traffic shaping, stateful firewall interception, and MITM analysis because traditional protocols transmit predictable plaintext headers (such as `Host`, `User-Agent`, and `Authorization`), static API endpoints, and recognizable JSON schemas.

ONP replaces human-readable text and static endpoints with an ultra-compact 8-byte binary envelope, ephemeral Curve25519 (X25519) key agreements, hardware-accelerated ChaCha20-Poly1305 authenticated encryption, and dynamically mutating polymorphic rolling opcodes. Beyond the initial framing envelope, every byte transmitted over the wire is indistinguishable from cryptographic pseudorandom noise.

---

## Core Pillars & Architectural Principles

### 1. Zero Text on the Wire
Traditional web requests spend between 400 and 1,200 bytes transmitting ASCII metadata before any payload bytes are transferred. ONP completely eliminates ASCII serialization over the wire. All control metadata is packed into fixed-size numeric bitfields, reducing protocol framing overhead by over 95%.

### 2. Polymorphic Rolling Opcodes
Network monitoring appliances, firewalls, and reverse-engineers rely on static command identifiers to fingerprint actions (such as identifying login requests, download triggers, or game state updates). 

ONP neutralizes this vector via cryptographically seeded opcode permutation:
- During the cryptographic handshake, an ephemeral 32-byte Opcode Seed is derived.
- Logical application opcodes (e.g., `DATA_STREAM`, `DOWNLOAD_MANIFEST`, `GAME_UPDATE`) are passed through an HMAC-SHA256 deterministic shuffle function.
- The resulting physical wire opcode changes on every single connection. An attacker inspecting two identical actions across two sessions observes completely unrelated numeric values.

### 3. Ephemeral Forward Secrecy & Mutual Verification
- **Perfect Forward Secrecy (PFS)**: Each session generates dynamic Curve25519 keypairs in RAM. Master secrets are derived via HKDF-SHA256 and never written to disk.
- **Ed25519 Host Key Verification**: During the connection handshake, the server signs a 96-byte transcript `[ClientPub || ClientNonce || ServerPub || ServerNonce]` using its private host identity key. The client verifies this signature before session keys are active, rendering Man-in-the-Middle (MitM) proxies, TLS splitters, and spoofed endpoints immediately non-functional.
- **Memory Zeroization**: Calling session teardown explicitly scrubs ephemeral keys and state vectors from memory, preventing memory-dump recovery.

### 4. Anti-Replay Sliding Window
Every encrypted packet carries a 96-bit monotonic sequence counter validated against a 64-bit sliding window filter:
- Duplicated or replayed packets are rejected at the lowest network layer in O(1) CPU time.
- Packets jumping out of the sliding window are immediately dropped, preventing state-exhaustion and replay denial-of-service vectors.

### 5. Universal Wire Tunnel
ONP provides an integrated Wire Tunnel interface that transparently encapsulates standard HTTP/REST requests inside encrypted binary WebSocket or TCP frames. APIs, manifest delivery endpoints, and configuration fetches execute through the encrypted stream without exposing URLs, query parameters, or target hostnames to intermediate network hops.

---

## Supported Projects & Use Cases

ONP is designed for applications requiring high-throughput binary transmission, wire-level confidentiality, and immunity to network throttling:

- **Game Launchers & Distribution Clients**: Fast, secure delivery of manifests, differential update payloads, and authentication tokens without exposing backend storage origins or content pipelines.
- **Real-Time Multiplayer & Engine Networking**: Low-latency binary input replication, player state synchronization, and lobby management for game engines (Unreal Engine, Unity, Godot, Bevy).
- **Private Peer-to-Peer & Mesh Overlays**: Encrypted node-to-node relay systems and decentralized service discovery where ISP observation must be prevented.
- **Desktop Companion & System Applications**: Tauri, Electron, and native desktop clients requiring tamper-proof IPC or telemetry conduits to remote backend clusters.
- **Protected Microservice & Daemon Communication**: High-throughput headless daemons (Node.js / Rust / Go) exchanging structured binary messages across untrusted networks.
- **Bypass & Censorship-Resistant Proxies**: Wire-level obfuscation allowing traffic to pass through restrictive enterprise firewalls, educational filters, and state-level DPI gateways.

---

## Supported Platforms & Environments

ONP has zero native C/C++ compilation requirements and runs across all major operating systems, embedded architectures, and execution runtimes:

### Operating Systems
- **Windows**: Windows 10, Windows 11, Windows Server (x86_64, ARM64)
- **Linux**: Ubuntu, Debian, Fedora, Arch, Alpine, CentOS, RHEL (x86_64, aarch64, musl, glibc)
- **macOS**: Apple Silicon (M1/M2/M3/M4) and Intel (x86_64)
- **Mobile**: Android and iOS (via WebView runtime or compiled Rust FFI static/dynamic libraries)

### Web & Embedded Runtimes
- **Desktop Frameworks**: Tauri (WebView2 on Windows, WebKitGTK on Linux, WKWebView on macOS), Electron, Wails
- **Web Browsers**: Google Chrome, Mozilla Firefox, Apple Safari, Microsoft Edge, Opera, Brave
- **Server Runtimes**: Node.js (18.x, 20.x, 22.x, 24.x), Bun (1.0+), Deno (1.30+)

---

## Supported Languages & Implementations

| Language | Package / Module | Primary Capabilities |
| :--- | :--- | :--- |
| **Rust** | [`rust/onp-core`](rust/onp-core/)<br>[`rust/onp-transport`](rust/onp-transport/) | High-performance zero-copy deserialization (`bytes`), Tokio async networking, polymorphic opcode engine, ChaCha20-Poly1305. |
| **TypeScript / JavaScript** | [`typescript/`](typescript/) | Pure WebCrypto & Noble ciphers, zero external C++ bindings, universal isomorphic support across Node.js, WebViews, and browsers. |
| **C / C++** | [`rust/onp-ffi`](rust/onp-ffi/)<br>[`include/onp.h`](rust/onp-ffi/include/onp.h) | Stable C-ABI dynamic (`.dll`/`.so`/`.dylib`) and static (`.lib`/`.a`) libraries for Unreal Engine, custom game engines, and native servers. |
| **Mobile (Android & iOS)** | [`docs/03-guides/mobile-integration.md`](docs/03-guides/mobile-integration.md) | Kotlin/JNI on Android, Swift/XCFramework on iOS, Flutter Dart FFI, and React Native. |
| **Python** | [`docs/03-guides/python-integration.md`](docs/03-guides/python-integration.md) | Standard library `ctypes` bindings and `asyncio` networking with native performance. |
| **C# (.NET) / Unity** | [`docs/03-guides/csharp-dotnet.md`](docs/03-guides/csharp-dotnet.md) | P/Invoke `DllImport`, memory pinning, and Unity game engine client integration. |
| **Go** | [`docs/03-guides/golang-integration.md`](docs/03-guides/golang-integration.md) | Cgo bindings with zero-copy buffer passing and `net.Conn` streaming sockets. |

---

## Architecture & Modules

- **Core Protocol Engine ([`rust/onp-core`](rust/onp-core/))**: High-throughput binary framing, ChaCha20-Poly1305 AEAD, X25519 ECDH, and seed-derived polymorphic opcode permutation.
- **Async Network Transport ([`rust/onp-transport`](rust/onp-transport/))**: Tokio-based asynchronous TCP framing, codec encoders/decoders, and state machines.
- **C-ABI Native FFI ([`rust/onp-ffi`](rust/onp-ffi/))**: C99 and C++ compatible dynamic (`.dll`/`.so`/`.dylib`) and static (`.lib`/`.a`) libraries for Unreal Engine, Unity, custom game engines, and mobile runtimes.
- **TypeScript / JavaScript SDK ([`typescript/`](typescript/))**: Published as [`@opela-team/onp`](https://www.npmjs.com/package/@opela-team/onp) on npm for Node.js, WebViews (Tauri, Electron), and browsers.

---

## Packet Wire Layout

Every ONP packet is structured into a strictly packed binary layout without dynamic padding:

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

### Framing Fields:
- **Magic (2 Bytes)**: ASCII `ON` (`0x4F`, `0x4E`) identifying ONP framing.
- **Version (1 Byte)**: Current protocol specification version (`0x01`).
- **Flags (1 Byte)**: Bitmask controlling frame semantics (`HANDSHAKE_SYN = 0x01`, `HANDSHAKE_ACK = 0x02`, `ENCRYPTED = 0x04`, `COMPRESSED = 0x08`, `ERROR = 0x80`).
- **Payload Length (4 Bytes)**: 32-bit little-endian unsigned integer indicating ciphertext byte length.
- **Nonce (12 Bytes)**: 96-bit sequence number preventing replay and reordering attacks.
- **Ciphertext**: Authenticated encrypted payload containing the 2-byte polymorphic opcode and application data.
- **Poly1305 Tag (16 Bytes)**: Cryptographic message authentication code verifying wire integrity.

---

## Quick Start: TypeScript / JavaScript

### Installation
Install the official client/server SDK from the public npm registry:

```bash
npm install @opela-team/onp
```

### WebSocket Client Example

```typescript
import { OnpWebSocketClient } from '@opela-team/onp';

const client = new OnpWebSocketClient({
  url: 'wss://example.com/ws',
  autoConnect: true,
});

client.on('connection_ready', async () => {
  console.log('ONP session established with verified host identity.');

  // 1. Send encrypted real-time event
  client.send('user_presence', { status: 'online', channel: 'lobby' });

  // 2. Correlated Request / Response
  const response = await client.request('check_game_update', { appId: '480' }, 5000);
  console.log('Response:', response);

  // 3. Universal Wire Tunnel (REST over encrypted binary WebSocket)
  const tunnelRes = await client.tunnelRequest('GET', 'https://api.internal/v1/config');
  console.log('Tunnel Data:', tunnelRes.data);
});

client.on('direct_message', (payload) => {
  console.log('Received decrypted message:', payload);
});
```

---

## Quick Start: Rust Core

Add the crate to your `Cargo.toml`:

```toml
[dependencies]
onp-core = { path = "rust/onp-core" }
tokio = { version = "1.0", features = ["full"] }
```

### Session Encryption & Decryption

```rust
use onp_core::session::OnpSession;
use onp_core::constants::LogicalOpcode;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize client and server sessions
    let mut client = OnpSession::new_client();
    let mut server = OnpSession::new_server();

    // 2. Execute Ephemeral Curve25519 Handshake
    let syn_frame = client.create_handshake_syn()?;
    let ack_frame = server.process_handshake_syn(&syn_frame)?;
    client.process_handshake_ack(&ack_frame)?;

    // 3. Encrypt payload with polymorphic opcode
    let payload = b"Hello from Rust ONP Core";
    let encrypted_frame = client.encrypt(LogicalOpcode::DataStream, payload)?;

    // 4. Decrypt and verify payload
    let (opcode, decrypted_bytes) = server.decrypt(&encrypted_frame)?;
    println!("Resolved Opcode: {:?}", opcode);
    println!("Decrypted String: {}", String::from_utf8_lossy(&decrypted_bytes));

    Ok(())
}
```

---

## Quick Start: C / C++ Native Engine

Compile the native C-ABI shared library with `cargo build --release -p onp-ffi`. Include `onp.h` and link against `onp_ffi`:

```cpp
#include <iostream>
#include <vector>
#include "onp.h"

int main() {
    // 1. Allocate sessions
    OnpSession* client = onp_session_new_client();
    OnpSession* server = onp_session_new_server();

    // 2. Perform 3-step handshake
    std::vector<uint8_t> syn(256), ack(256);
    size_t syn_len = 0, ack_len = 0;

    onp_session_create_handshake_syn(client, syn.data(), syn.size(), &syn_len);
    onp_session_process_handshake_syn(server, syn.data(), syn_len, ack.data(), ack.size(), &ack_len);
    onp_session_process_handshake_ack(client, ack.data(), ack_len);

    // 3. Encrypt application payload
    std::string msg = "Encrypted packet from C++ engine";
    std::vector<uint8_t> frame(msg.size() + onp_overhead_size());
    size_t frame_len = 0;
    onp_session_encrypt(client, ONP_OPCODE_LOBBY_JOIN, (const uint8_t*)msg.data(), msg.size(), frame.data(), frame.size(), &frame_len);

    // 4. Decrypt and verify payload
    std::vector<uint8_t> decrypted(frame_len);
    size_t dec_len = 0;
    uint16_t opcode = 0;
    onp_session_decrypt(server, frame.data(), frame_len, &opcode, decrypted.data(), decrypted.size(), &dec_len);

    std::cout << "Decrypted (" << dec_len << " bytes): " << std::string((char*)decrypted.data(), dec_len) << std::endl;

    // 5. Clean up memory
    onp_session_destroy(client);
    onp_session_destroy(server);
    return 0;
}
```

See the [C and C++ Integration Guide](docs/03-guides/cpp-integration.md) for full details, socket loops, and Unreal Engine setup.

---

## Cryptographic Primitives Reference

- **Key Agreement**: Curve25519 (X25519 ECDH) per session (RFC 7748)
- **Host Authentication**: Ed25519 Digital Signatures over 96-byte handshake transcripts (RFC 8032)
- **Key Derivation**: HKDF-SHA256 (RFC 5869)
- **Authenticated Encryption**: ChaCha20-Poly1305 AEAD (RFC 8439)
- **Polymorphic Opcode Mutation**: HMAC-SHA256
- **Anti-Replay Protection**: 96-bit monotonic nonce sequence with a 64-packet sliding window filter

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
