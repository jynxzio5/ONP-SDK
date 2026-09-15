# ONP vs. HTTPS: Security Architecture, Anti-Tampering, and Trade-Offs

This document provides a technical comparison between the Opela Nexus Protocol (ONP) and standard HTTPS/REST, analyzing security guarantees, anti-tampering capabilities, network metadata leakage, framing efficiency, and operational trade-offs.

---

## 1. Executive Summary

Standard HTTPS (TLS 1.2/1.3 + HTTP/1.1 or HTTP/2) was designed to protect data in transit between a web browser and a trusted server across an untrusted network. However, HTTPS assumes the client operating environment itself is trusted.

In scenarios where the client environment is untrusted—such as desktop game clients, mobile applications, proprietary licensing daemons, and embedded hardware—HTTPS presents severe vulnerabilities:
- **Trivial Local Proxy Interception**: Users can install root certificates in the OS trust store to decrypt, log, and forge HTTPS requests using proxy tools (Charles, Fiddler, Burp Suite).
- **Network Metadata Leakage**: Server Name Indication (SNI) in TLS `ClientHello` packets broadcasts the destination hostname in plaintext.
- **Static Endpoint Fingerprinting**: Predictable URLs (e.g., `POST /api/v1/auth`) and JSON schemas allow automated detection, rate-limiting, and firewall blacklisting.
- **High Protocol Overhead**: 400 to 1,200 bytes of ASCII metadata per transaction degrades throughput for real-time applications.

ONP was engineered to solve these exact limitations through direct ephemeral Curve25519 key agreements, transcript-bound Ed25519 authentication, polymorphic rolling opcodes, and ultra-compact 38-byte binary framing.

---

## 2. Security & Anti-Tampering Comparison

### Local Proxy Interception & Response Forgery

| Attack Vector | Standard HTTPS / REST | Opela Nexus Protocol (ONP) |
| :--- | :--- | :--- |
| **Trust Model** | Hierarchical X.509 Certificate Authorities (CAs) stored in operating system trust stores. | Direct peer-to-peer Ephemeral Diffie-Hellman (X25519) + Ed25519 host key pinning. |
| **User-Installed Root CAs** | **Vulnerable**: A user can install a proxy CA in Windows CertMgr, macOS Keychain, or Android/iOS Settings to silently decrypt traffic. | **Immune**: ONP does not query or respect OS certificate stores. The proxy cannot compute the shared secret or sign the transcript. |
| **SSL Pinning Bypass (Frida / Objection)** | **Vulnerable**: Hooking `SSLHandshake`, `SecTrustEvaluate`, or `X509TrustManager` in memory disables pinning instantly. | **Immune**: ONP uses custom native Rust/C crypto routines (`onp_ffi`) rather than system TLS frameworks. Hooking generic OS APIs has no effect. |
| **API Response Spoofing** | **Trivial**: Attackers can intercept `/api/license/verify` and replace `{"valid":false}` with `{"valid":true}` in Burp Suite. | **Cryptographically Blocked**: Packets are protected with ChaCha20-Poly1305. Any modified byte fails AEAD authentication and is immediately discarded. |

---

### Network Metadata & Deep Packet Inspection (DPI)

| Dimension | Standard HTTPS / REST | Opela Nexus Protocol (ONP) |
| :--- | :--- | :--- |
| **Server Name Indication (SNI)** | Transmitted in **plaintext** inside the TLS `ClientHello` packet unless Encrypted Client Hello (ECH) is universally deployed. | **Zero hostnames on the wire**. Connection targets are never broadcast within the protocol framing. |
| **Application Layer Paths** | Plaintext URLs and endpoints (e.g., `/api/v1/game/token`, `/telemetry`) are exposed to anyone terminating TLS. | Zero URLs, headers, or query parameters. The entire application payload is binary ciphertext. |
| **Command Fingerprinting** | Identifiable by request method (`GET`, `POST`), content length, and JSON structure. | **Polymorphic Opcodes**: Command IDs mutate pseudorandomly per session using an ephemeral HMAC-SHA256 seed. |
| **Wire Entropy** | Predictable ASCII HTTP headers and repeated JSON keys result in distinct compressibility signatures. | Payload after the 8-byte envelope header is cryptographically indistinguishable from random noise. |

---

## 3. Protocol Overhead and Latency

### Framing Efficiency

For a minimal application payload of 64 bytes (such as a heartbeat, telemetry coordinate, or authentication token):

```text
Standard HTTPS Request (HTTP/1.1 over TLS 1.3):
+-------------------------------------------------------------+
| TLS Record Header (5B)                                      |
| HTTP Request Line: POST /api/v1/auth HTTP/1.1 (28B)         |
| Host: auth.nexus.internal (27B)                             |
| User-Agent: Mozilla/5.0 ... (85B)                           |
| Authorization: Bearer eyJhbGciOi... (140B)                  |
| Content-Type: application/json (30B)                        |
| Content-Length: 64 (19B)                                    |
| Cookie: session_id=... (48B)                                |
| TLS MAC Tag (16B)                                           |
| Payload: {"token":"..."} (64B)                              |
+-------------------------------------------------------------+
Total Transmitted: ~462 bytes (Payload efficiency: 13.8%)

ONP Binary Wire Frame:
+-------------------------------------------------------------+
| Envelope Header: Magic (2B) + Ver (1B) + Flags (1B) + Len (4B) = 8B
| AEAD Nonce: Monotonic Sequence Counter (12B)               |
| Ciphertext: Polymorphic Opcode (2B) + Payload (64B)        |
| Authentication Tag: Poly1305 MAC (16B)                     |
+-------------------------------------------------------------+
Total Transmitted: 102 bytes (Payload efficiency: 62.7%)
```

### Serialization Latency
- **HTTPS/REST**: Requires string encoding, JSON serialization (`JSON.stringify` / `serde_json`), header parsing, and string matching on routing paths.
- **ONP**: Uses packed little-endian binary buffers. Envelopes and sequence numbers are parsed in nanoseconds without dynamic memory allocations (`zerocopy`).

---

## 4. Anti-Replay Protection

- **HTTPS**: TLS protects against replay within an individual TLS session. However, application-layer HTTP requests can often be replayed if intermediate servers do not implement strict idempotency keys, nonces, or database timestamp tracking.
- **ONP**: Enforces a built-in 64-packet bitmask sliding window at the wire level:
  - Every packet carries a 96-bit monotonic sequence counter.
  - Duplicates are detected and rejected in `O(1)` time using in-register bitwise operations (`bitmap & (1 << diff)`).
  - Out-of-window or replayed frames fail before reaching the application layer.

---

## 5. Operational Trade-Offs (When HTTPS is Preferred)

While ONP provides significant security and performance advantages, developers must consider the operational trade-offs:

### 1. Firewall & Captive Portal Traversal
- **HTTPS**: TCP port 443 with TLS is globally allowed across corporate firewalls, university networks, hotel captive portals, and cellular carriers.
- **ONP**: If running on arbitrary TCP ports (e.g., port 9100), edge firewalls may block the traffic.
  - *Mitigation*: ONP supports encapsulation inside standard binary WebSockets (`wss://`) over port 443, allowing it to traverse all standard proxies and firewalls without compromising binary encryption or polymorphic framing.

### 2. Edge Infrastructure & CDN Integration
- **HTTPS**: Can be fronted by managed edge networks (Cloudflare, AWS CloudFront, Fastly) for global anycast routing, edge caching, and automated DDoS mitigation.
- **ONP**: Because ONP is a stateful binary protocol, edge CDNs cannot terminate or cache packets without full protocol integration. It requires persistent backend daemon processes (implemented in Rust, Node.js, or Go).

### 3. Client Binary Dependencies
- **HTTPS**: Modern operating systems (Windows, macOS, Linux, iOS, Android) provide built-in HTTP client libraries (`NSURLSession`, `HttpClient`, `WinHttp`) requiring zero external dependencies.
- **ONP**: Native integration requires bundling `onp-ffi` (~250 KB shared library or static archive) or the TypeScript engine, introducing native code that client integrity verifiers must accommodate.

---

## 6. Architectural Decision Matrix

| Requirement | Recommended Protocol | Architectural Justification |
| :--- | :--- | :--- |
| **Public Web Frontends (SEO, Browser Caching)** | **HTTPS / REST** | Browsers require standard HTTP semantics, CDN asset caching, and CORS support. |
| **Client Anti-Tampering & Licensing** | **ONP** | Eliminates local proxy interception (Burp Suite, Charles) and response spoofing. |
| **Game Networking & Real-Time Telemetry** | **ONP** | Sub-millisecond parsing, 38-byte framing overhead, and anti-replay sliding window. |
| **Censorship & DPI Resistance** | **ONP** | No SNI domain exposure, no ASCII headers, and polymorphic mutating opcodes. |
| **Standard Third-Party REST Integrations** | **HTTPS / REST** | Standardized OpenAPI / Swagger contracts and HTTP status codes. |
| **Secure Internal Microservice Tunnels** | **ONP** | High-throughput binary RPC conduit that resists internal network snooping. |
