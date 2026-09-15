# Frequently Asked Questions (FAQ)

## 1. Why not just use standard TLS / HTTPS?

Standard TLS has three major limitations in adversarial or high-throughput environments:
1. **Metadata Leakage**: TLS handshakes transmit domain names (via SNI) in plaintext or predictable formats. Middleboxes and ISPs can easily see the host you are connecting to, even if they cannot read the encrypted payload.
2. **Predictable Packet Signatures**: HTTPS requests produce recognizable packet bursts and size patterns that allow machine learning DPI filters to classify traffic (e.g. video streaming vs. gaming vs. file download).
3. **Framing & CPU Overhead**: Parsing HTTP headers and large JSON strings creates significant GC pressure in managed languages and dynamic memory allocations in native code.

ONP produces constant-entropy pseudorandom noise with zero plaintext headers, hiding both the payload and the action being performed.

---

## 2. Can Wireshark or an ISP inspect what I am doing?

No. An eavesdropper recording wire traffic only sees:
- The initial 2-byte magic `ON` and length field.
- Pure high-entropy ChaCha20-Poly1305 ciphertext.

Because command opcodes are polymorphically permuted on every session, an observer cannot determine whether a 100-byte packet is a player movement, an RPC ping, or a database query.

---

## 3. How does ONP compare to WireGuard or QUIC?

- **WireGuard**: Operates at Layer 3 (IP network interface level) designed for full-system VPN tunneling. ONP operates at Layer 5/7 (Application Transport level), meaning applications embed ONP directly without requiring root/administrator permissions, TUN/TAP virtual adapters, or kernel drivers.
- **QUIC**: A multi-stream transport replacing TCP/TLS. ONP can run on top of TCP, WebSockets, or QUIC datagrams, acting as the encrypted message framing and polymorphic state layer.

---

## 4. Does ONP require native C++ compiler tools on Node.js?

No. The TypeScript implementation (`@jynxzio5/onp`) uses audited, pure JavaScript/WebCrypto implementations from `@noble/curves`, `@noble/ciphers`, and `@noble/hashes`. It installs and runs instantly without `node-gyp`, Python, or C++ compilers.

---

## 5. Can I use ONP in my own proprietary or commercial software?

Yes. The open-source `ONP-SDK` protocol engine is licensed under the permissive **MIT License**. You are free to integrate it into commercial desktop applications, game launchers, mobile apps, or proprietary servers without paying royalties or open-sourcing your own application logic.
