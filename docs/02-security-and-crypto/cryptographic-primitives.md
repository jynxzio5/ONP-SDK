# ONP Cryptographic Primitives Reference

## Standards Compliance

The Opela Nexus Protocol exclusively uses modern, high-security, constant-time cryptographic primitives standardized by the IETF:

| Primitive | Purpose | RFC / Specification | Security Strength |
| :--- | :--- | :--- | :--- |
| **Curve25519 (X25519)** | Ephemeral Key Exchange | [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748) | 128-bit security (~3072-bit RSA equivalent) |
| **ChaCha20-Poly1305** | Authenticated Encryption (AEAD) | [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439) | 256-bit symmetric security |
| **Ed25519** | Host Identity Signature Verification | [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032) | 128-bit security |
| **HKDF-SHA256** | Key Derivation Function | [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869) | 256-bit PRK expansion |
| **HMAC-SHA256** | Polymorphic Opcode Shuffling | [RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104) | 256-bit keyed hash |

---

## 1. Curve25519 (X25519) ECDH

Curve25519 is an elliptic curve designed for Diffie-Hellman operations over the prime field $2^{255} - 1$.

- **Montgomery Curve Equation**: $y^2 = x^3 + 486662x^2 + x$
- **Base Point**: $x = 9$
- **Immunity**: Immune to timing attacks, cache attacks, and invalid-curve attacks by design.
- **Key Sizes**: 32-byte private key, 32-byte public key.

---

## 2. ChaCha20-Poly1305 AEAD

ChaCha20-Poly1305 combines the 256-bit ChaCha20 stream cipher with the Poly1305 authenticator.

- **Key Size**: 32 bytes (256 bits).
- **Nonce Size**: 12 bytes (96 bits), derived from the monotonic frame sequence counter.
- **Associated Authenticated Data (AAD)**: In ONP, the 8-byte outer envelope header (`Magic`, `Version`, `Flags`, `PayloadLength`) is passed as AAD. Any tampering with flags or length immediately invalidates the Poly1305 tag before ciphertext decryption occurs.
- **Tag Size**: 16 bytes (128 bits).

---

## 3. Ed25519 Digital Signatures

Ed25519 is an EdDSA signature scheme using SHA-519 and Curve25519 in Edwards form:

- **Equation**: $-x^2 + y^2 = 1 - \frac{121665}{121666} x^2 y^2$
- **Application in ONP**: The server identity key is a long-term Ed25519 keypair. The client verifies the server's signature over the handshake transcript. Because Ed25519 verification is deterministic, there is zero risk of nonce reuse vulnerabilities.
