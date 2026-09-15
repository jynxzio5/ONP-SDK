# ONP Threat Model & Defensive Mitigations

## Overview

The Opela Nexus Protocol is designed under the assumption that the underlying network channel is entirely hostile. Intermediate nodes (ISPs, corporate gateways, state-sponsored filtering systems, and local eavesdroppers) may inspect, modify, replay, or inject arbitrary binary data.

---

## Threat Matrix

| Threat Vector | Standard Web (HTTPS / Plaintext WebSockets) | ONP Defense Mechanism |
| :--- | :--- | :--- |
| **Deep Packet Inspection (DPI)** | Exposes TLS Server Name Indication (SNI), request URLs, headers, and predictable packet sizes. | 8-byte fixed envelope header followed by pure pseudorandom ChaCha20-Poly1305 ciphertext. Indistinguishable from white noise. |
| **Static Opcode Fingerprinting** | Attackers map specific user actions to constant RPC method names or numeric message IDs. | **Polymorphic Rolling Opcodes**: Command IDs dynamically mutate on every connection based on cryptographically hashed seeds. |
| **Replay & Reflection Attacks** | Stored frames can be replayed to trigger unauthorized state changes or consume resources. | **Monotonic 96-bit Nonces & 64-bit Sliding Window**: Duplicate packets are dropped in O(1) CPU time before decryption. |
| **Man-in-the-Middle (MitM)** | Vulnerable to rogue CA roots, enterprise SSL inspection appliances, or splitters. | **Ed25519 Host Key Verification**: Server signs a 96-byte handshake transcript with its pinned identity key. |
| **Memory Dump Extraction** | Session keys remain resident in heap space after connection teardown. | **Active Zeroization**: Memory vectors holding secret keys and PRKs are explicitly wiped with zeros upon `.destroy()`. |
| **CPU Exhaustion DoS** | Parsing large JSON payloads requires recursive string allocations and parsing. | **Strict Bound Checks**: Frame headers are validated in 8 bytes; unauthenticated frames are dropped before payload decryption. |

---

## Defensive Implementations

### 1. DPI Wire Obfuscation
Beyond the first 8 bytes (`Magic` + `Version` + `Flags` + `PayloadLength`), every byte transmitted across the wire has high entropy ($H \approx 8.0 \text{ bits/byte}$). To an external packet sniffer like Wireshark, the payload contains neither strings, nor identifiable delimiters, nor repeated token signatures.

### 2. Window-Jumping DoS Protection
In basic sliding window filters, an attacker can inject a frame with an artificially inflated sequence number (e.g. $2^{31}$). If unchecked, this would advance the sliding window so far forward that all legitimate subsequent packets are dropped.

ONP defends against this via **Window Jump Rejection**:
- Sequence numbers advancing by more than the maximum window size ($W = 64$) without a valid cryptographic Poly1305 MAC tag are dropped.
- The window is only advanced **after** the AEAD decryption and MAC authentication succeed.

### 3. Forward Secrecy Guarantee
Because all symmetric keys are derived exclusively from ephemeral Curve25519 keypairs created in volatile RAM, an adversary who records wire traffic and later compromises the server's long-term host identity key cannot decrypt past traffic.
