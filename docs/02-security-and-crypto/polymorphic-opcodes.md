# Polymorphic Rolling Opcodes

## Overview

In traditional protocols, commands are identified by static strings or fixed integer constants (e.g. `0x0001 = PING`, `0x0020 = LOGIN`). Observers monitoring packet traffic can deduce user activity simply by watching packet lengths and command IDs.

ONP implements **Polymorphic Rolling Opcodes**, ensuring that physical wire opcodes mutate dynamically on every single connection.

---

## 1. The Polymorphic Permutation Flow

```text
[ Application Code ]
        |
        v
  Logical Opcode: LOBBY_JOIN (0x0020)
        |
        v
[ Opcode Table Engine ] <=== Keyed with 32-Byte Ephemeral OpcodeSeed
        |
        v
  Physical Wire Opcode: 0xD83F (Unique to this connection session)
        |
        v
[ ChaCha20-Poly1305 Encrypted Payload ]
        |
        v
[ Network Wire ]
        |
        v
[ Peer Decrypts Payload ]
        |
        v
[ Inverse Opcode Table Engine ]
        |
        v
  Resolved: LOBBY_JOIN (0x0020)
```

---

## 2. Permutation Algorithm

During session establishment, HKDF-SHA256 outputs a 32-byte `OpcodeSeed`.

For every logical opcode $L \in [0, 65535]$, the wire opcode $P$ is computed using a deterministic keyed permutation function:

```text
HashInput = OpcodeSeed (32B) || BigEndian(LogicalOpcode, 2B)
DerivedHash = HMAC-SHA256(OpcodeSeed, HashInput)

CandidateOpcode = (DerivedHash[0] << 8) | DerivedHash[1]
```

To guarantee an injective bijection (meaning no two logical opcodes map to the same physical wire opcode):
1. Candidate wire opcodes are stored in a lookup set.
2. If a collision occurs ($CandidateOpcode$ already mapped), linear probing with quadratic offset is applied until an unoccupied 16-bit slot is acquired.
3. The forward table `Logical -> Physical` and reverse table `Physical -> Logical` are populated in memory.

---

## 3. Security Benefits

- **Anti-Signature Matching**: Deep Packet Inspection engines cannot write regular expressions or snort/suricata signatures matching command codes.
- **Session Isolation**: Capture files recorded during Session A cannot assist in reverse-engineering or interpreting packets captured during Session B.
- **Zero Overhead**: Because both peers compute the permutation tables locally during the handshake, zero extra negotiation packets are sent across the wire.
