# ONP Session State Machine

## Overview

An ONP connection progresses through discrete states to guarantee that unauthenticated or unencrypted payloads are rejected prior to completing the cryptographic handshake.

---

## 1. State Transition Diagram

```text
    +-------------------+
    |   DISCONNECTED    |
    +-------------------+
              |
              | connect() / receive_connection()
              v
    +-------------------+
    |    HANDSHAKING    | <--- Ephemeral X25519 exchange in progress
    +-------------------+
              |
              | Key agreement verified & keys derived
              v
    +-------------------+
    |      ACTIVE       | <--- Full AEAD ChaCha20-Poly1305 encryption active
    +-------------------+
              |
              | destroy() / timeout / network drop / sliding window panic
              v
    +-------------------+
    |    TERMINATED     | <--- Memory explicitly zeroized
    +-------------------+
```

---

## 2. State Invariants

### 1. `DISCONNECTED`
- No socket active.
- Key vectors and sequence numbers are unitialized or zeroed.

### 2. `HANDSHAKING`
- Ephemeral Curve25519 keypair is generated in memory.
- Inbound frames must have either `HANDSHAKE_SYN` or `HANDSHAKE_ACK` flag set.
- Any frame with `ENCRYPTED` flag in this state triggers immediate connection abortion (`ProtocolError::UnexpectedFrame`).
- Handshake timeout enforced (default: 8,000 ms). If the handshake is not finalized within this duration, socket is dropped.

### 3. `ACTIVE`
- Both peers hold derived `ClientKey`, `ServerKey`, and `OpcodeSeed`.
- All transmitted frames must have `Flags::ENCRYPTED = 0x04`.
- Every incoming frame is checked against the **Anti-Replay Sliding Window** before attempting decryption.
- Polymorphic opcode mapping is active.

### 4. `TERMINATED`
- Calling `.destroy()` executes an explicit memory zeroization routine over:
  - Private Curve25519 secret key
  - Derived transmission keys (`tx_key`, `rx_key`)
  - 32-byte `OpcodeSeed`
  - Replay sliding window bitmask
- Once in `TERMINATED`, the session object cannot be re-activated. A new session must be created.
