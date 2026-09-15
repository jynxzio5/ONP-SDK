# ONP Cryptographic Handshake Flow

## Overview

The ONP handshake establishes mutual forward secrecy in a single round-trip ($1 \times \text{RTT}$) using ephemeral **Curve25519 (X25519)** Diffie-Hellman key agreement, validated by optional **Ed25519 Host Key Verification**.

---

## 1. Handshake Sequence Diagram

```text
    CLIENT                                                     SERVER
      |                                                           |
      | 1. Generate Ephemeral Keypair (C_priv, C_pub)             |
      |    Generate Client Nonce (16B Salt)                       |
      |                                                           |
      | ----------------- HANDSHAKE_SYN (48B Payload) ----------> |
      |      [ C_pub (32B) || C_nonce (16B) ]                     |
      |                                                           |
      |                                                           | 2. Generate Ephemeral Keypair (S_priv, S_pub)
      |                                                           |    Generate Server Nonce (16B Salt)
      |                                                           |    Compute Shared Secret:
      |                                                           |      SS = X25519(S_priv, C_pub)
      |                                                           |    Derive Keys via HKDF-SHA256:
      |                                                           |      [ ClientKey, ServerKey, OpcodeSeed ]
      |                                                           |    (Optional) Sign Transcript with Ed25519:
      |                                                           |      Sig = Ed25519_Sign(HostKey, Transcript)
      |                                                           |
      | <---------------- HANDSHAKE_ACK (48B or 112B) ----------- |
      |      [ S_pub (32B) || S_nonce (16B) || Optional Sig (64B) ]
      |                                                           |
      | 3. (Optional) Verify Ed25519 Signature                    |
      |    Compute Shared Secret:                                 |
      |      SS = X25519(C_priv, S_pub)                           |
      |    Derive Keys via HKDF-SHA256:                           |
      |      [ ClientKey, ServerKey, OpcodeSeed ]                 |
      |    Initialize Polymorphic Opcode Shuffler                 |
      |                                                           |
      | ================= ENCRYPTED SESSION ACTIVE =============  |
      |                                                           |
      | ----------------- Encrypted Frame ----------------------> |
      | <---------------- Encrypted Frame ----------------------- |
```

---

## 2. Handshake Payload Structures

### Step 1: `HANDSHAKE_SYN` Frame
- **Flags**: `HANDSHAKE_SYN = 0x01`
- **Payload Size**: 48 bytes
- **Layout**:
  - `0..32`: Client Ephemeral Curve25519 Public Key ($C_{\text{pub}}$)
  - `32..48`: Client Handshake Salt / Nonce ($C_{\text{nonce}}$, 16 bytes random)

### Step 2: `HANDSHAKE_ACK` Frame
- **Flags**: `HANDSHAKE_ACK = 0x02`
- **Payload Size**: 48 bytes (Standard) or 112 bytes (Host-Verified)
- **Layout**:
  - `0..32`: Server Ephemeral Curve25519 Public Key ($S_{\text{pub}}$)
  - `32..48`: Server Handshake Salt / Nonce ($S_{\text{nonce}}$, 16 bytes random)
  - `48..112`: (Optional) Ed25519 Digital Signature (64 bytes) over the 96-byte transcript:
    $$\text{Transcript} = C_{\text{pub}} \,\|\, C_{\text{nonce}} \,\|\, S_{\text{pub}} \,\|\, S_{\text{nonce}}$$

---

## 3. Cryptographic Key Derivation (HKDF)

Once the shared Diffie-Hellman secret is computed:

$$\text{SharedSecret} = \text{X25519}(\text{PrivateKey}, \text{PeerPublicKey})$$

A unified salt is constructed from both nonces:

$$\text{Salt} = C_{\text{nonce}} \oplus S_{\text{nonce}}$$

The session keys are derived using **HKDF-SHA256 (RFC 5869)**:

```text
PRK = HKDF-Extract(Salt, SharedSecret)

ClientKey  (32 Bytes) = HKDF-Expand(PRK, "ONP-V1-CLIENT-TX-KEY", 32)
ServerKey  (32 Bytes) = HKDF-Expand(PRK, "ONP-V1-SERVER-TX-KEY", 32)
OpcodeSeed (32 Bytes) = HKDF-Expand(PRK, "ONP-V1-OPCODE-SEED",   32)
```

- **Directional Separation**: The client encrypts using `ClientKey`; the server encrypts using `ServerKey`. A compromise of one key does not expose the reverse direction.
- **Dynamic Opcode Seed**: The derived `OpcodeSeed` is fed directly into the polymorphic rolling opcode engine.
