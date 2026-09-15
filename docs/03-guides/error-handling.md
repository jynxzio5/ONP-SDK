# Error Handling & Resilience

## Overview

ONP implements strict, fail-safe error handling. Cryptographic errors, sequence jumps, or framing corruptions immediately trigger defensive resets to prevent state-desynchronization attacks.

---

## 1. Protocol Error Codes

When a peer detects a fatal protocol violation, it transmits an unencrypted or encrypted `ERROR` frame (`Flags::ERROR = 0x20`) carrying a 2-byte error code followed by an optional UTF-8 diagnostic string:

| Code (Hex) | Name | Description | Recommended Action |
| :--- | :--- | :--- | :--- |
| `0x0001` | `INVALID_MAGIC` | Inbound bytes do not start with `ON` (`0x4F`, `0x4E`). | Terminate socket; verify remote endpoint protocol. |
| `0x0002` | `UNSUPPORTED_VERSION` | Version byte $\ne 1$. | Negotiate protocol downgrade or prompt client update. |
| `0x0003` | `PAYLOAD_OVERFLOW` | Declared payload length exceeds 16 MiB. | Disconnect immediately; drop buffer. |
| `0x0004` | `HANDSHAKE_FAILED` | Curve25519 point derivation or Ed25519 signature invalid. | Abort connection. Potential MitM attack detected. |
| `0x0005` | `DECRYPTION_FAILED` | Poly1305 MAC tag validation failed. | Packet was tampered with or corrupted on wire. Drop frame. |
| `0x0006` | `REPLAY_DETECTED` | Monotonic sequence number failed sliding window check. | Packet was replayed or duplicated. Drop silently. |
| `0x0007` | `UNKNOWN_OPCODE` | Inbound physical opcode could not be inverted in opcode table. | Verify peers are operating on synchronized session seed. |

---

## 2. Automatic Reconnection & Exponential Backoff

The TypeScript `OnpWebSocketClient` implements jittered exponential backoff for disconnects:

```typescript
const client = new OnpWebSocketClient({
  url: 'wss://example.com/ws',
  maxReconnectDelayMs: 15000, // Maximum ceiling for delay
});

client.on('error', (err) => {
  console.error('[ONP Error]:', err);
});

client.on('disconnect', () => {
  console.warn('Socket closed. Queued messages will automatically flush upon reconnection.');
});
```

- While disconnected, calls to `client.send()` buffer messages in an internal FIFO queue.
- Once the new handshake completes and keys are derived, all queued messages are encrypted with the **new session key** and transmitted in sequence.
