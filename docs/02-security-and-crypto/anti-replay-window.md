# Anti-Replay Sliding Window

## Overview

Replay attacks occur when an attacker intercepts a legitimate authenticated packet and re-transmits it at a later time to trigger actions (such as duplicating in-game purchases, repeating state commands, or causing desynchronization).

ONP implements an $O(1)$ constant-time **Sliding Window Bitmap Filter** modeled on IPsec (RFC 4303) and WireGuard.

---

## 1. Sliding Window Mechanics

Each session tracks:
- `last_seq`: The highest valid sequence number accepted so far (64-bit integer).
- `window_bitmap`: A 64-bit unsigned integer representing the reception state of the last 64 sequence numbers.

```text
       <-- Older Packets                      Newer Packets -->
       [ 0 | 1 | 1 | 1 | 0 | 1 | ... | 1 | 1 ]   (64-bit Bitmap)
                                             ^
                                             |
                                         last_seq
```

---

## 2. Inbound Packet Validation Rules

When a packet with sequence number $S$ arrives:

### Case 1: Packet is strictly ahead of window ($S > \text{last\_seq}$)
1. Compute the sequence advance delta: $\Delta = S - \text{last\_seq}$.
2. If $\Delta > 64$, all previous history is shifted out; `window_bitmap` is cleared and bit 0 is set.
3. If $\Delta \le 64$, shift `window_bitmap` left by $\Delta$ bits, set the lowest bit to `1`, and update $\text{last\_seq} = S$.
4. **Result**: Packet is accepted for cryptographic authentication.

### Case 2: Packet falls within window ($S \le \text{last\_seq}$ and $\text{last\_seq} - S < 64$)
1. Compute offset from head: $K = \text{last\_seq} - S$.
2. Check bit at position $K$ in `window_bitmap`:
   - If bit is `1`: The packet has **already been processed**. Drop immediately as a duplicate/replay attack.
   - If bit is `0`: Set bit to `1`. Accept packet as a delayed, out-of-order frame.

### Case 3: Packet is older than the window ($\text{last\_seq} - S \ge 64$)
- The packet is too old to verify reliably. Drop immediately.

---

## 3. Complexity & Performance

- **Time Complexity**: $O(1)$ constant time (bitwise shift, bitwise AND, and integer comparison).
- **Space Complexity**: 16 bytes of RAM per session (8-byte `u64` sequence + 8-byte `u64` bitmask).
- **Zero Allocations**: No hashes, heap lists, or database queries are performed to detect replays.
