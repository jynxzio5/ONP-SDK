# Getting Started with TypeScript & JavaScript

## Installation

Install the official client and server SDK from the public npm registry:

```bash
npm install @opela-team/onp
```

---

## Usage Guide

### 1. Connecting via WebSocket

The `OnpWebSocketClient` manages the full connection lifecycle, including automated Curve25519 handshakes, frame encoding, and exponential backoff reconnection:

```typescript
import { OnpWebSocketClient } from '@opela-team/onp';

const client = new OnpWebSocketClient({
  url: 'wss://example.com/ws',
  autoConnect: true,
  heartbeatIntervalMs: 30000,
  maxReconnectDelayMs: 15000,
});

// Fired once the cryptographic handshake completes
client.on('connection_ready', () => {
  console.log('ONP secure connection established.');

  // Transmit real-time event
  client.send('user_presence', {
    status: 'online',
    timestamp: Date.now(),
  });
});

// Handle incoming messages by event name
client.on('chat_message', (payload) => {
  console.log('Decrypted chat payload:', payload);
});

// Handle disconnects
client.on('disconnect', () => {
  console.log('Connection dropped. Client will auto-reconnect.');
});
```

---

### 2. Correlated Request / Response

When your application requires a direct response to a command (like an RPC call or game query), use `client.request()`:

```typescript
async function fetchGameStatus(appId: string) {
  try {
    // Automatically injects a unique _requestId and awaits the correlated response:
    const result = await client.request('check_game_status', { appId }, 5000);
    console.log('Game status:', result);
  } catch (error) {
    console.error('Request timed out or failed:', error);
  }
}
```

---

### 3. Node.js WebSocket Server Implementation

To accept ONP connections in a Node.js backend using the standard `ws` package:

```javascript
const { WebSocketServer } = require('ws');
const { OnpServerSession, Flags } = require('@jynxzio5/onp');

const wss = new WebSocketServer({ port: 8765 });

wss.on('connection', (ws) => {
  let session = null;

  ws.on('message', (rawBytes) => {
    // 1. Detect Handshake SYN
    if ((rawBytes[3] & Flags.HANDSHAKE_SYN) && !session) {
      session = new OnpServerSession();
      const ackFrame = session.processHandshakeSyn(rawBytes);
      ws.send(ackFrame);
      return;
    }

    // 2. Decrypt active encrypted frames
    if (session && (rawBytes[3] & Flags.ENCRYPTED)) {
      const { opcode, data } = session.decrypt(rawBytes);
      const json = JSON.parse(new TextDecoder().decode(data));
      console.log(`Received opcode 0x${opcode.toString(16)}:`, json);
    }
  });

  ws.on('close', () => {
    if (session) {
      session.destroy(); // Zeroize keys
    }
  });
});
```
