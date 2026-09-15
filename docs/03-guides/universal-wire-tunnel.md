# Universal ONP Wire Tunnel

## Overview

The Universal ONP Wire Tunnel allows applications to execute standard HTTP/REST requests (including `GET`, `POST`, `PUT`, headers, and file streams) over an encrypted ONP binary WebSocket connection.

This architecture enables clients to query private backend APIs, download game manifests, and fetch configurations without exposing target URLs, hostnames, query parameters, or authorization headers to intermediate firewalls, proxies, or ISPs.

---

## 1. How the Wire Tunnel Works

```text
[ Desktop App / Web Browser ]
             |
             | 1. client.tunnelRequest('GET', '/api/v1/manifest?appid=480')
             v
[ ONP WebSocket Client ]
             |
             | 2. Serialize HTTP Request into Binary JSON Payload
             | 3. Encrypt with ChaCha20-Poly1305 under Dynamic Opcode
             v
[ Hostile Network / Public Internet ]  <--- (Observers see only opaque encrypted binary noise)
             |
             v
[ ONP Tunnel Gateway ]
             |
             | 4. Decrypt Binary Frame & Validate Sequence
             | 5. Forward HTTP request internally to Core Service
             | 6. Encrypt HTTP Response (status, headers, body)
             v
[ Desktop App Receives Decrypted Response ]
```

---

## 2. Tunnel Request Format

A tunnel request is transmitted using the `ONP_TUNNEL` opcode (`0x0080`).

### Payload JSON Schema:
```json
{
  "_requestId": "req_1726385900_a8f2c",
  "method": "GET",
  "url": "/api/v1/manifest?appid=480",
  "headers": {
    "Authorization": "Bearer session_token_here",
    "Accept": "application/json"
  },
  "body": null
}
```

---

## 3. Tunnel Response Format

The server responds with opcode `ONP_TUNNEL_RESPONSE` (`0x0081`):

```json
{
  "_requestId": "req_1726385900_a8f2c",
  "status": 200,
  "statusText": "OK",
  "headers": {
    "content-type": "application/json"
  },
  "isBase64": false,
  "data": {
    "appId": "480",
    "status": "ready"
  }
}
```

---

## 4. Code Example

```typescript
import { OnpWebSocketClient } from '@jynxzio5/onp';

const client = new OnpWebSocketClient({ url: 'wss://example.com/ws' });

async function executeSecureFetch() {
  try {
    const res = await client.tunnelRequest(
      'POST',
      'https://internal-api.example.com/v1/telemetry',
      {
        headers: { 'Content-Type': 'application/json' },
        body: { event: 'level_complete', score: 12500 }
      },
      10000 // Timeout in ms
    );

    console.log('HTTP Status Code:', res.status);
    console.log('Returned Data:', res.data);
  } catch (error) {
    console.error('Tunnel request failed:', error);
  }
}
```
