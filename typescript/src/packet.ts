/**
 * High-level packet abstractions and handshake messages for TypeScript.
 */

import { HANDSHAKE_NONCE_SIZE, LogicalOpcode, PUBLIC_KEY_SIZE } from './constants';

export interface ApplicationPacket {
  opcode: LogicalOpcode;
  data: Buffer;
}

export class HandshakeSyn {
  public static readonly SIZE = PUBLIC_KEY_SIZE + HANDSHAKE_NONCE_SIZE; // 48 bytes
  public clientPublicKey: Buffer;
  public clientNonce: Buffer;

  constructor(clientPublicKey: Uint8Array, clientNonce: Uint8Array) {
    this.clientPublicKey = Buffer.from(clientPublicKey);
    this.clientNonce = Buffer.from(clientNonce);
  }

  public encode(): Buffer {
    return Buffer.concat([this.clientPublicKey, this.clientNonce]);
  }

  public static decode(buf: Uint8Array): HandshakeSyn {
    if (buf.length < this.SIZE) {
      throw new Error(`HandshakeSyn too short: expected ${this.SIZE}, got ${buf.length}`);
    }
    const clientPublicKey = Buffer.from(buf.subarray(0, PUBLIC_KEY_SIZE));
    const clientNonce = Buffer.from(buf.subarray(PUBLIC_KEY_SIZE, this.SIZE));
    return new HandshakeSyn(clientPublicKey, clientNonce);
  }
}

export class HandshakeAck {
  public static readonly SIZE = PUBLIC_KEY_SIZE + HANDSHAKE_NONCE_SIZE; // 48 bytes
  public serverPublicKey: Buffer;
  public serverNonce: Buffer;

  constructor(serverPublicKey: Uint8Array, serverNonce: Uint8Array) {
    this.serverPublicKey = Buffer.from(serverPublicKey);
    this.serverNonce = Buffer.from(serverNonce);
  }

  public encode(): Buffer {
    return Buffer.concat([this.serverPublicKey, this.serverNonce]);
  }

  public static decode(buf: Uint8Array): HandshakeAck {
    if (buf.length < this.SIZE) {
      throw new Error(`HandshakeAck too short: expected ${this.SIZE}, got ${buf.length}`);
    }
    const serverPublicKey = Buffer.from(buf.subarray(0, PUBLIC_KEY_SIZE));
    const serverNonce = Buffer.from(buf.subarray(PUBLIC_KEY_SIZE, this.SIZE));
    return new HandshakeAck(serverPublicKey, serverNonce);
  }
}
