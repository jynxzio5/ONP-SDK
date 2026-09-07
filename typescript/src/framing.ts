/**
 * Binary wire framing and envelope header serialization for ONP.
 */

import {
  ENVELOPE_HEADER_SIZE,
  MAX_FRAME_PAYLOAD_SIZE,
  NONCE_SIZE,
  PROTOCOL_MAGIC,
  PROTOCOL_VERSION,
} from './constants';

export class EnvelopeHeader {
  public magic: Uint8Array;
  public version: number;
  public flags: number;
  public payloadLen: number;

  constructor(flags: number, payloadLen: number) {
    this.magic = PROTOCOL_MAGIC;
    this.version = PROTOCOL_VERSION;
    this.flags = flags;
    this.payloadLen = payloadLen;
  }

  /**
   * Serializes the header into an 8-byte Uint8Array.
   */
  public encode(): Uint8Array {
    const buf = new Uint8Array(ENVELOPE_HEADER_SIZE);
    const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);

    buf[0] = this.magic[0];
    buf[1] = this.magic[1];
    buf[2] = this.version;
    buf[3] = this.flags;
    view.setUint32(4, this.payloadLen, true); // Little-Endian

    return buf;
  }

  /**
   * Deserializes and validates an 8-byte envelope header from buffer.
   */
  public static decode(buf: Uint8Array): EnvelopeHeader {
    if (buf.length < ENVELOPE_HEADER_SIZE) {
      throw new Error(`Buffer too short: expected 8 bytes, got ${buf.length}`);
    }

    if (buf[0] !== PROTOCOL_MAGIC[0] || buf[1] !== PROTOCOL_MAGIC[1]) {
      throw new Error(`Invalid protocol magic: [0x${buf[0].toString(16)}, 0x${buf[1].toString(16)}]`);
    }

    if (buf[2] !== PROTOCOL_VERSION) {
      throw new Error(`Unsupported protocol version: ${buf[2]}`);
    }

    const flags = buf[3];
    const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    const payloadLen = view.getUint32(4, true);

    if (payloadLen > MAX_FRAME_PAYLOAD_SIZE) {
      throw new Error(`Frame payload exceeds maximum size: ${payloadLen} > ${MAX_FRAME_PAYLOAD_SIZE}`);
    }

    return new EnvelopeHeader(flags, payloadLen);
  }
}

/**
 * Constructs a unique 96-bit (12-byte) AEAD Nonce from a 32-bit epoch and 64-bit sequence counter.
 */
export function constructNonce(epoch: number, sequence: bigint): Uint8Array {
  const nonce = new Uint8Array(NONCE_SIZE);
  const view = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);

  view.setUint32(0, epoch, true);
  view.setBigUint64(4, sequence, true);

  return nonce;
}

/**
 * Extracts the 64-bit sequence counter from a 96-bit AEAD Nonce.
 */
export function extractSequence(nonce: Uint8Array): bigint {
  const view = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
  return view.getBigUint64(4, true);
}
