/**
 * Session state machine, cryptographic handshake, and anti-replay filter for TypeScript.
 */

import * as crypto from 'crypto';
import {
  ENVELOPE_HEADER_SIZE,
  Flags,
  HANDSHAKE_NONCE_SIZE,
  LogicalOpcode,
  MAC_TAG_SIZE,
  NONCE_SIZE,
} from './constants';
import {
  decryptAead,
  deriveSessionKeys,
  encryptAead,
  KeyExchange,
  SessionKeys,
} from './crypto';
import { constructNonce, extractSequence, EnvelopeHeader } from './framing';
import { OpcodeTable } from './opcode';
import { ApplicationPacket, HandshakeAck, HandshakeSyn } from './packet';

export type SessionRole = 'client' | 'server';
export type SessionState = 'uninitialized' | 'syn_sent' | 'established';

export class AntiReplayWindow {
  private maxSequence: bigint = 0n;
  private bitmap: bigint = 0n;

  /**
   * Non-mutating sequence check against the 64-packet sliding window.
   * MUST be performed before AEAD decryption to filter duplicate or expired frames without mutating state.
   */
  public check(sequence: bigint): boolean {
    if (sequence <= 0n) return false;

    if (sequence > this.maxSequence) {
      return true;
    } else {
      const diff = this.maxSequence - sequence;
      if (diff >= 64n) {
        return false; // Packet fell outside the 64-packet sliding window
      }
      const bit = 1n << diff;
      if ((this.bitmap & bit) !== 0n) {
        return false; // Replay attack detected
      }
      return true;
    }
  }

  /**
   * Commits an authenticated sequence number into the sliding window.
   * MUST only be called AFTER cryptographic MAC tag verification succeeds.
   */
  public commit(sequence: bigint): void {
    if (sequence <= 0n) return;

    if (sequence > this.maxSequence) {
      const diff = sequence - this.maxSequence;
      if (diff < 64n) {
        this.bitmap = (this.bitmap << diff) | 1n;
      } else {
        this.bitmap = 1n;
      }
      this.maxSequence = sequence;
    } else {
      const diff = this.maxSequence - sequence;
      if (diff < 64n) {
        const bit = 1n << diff;
        this.bitmap |= bit;
      }
    }
  }

  /**
   * Legacy convenience helper (atomically checks and commits).
   */
  public checkAndUpdate(sequence: bigint): boolean {
    if (!this.check(sequence)) return false;
    this.commit(sequence);
    return true;
  }
}

export class OnpSession {
  public role: SessionRole;
  public state: SessionState = 'uninitialized';
  private keyExchange: KeyExchange | null = new KeyExchange();
  private localNonce: Buffer = crypto.randomBytes(HANDSHAKE_NONCE_SIZE);
  private peerNonce: Buffer = Buffer.alloc(HANDSHAKE_NONCE_SIZE);
  private sendKey: Buffer | null = null;
  private recvKey: Buffer | null = null;
  private sendSequence: bigint = 0n;
  private replayWindow: AntiReplayWindow = new AntiReplayWindow();
  private opcodeTable: OpcodeTable | null = null;
  private epoch: number = crypto.randomBytes(4).readUInt32LE(0);

  constructor(role: SessionRole) {
    this.role = role;
  }

  public isEstablished(): boolean {
    return this.state === 'established';
  }

  /**
   * CLIENT STEP 1: Initiates handshake by generating HANDSHAKE_SYN frame.
   */
  public createHandshakeSyn(): Buffer {
    if (this.role !== 'client') {
      throw new Error('Server cannot initiate HandshakeSyn');
    }
    if (!this.keyExchange) {
      throw new Error('Key exchange already consumed');
    }

    const syn = new HandshakeSyn(this.keyExchange.publicKey, this.localNonce);
    const payload = syn.encode();
    const header = new EnvelopeHeader(Flags.HANDSHAKE_SYN, payload.length);

    this.state = 'syn_sent';
    return Buffer.concat([Buffer.from(header.encode()), payload]);
  }

  /**
   * SERVER STEP 2: Processes incoming SYN and responds with HANDSHAKE_ACK.
   */
  public processHandshakeSyn(synFrame: Uint8Array): Buffer {
    if (this.role !== 'server') {
      throw new Error('Client cannot process HandshakeSyn as server');
    }

    const header = EnvelopeHeader.decode(synFrame);
    if ((header.flags & Flags.HANDSHAKE_SYN) === 0) {
      throw new Error('Expected HANDSHAKE_SYN flag');
    }

    const synPayload = synFrame.subarray(ENVELOPE_HEADER_SIZE);
    const syn = HandshakeSyn.decode(synPayload);
    this.peerNonce = syn.clientNonce;

    if (!this.keyExchange) {
      throw new Error('Server key exchange already consumed');
    }

    const serverPublicKey = this.keyExchange.publicKey;
    const sharedSecret = this.keyExchange.computeSharedSecret(syn.clientPublicKey);
    this.keyExchange = null; // Erase ephemeral private key immediately

    const keys = deriveSessionKeys(sharedSecret, this.peerNonce, this.localNonce);
    this.sendKey = keys.serverWriteKey;
    this.recvKey = keys.clientWriteKey;
    this.opcodeTable = new OpcodeTable(keys.opcodeSeed);
    this.state = 'established';

    const ack = new HandshakeAck(serverPublicKey, this.localNonce);
    const ackPayload = ack.encode();
    const ackHeader = new EnvelopeHeader(Flags.HANDSHAKE_ACK, ackPayload.length);

    return Buffer.concat([Buffer.from(ackHeader.encode()), ackPayload]);
  }

  /**
   * CLIENT STEP 3: Completes handshake from server's HANDSHAKE_ACK.
   */
  public processHandshakeAck(ackFrame: Uint8Array): void {
    if (this.role !== 'client' || this.state !== 'syn_sent') {
      throw new Error('Client is not in syn_sent state');
    }

    const header = EnvelopeHeader.decode(ackFrame);
    if ((header.flags & Flags.HANDSHAKE_ACK) === 0) {
      throw new Error('Expected HANDSHAKE_ACK flag');
    }

    const ackPayload = ackFrame.subarray(ENVELOPE_HEADER_SIZE);
    const ack = HandshakeAck.decode(ackPayload);
    this.peerNonce = ack.serverNonce;

    if (!this.keyExchange) {
      throw new Error('Client key exchange already consumed');
    }

    const sharedSecret = this.keyExchange.computeSharedSecret(ack.serverPublicKey);
    this.keyExchange = null; // Erase ephemeral private key immediately

    const keys = deriveSessionKeys(sharedSecret, this.localNonce, this.peerNonce);
    this.sendKey = keys.clientWriteKey;
    this.recvKey = keys.serverWriteKey;
    this.opcodeTable = new OpcodeTable(keys.opcodeSeed);
    this.state = 'established';
  }

  /**
   * Encrypts an application command into a complete ONP wire frame.
   */
  public encryptPacket(opcode: LogicalOpcode, payload: Uint8Array): Buffer {
    if (this.state !== 'established' || !this.sendKey || !this.opcodeTable) {
      throw new Error('Session is not established');
    }

    const physicalOpcode = this.opcodeTable.toPhysical(opcode);
    const opcodeBuf = Buffer.alloc(2);
    opcodeBuf.writeUInt16LE(physicalOpcode, 0);

    const plaintext = Buffer.concat([opcodeBuf, Buffer.from(payload)]);

    if (this.sendSequence >= 0xFFFFFFFFFFFFFFFFn) {
      throw new Error('Sequence counter exhausted (nonce reuse protection triggered)');
    }

    this.sendSequence += 1n;
    const nonce = constructNonce(this.epoch, this.sendSequence);

    const totalEncryptedLen = NONCE_SIZE + plaintext.length + MAC_TAG_SIZE;
    const header = new EnvelopeHeader(Flags.ENCRYPTED, totalEncryptedLen);
    const headerBytes = Buffer.from(header.encode());

    const ciphertextAndTag = encryptAead(this.sendKey, nonce, headerBytes, plaintext);

    return Buffer.concat([headerBytes, Buffer.from(nonce), ciphertextAndTag]);
  }

  /**
   * Decrypts an incoming ONP wire frame, checks anti-replay window, and resolves opcode.
   * Enforces strict two-phase validation: non-mutating sequence check prior to AEAD authentication,
   * committing sequence state only after ChaCha20-Poly1305 verification succeeds.
   */
  public decryptPacket(frame: Uint8Array): ApplicationPacket {
    if (this.state !== 'established' || !this.recvKey || !this.opcodeTable) {
      throw new Error('Session is not established');
    }

    const header = EnvelopeHeader.decode(frame);
    if ((header.flags & Flags.ENCRYPTED) === 0) {
      throw new Error('Expected ENCRYPTED flag');
    }

    const expectedTotal = ENVELOPE_HEADER_SIZE + header.payloadLen;
    if (frame.length < expectedTotal) {
      throw new Error(`Buffer too short: expected ${expectedTotal}, got ${frame.length}`);
    }

    const encryptedBlock = frame.subarray(ENVELOPE_HEADER_SIZE, expectedTotal);
    if (encryptedBlock.length < NONCE_SIZE + MAC_TAG_SIZE + 2) {
      throw new Error('Encrypted block too short');
    }

    const nonce = encryptedBlock.subarray(0, NONCE_SIZE);
    const sequence = extractSequence(nonce);

    // 1. Non-mutating sequence check (fails if already seen or behind window)
    if (!this.replayWindow.check(sequence)) {
      throw new Error(`Replay attack detected: sequence ${sequence} rejected by sliding window`);
    }

    const headerBytes = frame.subarray(0, ENVELOPE_HEADER_SIZE);
    const ciphertextAndTag = encryptedBlock.subarray(NONCE_SIZE);

    // 2. Cryptographic AEAD verification
    const plaintext = decryptAead(this.recvKey, nonce, headerBytes, ciphertextAndTag);
    if (plaintext.length < 2) {
      throw new Error('Plaintext too short to contain physical opcode');
    }

    // 3. Commit sequence to sliding window ONLY after authentication succeeds
    this.replayWindow.commit(sequence);

    const physicalOpcode = plaintext.readUInt16LE(0);
    const logicalOpcode = this.opcodeTable.toLogical(physicalOpcode);
    const data = plaintext.subarray(2);

    return {
      opcode: logicalOpcode,
      data,
    };
  }

  /**
   * Zeroizes symmetric keys, nonces, and session state from memory upon teardown.
   */
  public destroy(): void {
    if (this.sendKey) {
      this.sendKey.fill(0);
      this.sendKey = null;
    }
    if (this.recvKey) {
      this.recvKey.fill(0);
      this.recvKey = null;
    }
    this.localNonce.fill(0);
    this.peerNonce.fill(0);
    this.keyExchange = null;
    this.opcodeTable = null;
    this.state = 'uninitialized';
  }
}
