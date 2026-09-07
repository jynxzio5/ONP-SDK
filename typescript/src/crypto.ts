/**
 * Cryptographic operations for ONP: X25519 ECDH, HKDF-SHA256, and ChaCha20-Poly1305 AEAD.
 */

import * as crypto from 'crypto';
import { HANDSHAKE_NONCE_SIZE, NONCE_SIZE, PUBLIC_KEY_SIZE } from './constants';

const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');

export interface SessionKeys {
  clientWriteKey: Buffer;
  serverWriteKey: Buffer;
  opcodeSeed: Buffer;
}

export class KeyExchange {
  private privateKey: crypto.KeyObject;
  public publicKey: Buffer;

  constructor() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
    this.privateKey = privateKey;
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
    this.publicKey = spkiDer.subarray(spkiDer.length - PUBLIC_KEY_SIZE);
  }

  /**
   * Computes the Diffie-Hellman shared secret with the peer's raw 32-byte public key.
   */
  public computeSharedSecret(peerRawPublic: Uint8Array): Buffer {
    const peerDer = Buffer.concat([X25519_SPKI_PREFIX, Buffer.from(peerRawPublic)]);
    const peerPubKeyObj = crypto.createPublicKey({
      key: peerDer,
      format: 'der',
      type: 'spki',
    });

    return crypto.diffieHellman({
      privateKey: this.privateKey,
      publicKey: peerPubKeyObj,
    });
  }
}

/**
 * Derives symmetric session keys and polymorphic opcode seed from ECDH shared secret.
 */
export function deriveSessionKeys(
  sharedSecret: Uint8Array,
  clientNonce: Uint8Array,
  serverNonce: Uint8Array
): SessionKeys {
  const salt = Buffer.concat([Buffer.from(clientNonce), Buffer.from(serverNonce)]);
  const okm = crypto.hkdfSync(
    'sha256',
    Buffer.from(sharedSecret),
    salt,
    Buffer.from('ONP-v1-SESSION-KEYS'),
    96
  );

  const okmBuf = Buffer.from(okm);
  return {
    clientWriteKey: okmBuf.subarray(0, 32),
    serverWriteKey: okmBuf.subarray(32, 64),
    opcodeSeed: okmBuf.subarray(64, 96),
  };
}

/**
 * Encrypts plaintext using ChaCha20-Poly1305 with Associated Data (AAD).
 * Returns Buffer containing [Ciphertext || 16-byte MAC Tag].
 */
export function encryptAead(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array
): Buffer {
  const cipher = crypto.createCipheriv(
    'chacha20-poly1305',
    Buffer.from(key),
    Buffer.from(nonce),
    { authTagLength: 16 }
  );

  cipher.setAAD(Buffer.from(aad), { plaintextLength: plaintext.length });
  const ciphertext = cipher.update(Buffer.from(plaintext));
  const final = cipher.final();
  const tag = cipher.getAuthTag();

  return Buffer.concat([ciphertext, final, tag]);
}

/**
 * Decrypts ciphertext and verifies 16-byte Poly1305 MAC tag with Associated Data (AAD).
 */
export function decryptAead(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  ciphertextAndTag: Uint8Array
): Buffer {
  if (ciphertextAndTag.length < 16) {
    throw new Error('Ciphertext too short: missing 16-byte Poly1305 MAC tag');
  }

  const tag = ciphertextAndTag.subarray(ciphertextAndTag.length - 16);
  const ciphertext = ciphertextAndTag.subarray(0, ciphertextAndTag.length - 16);

  const decipher = crypto.createDecipheriv(
    'chacha20-poly1305',
    Buffer.from(key),
    Buffer.from(nonce),
    { authTagLength: 16 }
  );

  decipher.setAAD(Buffer.from(aad), { plaintextLength: ciphertext.length });
  decipher.setAuthTag(Buffer.from(tag));

  const plaintext = decipher.update(Buffer.from(ciphertext));
  const final = decipher.final();

  return Buffer.concat([plaintext, final]);
}
