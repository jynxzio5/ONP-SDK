//! Authenticated Encryption (ChaCha20-Poly1305) and Ephemeral Key Exchange (X25519 + HKDF-SHA256).

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::constants::{HANDSHAKE_NONCE_SIZE, NONCE_SIZE, PUBLIC_KEY_SIZE};
use crate::errors::{OnpError, OnpResult};

/// Ephemeral key exchange bundle holding the local secret and public key.
pub struct KeyExchange {
    secret: Option<EphemeralSecret>,
    pub public_key: [u8; PUBLIC_KEY_SIZE],
}

impl KeyExchange {
    /// Generates a fresh ephemeral Curve25519 keypair from system CSPRNG.
    pub fn new() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret).to_bytes();
        Self {
            secret: Some(secret),
            public_key,
        }
    }

    /// Performs Diffie-Hellman key exchange with peer's public key.
    /// Consumes the ephemeral secret so it can never be reused.
    pub fn complete(mut self, peer_public_bytes: &[u8; PUBLIC_KEY_SIZE]) -> OnpResult<[u8; 32]> {
        let secret = self.secret.take().ok_or_else(|| {
            OnpError::KeyExchangeFailed("Ephemeral secret already consumed".into())
        })?;
        let peer_public = PublicKey::from(*peer_public_bytes);
        let shared = secret.diffie_hellman(&peer_public);
        Ok(*shared.as_bytes())
    }
}

/// Derived 32-byte cryptographic keys and opcode permutation seed for an ONP session.
#[derive(Clone)]
pub struct SessionKeys {
    pub client_write_key: [u8; 32],
    pub server_write_key: [u8; 32],
    pub opcode_seed: [u8; 32],
}

/// Derives symmetric session keys and polymorphic opcode seed from ECDH shared secret.
pub fn derive_session_keys(
    shared_secret: &[u8; 32],
    client_nonce: &[u8; HANDSHAKE_NONCE_SIZE],
    server_nonce: &[u8; HANDSHAKE_NONCE_SIZE],
) -> OnpResult<SessionKeys> {
    let mut salt = [0u8; HANDSHAKE_NONCE_SIZE * 2];
    salt[..HANDSHAKE_NONCE_SIZE].copy_from_slice(client_nonce);
    salt[HANDSHAKE_NONCE_SIZE..].copy_from_slice(server_nonce);

    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let mut okm = [0u8; 96];
    hk.expand(b"ONP-v1-SESSION-KEYS", &mut okm)
        .map_err(|e| OnpError::KeyExchangeFailed(format!("HKDF expand error: {e}")))?;

    let mut client_write_key = [0u8; 32];
    let mut server_write_key = [0u8; 32];
    let mut opcode_seed = [0u8; 32];

    client_write_key.copy_from_slice(&okm[0..32]);
    server_write_key.copy_from_slice(&okm[32..64]);
    opcode_seed.copy_from_slice(&okm[64..96]);

    Ok(SessionKeys {
        client_write_key,
        server_write_key,
        opcode_seed,
    })
}

/// Encrypts plaintext using ChaCha20-Poly1305 with Associated Data (AAD).
pub fn encrypt_aead(
    key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
    plaintext: &[u8],
) -> OnpResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce_obj = Nonce::from_slice(nonce);

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    cipher
        .encrypt(nonce_obj, payload)
        .map_err(|_| OnpError::AuthenticationFailed)
}

/// Decrypts ciphertext and verifies Poly1305 MAC tag with Associated Data (AAD).
pub fn decrypt_aead(
    key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> OnpResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce_obj = Nonce::from_slice(nonce);

    let payload = Payload {
        msg: ciphertext_and_tag,
        aad,
    };

    cipher
        .decrypt(nonce_obj, payload)
        .map_err(|_| OnpError::AuthenticationFailed)
}
