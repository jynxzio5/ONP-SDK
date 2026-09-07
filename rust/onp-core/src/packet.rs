//! High-level packet abstractions, payload types, and handshake framing.

use crate::constants::{HANDSHAKE_NONCE_SIZE, LogicalOpcode, PUBLIC_KEY_SIZE};
use crate::errors::{OnpError, OnpResult};

/// High-level application packet containing resolved logical opcode and payload data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationPacket {
    pub opcode: LogicalOpcode,
    pub data: Vec<u8>,
}

impl ApplicationPacket {
    pub fn new(opcode: LogicalOpcode, data: Vec<u8>) -> Self {
        Self { opcode, data }
    }
}

/// Handshake Step 1: Client initiates session with ephemeral public key and nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeSyn {
    pub client_public_key: [u8; PUBLIC_KEY_SIZE],
    pub client_nonce: [u8; HANDSHAKE_NONCE_SIZE],
}

impl HandshakeSyn {
    pub const SIZE: usize = PUBLIC_KEY_SIZE + HANDSHAKE_NONCE_SIZE; // 48 bytes

    pub fn encode(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[..PUBLIC_KEY_SIZE].copy_from_slice(&self.client_public_key);
        buf[PUBLIC_KEY_SIZE..].copy_from_slice(&self.client_nonce);
        buf
    }

    pub fn decode(buf: &[u8]) -> OnpResult<Self> {
        if buf.len() < Self::SIZE {
            return Err(OnpError::BufferTooShort {
                expected: Self::SIZE,
                actual: buf.len(),
            });
        }
        let mut client_public_key = [0u8; PUBLIC_KEY_SIZE];
        let mut client_nonce = [0u8; HANDSHAKE_NONCE_SIZE];
        client_public_key.copy_from_slice(&buf[..PUBLIC_KEY_SIZE]);
        client_nonce.copy_from_slice(&buf[PUBLIC_KEY_SIZE..Self::SIZE]);
        Ok(Self {
            client_public_key,
            client_nonce,
        })
    }
}

/// Handshake Step 2: Server responds with ephemeral public key and salt nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeAck {
    pub server_public_key: [u8; PUBLIC_KEY_SIZE],
    pub server_nonce: [u8; HANDSHAKE_NONCE_SIZE],
}

impl HandshakeAck {
    pub const SIZE: usize = PUBLIC_KEY_SIZE + HANDSHAKE_NONCE_SIZE; // 48 bytes

    pub fn encode(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[..PUBLIC_KEY_SIZE].copy_from_slice(&self.server_public_key);
        buf[PUBLIC_KEY_SIZE..].copy_from_slice(&self.server_nonce);
        buf
    }

    pub fn decode(buf: &[u8]) -> OnpResult<Self> {
        if buf.len() < Self::SIZE {
            return Err(OnpError::BufferTooShort {
                expected: Self::SIZE,
                actual: buf.len(),
            });
        }
        let mut server_public_key = [0u8; PUBLIC_KEY_SIZE];
        let mut server_nonce = [0u8; HANDSHAKE_NONCE_SIZE];
        server_public_key.copy_from_slice(&buf[..PUBLIC_KEY_SIZE]);
        server_nonce.copy_from_slice(&buf[PUBLIC_KEY_SIZE..Self::SIZE]);
        Ok(Self {
            server_public_key,
            server_nonce,
        })
    }
}
