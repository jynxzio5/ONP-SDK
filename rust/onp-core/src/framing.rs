//! Binary wire framing, envelope headers, and nonce generation.

use crate::constants::{
    ENVELOPE_HEADER_SIZE, MAX_FRAME_PAYLOAD_SIZE, NONCE_SIZE, PROTOCOL_MAGIC, PROTOCOL_VERSION,
};
use crate::errors::{OnpError, OnpResult};

/// Unencrypted 8-byte outer envelope header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvelopeHeader {
    pub magic: [u8; 2],
    pub version: u8,
    pub flags: u8,
    pub payload_len: u32,
}

impl EnvelopeHeader {
    /// Creates a new header with current protocol version and magic.
    pub fn new(flags: u8, payload_len: u32) -> Self {
        Self {
            magic: PROTOCOL_MAGIC,
            version: PROTOCOL_VERSION,
            flags,
            payload_len,
        }
    }

    /// Serializes the header into an 8-byte array.
    pub fn encode(&self) -> [u8; ENVELOPE_HEADER_SIZE] {
        let mut buf = [0u8; ENVELOPE_HEADER_SIZE];
        buf[0..2].copy_from_slice(&self.magic);
        buf[2] = self.version;
        buf[3] = self.flags;
        buf[4..8].copy_from_slice(&self.payload_len.to_le_bytes());
        buf
    }

    /// Deserializes and validates an 8-byte envelope header.
    pub fn decode(buf: &[u8]) -> OnpResult<Self> {
        if buf.len() < ENVELOPE_HEADER_SIZE {
            return Err(OnpError::BufferTooShort {
                expected: ENVELOPE_HEADER_SIZE,
                actual: buf.len(),
            });
        }

        let magic = [buf[0], buf[1]];
        if magic != PROTOCOL_MAGIC {
            return Err(OnpError::InvalidMagic(buf[0], buf[1]));
        }

        let version = buf[2];
        if version != PROTOCOL_VERSION {
            return Err(OnpError::UnsupportedVersion {
                expected: PROTOCOL_VERSION,
                actual: version,
            });
        }

        let flags = buf[3];
        let payload_len = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);

        if payload_len as usize > MAX_FRAME_PAYLOAD_SIZE {
            return Err(OnpError::FrameTooLarge {
                size: payload_len as usize,
                max: MAX_FRAME_PAYLOAD_SIZE,
            });
        }

        Ok(Self {
            magic,
            version,
            flags,
            payload_len,
        })
    }
}

/// Constructs a unique 96-bit (12-byte) AEAD Nonce from epoch and monotonic sequence counter.
pub fn construct_nonce(epoch: u32, sequence: u64) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    nonce[0..4].copy_from_slice(&epoch.to_le_bytes());
    nonce[4..12].copy_from_slice(&sequence.to_le_bytes());
    nonce
}

/// Extracts sequence counter from a 96-bit AEAD Nonce.
pub fn extract_sequence(nonce: &[u8; NONCE_SIZE]) -> u64 {
    u64::from_le_bytes([
        nonce[4], nonce[5], nonce[6], nonce[7],
        nonce[8], nonce[9], nonce[10], nonce[11],
    ])
}
