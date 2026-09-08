//! Protocol error types and diagnostics.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum OnpError {
    #[error("Invalid protocol magic: expected [0x4F, 0x4E], received [{0:#04X}, {1:#04X}]")]
    InvalidMagic(u8, u8),

    #[error("Unsupported protocol version: expected {expected}, received {actual}")]
    UnsupportedVersion { expected: u8, actual: u8 },

    #[error("Buffer too short: expected at least {expected} bytes, received {actual}")]
    BufferTooShort { expected: usize, actual: usize },

    #[error("Frame exceeds maximum allowed size: {size} > {max}")]
    FrameTooLarge { size: usize, max: usize },

    #[error("Cryptographic verification failed: invalid authentication tag or corrupted ciphertext")]
    AuthenticationFailed,

    #[error("Key exchange failed: {0}")]
    KeyExchangeFailed(String),

    #[error("Replay attack detected: sequence number {sequence} was already processed or falls outside the 64-packet window")]
    ReplayDetected { sequence: u64 },

    #[error("Sequence counter exhausted: maximum 64-bit sequence reached, session must be renegotiated to prevent nonce reuse")]
    SequenceExhausted,

    #[error("Handshake sequence violation: unexpected state {state} for received packet with flags {flags:#04X}")]
    HandshakeStateError { state: &'static str, flags: u8 },

    #[error("Unknown or invalid physical opcode: {0:#06X}")]
    UnknownOpcode(u16),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type OnpResult<T> = Result<T, OnpError>;
