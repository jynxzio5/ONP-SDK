//! Protocol constants, magic bytes, flags, and standard logical opcodes.

/// 2-byte protocol magic identifier: "ON" in ASCII (0x4F, 0x4E).
pub const PROTOCOL_MAGIC: [u8; 2] = [0x4F, 0x4E];

/// Current major protocol version.
pub const PROTOCOL_VERSION: u8 = 1;

/// Length in bytes of the unencrypted outer envelope header.
/// 2 (Magic) + 1 (Version) + 1 (Flags) + 4 (PayloadLen) = 8 bytes.
pub const ENVELOPE_HEADER_SIZE: usize = 8;

/// Size of the ChaCha20-Poly1305 AEAD Nonce in bytes.
pub const NONCE_SIZE: usize = 12;

/// Size of the Poly1305 authentication tag in bytes.
pub const MAC_TAG_SIZE: usize = 16;

/// Size of the ephemeral Curve25519 public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Size of the handshake salt random token in bytes.
pub const HANDSHAKE_NONCE_SIZE: usize = 16;

/// Maximum payload size supported per single frame (16 MiB).
pub const MAX_FRAME_PAYLOAD_SIZE: usize = 16 * 1024 * 1024;

/// Protocol control flags.
pub mod flags {
    pub const HANDSHAKE_SYN: u8 = 0x01;
    pub const HANDSHAKE_ACK: u8 = 0x02;
    pub const COMPRESSED: u8    = 0x04;
    pub const ENCRYPTED: u8     = 0x08;
    pub const HEARTBEAT: u8     = 0x10;
    pub const ERROR: u8         = 0x20;
    pub const TERMINATE: u8     = 0x80;
}

/// Standard logical application opcodes.
/// In ONP, these are NEVER transmitted as static numbers over the wire;
/// they are mapped polymorphically to session-specific physical IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum LogicalOpcode {
    SysPing         = 0x0001,
    SysPong         = 0x0002,
    SysDisconnect   = 0x0003,
    AuthToken       = 0x0010,
    AuthResult      = 0x0011,
    LobbyJoin       = 0x0020,
    LobbyState      = 0x0021,
    CloudSavePut    = 0x0030,
    CloudSaveGet    = 0x0031,
    RpcCall         = 0x0050,
    RpcReply        = 0x0051,
    Custom(u16),
}

impl LogicalOpcode {
    pub fn as_u16(&self) -> u16 {
        match self {
            Self::SysPing => 0x0001,
            Self::SysPong => 0x0002,
            Self::SysDisconnect => 0x0003,
            Self::AuthToken => 0x0010,
            Self::AuthResult => 0x0011,
            Self::LobbyJoin => 0x0020,
            Self::LobbyState => 0x0021,
            Self::CloudSavePut => 0x0030,
            Self::CloudSaveGet => 0x0031,
            Self::RpcCall => 0x0050,
            Self::RpcReply => 0x0051,
            Self::Custom(val) => *val,
        }
    }

    pub fn from_u16(val: u16) -> Self {
        match val {
            0x0001 => Self::SysPing,
            0x0002 => Self::SysPong,
            0x0003 => Self::SysDisconnect,
            0x0010 => Self::AuthToken,
            0x0011 => Self::AuthResult,
            0x0020 => Self::LobbyJoin,
            0x0021 => Self::LobbyState,
            0x0030 => Self::CloudSavePut,
            0x0031 => Self::CloudSaveGet,
            0x0050 => Self::RpcCall,
            0x0051 => Self::RpcReply,
            other => Self::Custom(other),
        }
    }
}
