//! Polymorphic Rolling Opcode Engine.
//! Translates logical application commands into pseudo-random physical IDs derived
//! from the ephemeral session seed, guaranteeing that wire opcodes mutate on every connection.

use std::collections::HashMap;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::constants::LogicalOpcode;
use crate::errors::{OnpError, OnpResult};

type HmacSha256 = Hmac<Sha256>;

/// Lookup tables for bidirectional O(1) polymorphic opcode mapping.
#[derive(Clone, Debug)]
pub struct OpcodeTable {
    seed: [u8; 32],
    forward_map: HashMap<u16, u16>,
    reverse_map: HashMap<u16, u16>,
}

impl OpcodeTable {
    /// Generates a new polymorphic opcode table from a 32-byte session seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let forward_map = HashMap::new();
        let reverse_map = HashMap::new();

        // Standard opcodes to pre-populate
        let standard_opcodes = [
            LogicalOpcode::SysPing.as_u16(),
            LogicalOpcode::SysPong.as_u16(),
            LogicalOpcode::SysDisconnect.as_u16(),
            LogicalOpcode::AuthToken.as_u16(),
            LogicalOpcode::AuthResult.as_u16(),
            LogicalOpcode::LobbyJoin.as_u16(),
            LogicalOpcode::LobbyState.as_u16(),
            LogicalOpcode::CloudSavePut.as_u16(),
            LogicalOpcode::CloudSaveGet.as_u16(),
            LogicalOpcode::RpcCall.as_u16(),
            LogicalOpcode::RpcReply.as_u16(),
        ];

        let mut table = Self {
            seed: *seed,
            forward_map,
            reverse_map,
        };

        for &logical in &standard_opcodes {
            table.register_logical(logical);
        }

        table
    }

    /// Derives a deterministic, pseudo-random physical opcode for a logical ID.
    fn derive_physical(&self, logical: u16) -> u16 {
        let mut mac = HmacSha256::new_from_slice(&self.seed)
            .expect("HMAC can take key of any size");
        mac.update(&logical.to_le_bytes());
        mac.update(b"ONP-OPCODE-DERIVATION");
        let result = mac.finalize().into_bytes();

        let raw = u16::from_le_bytes([result[0], result[1]]);
        // Ensure non-zero physical ID in [1, 65535]
        if raw == 0 { 0x0001 } else { raw }
    }

    /// Registers a logical opcode into the forward and reverse lookup maps with collision avoidance.
    pub fn register_logical(&mut self, logical: u16) -> u16 {
        if let Some(&existing) = self.forward_map.get(&logical) {
            return existing;
        }

        let mut candidate = self.derive_physical(logical);

        // Linear probing to resolve collisions deterministically
        while self.reverse_map.contains_key(&candidate) {
            candidate = candidate.wrapping_add(1);
            if candidate == 0 {
                candidate = 1;
            }
        }

        self.forward_map.insert(logical, candidate);
        self.reverse_map.insert(candidate, logical);
        candidate
    }

    /// Maps a logical application command to its current polymorphic physical ID for transmission.
    pub fn to_physical(&mut self, logical: LogicalOpcode) -> u16 {
        let id = logical.as_u16();
        if let Some(&physical) = self.forward_map.get(&id) {
            physical
        } else {
            self.register_logical(id)
        }
    }

    /// Resolves an incoming physical ID from the wire back into its logical application opcode.
    pub fn to_logical(&self, physical: u16) -> OnpResult<LogicalOpcode> {
        self.reverse_map
            .get(&physical)
            .copied()
            .map(LogicalOpcode::from_u16)
            .ok_or(OnpError::UnknownOpcode(physical))
    }
}
