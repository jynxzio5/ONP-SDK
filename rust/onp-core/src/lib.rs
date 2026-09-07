//! # Opela Nexus Protocol (ONP) Core
//!
//! A zero-knowledge, high-speed binary wire protocol engineered for Opela Nexus.
//! Features:
//! - Total packet confidentiality with ChaCha20-Poly1305 AEAD.
//! - Ephemeral Diffie-Hellman Key Exchange (Curve25519) + HKDF-SHA256.
//! - Polymorphic rolling opcodes derived from session seeds.
//! - Monotonic sequence numbering and 64-bit sliding window anti-replay protection.

pub mod constants;
pub mod crypto;
pub mod errors;
pub mod framing;
pub mod opcode;
pub mod packet;
pub mod session;

pub use constants::{flags, LogicalOpcode, PROTOCOL_MAGIC, PROTOCOL_VERSION};
pub use errors::{OnpError, OnpResult};
pub use framing::{EnvelopeHeader, construct_nonce, extract_sequence};
pub use opcode::OpcodeTable;
pub use packet::{ApplicationPacket, HandshakeAck, HandshakeSyn};
pub use session::{AntiReplayWindow, OnpSession, SessionRole, SessionState};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_encode_decode() {
        let original = EnvelopeHeader::new(flags::ENCRYPTED | flags::HEARTBEAT, 1024);
        let encoded = original.encode();
        let decoded = EnvelopeHeader::decode(&encoded).expect("Decode should succeed");
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_polymorphic_opcode_uniqueness() {
        let seed1 = [0x42u8; 32];
        let seed2 = [0x99u8; 32];

        let mut table1 = OpcodeTable::from_seed(&seed1);
        let mut table2 = OpcodeTable::from_seed(&seed2);

        let phys1 = table1.to_physical(LogicalOpcode::LobbyJoin);
        let phys2 = table2.to_physical(LogicalOpcode::LobbyJoin);

        // Different seeds MUST produce different physical opcodes
        assert_ne!(phys1, phys2);

        // Reverse mapping must perfectly restore the original logical opcode
        assert_eq!(table1.to_logical(phys1).unwrap(), LogicalOpcode::LobbyJoin);
        assert_eq!(table2.to_logical(phys2).unwrap(), LogicalOpcode::LobbyJoin);
    }

    #[test]
    fn test_crypto_tamper_resistance() {
        let mut client = OnpSession::new_client();
        let mut server = OnpSession::new_server();

        // 1. Handshake
        let syn_frame = client.create_handshake_syn().unwrap();
        let ack_frame = server.process_handshake_syn(&syn_frame).unwrap();
        client.process_handshake_ack(&ack_frame).unwrap();

        assert!(client.is_established());
        assert!(server.is_established());

        // 2. Encrypt packet
        let mut frame = client
            .encrypt_packet(LogicalOpcode::SysPing, b"SAFE_PAYLOAD_123")
            .unwrap();

        // 3. Tamper with a single byte in ciphertext
        let last_idx = frame.len() - 1;
        frame[last_idx] ^= 0x01; // flip 1 bit

        // 4. Decrypt must fail authentication
        let result = server.decrypt_packet(&frame);
        assert!(result.is_err());
    }

    #[test]
    fn test_anti_replay_window() {
        let mut client = OnpSession::new_client();
        let mut server = OnpSession::new_server();

        let syn_frame = client.create_handshake_syn().unwrap();
        let ack_frame = server.process_handshake_syn(&syn_frame).unwrap();
        client.process_handshake_ack(&ack_frame).unwrap();

        let frame = client
            .encrypt_packet(LogicalOpcode::LobbyJoin, b"LOBBY_DATA")
            .unwrap();

        // First receive must succeed
        let packet = server.decrypt_packet(&frame).unwrap();
        assert_eq!(packet.opcode, LogicalOpcode::LobbyJoin);
        assert_eq!(packet.data, b"LOBBY_DATA");

        // Replaying the exact same packet must be rejected
        let replay_result = server.decrypt_packet(&frame);
        match replay_result {
            Err(OnpError::ReplayDetected { sequence: 1 }) => (),
            other => panic!("Expected ReplayDetected error, got: {:?}", other),
        }
    }

    #[test]
    fn test_full_bidirectional_session() {
        let mut client = OnpSession::new_client();
        let mut server = OnpSession::new_server();

        // Handshake
        let syn = client.create_handshake_syn().unwrap();
        let ack = server.process_handshake_syn(&syn).unwrap();
        client.process_handshake_ack(&ack).unwrap();

        // Client -> Server
        let client_msg = b"OPELA_CLIENT_REQUEST_TOKEN";
        let c_frame = client.encrypt_packet(LogicalOpcode::AuthToken, client_msg).unwrap();
        let s_received = server.decrypt_packet(&c_frame).unwrap();
        assert_eq!(s_received.opcode, LogicalOpcode::AuthToken);
        assert_eq!(s_received.data, client_msg);

        // Server -> Client
        let server_reply = b"AUTH_SUCCESS_TOKEN_998877";
        let s_frame = server.encrypt_packet(LogicalOpcode::AuthResult, server_reply).unwrap();
        let c_received = client.decrypt_packet(&s_frame).unwrap();
        assert_eq!(c_received.opcode, LogicalOpcode::AuthResult);
        assert_eq!(c_received.data, server_reply);
    }
}
