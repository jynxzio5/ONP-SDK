//! Session lifecycle, cryptographic handshake state machine, and anti-replay protection.

use rand::rngs::OsRng;
use rand::RngCore;

use crate::constants::{
    flags, ENVELOPE_HEADER_SIZE, HANDSHAKE_NONCE_SIZE, LogicalOpcode, MAC_TAG_SIZE, NONCE_SIZE,
};
use crate::crypto::{
    decrypt_aead, derive_session_keys, encrypt_aead, KeyExchange,
};
use crate::errors::{OnpError, OnpResult};
use crate::framing::{construct_nonce, extract_sequence, EnvelopeHeader};
use crate::opcode::OpcodeTable;
use crate::packet::{ApplicationPacket, HandshakeAck, HandshakeSyn};

/// Role assumed by an endpoint in the ONP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    Client,
    Server,
}

/// Internal state machine of the session handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Uninitialized,
    SynSent,
    Established,
}

/// 64-packet sliding window filter to block replay attacks in O(1) time.
#[derive(Debug, Clone, Default)]
pub struct AntiReplayWindow {
    max_sequence: u64,
    bitmap: u64,
}

impl AntiReplayWindow {
    pub fn new() -> Self {
        Self {
            max_sequence: 0,
            bitmap: 0,
        }
    }

    /// Validates whether a sequence number is acceptable and updates window state.
    pub fn check_and_update(&mut self, sequence: u64) -> bool {
        if sequence == 0 {
            return false;
        }

        if sequence > self.max_sequence {
            let diff = sequence - self.max_sequence;
            if diff < 64 {
                self.bitmap = (self.bitmap << diff) | 1;
            } else {
                self.bitmap = 1;
            }
            self.max_sequence = sequence;
            true
        } else {
            let diff = self.max_sequence - sequence;
            if diff >= 64 {
                // Too old, fell outside sliding window
                false
            } else {
                let bit = 1u64 << diff;
                if (self.bitmap & bit) != 0 {
                    // Already received
                    false
                } else {
                    self.bitmap |= bit;
                    true
                }
            }
        }
    }
}

/// Complete cryptographically authenticated and polymorphic session manager.
pub struct OnpSession {
    pub role: SessionRole,
    pub state: SessionState,
    key_exchange: Option<KeyExchange>,
    local_nonce: [u8; HANDSHAKE_NONCE_SIZE],
    peer_nonce: [u8; HANDSHAKE_NONCE_SIZE],
    send_key: Option<[u8; 32]>,
    recv_key: Option<[u8; 32]>,
    send_sequence: u64,
    replay_window: AntiReplayWindow,
    opcode_table: Option<OpcodeTable>,
    epoch: u32,
}

impl OnpSession {
    /// Creates a new client session.
    pub fn new_client() -> Self {
        let mut local_nonce = [0u8; HANDSHAKE_NONCE_SIZE];
        OsRng.fill_bytes(&mut local_nonce);
        Self {
            role: SessionRole::Client,
            state: SessionState::Uninitialized,
            key_exchange: Some(KeyExchange::new()),
            local_nonce,
            peer_nonce: [0u8; HANDSHAKE_NONCE_SIZE],
            send_key: None,
            recv_key: None,
            send_sequence: 0,
            replay_window: AntiReplayWindow::new(),
            opcode_table: None,
            epoch: rand::random(),
        }
    }

    /// Creates a new server session.
    pub fn new_server() -> Self {
        let mut local_nonce = [0u8; HANDSHAKE_NONCE_SIZE];
        OsRng.fill_bytes(&mut local_nonce);
        Self {
            role: SessionRole::Server,
            state: SessionState::Uninitialized,
            key_exchange: Some(KeyExchange::new()),
            local_nonce,
            peer_nonce: [0u8; HANDSHAKE_NONCE_SIZE],
            send_key: None,
            recv_key: None,
            send_sequence: 0,
            replay_window: AntiReplayWindow::new(),
            opcode_table: None,
            epoch: rand::random(),
        }
    }

    /// Returns true if the session handshake is established and ready for encrypted traffic.
    pub fn is_established(&self) -> bool {
        self.state == SessionState::Established
    }

    /// CLIENT STEP 1: Generates the wire-encoded `HANDSHAKE_SYN` frame.
    pub fn create_handshake_syn(&mut self) -> OnpResult<Vec<u8>> {
        if self.role != SessionRole::Client {
            return Err(OnpError::HandshakeStateError {
                state: "ServerCannotInitiateSyn",
                flags: flags::HANDSHAKE_SYN,
            });
        }

        let kx = self.key_exchange.as_ref().ok_or_else(|| {
            OnpError::KeyExchangeFailed("Key exchange state missing".into())
        })?;

        let syn = HandshakeSyn {
            client_public_key: kx.public_key,
            client_nonce: self.local_nonce,
        };

        let payload = syn.encode();
        let header = EnvelopeHeader::new(flags::HANDSHAKE_SYN, payload.len() as u32);

        let mut frame = Vec::with_capacity(ENVELOPE_HEADER_SIZE + payload.len());
        frame.extend_from_slice(&header.encode());
        frame.extend_from_slice(&payload);

        self.state = SessionState::SynSent;
        Ok(frame)
    }

    /// SERVER STEP 2: Processes incoming `HANDSHAKE_SYN` and generates the response `HANDSHAKE_ACK` frame.
    pub fn process_handshake_syn(&mut self, syn_frame: &[u8]) -> OnpResult<Vec<u8>> {
        if self.role != SessionRole::Server {
            return Err(OnpError::HandshakeStateError {
                state: "ClientCannotProcessSyn",
                flags: flags::HANDSHAKE_SYN,
            });
        }

        let header = EnvelopeHeader::decode(syn_frame)?;
        if header.flags & flags::HANDSHAKE_SYN == 0 {
            return Err(OnpError::HandshakeStateError {
                state: "ExpectedHandshakeSynFlag",
                flags: header.flags,
            });
        }

        let syn_payload = &syn_frame[ENVELOPE_HEADER_SIZE..];
        let syn = HandshakeSyn::decode(syn_payload)?;
        self.peer_nonce = syn.client_nonce;

        let kx = self.key_exchange.take().ok_or_else(|| {
            OnpError::KeyExchangeFailed("Server key exchange already consumed".into())
        })?;
        let server_public_key = kx.public_key;

        // Perform Diffie-Hellman
        let shared_secret = kx.complete(&syn.client_public_key)?;

        // Derive Keys: ClientWriteKey, ServerWriteKey, OpcodeSeed
        let keys = derive_session_keys(&shared_secret, &self.peer_nonce, &self.local_nonce)?;

        // For server: send_key = server_write_key, recv_key = client_write_key
        self.send_key = Some(keys.server_write_key);
        self.recv_key = Some(keys.client_write_key);
        self.opcode_table = Some(OpcodeTable::from_seed(&keys.opcode_seed));
        self.state = SessionState::Established;

        let ack = HandshakeAck {
            server_public_key,
            server_nonce: self.local_nonce,
        };

        let ack_payload = ack.encode();
        let ack_header = EnvelopeHeader::new(flags::HANDSHAKE_ACK, ack_payload.len() as u32);

        let mut frame = Vec::with_capacity(ENVELOPE_HEADER_SIZE + ack_payload.len());
        frame.extend_from_slice(&ack_header.encode());
        frame.extend_from_slice(&ack_payload);

        Ok(frame)
    }

    /// CLIENT STEP 3: Processes incoming `HANDSHAKE_ACK` from server to finalize connection.
    pub fn process_handshake_ack(&mut self, ack_frame: &[u8]) -> OnpResult<()> {
        if self.role != SessionRole::Client || self.state != SessionState::SynSent {
            return Err(OnpError::HandshakeStateError {
                state: "ClientNotInSynSentState",
                flags: flags::HANDSHAKE_ACK,
            });
        }

        let header = EnvelopeHeader::decode(ack_frame)?;
        if header.flags & flags::HANDSHAKE_ACK == 0 {
            return Err(OnpError::HandshakeStateError {
                state: "ExpectedHandshakeAckFlag",
                flags: header.flags,
            });
        }

        let ack_payload = &ack_frame[ENVELOPE_HEADER_SIZE..];
        let ack = HandshakeAck::decode(ack_payload)?;
        self.peer_nonce = ack.server_nonce;

        let kx = self.key_exchange.take().ok_or_else(|| {
            OnpError::KeyExchangeFailed("Client key exchange already consumed".into())
        })?;

        // Perform Diffie-Hellman
        let shared_secret = kx.complete(&ack.server_public_key)?;

        // Derive Keys
        let keys = derive_session_keys(&shared_secret, &self.local_nonce, &self.peer_nonce)?;

        // For client: send_key = client_write_key, recv_key = server_write_key
        self.send_key = Some(keys.client_write_key);
        self.recv_key = Some(keys.server_write_key);
        self.opcode_table = Some(OpcodeTable::from_seed(&keys.opcode_seed));
        self.state = SessionState::Established;

        Ok(())
    }

    /// Encrypts an application command into a complete ONP wire frame.
    /// Maps the logical opcode to the polymorphic physical ID, generates a monotonic nonce,
    /// and encrypts using ChaCha20-Poly1305 with the envelope header as AAD.
    pub fn encrypt_packet(
        &mut self,
        opcode: LogicalOpcode,
        payload: &[u8],
    ) -> OnpResult<Vec<u8>> {
        if self.state != SessionState::Established {
            return Err(OnpError::HandshakeStateError {
                state: "SessionNotEstablished",
                flags: 0,
            });
        }

        let send_key = self.send_key.as_ref().unwrap();
        let opcode_table = self.opcode_table.as_mut().unwrap();

        // 1. Resolve polymorphic physical opcode
        let physical_opcode = opcode_table.to_physical(opcode);

        // 2. Prepare plaintext = [PhysicalOpcode (2B LE) || Payload]
        let mut plaintext = Vec::with_capacity(2 + payload.len());
        plaintext.extend_from_slice(&physical_opcode.to_le_bytes());
        plaintext.extend_from_slice(payload);

        // 3. Monotonic sequence counter
        self.send_sequence += 1;
        let nonce = construct_nonce(self.epoch, self.send_sequence);

        // 4. Header: Flags = ENCRYPTED, PayloadLen = NONCE_SIZE (12) + CIPHERTEXT + MAC_TAG_SIZE (16)
        let total_encrypted_len = (NONCE_SIZE + plaintext.len() + MAC_TAG_SIZE) as u32;
        let header = EnvelopeHeader::new(flags::ENCRYPTED, total_encrypted_len);
        let header_bytes = header.encode();

        // 5. Encrypt with AAD = Header
        let ciphertext_and_tag = encrypt_aead(send_key, &nonce, &header_bytes, &plaintext)?;

        // 6. Assemble frame: [Header (8B) || Nonce (12B) || Ciphertext+Tag]
        let mut frame = Vec::with_capacity(ENVELOPE_HEADER_SIZE + total_encrypted_len as usize);
        frame.extend_from_slice(&header_bytes);
        frame.extend_from_slice(&nonce);
        frame.extend_from_slice(&ciphertext_and_tag);

        Ok(frame)
    }

    /// Decrypts an incoming ONP wire frame, checks anti-replay window, verifies AEAD tag,
    /// and maps the polymorphic opcode back to the application logical opcode.
    pub fn decrypt_packet(&mut self, frame: &[u8]) -> OnpResult<ApplicationPacket> {
        if self.state != SessionState::Established {
            return Err(OnpError::HandshakeStateError {
                state: "SessionNotEstablished",
                flags: 0,
            });
        }

        let header = EnvelopeHeader::decode(frame)?;
        if header.flags & flags::ENCRYPTED == 0 {
            return Err(OnpError::HandshakeStateError {
                state: "ExpectedEncryptedFlag",
                flags: header.flags,
            });
        }

        let expected_frame_len = ENVELOPE_HEADER_SIZE + header.payload_len as usize;
        if frame.len() < expected_frame_len {
            return Err(OnpError::BufferTooShort {
                expected: expected_frame_len,
                actual: frame.len(),
            });
        }

        let encrypted_block = &frame[ENVELOPE_HEADER_SIZE..expected_frame_len];
        if encrypted_block.len() < NONCE_SIZE + MAC_TAG_SIZE + 2 {
            return Err(OnpError::BufferTooShort {
                expected: NONCE_SIZE + MAC_TAG_SIZE + 2,
                actual: encrypted_block.len(),
            });
        }

        // 1. Extract 12-byte Nonce and verify anti-replay sequence
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&encrypted_block[..NONCE_SIZE]);
        let sequence = extract_sequence(&nonce);

        if !self.replay_window.check_and_update(sequence) {
            return Err(OnpError::ReplayDetected { sequence });
        }

        // 2. Decrypt ciphertext using recv_key and Header as AAD
        let recv_key = self.recv_key.as_ref().unwrap();
        let header_bytes = &frame[..ENVELOPE_HEADER_SIZE];
        let ciphertext_and_tag = &encrypted_block[NONCE_SIZE..];

        let plaintext = decrypt_aead(recv_key, &nonce, header_bytes, ciphertext_and_tag)?;

        if plaintext.len() < 2 {
            return Err(OnpError::BufferTooShort {
                expected: 2,
                actual: plaintext.len(),
            });
        }

        // 3. Extract physical opcode and resolve to logical opcode
        let physical_opcode = u16::from_le_bytes([plaintext[0], plaintext[1]]);
        let opcode_table = self.opcode_table.as_ref().unwrap();
        let logical_opcode = opcode_table.to_logical(physical_opcode)?;

        let payload_data = plaintext[2..].to_vec();

        Ok(ApplicationPacket {
            opcode: logical_opcode,
            data: payload_data,
        })
    }
}
