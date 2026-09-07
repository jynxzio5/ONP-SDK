//! Async TCP transport implementation for ONP client and server.

use std::io;
use bytes::Bytes;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;
use futures_util::{SinkExt, StreamExt};

use onp_core::constants::LogicalOpcode;
use onp_core::errors::{OnpError, OnpResult};
use onp_core::packet::ApplicationPacket;
use onp_core::session::OnpSession;

use crate::codec::OnpCodec;

/// Established, cryptographically secured ONP TCP connection.
pub struct OnpTcpConnection {
    framed: Framed<TcpStream, OnpCodec>,
    pub session: OnpSession,
}

impl OnpTcpConnection {
    /// Connects to a remote ONP server and completes the cryptographic handshake.
    pub async fn connect(addr: &str) -> OnpResult<Self> {
        let stream = TcpStream::connect(addr).await.map_err(OnpError::Io)?;
        let mut framed = Framed::new(stream, OnpCodec::new());
        let mut session = OnpSession::new_client();

        // 1. Send Handshake SYN
        let syn_frame = session.create_handshake_syn()?;
        framed
            .send(Bytes::from(syn_frame))
            .await
            .map_err(|e| OnpError::Io(e))?;

        // 2. Await Handshake ACK
        let ack_bytes = framed
            .next()
            .await
            .ok_or_else(|| OnpError::Io(io::Error::new(io::ErrorKind::UnexpectedEof, "Connection closed during handshake")))?
            .map_err(OnpError::Io)?;

        session.process_handshake_ack(&ack_bytes)?;

        Ok(Self { framed, session })
    }

    /// Accepts an incoming TCP stream on the server and completes the cryptographic handshake.
    pub async fn accept(stream: TcpStream) -> OnpResult<Self> {
        let mut framed = Framed::new(stream, OnpCodec::new());
        let mut session = OnpSession::new_server();

        // 1. Receive Handshake SYN
        let syn_bytes = framed
            .next()
            .await
            .ok_or_else(|| OnpError::Io(io::Error::new(io::ErrorKind::UnexpectedEof, "Connection closed before handshake")))?
            .map_err(OnpError::Io)?;

        // 2. Process SYN and generate ACK
        let ack_frame = session.process_handshake_syn(&syn_bytes)?;

        // 3. Send Handshake ACK
        framed
            .send(Bytes::from(ack_frame))
            .await
            .map_err(OnpError::Io)?;

        Ok(Self { framed, session })
    }

    /// Transmits an encrypted application command with rolling polymorphic opcode.
    pub async fn send_packet(&mut self, opcode: LogicalOpcode, payload: &[u8]) -> OnpResult<()> {
        let frame = self.session.encrypt_packet(opcode, payload)?;
        self.framed
            .send(Bytes::from(frame))
            .await
            .map_err(OnpError::Io)
    }

    /// Receives and decrypts the next incoming application packet.
    pub async fn recv_packet(&mut self) -> OnpResult<ApplicationPacket> {
        let frame = self
            .framed
            .next()
            .await
            .ok_or_else(|| OnpError::Io(io::Error::new(io::ErrorKind::UnexpectedEof, "Connection closed")))?
            .map_err(OnpError::Io)?;

        self.session.decrypt_packet(&frame)
    }
}
