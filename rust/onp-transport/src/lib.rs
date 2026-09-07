//! # Opela Nexus Protocol (ONP) Transport Engine
//!
//! Tokio-based async network stream wrappers, codecs, and connection managers.

pub mod codec;
pub mod tcp;

pub use codec::OnpCodec;
pub use tcp::OnpTcpConnection;

#[cfg(test)]
mod tests {
    use super::*;
    use onp_core::constants::LogicalOpcode;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_live_tcp_handshake_and_echo() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn server loop
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn = OnpTcpConnection::accept(stream).await.unwrap();

            // Receive ping
            let packet = conn.recv_packet().await.unwrap();
            assert_eq!(packet.opcode, LogicalOpcode::SysPing);
            assert_eq!(packet.data, b"TCP_PING_123");

            // Reply pong
            conn.send_packet(LogicalOpcode::SysPong, b"TCP_PONG_CONFIRMED")
                .await
                .unwrap();
        });

        // Client connects
        let mut client_conn = OnpTcpConnection::connect(&addr.to_string()).await.unwrap();

        // Client sends ping
        client_conn
            .send_packet(LogicalOpcode::SysPing, b"TCP_PING_123")
            .await
            .unwrap();

        // Client receives pong
        let reply = client_conn.recv_packet().await.unwrap();
        assert_eq!(reply.opcode, LogicalOpcode::SysPong);
        assert_eq!(reply.data, b"TCP_PONG_CONFIRMED");

        server_task.await.unwrap();
    }
}
