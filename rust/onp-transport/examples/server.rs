//! Example Standalone ONP Echo & Benchmark Server.
//! Run with: cargo run -p onp-transport --example server

use std::error::Error;
use tokio::net::TcpListener;
use onp_core::constants::LogicalOpcode;
use onp_transport::OnpTcpConnection;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let bind_addr = "127.0.0.1:9095";
    let listener = TcpListener::bind(bind_addr).await?;
    println!("[ONP-SERVER] 🚀 Server listening on {}...", bind_addr);
    println!("[ONP-SERVER] Waiting for encrypted client connections with rolling opcodes...");

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        println!("[ONP-SERVER] 🔗 Accepted TCP stream from {}", peer_addr);

        tokio::spawn(async move {
            match OnpTcpConnection::accept(stream).await {
                Ok(mut conn) => {
                    println!("[ONP-SERVER] ✅ Handshake completed with {}! Cipher active: ChaCha20-Poly1305", peer_addr);
                    
                    while let Ok(packet) = conn.recv_packet().await {
                        println!(
                            "[ONP-SERVER] 📦 Decrypted packet: Opcode={:?}, PayloadSize={} bytes",
                            packet.opcode,
                            packet.data.len()
                        );

                        // Echo or respond
                        match packet.opcode {
                            LogicalOpcode::SysPing => {
                                let _ = conn.send_packet(LogicalOpcode::SysPong, &packet.data).await;
                            }
                            LogicalOpcode::LobbyJoin => {
                                let reply = b"{\"status\":\"LOBBY_JOINED\",\"roomId\":42}";
                                let _ = conn.send_packet(LogicalOpcode::LobbyState, reply).await;
                            }
                            _ => {
                                let _ = conn.send_packet(packet.opcode, &packet.data).await;
                            }
                        }
                    }
                    println!("[ONP-SERVER] 🔌 Connection closed by {}", peer_addr);
                }
                Err(e) => {
                    eprintln!("[ONP-SERVER] ❌ Handshake failed with {}: {}", peer_addr, e);
                }
            }
        });
    }
}
