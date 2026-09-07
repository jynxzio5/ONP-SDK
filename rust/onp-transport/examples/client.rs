//! Example Standalone ONP Client.
//! Run with: cargo run -p onp-transport --example client

use std::error::Error;
use std::time::Instant;
use onp_core::constants::LogicalOpcode;
use onp_transport::OnpTcpConnection;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let server_addr = "127.0.0.1:9095";
    println!("[ONP-CLIENT] 🔌 Connecting to {}...", server_addr);

    let start_handshake = Instant::now();
    let mut conn = OnpTcpConnection::connect(server_addr).await?;
    println!(
        "[ONP-CLIENT] ✅ Connected & Handshake established in {:.2?}!",
        start_handshake.elapsed()
    );

    // Send encrypted LobbyJoin action
    let lobby_request = b"PLAYER_UUID_1337_JOIN_RANKED";
    println!("[ONP-CLIENT] 📤 Sending LobbyJoin packet (Polymorphic Opcode on wire)...");
    conn.send_packet(LogicalOpcode::LobbyJoin, lobby_request).await?;

    // Await encrypted response
    let response = conn.recv_packet().await?;
    println!(
        "[ONP-CLIENT] 📥 Received response: Opcode={:?}, Body={}",
        response.opcode,
        String::from_utf8_lossy(&response.data)
    );

    // Measure Ping-Pong latency
    println!("[ONP-CLIENT] ⚡ Measuring Ping-Pong round-trip latency...");
    for i in 1..=5 {
        let ping_time = Instant::now();
        conn.send_packet(LogicalOpcode::SysPing, format!("PING_{}", i).as_bytes()).await?;
        let _pong = conn.recv_packet().await?;
        println!("[ONP-CLIENT]    Round #{}: Latency = {:.2?}", i, ping_time.elapsed());
    }

    println!("[ONP-CLIENT] 🎉 All operations verified! Clean protocol shutdown.");
    Ok(())
}
