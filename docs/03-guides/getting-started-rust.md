# Getting Started with Rust

## Crates Overview

ONP is split into two specialized Rust crates:
1. **`onp-core`**: Pure protocol engine with zero external network dependencies. Implements envelope codecs, ChaCha20-Poly1305, Curve25519, polymorphic opcode generation, and sliding window filters.
2. **`onp-transport`**: Asynchronous networking runtime on top of `tokio` and `tokio-util`.

---

## 1. Dependency Setup

Add to your `Cargo.toml`:

```toml
[dependencies]
onp-core = { path = "rust/onp-core" }
onp-transport = { path = "rust/onp-transport" }
tokio = { version = "1.0", features = ["full"] }
```

---

## 2. Low-Level In-Memory Handshake & Framing

```rust
use onp_core::session::OnpSession;
use onp_core::constants::LogicalOpcode;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize sessions
    let mut client = OnpSession::new_client();
    let mut server = OnpSession::new_server();

    // 2. Perform 1-RTT Handshake
    let syn = client.create_handshake_syn()?;
    let ack = server.process_handshake_syn(&syn)?;
    client.process_handshake_ack(&ack)?;

    println!("Handshake verified successfully.");

    // 3. Encrypt payload
    let msg = b"Binary telemetry payload from Rust";
    let encrypted_frame = client.encrypt(LogicalOpcode::DataStream, msg)?;

    // 4. Decrypt payload
    let (opcode, decrypted) = server.decrypt(&encrypted_frame)?;
    println!("Decrypted Opcode: {:?}", opcode);
    println!("Decrypted Content: {}", String::from_utf8_lossy(&decrypted));

    // 5. Explicitly zeroize keys
    client.destroy();
    server.destroy();

    Ok(())
}
```

---

## 3. Live Asynchronous TCP Server (`onp-transport`)

```rust
use onp_transport::tcp::OnpTcpListener;
use onp_core::constants::LogicalOpcode;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut listener = OnpTcpListener::bind("127.0.0.1:9000").await?;
    println!("ONP TCP server listening on 127.0.0.1:9000");

    while let Ok(mut socket) = listener.accept().await {
        tokio::spawn(async move {
            while let Ok(Some((opcode, payload))) = socket.read_frame().await {
                println!("Received frame: {:?} ({} bytes)", opcode, payload.len());

                // Echo reply
                if let Err(e) = socket.send_frame(LogicalOpcode::RpcReply, &payload).await {
                    eprintln!("Failed to send reply: {}", e);
                    break;
                }
            }
        });
    }

    Ok(())
}
```
