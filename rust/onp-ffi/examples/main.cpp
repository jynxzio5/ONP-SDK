/**
 * Opela Nexus Protocol (ONP) - C++ Native Usage Example
 *
 * Demonstrates:
 * 1. Initializing client and server sessions
 * 2. Performing the 3-step X25519 + HKDF-SHA256 handshake
 * 3. Encrypting application payloads with polymorphic opcodes
 * 4. Decrypting payloads and verifying AEAD integrity
 * 5. Anti-replay sliding window validation
 *
 * Compilation (MSVC):
 *   cl /EHsc /I../include main.cpp /link /LIBPATH:../../target/release onp_ffi.dll.lib
 *
 * Compilation (GCC / Clang):
 *   g++ -std=c++17 -I../include main.cpp -L../../target/release -lonp_ffi -o onp_example
 */

#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include "onp.h"

int main() {
    std::cout << "[ONP Native C++ Example]" << std::endl;
    std::cout << "ONP Protocol Version: " << onp_version() << std::endl;
    std::cout << "Max Frame Payload: " << onp_max_payload_size() << " bytes" << std::endl;
    std::cout << "Cryptographic Overhead: " << onp_overhead_size() << " bytes\n" << std::endl;

    // 1. Initialize Client and Server Session Handles
    OnpSession* client = onp_session_new_client();
    OnpSession* server = onp_session_new_server();

    if (!client || !server) {
        std::cerr << "Failed to allocate ONP session memory." << std::endl;
        return 1;
    }

    // 2. Client Step 1: Generate HANDSHAKE_SYN
    std::vector<uint8_t> syn_buf(256);
    size_t syn_len = 0;
    int32_t status = onp_session_create_handshake_syn(client, syn_buf.data(), syn_buf.size(), &syn_len);
    if (status != ONP_OK) {
        std::cerr << "Failed to generate HANDSHAKE_SYN: " << status << std::endl;
        return 1;
    }
    syn_buf.resize(syn_len);
    std::cout << "1. Client created HANDSHAKE_SYN (" << syn_len << " bytes)" << std::endl;

    // 3. Server Step 2: Process HANDSHAKE_SYN and Generate HANDSHAKE_ACK
    std::vector<uint8_t> ack_buf(256);
    size_t ack_len = 0;
    status = onp_session_process_handshake_syn(
        server,
        syn_buf.data(),
        syn_buf.size(),
        ack_buf.data(),
        ack_buf.size(),
        &ack_len
    );
    if (status != ONP_OK) {
        std::cerr << "Server failed to process HANDSHAKE_SYN: " << status << std::endl;
        return 1;
    }
    ack_buf.resize(ack_len);
    std::cout << "2. Server processed SYN and generated HANDSHAKE_ACK (" << ack_len << " bytes)" << std::endl;

    // 4. Client Step 3: Process HANDSHAKE_ACK
    status = onp_session_process_handshake_ack(client, ack_buf.data(), ack_buf.size());
    if (status != ONP_OK) {
        std::cerr << "Client failed to process HANDSHAKE_ACK: " << status << std::endl;
        return 1;
    }
    std::cout << "3. Client processed ACK. Both sessions established!" << std::endl;
    std::cout << "   Client Established: " << (onp_session_is_established(client) ? "YES" : "NO") << std::endl;
    std::cout << "   Server Established: " << (onp_session_is_established(server) ? "YES" : "NO") << "\n" << std::endl;

    // 5. Client: Encrypt an Application Packet
    const std::string message = "Nexus C++ Core Engine online and authenticated.";
    std::vector<uint8_t> frame_buf(message.size() + onp_overhead_size());
    size_t frame_len = 0;

    status = onp_session_encrypt(
        client,
        ONP_OPCODE_LOBBY_JOIN,
        reinterpret_cast<const uint8_t*>(message.data()),
        message.size(),
        frame_buf.data(),
        frame_buf.size(),
        &frame_len
    );
    if (status != ONP_OK) {
        std::cerr << "Encryption failed: " << status << std::endl;
        return 1;
    }
    frame_buf.resize(frame_len);
    std::cout << "4. Encrypted packet: " << message.size() << " bytes plaintext -> "
              << frame_len << " bytes wire frame" << std::endl;

    // 6. Server: Decrypt Application Packet
    std::vector<uint8_t> decrypted_buf(frame_len);
    size_t decrypted_len = 0;
    uint16_t received_opcode = 0;

    status = onp_session_decrypt(
        server,
        frame_buf.data(),
        frame_buf.size(),
        &received_opcode,
        decrypted_buf.data(),
        decrypted_buf.size(),
        &decrypted_len
    );
    if (status != ONP_OK) {
        std::cerr << "Decryption failed: " << status << std::endl;
        return 1;
    }

    std::string received_str(reinterpret_cast<char*>(decrypted_buf.data()), decrypted_len);
    std::cout << "5. Server successfully decrypted packet:" << std::endl;
    std::cout << "   Opcode: 0x" << std::hex << received_opcode << std::dec
              << " (Matches ONP_OPCODE_LOBBY_JOIN: " << (received_opcode == ONP_OPCODE_LOBBY_JOIN ? "YES" : "NO") << ")" << std::endl;
    std::cout << "   Payload: \"" << received_str << "\"\n" << std::endl;

    // 7. Security Verification: Replay Attack Rejection
    std::cout << "6. Testing Anti-Replay Sliding Window defense..." << std::endl;
    int32_t replay_status = onp_session_decrypt(
        server,
        frame_buf.data(),
        frame_buf.size(),
        &received_opcode,
        decrypted_buf.data(),
        decrypted_buf.size(),
        &decrypted_len
    );

    if (replay_status == ONP_ERR_REPLAY_DETECTED) {
        std::cout << "   SUCCESS: Replayed frame was blocked immediately (Error code: "
                  << replay_status << ")" << std::endl;
    } else {
        std::cerr << "   FAILURE: Replayed frame was not rejected! Status: " << replay_status << std::endl;
    }

    // 8. Cleanup and Secure Memory Zeroization
    onp_session_destroy(client);
    onp_session_destroy(server);
    std::cout << "\n7. Sessions destroyed and key memory zeroized." << std::endl;

    return 0;
}
