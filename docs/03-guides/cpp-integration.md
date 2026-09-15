# C and C++ Integration Guide

This guide details how to integrate the Opela Nexus Protocol (ONP) into native C and C++ applications, game engines (such as Unreal Engine and custom DirectX/Vulkan engines), and high-performance server architectures.

---

## 1. Overview

ONP exposes a pure C-ABI foreign function interface through `onp-ffi`. The native library provides:
- Complete zero-copy buffer operations where possible.
- In-memory cryptographic session management (Curve25519 ECDH + ChaCha20-Poly1305 AEAD).
- Dynamic polymorphic opcode translation.
- 64-packet anti-replay sliding window.
- Compatibility with MSVC, Clang, and GCC across Windows, Linux, and macOS.

The C interface is defined in [`rust/onp-ffi/include/onp.h`](../../rust/onp-ffi/include/onp.h).

---

## 2. Compiling the FFI Library

Navigate to the `rust/` workspace and build the release target:

```bash
cd rust
cargo build --release -p onp-ffi
```

This generates:
- **Windows**: `target/release/onp_ffi.dll` (dynamic library) and `target/release/onp_ffi.lib` (import and static library).
- **Linux**: `target/release/libonp_ffi.so` (shared object) and `target/release/libonp_ffi.a` (static archive).
- **macOS**: `target/release/libonp_ffi.dylib` (dynamic library) and `target/release/libonp_ffi.a` (static archive).

---

## 3. Project Configuration

### CMake Configuration

Add the following to your `CMakeLists.txt`:

```cmake
cmake_minimum_required(VERSION 3.15)
project(GameClient CXX)

set(CMAKE_CXX_STANDARD 17)

# Include ONP C Header
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/path/to/onp-ffi/include)

add_executable(GameClient main.cpp)

# Link against the ONP shared library
if (WIN32)
    target_link_libraries(GameClient PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/path/to/onp_ffi.dll)
elseif (APPLE)
    target_link_libraries(GameClient PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/path/to/libonp_ffi.dylib)
else ()
    target_link_libraries(GameClient PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/path/to/libonp_ffi.so)
endif ()
```

---

## 4. Native C++ Client Implementation

The following example shows an end-to-end client session lifecycle including handshake, frame encryption, frame decryption, and session termination.

```cpp
#include <iostream>
#include <vector>
#include <string>
#include "onp.h"

class OnpClient {
private:
    OnpSession* session;

public:
    OnpClient() {
        session = onp_session_new_client();
        if (!session) {
            throw std::runtime_error("Failed to allocate ONP client session");
        }
    }

    ~OnpClient() {
        if (session) {
            onp_session_destroy(session);
            session = nullptr;
        }
    }

    // Step 1: Create Handshake SYN
    std::vector<uint8_t> createHandshakeSyn() {
        std::vector<uint8_t> syn_buf(256);
        size_t syn_len = 0;
        int32_t rc = onp_session_create_handshake_syn(session, syn_buf.data(), syn_buf.size(), &syn_len);
        if (rc != ONP_OK) {
            throw std::runtime_error("Failed to generate SYN frame");
        }
        syn_buf.resize(syn_len);
        return syn_buf;
    }

    // Step 2: Complete Handshake with Server ACK
    void processHandshakeAck(const std::vector<uint8_t>& ack_frame) {
        int32_t rc = onp_session_process_handshake_ack(session, ack_frame.data(), ack_frame.size());
        if (rc != ONP_OK) {
            throw std::runtime_error("Failed to process ACK frame: error code " + std::to_string(rc));
        }
    }

    bool isConnected() const {
        return onp_session_is_established(session) == 1;
    }

    // Encrypt application payload
    std::vector<uint8_t> encrypt(uint16_t opcode, const std::string& message) {
        std::vector<uint8_t> frame(message.size() + onp_overhead_size());
        size_t frame_len = 0;

        int32_t rc = onp_session_encrypt(
            session,
            opcode,
            reinterpret_cast<const uint8_t*>(message.data()),
            message.size(),
            frame.data(),
            frame.size(),
            &frame_len
        );

        if (rc != ONP_OK) {
            throw std::runtime_error("Encryption error: " + std::to_string(rc));
        }
        frame.resize(frame_len);
        return frame;
    }

    // Decrypt incoming wire frame
    std::pair<uint16_t, std::string> decrypt(const std::vector<uint8_t>& frame) {
        std::vector<uint8_t> payload(frame.size());
        size_t payload_len = 0;
        uint16_t opcode = 0;

        int32_t rc = onp_session_decrypt(
            session,
            frame.data(),
            frame.size(),
            &opcode,
            payload.data(),
            payload.size(),
            &payload_len
        );

        if (rc != ONP_OK) {
            throw std::runtime_error("Decryption error: " + std::to_string(rc));
        }

        std::string result(reinterpret_cast<char*>(payload.data()), payload_len);
        return {opcode, result};
    }
};
```

---

## 5. Integrating with Sockets (WinSock2 / POSIX)

ONP operates at the presentation and session layer. It accepts raw byte buffers and returns encrypted wire frames. The transport layer is network-agnostic.

### Sending Over TCP Sockets

```cpp
bool sendFrame(SOCKET sock, const std::vector<uint8_t>& frame) {
    size_t total_sent = 0;
    while (total_sent < frame.size()) {
        int bytes = send(sock, reinterpret_cast<const char*>(frame.data() + total_sent), 
                         static_cast<int>(frame.size() - total_sent), 0);
        if (bytes <= 0) {
            return false;
        }
        total_sent += bytes;
    }
    return true;
}
```

### Reading Frames from TCP Sockets

Because ONP uses an 8-byte fixed envelope header, reading frames over a stream socket follows a two-stage read pattern:

1. Read exactly 8 bytes (`ENVELOPE_HEADER_SIZE`).
2. Verify `magic` (`0x4F`, `0x4E`).
3. Extract `payload_len` from bytes 4 to 7 (32-bit little-endian).
4. Read exactly `payload_len` bytes into the buffer.
5. Pass the complete `8 + payload_len` buffer to `onp_session_decrypt`.

```cpp
bool readExact(SOCKET sock, uint8_t* buffer, size_t length) {
    size_t total_read = 0;
    while (total_read < length) {
        int bytes = recv(sock, reinterpret_cast<char*>(buffer + total_read), 
                         static_cast<int>(length - total_read), 0);
        if (bytes <= 0) {
            return false;
        }
        total_read += bytes;
    }
    return true;
}

std::vector<uint8_t> receiveFrame(SOCKET sock) {
    uint8_t header[8];
    if (!readExact(sock, header, 8)) {
        return {};
    }

    if (header[0] != ONP_MAGIC_BYTE_0 || header[1] != ONP_MAGIC_BYTE_1) {
        std::cerr << "Invalid ONP protocol magic bytes" << std::endl;
        return {};
    }

    uint32_t payload_len = *reinterpret_cast<uint32_t*>(header + 4);
    if (payload_len > ONP_MAX_FRAME_PAYLOAD_SIZE) {
        std::cerr << "Frame exceeds maximum payload size" << std::endl;
        return {};
    }

    std::vector<uint8_t> full_frame(8 + payload_len);
    std::memcpy(full_frame.data(), header, 8);
    if (!readExact(sock, full_frame.data() + 8, payload_len)) {
        return {};
    }

    return full_frame;
}
```

---

## 6. Unreal Engine Integration

When integrating into Unreal Engine (UE5 / UE4):

1. Create a third-party module directory: `Source/ThirdParty/ONP/`.
2. Place `onp.h` in `Source/ThirdParty/ONP/include/`.
3. Place `onp_ffi.dll` and `onp_ffi.lib` in `Source/ThirdParty/ONP/lib/Win64/`.
4. In your module `Build.cs`:

```csharp
using UnrealBuildTool;
using System.IO;

public class MyGame : ModuleRules
{
    public MyGame(ReadOnlyTargetRules Target) : base(Target)
    {
        PCHUsage = PCHUsageMode.UseExplicitOrSharedPCHs;

        string ThirdPartyPath = Path.Combine(ModuleDirectory, "../ThirdParty/ONP");
        PublicIncludePaths.Add(Path.Combine(ThirdPartyPath, "include"));

        if (Target.Platform == UnrealTargetPlatform.Win64)
        {
            PublicAdditionalLibraries.Add(Path.Combine(ThirdPartyPath, "lib/Win64/onp_ffi.dll.lib"));
            RuntimeDependencies.Add("$(BinaryOutputDir)/onp_ffi.dll", Path.Combine(ThirdPartyPath, "lib/Win64/onp_ffi.dll"));
        }
    }
}
```

5. Wrap the C-API calls in an Unreal Subsystem (`UGameInstanceSubsystem`) to manage session persistence across level transitions.
