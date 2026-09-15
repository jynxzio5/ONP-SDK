# Multi-Platform Deployment Guide

The Opela Nexus Protocol (ONP) is engineered for zero-dependency native execution across client devices, mobile operating systems, embedded hardware, and distributed cloud backends.

This guide provides compilation targets, packaging instructions, and runtime deployment practices for all major operating systems and architectures.

---

## 1. Supported Platform Matrix

| Platform | Architectures | Binary Output | Integration Mechanism |
| :--- | :--- | :--- | :--- |
| **Windows** | `x86_64`, `aarch64` | `onp_ffi.dll`, `onp_ffi.lib` | C-ABI DLL, P/Invoke, MSVC / MinGW |
| **Linux** | `x86_64`, `aarch64`, `armv7` | `libonp_ffi.so`, `libonp_ffi.a` | C-ABI Shared Object, Glibc / Musl |
| **macOS** | Apple Silicon (`arm64`), Intel (`x86_64`) | `libonp_ffi.dylib`, `libonp_ffi.a` | Universal Mach-O Binary, Framework |
| **Android** | `arm64-v8a`, `armeabi-v7a`, `x86_64` | `libonp_ffi.so` | Android NDK, JNI / NativeActivity |
| **iOS** | `arm64` (Device), `x86_64` (Simulator) | `ONP.xcframework` | Static C Archive, Swift C-Bridging |
| **Web / Browsers** | `wasm32-unknown-unknown` | `.wasm` or Pure TypeScript | WebCrypto API / WebSockets / WebRTC |

---

## 2. Windows

### Prerequisites
- Visual Studio 2022 (MSVC toolchain `x86_64-pc-windows-msvc`) or LLVM MinGW.
- Rust toolchain (`stable-x86_64-pc-windows-msvc`).

### Compilation
```cmd
cargo build --release -p onp-ffi --target x86_64-pc-windows-msvc
```

The resulting files are located in `rust/target/x86_64-pc-windows-msvc/release/`:
- `onp_ffi.dll`: Dynamic link library for runtime deployment.
- `onp_ffi.dll.lib`: Import library for linking with MSVC `link.exe`.
- `onp_ffi.lib`: Full static archive if linking without dynamic runtime dependencies.

### Socket API Note
On Windows, initialize WinSock before calling socket operations:
```cpp
WSADATA wsaData;
WSAStartup(MAKEWORD(2, 2), &wsaData);
// ... perform ONP encrypted network I/O ...
WSACleanup();
```

---

## 3. Linux (Cloud Servers and Embedded Devices)

### Standard Glibc (Ubuntu, Debian, RHEL, Arch)
```bash
cargo build --release -p onp-ffi --target x86_64-unknown-linux-gnu
```

### Static Musl (Alpine Linux, Distroless Containers)
Producing fully self-contained binaries without libc dependencies:
```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release -p onp-ffi --target x86_64-unknown-linux-musl
```

### ARM64 (AWS Graviton, Raspberry Pi 4/5)
```bash
rustup target add aarch64-unknown-linux-gnu
cargo build --release -p onp-ffi --target aarch64-unknown-linux-gnu
```

---

## 4. macOS (Universal Binaries)

To support both Apple Silicon (M1/M2/M3/M4) and Intel Macs with a single universal dynamic library:

```bash
rustup target add aarch64-apple-darwin
rustup target add x86_64-apple-darwin

cargo build --release -p onp-ffi --target aarch64-apple-darwin
cargo build --release -p onp-ffi --target x86_64-apple-darwin

# Combine into a single universal Mach-O binary with lipo
lipo -create \
  target/aarch64-apple-darwin/release/libonp_ffi.dylib \
  target/x86_64-apple-darwin/release/libonp_ffi.dylib \
  -output target/release/libonp_ffi.dylib
```

---

## 5. Android (NDK & JNI)

ONP can be built for Android devices using `cargo-ndk`.

### Setup
```bash
cargo install cargo-ndk
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
```

### Building for Architectures
Set your `ANDROID_NDK_HOME` environment variable and run:

```bash
# ARM64 (standard for modern Android devices)
cargo ndk -t arm64-v8a build --release -p onp-ffi

# ARMv7 (32-bit legacy devices)
cargo ndk -t armeabi-v7a build --release -p onp-ffi

# x86_64 (Android Studio Emulator)
cargo ndk -t x86_64 build --release -p onp-ffi
```

### Placement in Android Project
Copy the `.so` files into your Android app module:
```
app/src/main/jniLibs/
├── arm64-v8a/
│   └── libonp_ffi.so
├── armeabi-v7a/
│   └── libonp_ffi.so
└── x86_64/
    └── libonp_ffi.so
```

---

## 6. iOS (XCFramework & Swift)

For iOS applications, compile static libraries for device and simulator, then package into an `XCFramework`.

```bash
rustup target add aarch64-apple-ios
rustup target add aarch64-apple-ios-sim

cargo build --release -p onp-ffi --target aarch64-apple-ios
cargo build --release -p onp-ffi --target aarch64-apple-ios-sim

# Package as XCFramework
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libonp_ffi.a \
  -headers include/ \
  -library target/aarch64-apple-ios-sim/release/libonp_ffi.a \
  -headers include/ \
  -output ONP.xcframework
```

### Swift Bridging Header
In your Xcode project, add `#include "onp.h"` to your Objective-C Bridging Header. The C functions (`onp_session_new_client`, `onp_session_encrypt`, etc.) become directly callable from Swift.

---

## 7. WebAssembly and Browsers

For web browsers, WebWorkers, and WebViews, ONP is available through two avenues:

1. **Pure TypeScript Engine (`typescript/`)**:
   Uses standard JavaScript WebCrypto (`crypto.subtle`) for high compatibility and zero compilation overhead.
2. **WebAssembly Target**:
   Compile the core Rust crate to WebAssembly:
   ```bash
   wasm-pack build rust/onp-core --target web --release
   ```

### Browser Transport Compatibility
Because raw TCP sockets are restricted in sandboxed web environments, ONP frames run inside:
- **Binary WebSockets**: Each WebSocket binary message encapsulates one or more complete ONP wire frames.
- **WebRTC DataChannels**: Zero-overhead UDP-like datagram delivery with ordered/reliable delivery flags.
