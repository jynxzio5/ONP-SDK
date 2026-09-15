# Mobile Integration Guide (Android, iOS, React Native, Flutter)

This guide provides end-to-end integration instructions for deploying the Opela Nexus Protocol (ONP) on mobile platforms, covering native Android (Kotlin / JNI), native iOS (Swift / XCFramework), and cross-platform mobile frameworks (Flutter Dart FFI and React Native).

---

## 1. Overview

Mobile environments present unique networking constraints: frequent network handoffs (Wi-Fi to Cellular), carrier-grade NAT timeouts, aggressive OS process suspension, and battery optimization policies.

ONP addresses these constraints with:
- **Stateless Handshake & Fast Resumption**: Ephemeral X25519 key agreements that can be renegotiated in a single round-trip (`SYN` -> `ACK`).
- **Low Power & Minimal Battery Drain**: Hardware-accelerated ChaCha20-Poly1305 utilizing ARMv8 Crypto Extensions / NEON SIMD instructions.
- **Zero Allocations in Steady State**: Compact 8-byte framing with fixed cryptographic overhead (38 bytes total).
- **Network Agnostic**: Operates identically over TCP (`java.net.Socket`, `NWConnection`), WebSockets, or UDP-like datagrams.

---

## 2. Compiling Native Mobile Binaries

ONP's native C-ABI engine (`rust/onp-ffi`) must be cross-compiled for target mobile CPU architectures.

### Android Toolchain Setup

Install the target architectures and `cargo-ndk`:

```bash
cargo install cargo-ndk
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
```

Build the release shared libraries:

```bash
# 64-bit ARM (Standard modern Android devices)
cargo ndk -t arm64-v8a -o ./android_libs build --release -p onp-ffi

# 32-bit ARM (Legacy Android devices)
cargo ndk -t armeabi-v7a -o ./android_libs build --release -p onp-ffi

# x86_64 (Android Studio Emulator)
cargo ndk -t x86_64 -o ./android_libs build --release -p onp-ffi
```

Place the generated `.so` files in your Android Studio project under:
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

### iOS Toolchain Setup

Install the Apple targets:

```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
```

Compile the static libraries:

```bash
# Physical iOS Device (iPhone / iPad)
cargo build --release -p onp-ffi --target aarch64-apple-ios

# iOS Simulator (Apple Silicon Mac)
cargo build --release -p onp-ffi --target aarch64-apple-ios-sim

# iOS Simulator (Intel Mac)
cargo build --release -p onp-ffi --target x86_64-apple-ios
```

Combine the simulator targets into a fat binary, then build the `ONP.xcframework`:

```bash
# Combine simulator architectures
lipo -create \
  target/aarch64-apple-ios-sim/release/libonp_ffi.a \
  target/x86_64-apple-ios/release/libonp_ffi.a \
  -output target/libonp_ffi_sim.a

# Generate XCFramework
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libonp_ffi.a \
  -headers rust/onp-ffi/include/ \
  -library target/libonp_ffi_sim.a \
  -headers rust/onp-ffi/include/ \
  -output ONP.xcframework
```

Drag `ONP.xcframework` into your Xcode project under **Frameworks, Libraries, and Embedded Content** and set to **Do Not Embed** (static library).

---

## 3. Native Android Integration (Kotlin & JNI)

### 1. Kotlin Session Class (`OnpSession.kt`)

```kotlin
package com.opela.nexus.protocol

class OnpSession(val isClient: Boolean = true) : AutoCloseable {

    private var nativeHandle: Long = 0

    init {
        nativeHandle = if (isClient) nativeNewClient() else nativeNewServer()
        if (nativeHandle == 0L) {
            throw OutOfMemoryError("Failed to allocate ONP session")
        }
    }

    val isEstablished: Boolean
        get() = nativeHandle != 0L && nativeIsEstablished(nativeHandle) == 1

    fun createHandshakeSyn(): ByteArray {
        checkActive()
        return nativeCreateHandshakeSyn(nativeHandle)
            ?: throw IllegalStateException("Failed to create Handshake SYN")
    }

    fun processHandshakeSyn(synFrame: ByteArray): ByteArray {
        checkActive()
        return nativeProcessHandshakeSyn(nativeHandle, synFrame)
            ?: throw IllegalStateException("Failed to process Handshake SYN")
    }

    fun processHandshakeAck(ackFrame: ByteArray) {
        checkActive()
        val rc = nativeProcessHandshakeAck(nativeHandle, ackFrame)
        if (rc != 0) {
            throw IllegalStateException("Failed to process Handshake ACK (error: $rc)")
        }
    }

    fun encrypt(opcode: Int, payload: ByteArray): ByteArray {
        checkActive()
        return nativeEncrypt(nativeHandle, opcode, payload)
            ?: throw IllegalStateException("Encryption failed")
    }

    fun decrypt(frame: ByteArray): Pair<Int, ByteArray> {
        checkActive()
        val result = nativeDecrypt(nativeHandle, frame)
            ?: throw IllegalStateException("Decryption failed or replay detected")
        return result
    }

    private fun checkActive() {
        if (nativeHandle == 0L) throw IllegalStateException("Session closed")
    }

    override fun close() {
        if (nativeHandle != 0L) {
            nativeDestroy(nativeHandle)
            nativeHandle = 0L
        }
    }

    companion object {
        init {
            System.loadLibrary("onp_jni") // or System.loadLibrary("onp_ffi") with JNA
        }

        @JvmStatic private external fun nativeNewClient(): Long
        @JvmStatic private external fun nativeNewServer(): Long
        @JvmStatic private external fun nativeIsEstablished(handle: Long): Int
        @JvmStatic private external fun nativeDestroy(handle: Long)
        @JvmStatic private external fun nativeCreateHandshakeSyn(handle: Long): ByteArray?
        @JvmStatic private external fun nativeProcessHandshakeSyn(handle: Long, syn: ByteArray): ByteArray?
        @JvmStatic private external fun nativeProcessHandshakeAck(handle: Long, ack: ByteArray): Int
        @JvmStatic private external fun nativeEncrypt(handle: Long, opcode: Int, payload: ByteArray): ByteArray?
        @JvmStatic private external fun nativeDecrypt(handle: Long, frame: ByteArray): Pair<Int, ByteArray>?
    }
}
```

---

## 4. Native iOS Integration (Swift & XCFramework)

In Xcode, ensure your bridging header includes `onp.h`:

```objc
// YourApp-Bridging-Header.h
#import "onp.h"
```

### Swift Session Wrapper (`OnpSession.swift`)

```swift
import Foundation

public final class OnpSession {
    private var handle: OpaquePointer?

    public init(isClient: Bool = true) {
        self.handle = isClient ? onp_session_new_client() : onp_session_new_server()
        guard self.handle != nil else {
            fatalError("Failed to allocate ONP session")
        }
    }

    deinit {
        destroy()
    }

    public func destroy() {
        if let h = handle {
            onp_session_destroy(h)
            handle = nil
        }
    }

    public var isEstablished: Bool {
        guard let h = handle else { return false }
        return onp_session_is_established(h) == 1
    }

    public func createHandshakeSyn() throws -> Data {
        guard let h = handle else { throw OnpError.sessionClosed }
        var buffer = Data(count: 256)
        var outLen: Int = 0

        let status = buffer.withUnsafeMutableBytes { (ptr: UnsafeMutableRawBufferPointer) -> Int32 in
            guard let base = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return ONP_ERR_NULL_PTR }
            return onp_session_create_handshake_syn(h, base, ptr.count, &outLen)
        }

        guard status == ONP_OK else { throw OnpError.nativeError(code: status) }
        return buffer.prefix(outLen)
    }

    public func processHandshakeAck(ackData: Data) throws {
        guard let h = handle else { throw OnpError.sessionClosed }
        let status = ackData.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) -> Int32 in
            guard let base = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return ONP_ERR_NULL_PTR }
            return onp_session_process_handshake_ack(h, base, ptr.count)
        }
        guard status == ONP_OK else { throw OnpError.nativeError(code: status) }
    }

    public func encrypt(opcode: UInt16, payload: Data) throws -> Data {
        guard let h = handle else { throw OnpError.sessionClosed }
        let overhead = onp_overhead_size()
        var buffer = Data(count: payload.count + overhead)
        var outLen: Int = 0

        let status = payload.withUnsafeBytes { pIn -> Int32 in
            let baseIn = pIn.baseAddress?.assumingMemoryBound(to: UInt8.self)
            return buffer.withUnsafeMutableBytes { pOut -> Int32 in
                guard let baseOut = pOut.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return ONP_ERR_NULL_PTR }
                return onp_session_encrypt(h, opcode, baseIn, pIn.count, baseOut, pOut.count, &outLen)
            }
        }

        guard status == ONP_OK else { throw OnpError.nativeError(code: status) }
        return buffer.prefix(outLen)
    }

    public func decrypt(frame: Data) throws -> (opcode: UInt16, payload: Data) {
        guard let h = handle else { throw OnpError.sessionClosed }
        var outBuffer = Data(count: frame.count)
        var outLen: Int = 0
        var outOpcode: UInt16 = 0

        let status = frame.withUnsafeBytes { pFrame -> Int32 in
            guard let baseFrame = pFrame.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return ONP_ERR_NULL_PTR }
            return outBuffer.withUnsafeMutableBytes { pOut -> Int32 in
                guard let baseOut = pOut.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return ONP_ERR_NULL_PTR }
                return onp_session_decrypt(h, baseFrame, pFrame.count, &outOpcode, baseOut, pOut.count, &outLen)
            }
        }

        guard status == ONP_OK else { throw OnpError.nativeError(code: status) }
        return (outOpcode, outBuffer.prefix(outLen))
    }
}

public enum OnpError: Error {
    case sessionClosed
    case nativeError(code: Int32)
}
```

---

## 5. Flutter Integration (Dart FFI)

Flutter applications can invoke `onp_ffi` directly through `dart:ffi` without Java or Objective-C channel overhead.

### Dart FFI Binding (`onp_bindings.dart`)

```dart
import 'dart:ffi' as ffi;
import 'dart:io';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';

typedef NativeNewClient = ffi.Pointer<ffi.Void> Function();
typedef DartNewClient = ffi.Pointer<ffi.Void> Function();

typedef NativeDestroy = ffi.Void Function(ffi.Pointer<ffi.Void>);
typedef DartDestroy = void Function(ffi.Pointer<ffi.Void>);

typedef NativeEncrypt = ffi.Int32 Function(
    ffi.Pointer<ffi.Void>,
    ffi.Uint16,
    ffi.Pointer<ffi.Uint8>,
    ffi.Size,
    ffi.Pointer<ffi.Uint8>,
    ffi.Size,
    ffi.Pointer<ffi.Size>
);
typedef DartEncrypt = int Function(
    ffi.Pointer<ffi.Void>,
    int,
    ffi.Pointer<ffi.Uint8>,
    int,
    ffi.Pointer<ffi.Uint8>,
    int,
    ffi.Pointer<ffi.Size>
);

class OnpFlutterSession {
  late ffi.DynamicLibrary _lib;
  ffi.Pointer<ffi.Void>? _session;

  late DartNewClient _newClient;
  late DartDestroy _destroy;
  late DartEncrypt _encrypt;

  OnpFlutterSession() {
    if (Platform.isAndroid) {
      _lib = ffi.DynamicLibrary.open('libonp_ffi.so');
    } else if (Platform.isIOS) {
      _lib = ffi.DynamicLibrary.process();
    } else {
      throw UnsupportedError('Unsupported mobile platform');
    }

    _newClient = _lib.lookupFunction<NativeNewClient, DartNewClient>('onp_session_new_client');
    _destroy = _lib.lookupFunction<NativeDestroy, DartDestroy>('onp_session_destroy');
    _encrypt = _lib.lookupFunction<NativeEncrypt, DartEncrypt>('onp_session_encrypt');

    _session = _newClient();
  }

  Uint8List encrypt(int opcode, Uint8List payload) {
    final payloadPtr = malloc<ffi.Uint8>(payload.length);
    final outCap = payload.length + 38;
    final outPtr = malloc<ffi.Uint8>(outCap);
    final outLenPtr = malloc<ffi.Size>();

    try {
      payloadPtr.asTypedList(payload.length).setAll(0, payload);

      final status = _encrypt(
        _session!,
        opcode,
        payloadPtr,
        payload.length,
        outPtr,
        outCap,
        outLenPtr,
      );

      if (status != 0) {
        throw Exception('Encryption error: $status');
      }

      final outLen = outLenPtr.value;
      return Uint8List.fromList(outPtr.asTypedList(outLen));
    } finally {
      malloc.free(payloadPtr);
      malloc.free(outPtr);
      malloc.free(outLenPtr);
    }
  }

  void dispose() {
    if (_session != null) {
      _destroy(_session!);
      _session = null;
    }
  }
}
```

---

## 6. React Native Integration

For React Native, developers have two architectural options:

1. **Pure TypeScript Engine**: Use `@opela-team/onp` directly with the `react-native-quick-crypto` or WebCrypto polyfill.
2. **JSI / TurboModule**: Bind directly to `libonp_ffi.so` (Android) and `libonp_ffi.a` (iOS) using modern React Native C++ TurboModules for zero-copy binary bridge performance.

---

## 7. Mobile Best Practices

### Handling App Suspension and Resumption
When an app moves to the background on iOS or Android:
1. Sockets may be terminated or frozen by the operating system after a brief grace period (e.g., 30 seconds).
2. Store the ephemeral session state or teardown cleanly with `onp_session_destroy()`.
3. Upon returning to foreground (`didBecomeActiveNotification` on iOS or `onResume` on Android), re-execute the lightweight 3-step handshake (`SYN` -> `ACK`).

### Handling Cellular / Wi-Fi Handoffs
Mobile IP addresses change when switching between Wi-Fi and mobile data networks:
- Because ONP is transport-agnostic, existing session symmetric keys remain cryptographically valid if renegotiating over a fresh TCP connection or new UDP transport.
- The 64-packet anti-replay sliding window protects against out-of-order packets during cell tower transitions.
- If packets are dropped during handover, client and server will detect sequence gaps; if sequence exhaustion occurs, re-handshake immediately.
