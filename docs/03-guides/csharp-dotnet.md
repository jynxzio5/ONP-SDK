# C# and .NET Integration Guide

This guide details how to integrate the Opela Nexus Protocol (ONP) in C# .NET 8 / 9 applications and the Unity Game Engine using native P/Invoke bindings to `onp_ffi`.

---

## 1. Prerequisites & Library Placement

Compile the release binaries:

```bash
cd rust
cargo build --release -p onp-ffi
```

### For .NET Core / .NET 8+
Place the binary in your output directory (or specify a `[DefaultDllImportSearchPaths]` or custom resolver):
- Windows: `runtimes/win-x64/native/onp_ffi.dll`
- Linux: `runtimes/linux-x64/native/libonp_ffi.so`
- macOS: `runtimes/osx-arm64/native/libonp_ffi.dylib`

### For Unity Game Engine
Place the compiled libraries in your Unity project:
- Windows: `Assets/Plugins/x86_64/onp_ffi.dll`
- Linux: `Assets/Plugins/x86_64/libonp_ffi.so`
- macOS: `Assets/Plugins/macOS/libonp_ffi.dylib`
- Android: `Assets/Plugins/Android/libs/arm64-v8a/libonp_ffi.so`
- iOS: `Assets/Plugins/iOS/libonp_ffi.a`

---

## 2. Safe P/Invoke Bindings (`OnpNative.cs`)

```csharp
using System;
using System.Runtime.InteropServices;

namespace Opela.Nexus.Protocol
{
    public static class OnpNative
    {
        private const string LibName = "onp_ffi";

        public const int ONP_OK = 0;
        public const int ONP_ERR_NULL_PTR = -1;
        public const int ONP_ERR_BUFFER_TOO_SMALL = -2;
        public const int ONP_ERR_INVALID_STATE = -3;
        public const int ONP_ERR_CRYPTO_FAILED = -4;
        public const int ONP_ERR_REPLAY_DETECTED = -5;
        public const int ONP_ERR_UNKNOWN_OPCODE = -6;
        public const int ONP_ERR_FRAME_CORRUPT = -7;
        public const int ONP_ERR_SEQUENCE_EXHAUSTED = -8;
        public const int ONP_ERR_FRAME_TOO_LARGE = -9;

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint onp_version();

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        public static extern UIntPtr onp_max_payload_size();

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        public static extern UIntPtr onp_overhead_size();

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr onp_session_new_client();

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr onp_session_new_server();

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int onp_session_is_established(IntPtr session);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void onp_session_destroy(IntPtr session);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        public static extern unsafe int onp_session_create_handshake_syn(
            IntPtr session,
            byte* outBuf,
            UIntPtr outCapacity,
            UIntPtr* outLen
        );

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        public static extern unsafe int onp_session_process_handshake_syn(
            IntPtr session,
            byte* inSyn,
            UIntPtr inSynLen,
            byte* outAck,
            UIntPtr outCapacity,
            UIntPtr* outLen
        );

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        public static extern unsafe int onp_session_process_handshake_ack(
            IntPtr session,
            byte* inAck,
            UIntPtr inAckLen
        );

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        public static extern unsafe int onp_session_encrypt(
            IntPtr session,
            ushort opcode,
            byte* payload,
            UIntPtr payloadLen,
            byte* outBuf,
            UIntPtr outCapacity,
            UIntPtr* outLen
        );

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        public static extern unsafe int onp_session_decrypt(
            IntPtr session,
            byte* frame,
            UIntPtr frameLen,
            ushort* outOpcode,
            byte* outBuf,
            UIntPtr outCapacity,
            UIntPtr* outLen
        );
    }
}
```

---

## 3. High-Level Managed Wrapper (`OnpSession.cs`)

```csharp
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Opela.Nexus.Protocol
{
    public sealed class OnpSession : IDisposable
    {
        private IntPtr _handle;
        private bool _disposed;

        public bool IsEstablished => _handle != IntPtr.Zero && OnpNative.onp_session_is_established(_handle) == 1;

        public OnpSession(bool isClient = true)
        {
            _handle = isClient ? OnpNative.onp_session_new_client() : OnpNative.onp_session_new_server();
            if (_handle == IntPtr.Zero)
            {
                throw new OutOfMemoryException("Failed to allocate ONP session.");
            }
        }

        public unsafe byte[] CreateHandshakeSyn()
        {
            ThrowIfDisposed();
            byte[] buffer = new byte[256];
            UIntPtr outLen;

            fixed (byte* pBuf = buffer)
            {
                int rc = OnpNative.onp_session_create_handshake_syn(_handle, pBuf, (UIntPtr)buffer.Length, &outLen);
                if (rc != OnpNative.ONP_OK)
                {
                    throw new InvalidOperationException($"Failed to create Handshake SYN. Code: {rc}");
                }
            }

            Array.Resize(ref buffer, (int)outLen);
            return buffer;
        }

        public unsafe byte[] ProcessHandshakeSyn(ReadOnlySpan<byte> synFrame)
        {
            ThrowIfDisposed();
            byte[] ackBuf = new byte[256];
            UIntPtr outLen;

            fixed (byte* pSyn = synFrame)
            fixed (byte* pAck = ackBuf)
            {
                int rc = OnpNative.onp_session_process_handshake_syn(
                    _handle, pSyn, (UIntPtr)synFrame.Length, pAck, (UIntPtr)ackBuf.Length, &outLen
                );
                if (rc != OnpNative.ONP_OK)
                {
                    throw new InvalidOperationException($"Failed to process Handshake SYN. Code: {rc}");
                }
            }

            Array.Resize(ref ackBuf, (int)outLen);
            return ackBuf;
        }

        public unsafe void ProcessHandshakeAck(ReadOnlySpan<byte> ackFrame)
        {
            ThrowIfDisposed();
            fixed (byte* pAck = ackFrame)
            {
                int rc = OnpNative.onp_session_process_handshake_ack(_handle, pAck, (UIntPtr)ackFrame.Length);
                if (rc != OnpNative.ONP_OK)
                {
                    throw new InvalidOperationException($"Failed to process Handshake ACK. Code: {rc}");
                }
            }
        }

        public unsafe byte[] Encrypt(ushort opcode, ReadOnlySpan<byte> payload)
        {
            ThrowIfDisposed();
            int overhead = (int)OnpNative.onp_overhead_size();
            byte[] outBuf = new byte[payload.Length + overhead];
            UIntPtr outLen;

            fixed (byte* pPayload = payload)
            fixed (byte* pOut = outBuf)
            {
                int rc = OnpNative.onp_session_encrypt(
                    _handle, opcode, pPayload, (UIntPtr)payload.Length, pOut, (UIntPtr)outBuf.Length, &outLen
                );
                if (rc != OnpNative.ONP_OK)
                {
                    throw new InvalidOperationException($"Encryption failed. Code: {rc}");
                }
            }

            Array.Resize(ref outBuf, (int)outLen);
            return outBuf;
        }

        public unsafe (ushort Opcode, byte[] Payload) Decrypt(ReadOnlySpan<byte> frame)
        {
            ThrowIfDisposed();
            byte[] outBuf = new byte[frame.Length];
            UIntPtr outLen;
            ushort opcode;

            fixed (byte* pFrame = frame)
            fixed (byte* pOut = outBuf)
            {
                int rc = OnpNative.onp_session_decrypt(
                    _handle, pFrame, (UIntPtr)frame.Length, &opcode, pOut, (UIntPtr)outBuf.Length, &outLen
                );
                if (rc != OnpNative.ONP_OK)
                {
                    throw new InvalidOperationException($"Decryption failed. Code: {rc}");
                }
            }

            Array.Resize(ref outBuf, (int)outLen);
            return (opcode, outBuf);
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(OnpSession));
            }
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                if (_handle != IntPtr.Zero)
                {
                    OnpNative.onp_session_destroy(_handle);
                    _handle = IntPtr.Zero;
                }
                _disposed = true;
                GC.SuppressFinalize(this);
            }
        }

        ~OnpSession()
        {
            Dispose();
        }
    }
}
```

---

## 4. Unity MonoBehaviour Example

```csharp
using UnityEngine;
using Opela.Nexus.Protocol;
using System.Text;

public class NetworkManager : MonoBehaviour
{
    private OnpSession _clientSession;

    void Start()
    {
        _clientSession = new OnpSession(isClient: true);
        Debug.Log("Initialized ONP Client Session.");
    }

    public byte[] OnConnectedToServer()
    {
        // Generate initial handshake SYN to send over TCP/WebSocket
        byte[] synPacket = _clientSession.CreateHandshakeSyn();
        return synPacket;
    }

    public void OnReceivedServerAck(byte[] ackPacket)
    {
        _clientSession.ProcessHandshakeAck(ackPacket);
        Debug.Log($"Handshake Established: {_clientSession.IsEstablished}");

        // Send authenticated game join request
        byte[] payload = Encoding.UTF8.GetBytes("{\"player_id\":\"user_789\"}");
        byte[] encryptedFrame = _clientSession.Encrypt(0x0020, payload); // 0x0020 = LOBBY_JOIN

        SendOverSocket(encryptedFrame);
    }

    private void SendOverSocket(byte[] data)
    {
        // Transmit bytes over network socket
    }

    void OnDestroy()
    {
        _clientSession?.Dispose();
    }
}
```
