# Go Integration Guide

This guide details how to integrate the Opela Nexus Protocol (ONP) in Go applications using Cgo to bind directly to the native `onp_ffi` C-ABI shared or static library.

---

## 1. Prerequisites

Compile `onp-ffi` from the `rust/` workspace:

```bash
cd rust
cargo build --release -p onp-ffi
```

Place the compiled library and `onp.h` in your Go project:

```
my-go-project/
├── onp/
│   ├── include/
│   │   └── onp.h
│   ├── lib/
│   │   └── libonp_ffi.a (or libonp_ffi.so / onp_ffi.dll)
│   └── onp.go
└── main.go
```

---

## 2. Go Cgo Package (`onp/onp.go`)

```go
package onp

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo LDFLAGS: -L${SRCDIR}/lib -lonp_ffi
#include "onp.h"
#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

// Standard Logical Opcodes
const (
	OpcodeSysPing       uint16 = 0x0001
	OpcodeSysPong       uint16 = 0x0002
	OpcodeSysDisconnect uint16 = 0x0003
	OpcodeAuthToken     uint16 = 0x0010
	OpcodeAuthResult    uint16 = 0x0011
	OpcodeLobbyJoin     uint16 = 0x0020
	OpcodeLobbyState    uint16 = 0x0021
	OpcodeCloudSavePut  uint16 = 0x0030
	OpcodeCloudSaveGet  uint16 = 0x0031
	OpcodeRpcCall       uint16 = 0x0050
	OpcodeRpcReply      uint16 = 0x0051
)

var (
	ErrNullPtr           = errors.New("onp: null pointer")
	ErrBufferTooSmall    = errors.New("onp: buffer too small")
	ErrInvalidState      = errors.New("onp: invalid session state")
	ErrCryptoFailed      = errors.New("onp: cryptographic authentication failed")
	ErrReplayDetected    = errors.New("onp: replay attack detected")
	ErrUnknownOpcode     = errors.New("onp: unknown physical opcode")
	ErrFrameCorrupt      = errors.New("onp: frame format corrupt")
	ErrSequenceExhausted = errors.New("onp: sequence counter exhausted")
	ErrGeneric           = errors.New("onp: unclassified error")
)

func mapError(code C.int32_t) error {
	switch code {
	case C.ONP_OK:
		return nil
	case C.ONP_ERR_NULL_PTR:
		return ErrNullPtr
	case C.ONP_ERR_BUFFER_TOO_SMALL:
		return ErrBufferTooSmall
	case C.ONP_ERR_INVALID_STATE:
		return ErrInvalidState
	case C.ONP_ERR_CRYPTO_FAILED:
		return ErrCryptoFailed
	case C.ONP_ERR_REPLAY_DETECTED:
		return ErrReplayDetected
	case C.ONP_ERR_UNKNOWN_OPCODE:
		return ErrUnknownOpcode
	case C.ONP_ERR_FRAME_CORRUPT:
		return ErrFrameCorrupt
	case C.ONP_ERR_SEQUENCE_EXHAUSTED:
		return ErrSequenceExhausted
	default:
		return fmt.Errorf("%w (code: %d)", ErrGeneric, code)
	}
}

// Session represents a cryptographic ONP session state machine.
type Session struct {
	ptr *C.OnpSession
}

// NewClientSession initializes a new client ONP session.
func NewClientSession() (*Session, error) {
	ptr := C.onp_session_new_client()
	if ptr == nil {
		return nil, errors.New("onp: failed to allocate client session")
	}
	s := &Session{ptr: ptr}
	runtime.SetFinalizer(s, (*Session).Destroy)
	return s, nil
}

// NewServerSession initializes a new server ONP session.
func NewServerSession() (*Session, error) {
	ptr := C.onp_session_new_server()
	if ptr == nil {
		return nil, errors.New("onp: failed to allocate server session")
	}
	s := &Session{ptr: ptr}
	runtime.SetFinalizer(s, (*Session).Destroy)
	return s, nil
}

// Destroy cleans up session resources and zeroizes key material.
func (s *Session) Destroy() {
	if s.ptr != nil {
		C.onp_session_destroy(s.ptr)
		s.ptr = nil
	}
}

// IsEstablished returns true if the handshake is complete.
func (s *Session) IsEstablished() bool {
	if s.ptr == nil {
		return false
	}
	return C.onp_session_is_established(s.ptr) == 1
}

// CreateHandshakeSyn generates the initial HANDSHAKE_SYN frame (Client step 1).
func (s *Session) CreateHandshakeSyn() ([]byte, error) {
	outBuf := make([]byte, 256)
	var outLen C.size_t

	rc := C.onp_session_create_handshake_syn(
		s.ptr,
		(*C.uint8_t)(unsafe.Pointer(&outBuf[0])),
		C.size_t(len(outBuf)),
		&outLen,
	)
	if err := mapError(rc); err != nil {
		return nil, err
	}
	return outBuf[:outLen], nil
}

// ProcessHandshakeSyn processes a client SYN and produces a server ACK (Server step 2).
func (s *Session) ProcessHandshakeSyn(syn []byte) ([]byte, error) {
	if len(syn) == 0 {
		return nil, ErrBufferTooSmall
	}
	outBuf := make([]byte, 256)
	var outLen C.size_t

	rc := C.onp_session_process_handshake_syn(
		s.ptr,
		(*C.uint8_t)(unsafe.Pointer(&syn[0])),
		C.size_t(len(syn)),
		(*C.uint8_t)(unsafe.Pointer(&outBuf[0])),
		C.size_t(len(outBuf)),
		&outLen,
	)
	if err := mapError(rc); err != nil {
		return nil, err
	}
	return outBuf[:outLen], nil
}

// ProcessHandshakeAck finalizes the client handshake with server ACK (Client step 3).
func (s *Session) ProcessHandshakeAck(ack []byte) error {
	if len(ack) == 0 {
		return ErrBufferTooSmall
	}
	rc := C.onp_session_process_handshake_ack(
		s.ptr,
		(*C.uint8_t)(unsafe.Pointer(&ack[0])),
		C.size_t(len(ack)),
	)
	return mapError(rc)
}

// Encrypt wraps a payload in an authenticated and polymorphic ONP frame.
func (s *Session) Encrypt(opcode uint16, payload []byte) ([]byte, error) {
	overhead := int(C.onp_overhead_size())
	outCap := len(payload) + overhead
	outBuf := make([]byte, outCap)
	var outLen C.size_t

	var pPayload *C.uint8_t
	if len(payload) > 0 {
		pPayload = (*C.uint8_t)(unsafe.Pointer(&payload[0]))
	}

	rc := C.onp_session_encrypt(
		s.ptr,
		C.uint16_t(opcode),
		pPayload,
		C.size_t(len(payload)),
		(*C.uint8_t)(unsafe.Pointer(&outBuf[0])),
		C.size_t(outCap),
		&outLen,
	)
	if err := mapError(rc); err != nil {
		return nil, err
	}
	return outBuf[:outLen], nil
}

// Decrypt authenticates and decrypts an incoming wire frame.
func (s *Session) Decrypt(frame []byte) (uint16, []byte, error) {
	if len(frame) == 0 {
		return 0, nil, ErrBufferTooSmall
	}
	outBuf := make([]byte, len(frame))
	var outLen C.size_t
	var outOpcode C.uint16_t

	rc := C.onp_session_decrypt(
		s.ptr,
		(*C.uint8_t)(unsafe.Pointer(&frame[0])),
		C.size_t(len(frame)),
		&outOpcode,
		(*C.uint8_t)(unsafe.Pointer(&outBuf[0])),
		C.size_t(len(outBuf)),
		&outLen,
	)
	if err := mapError(rc); err != nil {
		return 0, nil, err
	}
	return uint16(outOpcode), outBuf[:outLen], nil
}
```

---

## 3. Go Socket Integration Example

```go
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"my-go-project/onp"
)

func handleClient(conn net.Conn) {
	defer conn.Close()
	server, err := onp.NewServerSession()
	if err != nil {
		fmt.Printf("Session allocation failed: %v\n", err)
		return
	}
	defer server.Destroy()

	// 1. Read SYN Frame
	synFrame, err := readFrame(conn)
	if err != nil {
		return
	}

	// 2. Process SYN and Write ACK Frame
	ackFrame, err := server.ProcessHandshakeSyn(synFrame)
	if err != nil {
		return
	}
	if _, err := conn.Write(ackFrame); err != nil {
		return
	}

	// 3. Receive Encrypted Traffic Loop
	for {
		frame, err := readFrame(conn)
		if err != nil {
			break
		}

		opcode, data, err := server.Decrypt(frame)
		if err != nil {
			fmt.Printf("Decryption or replay error: %v\n", err)
			break
		}

		fmt.Printf("Received Opcode 0x%04x: %s\n", opcode, string(data))
	}
}

func readFrame(r io.Reader) ([]byte, error) {
	header := make([]byte, 8)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	// Envelope layout: Magic (2B) | Version (1B) | Flags (1B) | PayloadLen (4B LE)
	payloadLen := binary.LittleEndian.Uint32(header[4:8])
	fullFrame := make([]byte, 8+payloadLen)
	copy(fullFrame[:8], header)

	if _, err := io.ReadFull(r, fullFrame[8:]); err != nil {
		return nil, err
	}
	return fullFrame, nil
}
```
