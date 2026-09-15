//! C Foreign Function Interface (FFI) bindings for Opela Nexus Protocol (ONP).
//!
//! Provides a stable C-ABI dynamic and static library interface allowing
//! C, C++, Python, C# (.NET), Go, and other native runtimes to manage ONP sessions,
//! execute cryptographic handshakes, and encrypt/decrypt polymorphic wire frames.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;

use onp_core::constants::{
    ENVELOPE_HEADER_SIZE, MAC_TAG_SIZE, MAX_FRAME_PAYLOAD_SIZE, NONCE_SIZE, PROTOCOL_VERSION,
};
use onp_core::errors::OnpError;
use onp_core::{LogicalOpcode, OnpSession};

// Status and Error Codes
pub const ONP_OK: i32 = 0;
pub const ONP_ERR_NULL_PTR: i32 = -1;
pub const ONP_ERR_BUFFER_TOO_SMALL: i32 = -2;
pub const ONP_ERR_INVALID_STATE: i32 = -3;
pub const ONP_ERR_CRYPTO_FAILED: i32 = -4;
pub const ONP_ERR_REPLAY_DETECTED: i32 = -5;
pub const ONP_ERR_UNKNOWN_OPCODE: i32 = -6;
pub const ONP_ERR_FRAME_CORRUPT: i32 = -7;
pub const ONP_ERR_SEQUENCE_EXHAUSTED: i32 = -8;
pub const ONP_ERR_FRAME_TOO_LARGE: i32 = -9;
pub const ONP_ERR_GENERIC: i32 = -99;

fn map_error(err: OnpError) -> i32 {
    match err {
        OnpError::BufferTooShort { .. } => ONP_ERR_BUFFER_TOO_SMALL,
        OnpError::FrameTooLarge { .. } => ONP_ERR_FRAME_TOO_LARGE,
        OnpError::HandshakeStateError { .. } => ONP_ERR_INVALID_STATE,
        OnpError::AuthenticationFailed | OnpError::KeyExchangeFailed(_) => ONP_ERR_CRYPTO_FAILED,
        OnpError::ReplayDetected { .. } => ONP_ERR_REPLAY_DETECTED,
        OnpError::UnknownOpcode(_) => ONP_ERR_UNKNOWN_OPCODE,
        OnpError::InvalidMagic(..) | OnpError::UnsupportedVersion { .. } => ONP_ERR_FRAME_CORRUPT,
        OnpError::SequenceExhausted => ONP_ERR_SEQUENCE_EXHAUSTED,
        _ => ONP_ERR_GENERIC,
    }
}

/// Returns the ONP wire protocol version.
#[no_mangle]
pub extern "C" fn onp_version() -> u32 {
    PROTOCOL_VERSION as u32
}

/// Returns the maximum allowed payload size per frame (in bytes).
#[no_mangle]
pub extern "C" fn onp_max_payload_size() -> usize {
    MAX_FRAME_PAYLOAD_SIZE
}

/// Returns the fixed wire frame encryption overhead size (in bytes).
/// Envelope header (8) + Nonce (12) + Physical Opcode (2) + Poly1305 MAC Tag (16) = 38 bytes.
#[no_mangle]
pub extern "C" fn onp_overhead_size() -> usize {
    ENVELOPE_HEADER_SIZE + NONCE_SIZE + 2 + MAC_TAG_SIZE
}

/// Allocates and initializes a new client ONP session instance.
/// Returns null pointer on memory allocation failure.
#[no_mangle]
pub extern "C" fn onp_session_new_client() -> *mut OnpSession {
    let result = catch_unwind(|| Box::into_raw(Box::new(OnpSession::new_client())));
    result.unwrap_or(ptr::null_mut())
}

/// Allocates and initializes a new server ONP session instance.
/// Returns null pointer on memory allocation failure.
#[no_mangle]
pub extern "C" fn onp_session_new_server() -> *mut OnpSession {
    let result = catch_unwind(|| Box::into_raw(Box::new(OnpSession::new_server())));
    result.unwrap_or(ptr::null_mut())
}

/// Returns 1 if session handshake is established, 0 if not, or negative error code if session pointer is null.
#[no_mangle]
pub extern "C" fn onp_session_is_established(session: *const OnpSession) -> i32 {
    if session.is_null() {
        return ONP_ERR_NULL_PTR;
    }
    let s = unsafe { &*session };
    if s.is_established() {
        1
    } else {
        0
    }
}

/// Safely destroys an ONP session, zeroizes keys from memory, and frees allocated memory.
#[no_mangle]
pub extern "C" fn onp_session_destroy(session: *mut OnpSession) {
    if session.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(move || {
        let mut boxed = unsafe { Box::from_raw(session) };
        boxed.destroy();
    }));
}

/// CLIENT STEP 1: Generates the HANDSHAKE_SYN frame to initiate connection.
///
/// If out_buf is NULL or out_capacity is too small, writes the required length to *out_len
/// and returns ONP_ERR_BUFFER_TOO_SMALL.
#[no_mangle]
pub extern "C" fn onp_session_create_handshake_syn(
    session: *mut OnpSession,
    out_buf: *mut u8,
    out_capacity: usize,
    out_len: *mut usize,
) -> i32 {
    if session.is_null() || out_len.is_null() {
        return ONP_ERR_NULL_PTR;
    }

    let s = unsafe { &mut *session };
    let result = catch_unwind(AssertUnwindSafe(move || {
        match s.create_handshake_syn() {
            Ok(frame) => {
                unsafe { *out_len = frame.len() };
                if out_buf.is_null() || out_capacity < frame.len() {
                    return ONP_ERR_BUFFER_TOO_SMALL;
                }
                unsafe {
                    ptr::copy_nonoverlapping(frame.as_ptr(), out_buf, frame.len());
                }
                ONP_OK
            }
            Err(e) => map_error(e),
        }
    }));

    result.unwrap_or(ONP_ERR_GENERIC)
}

/// SERVER STEP 2: Processes incoming HANDSHAKE_SYN from client and generates HANDSHAKE_ACK.
///
/// If out_ack is NULL or out_capacity is too small, writes the required length to *out_len
/// and returns ONP_ERR_BUFFER_TOO_SMALL.
#[no_mangle]
pub extern "C" fn onp_session_process_handshake_syn(
    session: *mut OnpSession,
    in_syn: *const u8,
    in_syn_len: usize,
    out_ack: *mut u8,
    out_capacity: usize,
    out_len: *mut usize,
) -> i32 {
    if session.is_null() || in_syn.is_null() || out_len.is_null() {
        return ONP_ERR_NULL_PTR;
    }

    let s = unsafe { &mut *session };
    let syn_slice = unsafe { slice::from_raw_parts(in_syn, in_syn_len) };

    let result = catch_unwind(AssertUnwindSafe(move || {
        match s.process_handshake_syn(syn_slice) {
            Ok(ack_frame) => {
                unsafe { *out_len = ack_frame.len() };
                if out_ack.is_null() || out_capacity < ack_frame.len() {
                    return ONP_ERR_BUFFER_TOO_SMALL;
                }
                unsafe {
                    ptr::copy_nonoverlapping(ack_frame.as_ptr(), out_ack, ack_frame.len());
                }
                ONP_OK
            }
            Err(e) => map_error(e),
        }
    }));

    result.unwrap_or(ONP_ERR_GENERIC)
}

/// CLIENT STEP 3: Processes incoming HANDSHAKE_ACK from server to finalize session establishment.
#[no_mangle]
pub extern "C" fn onp_session_process_handshake_ack(
    session: *mut OnpSession,
    in_ack: *const u8,
    in_ack_len: usize,
) -> i32 {
    if session.is_null() || in_ack.is_null() {
        return ONP_ERR_NULL_PTR;
    }

    let s = unsafe { &mut *session };
    let ack_slice = unsafe { slice::from_raw_parts(in_ack, in_ack_len) };

    let result = catch_unwind(AssertUnwindSafe(move || {
        match s.process_handshake_ack(ack_slice) {
            Ok(()) => ONP_OK,
            Err(e) => map_error(e),
        }
    }));

    result.unwrap_or(ONP_ERR_GENERIC)
}

/// Encrypts an application payload into a polymorphic ONP wire frame.
///
/// If out_buf is NULL or out_capacity is too small, writes the required length to *out_len
/// and returns ONP_ERR_BUFFER_TOO_SMALL.
#[no_mangle]
pub extern "C" fn onp_session_encrypt(
    session: *mut OnpSession,
    opcode: u16,
    payload: *const u8,
    payload_len: usize,
    out_buf: *mut u8,
    out_capacity: usize,
    out_len: *mut usize,
) -> i32 {
    if session.is_null() || out_len.is_null() {
        return ONP_ERR_NULL_PTR;
    }
    if payload_len > 0 && payload.is_null() {
        return ONP_ERR_NULL_PTR;
    }

    let s = unsafe { &mut *session };
    let payload_slice = if payload_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(payload, payload_len) }
    };
    let logical_opcode = LogicalOpcode::from_u16(opcode);

    let result = catch_unwind(AssertUnwindSafe(move || {
        match s.encrypt_packet(logical_opcode, payload_slice) {
            Ok(frame) => {
                unsafe { *out_len = frame.len() };
                if out_buf.is_null() || out_capacity < frame.len() {
                    return ONP_ERR_BUFFER_TOO_SMALL;
                }
                unsafe {
                    ptr::copy_nonoverlapping(frame.as_ptr(), out_buf, frame.len());
                }
                ONP_OK
            }
            Err(e) => map_error(e),
        }
    }));

    result.unwrap_or(ONP_ERR_GENERIC)
}

/// Decrypts an incoming ONP wire frame, checks anti-replay window, and extracts the
/// application payload and logical opcode.
///
/// If out_buf is NULL or out_capacity is too small, writes the required payload length to *out_len
/// and returns ONP_ERR_BUFFER_TOO_SMALL without committing sequence progression.
#[no_mangle]
pub extern "C" fn onp_session_decrypt(
    session: *mut OnpSession,
    frame: *const u8,
    frame_len: usize,
    out_opcode: *mut u16,
    out_buf: *mut u8,
    out_capacity: usize,
    out_len: *mut usize,
) -> i32 {
    if session.is_null() || frame.is_null() || out_opcode.is_null() || out_len.is_null() {
        return ONP_ERR_NULL_PTR;
    }

    let s = unsafe { &mut *session };
    let frame_slice = unsafe { slice::from_raw_parts(frame, frame_len) };

    let result = catch_unwind(AssertUnwindSafe(move || {
        match s.decrypt_packet(frame_slice) {
            Ok(packet) => {
                unsafe {
                    *out_opcode = packet.opcode.as_u16();
                    *out_len = packet.data.len();
                }

                if out_buf.is_null() || out_capacity < packet.data.len() {
                    return ONP_ERR_BUFFER_TOO_SMALL;
                }

                if !packet.data.is_empty() {
                    unsafe {
                        ptr::copy_nonoverlapping(packet.data.as_ptr(), out_buf, packet.data.len());
                    }
                }
                ONP_OK
            }
            Err(e) => map_error(e),
        }
    }));

    result.unwrap_or(ONP_ERR_GENERIC)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ffi_lifecycle_and_handshake() {
        let client = onp_session_new_client();
        let server = onp_session_new_server();
        assert!(!client.is_null());
        assert!(!server.is_null());

        assert_eq!(onp_session_is_established(client), 0);
        assert_eq!(onp_session_is_established(server), 0);

        // 1. Client SYN
        let mut syn_buf = vec![0u8; 256];
        let mut syn_len = 0usize;
        let ret = onp_session_create_handshake_syn(client, syn_buf.as_mut_ptr(), syn_buf.len(), &mut syn_len);
        assert_eq!(ret, ONP_OK);
        assert!(syn_len > 0);

        // 2. Server processes SYN, creates ACK
        let mut ack_buf = vec![0u8; 256];
        let mut ack_len = 0usize;
        let ret = onp_session_process_handshake_syn(
            server,
            syn_buf.as_ptr(),
            syn_len,
            ack_buf.as_mut_ptr(),
            ack_buf.len(),
            &mut ack_len,
        );
        assert_eq!(ret, ONP_OK);
        assert!(ack_len > 0);
        assert_eq!(onp_session_is_established(server), 1);

        // 3. Client processes ACK
        let ret = onp_session_process_handshake_ack(client, ack_buf.as_ptr(), ack_len);
        assert_eq!(ret, ONP_OK);
        assert_eq!(onp_session_is_established(client), 1);

        // 4. Client encrypts packet
        let payload = b"Hello from C FFI";
        let mut enc_buf = vec![0u8; 512];
        let mut enc_len = 0usize;
        let ret = onp_session_encrypt(
            client,
            0x0020, // LobbyJoin
            payload.as_ptr(),
            payload.len(),
            enc_buf.as_mut_ptr(),
            enc_buf.len(),
            &mut enc_len,
        );
        assert_eq!(ret, ONP_OK);
        assert!(enc_len > payload.len());

        // 5. Server decrypts packet
        let mut dec_buf = vec![0u8; 512];
        let mut dec_len = 0usize;
        let mut dec_opcode = 0u16;
        let ret = onp_session_decrypt(
            server,
            enc_buf.as_ptr(),
            enc_len,
            &mut dec_opcode,
            dec_buf.as_mut_ptr(),
            dec_buf.len(),
            &mut dec_len,
        );
        assert_eq!(ret, ONP_OK);
        assert_eq!(dec_opcode, 0x0020);
        assert_eq!(&dec_buf[..dec_len], payload);

        // Clean up
        onp_session_destroy(client);
        onp_session_destroy(server);
    }

    #[test]
    fn test_ffi_buffer_too_small_queries() {
        let client = onp_session_new_client();
        let mut out_len = 0usize;

        // Query required length by passing null or 0 capacity
        let ret = onp_session_create_handshake_syn(client, ptr::null_mut(), 0, &mut out_len);
        assert_eq!(ret, ONP_ERR_BUFFER_TOO_SMALL);
        assert!(out_len > 0);

        onp_session_destroy(client);
    }
}
