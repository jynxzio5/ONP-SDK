/**
 * Opela Nexus Protocol (ONP) - C/C++ Native API
 *
 * High-performance encrypted polymorphic binary communication protocol.
 * C99 and C++ compatible native interface.
 *
 * Copyright (c) 2025 Opela Nexus Architecture Group. MIT Licensed.
 */

#ifndef ONP_H
#define ONP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dynamic library export/import macros */
#if defined(_WIN32) || defined(_WIN64)
  #if defined(ONP_STATIC)
    #define ONP_API
  #elif defined(ONP_EXPORTS)
    #define ONP_API __declspec(dllexport)
  #else
    #define ONP_API __declspec(dllimport)
  #endif
#else
  #if defined(__GNUC__) && __GNUC__ >= 4
    #define ONP_API __attribute__((visibility("default")))
  #else
    #define ONP_API
  #endif
#endif

/* Return and Status Codes */
#define ONP_OK                       0
#define ONP_ERR_NULL_PTR            -1
#define ONP_ERR_BUFFER_TOO_SMALL    -2
#define ONP_ERR_INVALID_STATE       -3
#define ONP_ERR_CRYPTO_FAILED       -4
#define ONP_ERR_REPLAY_DETECTED     -5
#define ONP_ERR_UNKNOWN_OPCODE      -6
#define ONP_ERR_FRAME_CORRUPT       -7
#define ONP_ERR_SEQUENCE_EXHAUSTED  -8
#define ONP_ERR_FRAME_TOO_LARGE     -9
#define ONP_ERR_GENERIC             -99

/* Wire Protocol Constants */
#define ONP_MAGIC_BYTE_0            0x4F /* 'O' */
#define ONP_MAGIC_BYTE_1            0x4E /* 'N' */
#define ONP_CURRENT_VERSION         1
#define ONP_ENVELOPE_HEADER_SIZE    8
#define ONP_NONCE_SIZE              12
#define ONP_MAC_TAG_SIZE            16
#define ONP_OVERHEAD_SIZE           38
#define ONP_MAX_FRAME_PAYLOAD_SIZE  (16 * 1024 * 1024)

/* Standard Logical Application Opcodes */
#define ONP_OPCODE_SYS_PING         0x0001
#define ONP_OPCODE_SYS_PONG         0x0002
#define ONP_OPCODE_SYS_DISCONNECT   0x0003
#define ONP_OPCODE_AUTH_TOKEN       0x0010
#define ONP_OPCODE_AUTH_RESULT      0x0011
#define ONP_OPCODE_LOBBY_JOIN       0x0020
#define ONP_OPCODE_LOBBY_STATE      0x0021
#define ONP_OPCODE_CLOUD_SAVE_PUT   0x0030
#define ONP_OPCODE_CLOUD_SAVE_GET   0x0031
#define ONP_OPCODE_RPC_CALL         0x0050
#define ONP_OPCODE_RPC_REPLY        0x0051

/**
 * Opaque handle representing an ONP session state machine.
 */
typedef struct OnpSession OnpSession;

/**
 * Returns the protocol version supported by the native library.
 */
ONP_API uint32_t onp_version(void);

/**
 * Returns the maximum frame payload size in bytes.
 */
ONP_API size_t onp_max_payload_size(void);

/**
 * Returns the total cryptographic framing overhead in bytes (38 bytes).
 */
ONP_API size_t onp_overhead_size(void);

/**
 * Allocates and initializes a new Client session instance.
 * Generates an ephemeral X25519 keypair and OsRng handshake nonce.
 *
 * Returns NULL if memory allocation fails.
 */
ONP_API OnpSession* onp_session_new_client(void);

/**
 * Allocates and initializes a new Server session instance.
 * Generates an ephemeral X25519 keypair and OsRng handshake nonce.
 *
 * Returns NULL if memory allocation fails.
 */
ONP_API OnpSession* onp_session_new_server(void);

/**
 * Checks whether the session handshake has been completed.
 *
 * Returns:
 *   1 if established
 *   0 if not established
 *  -1 if session pointer is NULL
 */
ONP_API int32_t onp_session_is_established(const OnpSession* session);

/**
 * Safely destroys the session, zeroizes cryptographic keys and nonces,
 * and deallocates memory.
 */
ONP_API void onp_session_destroy(OnpSession* session);

/**
 * [CLIENT STEP 1]
 * Generates the HANDSHAKE_SYN wire frame containing the client ephemeral public key
 * and random nonce token.
 *
 * Parameters:
 *   session      - Valid client session pointer
 *   out_buf      - Destination buffer for the wire frame
 *   out_capacity - Capacity of out_buf in bytes
 *   out_len      - Pointer to receive the actual frame length written
 *
 * Returns:
 *   ONP_OK on success
 *   ONP_ERR_BUFFER_TOO_SMALL if out_capacity is insufficient (out_len receives required bytes)
 *   ONP_ERR_NULL_PTR if session or out_len is NULL
 *   ONP_ERR_INVALID_STATE if called on a server session
 */
ONP_API int32_t onp_session_create_handshake_syn(
    OnpSession* session,
    uint8_t* out_buf,
    size_t out_capacity,
    size_t* out_len
);

/**
 * [SERVER STEP 2]
 * Processes the received HANDSHAKE_SYN wire frame from the client, computes the
 * ECDH shared secret, derives session keys, and generates the HANDSHAKE_ACK wire frame.
 *
 * Parameters:
 *   session      - Valid server session pointer
 *   in_syn       - Incoming HANDSHAKE_SYN frame bytes
 *   in_syn_len   - Length of in_syn in bytes
 *   out_ack      - Destination buffer for the HANDSHAKE_ACK frame
 *   out_capacity - Capacity of out_ack in bytes
 *   out_len      - Pointer to receive the actual ACK length written
 *
 * Returns:
 *   ONP_OK on success
 *   ONP_ERR_BUFFER_TOO_SMALL if out_capacity is insufficient
 *   ONP_ERR_NULL_PTR if any required pointer is NULL
 *   ONP_ERR_FRAME_CORRUPT if frame header is invalid
 *   ONP_ERR_CRYPTO_FAILED if key exchange or derivation fails
 */
ONP_API int32_t onp_session_process_handshake_syn(
    OnpSession* session,
    const uint8_t* in_syn,
    size_t in_syn_len,
    uint8_t* out_ack,
    size_t out_capacity,
    size_t* out_len
);

/**
 * [CLIENT STEP 3]
 * Processes the received HANDSHAKE_ACK wire frame from the server, computes the
 * ECDH shared secret, derives symmetric session keys and polymorphic opcode tables,
 * and transitions the client session into the Established state.
 *
 * Parameters:
 *   session    - Valid client session pointer in SynSent state
 *   in_ack     - Incoming HANDSHAKE_ACK frame bytes
 *   in_ack_len - Length of in_ack in bytes
 *
 * Returns:
 *   ONP_OK on success
 *   ONP_ERR_NULL_PTR if session or in_ack is NULL
 *   ONP_ERR_INVALID_STATE if client is not in SynSent state
 *   ONP_ERR_CRYPTO_FAILED if key exchange fails
 */
ONP_API int32_t onp_session_process_handshake_ack(
    OnpSession* session,
    const uint8_t* in_ack,
    size_t in_ack_len
);

/**
 * Encrypts an application payload into a polymorphic ONP wire frame.
 * Resolves logical opcode to physical opcode, embeds sequence counter,
 * and encrypts with ChaCha20-Poly1305 using the 8-byte envelope header as AAD.
 *
 * Parameters:
 *   session      - Established session pointer
 *   opcode       - Logical application opcode (e.g., ONP_OPCODE_LOBBY_JOIN)
 *   payload      - Plaintext payload buffer
 *   payload_len  - Length of payload in bytes
 *   out_buf      - Destination buffer for the complete wire frame
 *   out_capacity - Capacity of out_buf in bytes (must be at least payload_len + 38)
 *   out_len      - Pointer to receive the actual frame length written
 *
 * Returns:
 *   ONP_OK on success
 *   ONP_ERR_BUFFER_TOO_SMALL if out_capacity is insufficient
 *   ONP_ERR_INVALID_STATE if session is not established
 *   ONP_ERR_SEQUENCE_EXHAUSTED if 64-bit sequence counter wraps
 */
ONP_API int32_t onp_session_encrypt(
    OnpSession* session,
    uint16_t opcode,
    const uint8_t* payload,
    size_t payload_len,
    uint8_t* out_buf,
    size_t out_capacity,
    size_t* out_len
);

/**
 * Decrypts an incoming ONP wire frame.
 * Validates envelope header, checks the 64-packet anti-replay sliding window,
 * verifies the Poly1305 MAC tag, and decodes the polymorphic physical opcode.
 * Sequence state is committed only after successful MAC verification.
 *
 * Parameters:
 *   session          - Established session pointer
 *   frame            - Complete incoming ONP wire frame
 *   frame_len        - Length of frame in bytes
 *   out_opcode       - Pointer to receive the decoded logical application opcode
 *   out_buf          - Destination buffer for the decrypted plaintext payload
 *   out_capacity     - Capacity of out_buf in bytes
 *   out_len          - Pointer to receive the plaintext length written
 *
 * Returns:
 *   ONP_OK on success
 *   ONP_ERR_BUFFER_TOO_SMALL if out_capacity is insufficient (out_len receives needed bytes)
 *   ONP_ERR_REPLAY_DETECTED if packet was replayed or falls behind sliding window
 *   ONP_ERR_CRYPTO_FAILED if ciphertext or MAC tag is tampered/corrupted
 *   ONP_ERR_UNKNOWN_OPCODE if physical opcode does not map to a known logical opcode
 */
ONP_API int32_t onp_session_decrypt(
    OnpSession* session,
    const uint8_t* frame,
    size_t frame_len,
    uint16_t* out_opcode,
    uint8_t* out_buf,
    size_t out_capacity,
    size_t* out_len
);

#ifdef __cplusplus
}
#endif

#endif /* ONP_H */
