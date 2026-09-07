/**
 * Opela Nexus Protocol (ONP) Constants & Flags.
 */

export const PROTOCOL_MAGIC = new Uint8Array([0x4F, 0x4E]); // "ON"
export const PROTOCOL_VERSION = 1;
export const ENVELOPE_HEADER_SIZE = 8;
export const NONCE_SIZE = 12;
export const MAC_TAG_SIZE = 16;
export const PUBLIC_KEY_SIZE = 32;
export const HANDSHAKE_NONCE_SIZE = 16;
export const MAX_FRAME_PAYLOAD_SIZE = 16 * 1024 * 1024; // 16 MiB

export const Flags = {
  HANDSHAKE_SYN: 0x01,
  HANDSHAKE_ACK: 0x02,
  COMPRESSED:    0x04,
  ENCRYPTED:     0x08,
  HEARTBEAT:     0x10,
  ERROR:         0x20,
  TERMINATE:     0x80,
} as const;

export enum LogicalOpcode {
  SysPing         = 0x0001,
  SysPong         = 0x0002,
  SysDisconnect   = 0x0003,
  AuthToken       = 0x0010,
  AuthResult      = 0x0011,
  LobbyJoin       = 0x0020,
  LobbyState      = 0x0021,
  CloudSavePut    = 0x0030,
  CloudSaveGet    = 0x0031,
  RpcCall         = 0x0050,
  RpcReply        = 0x0051,
}
