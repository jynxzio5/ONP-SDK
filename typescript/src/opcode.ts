/**
 * Polymorphic Rolling Opcode Engine for TypeScript.
 * Dynamically maps logical application opcodes to session-specific physical IDs.
 */

import * as crypto from 'crypto';
import { LogicalOpcode } from './constants';

export class OpcodeTable {
  private seed: Buffer;
  private forwardMap: Map<number, number> = new Map();
  private reverseMap: Map<number, number> = new Map();

  constructor(seed: Uint8Array) {
    this.seed = Buffer.from(seed);

    const standardOpcodes = [
      LogicalOpcode.SysPing,
      LogicalOpcode.SysPong,
      LogicalOpcode.SysDisconnect,
      LogicalOpcode.AuthToken,
      LogicalOpcode.AuthResult,
      LogicalOpcode.LobbyJoin,
      LogicalOpcode.LobbyState,
      LogicalOpcode.CloudSavePut,
      LogicalOpcode.CloudSaveGet,
      LogicalOpcode.RpcCall,
      LogicalOpcode.RpcReply,
    ];

    for (const logical of standardOpcodes) {
      this.registerLogical(logical);
    }
  }

  private derivePhysical(logical: number): number {
    const hmac = crypto.createHmac('sha256', this.seed);
    const buf = Buffer.alloc(2);
    buf.writeUInt16LE(logical, 0);
    hmac.update(buf);
    hmac.update(Buffer.from('ONP-OPCODE-DERIVATION'));
    const digest = hmac.digest();

    const raw = digest.readUInt16LE(0);
    return raw === 0 ? 1 : raw;
  }

  public registerLogical(logical: number): number {
    const existing = this.forwardMap.get(logical);
    if (existing !== undefined) {
      return existing;
    }

    let candidate = this.derivePhysical(logical);

    // Linear probing for deterministic collision resolution
    while (this.reverseMap.has(candidate)) {
      candidate = (candidate + 1) & 0xffff;
      if (candidate === 0) {
        candidate = 1;
      }
    }

    this.forwardMap.set(logical, candidate);
    this.reverseMap.set(candidate, logical);
    return candidate;
  }

  public toPhysical(logical: LogicalOpcode | number): number {
    const val = typeof logical === 'number' ? logical : (logical as number);
    const physical = this.forwardMap.get(val);
    if (physical !== undefined) {
      return physical;
    }
    return this.registerLogical(val);
  }

  public toLogical(physical: number): LogicalOpcode {
    const logical = this.reverseMap.get(physical);
    if (logical === undefined) {
      throw new Error(`Unknown polymorphic physical opcode: 0x${physical.toString(16)}`);
    }
    return logical as LogicalOpcode;
  }
}
