/**
 * Node.js net.Socket asynchronous transport engine for ONP.
 */

import * as net from 'net';
import { EventEmitter } from 'events';
import { ENVELOPE_HEADER_SIZE, LogicalOpcode } from './constants';
import { EnvelopeHeader } from './framing';
import { ApplicationPacket } from './packet';
import { OnpSession } from './session';

export class OnpStreamParser extends EventEmitter {
  private buffer: Buffer = Buffer.alloc(0);

  public feed(chunk: Buffer): void {
    this.buffer = Buffer.concat([this.buffer, chunk]);

    while (this.buffer.length >= ENVELOPE_HEADER_SIZE) {
      const header = EnvelopeHeader.decode(this.buffer.subarray(0, ENVELOPE_HEADER_SIZE));
      const totalLen = ENVELOPE_HEADER_SIZE + header.payloadLen;

      if (this.buffer.length < totalLen) {
        break; // Wait for more data
      }

      const frame = this.buffer.subarray(0, totalLen);
      this.buffer = this.buffer.subarray(totalLen);
      this.emit('frame', frame);
    }
  }
}

export class OnpSocket extends EventEmitter {
  public socket: net.Socket;
  public session: OnpSession;
  private parser: OnpStreamParser = new OnpStreamParser();

  constructor(socket: net.Socket, session: OnpSession) {
    super();
    this.socket = socket;
    this.session = session;

    this.parser.on('frame', (frame: Buffer) => {
      try {
        const packet = this.session.decryptPacket(frame);
        this.emit('packet', packet);
      } catch (err) {
        this.emit('error', err);
      }
    });

    this.socket.on('data', (chunk) => this.parser.feed(chunk));
    this.socket.on('close', (hadError) => this.emit('close', hadError));
    this.socket.on('error', (err) => this.emit('error', err));
  }

  public sendPacket(opcode: LogicalOpcode, payload: Uint8Array): void {
    const frame = this.session.encryptPacket(opcode, payload);
    this.socket.write(frame);
  }

  public close(): void {
    this.socket.end();
  }
}

/**
 * Connects to a remote ONP server and establishes an authenticated session.
 */
export async function connectOnp(host: string, port: number): Promise<OnpSocket> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port });
    const session = new OnpSession('client');
    const parser = new OnpStreamParser();

    socket.once('error', reject);

    socket.on('connect', () => {
      try {
        const synFrame = session.createHandshakeSyn();
        socket.write(synFrame);
      } catch (err) {
        reject(err);
      }
    });

    const onHandshakeFrame = (frame: Buffer) => {
      try {
        session.processHandshakeAck(frame);
        parser.off('frame', onHandshakeFrame);
        socket.off('data', onData);

        const onpSocket = new OnpSocket(socket, session);
        resolve(onpSocket);
      } catch (err) {
        socket.destroy();
        reject(err);
      }
    };

    const onData = (chunk: Buffer) => parser.feed(chunk);
    parser.on('frame', onHandshakeFrame);
    socket.on('data', onData);
  });
}

/**
 * Creates an ONP server that accepts incoming connections and conducts handshakes automatically.
 */
export function createOnpServer(
  onConnection: (socket: OnpSocket) => void
): net.Server {
  const server = net.createServer((socket) => {
    const session = new OnpSession('server');
    const parser = new OnpStreamParser();

    const onHandshakeFrame = (frame: Buffer) => {
      try {
        const ackFrame = session.processHandshakeSyn(frame);
        socket.write(ackFrame);

        parser.off('frame', onHandshakeFrame);
        socket.off('data', onData);

        const onpSocket = new OnpSocket(socket, session);
        onConnection(onpSocket);
      } catch (err) {
        socket.destroy();
      }
    };

    const onData = (chunk: Buffer) => parser.feed(chunk);
    parser.on('frame', onHandshakeFrame);
    socket.on('data', onData);
  });

  return server;
}
