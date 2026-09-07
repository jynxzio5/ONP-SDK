import test from 'node:test';
import * as assert from 'node:assert';
import {
  EnvelopeHeader,
  Flags,
  LogicalOpcode,
  OpcodeTable,
  OnpSession,
  createOnpServer,
  connectOnp,
} from '../index';

test('EnvelopeHeader: encode and decode', () => {
  const header = new EnvelopeHeader(Flags.ENCRYPTED | Flags.HEARTBEAT, 2048);
  const encoded = header.encode();
  const decoded = EnvelopeHeader.decode(encoded);

  assert.strictEqual(decoded.version, 1);
  assert.strictEqual(decoded.flags, Flags.ENCRYPTED | Flags.HEARTBEAT);
  assert.strictEqual(decoded.payloadLen, 2048);
});

test('OpcodeTable: polymorphic mapping and uniqueness across seeds', () => {
  const seedA = new Uint8Array(32).fill(0x11);
  const seedB = new Uint8Array(32).fill(0x22);

  const tableA = new OpcodeTable(seedA);
  const tableB = new OpcodeTable(seedB);

  const physA = tableA.toPhysical(LogicalOpcode.LobbyJoin);
  const physB = tableB.toPhysical(LogicalOpcode.LobbyJoin);

  assert.notStrictEqual(physA, physB, 'Different seeds must produce different physical opcodes');
  assert.strictEqual(tableA.toLogical(physA), LogicalOpcode.LobbyJoin);
  assert.strictEqual(tableB.toLogical(physB), LogicalOpcode.LobbyJoin);
});

test('OnpSession: end-to-end handshake, encryption, and replay protection', () => {
  const client = new OnpSession('client');
  const server = new OnpSession('server');

  // Handshake
  const syn = client.createHandshakeSyn();
  const ack = server.processHandshakeSyn(syn);
  client.processHandshakeAck(ack);

  assert.strictEqual(client.isEstablished(), true);
  assert.strictEqual(server.isEstablished(), true);

  // Client -> Server
  const message = Buffer.from('CLIENT_SECRET_PAYLOAD_1337');
  const frame = client.encryptPacket(LogicalOpcode.AuthToken, message);

  const decrypted = server.decryptPacket(frame);
  assert.strictEqual(decrypted.opcode, LogicalOpcode.AuthToken);
  assert.deepStrictEqual(decrypted.data, message);

  // Replay protection: replaying the same frame must throw
  assert.throws(() => {
    server.decryptPacket(frame);
  }, /Replay attack detected/);

  // Server -> Client
  const reply = Buffer.from('SERVER_TOKEN_RESPONSE_8888');
  const replyFrame = server.encryptPacket(LogicalOpcode.AuthResult, reply);

  const clientReceived = client.decryptPacket(replyFrame);
  assert.strictEqual(clientReceived.opcode, LogicalOpcode.AuthResult);
  assert.deepStrictEqual(clientReceived.data, reply);
});

test('OnpSocket: live TCP client-server round-trip', async () => {
  let serverSocketReady: any = null;

  const server = createOnpServer((onpSocket) => {
    serverSocketReady = onpSocket;
    onpSocket.on('packet', (packet) => {
      if (packet.opcode === LogicalOpcode.SysPing) {
        onpSocket.sendPacket(LogicalOpcode.SysPong, packet.data);
      }
    });
  });

  await new Promise<void>((res) => server.listen(0, '127.0.0.1', () => res()));
  const port = (server.address() as any).port;

  const clientSocket = await connectOnp('127.0.0.1', port);

  const pongReceived = new Promise<Buffer>((resolve) => {
    clientSocket.on('packet', (packet) => {
      if (packet.opcode === LogicalOpcode.SysPong) {
        resolve(packet.data);
      }
    });
  });

  clientSocket.sendPacket(LogicalOpcode.SysPing, Buffer.from('PING_FROM_NODE_CLIENT'));
  const pongData = await pongReceived;
  assert.strictEqual(pongData.toString(), 'PING_FROM_NODE_CLIENT');

  clientSocket.close();
  if (serverSocketReady) serverSocketReady.close();
  server.close();
});
