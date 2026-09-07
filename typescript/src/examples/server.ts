/**
 * Standalone ONP Server example in TypeScript.
 */

import { createOnpServer, LogicalOpcode, OnpSocket } from '../index';

const PORT = 9095;
const HOST = '127.0.0.1';

const server = createOnpServer((socket: OnpSocket) => {
  console.log('[ONP-TS-SERVER] 🔗 Client connected and authenticated with ephemeral X25519!');

  socket.on('packet', (packet) => {
    console.log(
      `[ONP-TS-SERVER] 📦 Received packet: Opcode=${LogicalOpcode[packet.opcode] || packet.opcode} (0x${packet.opcode.toString(16)}), Size=${packet.data.length}B`
    );

    if (packet.opcode === LogicalOpcode.SysPing) {
      console.log('[ONP-TS-SERVER] ⚡ Responding to Ping with Pong...');
      socket.sendPacket(LogicalOpcode.SysPong, packet.data);
    } else if (packet.opcode === LogicalOpcode.LobbyJoin) {
      console.log('[ONP-TS-SERVER] 🎮 Handling LobbyJoin request...');
      const response = Buffer.from(JSON.stringify({ status: 'JOINED', lobbyId: 'ranked-eu-01' }));
      socket.sendPacket(LogicalOpcode.LobbyState, response);
    }
  });

  socket.on('close', () => {
    console.log('[ONP-TS-SERVER] 🔌 Client disconnected.');
  });

  socket.on('error', (err) => {
    console.error('[ONP-TS-SERVER] ❌ Connection error:', err);
  });
});

server.listen(PORT, HOST, () => {
  console.log(`[ONP-TS-SERVER] 🚀 Server listening on ${HOST}:${PORT}`);
  console.log('[ONP-TS-SERVER] Ready for encrypted, polymorphic client streams.');
});
