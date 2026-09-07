/**
 * Standalone ONP Client example in TypeScript.
 */

import { connectOnp, LogicalOpcode } from '../index';

const PORT = 9095;
const HOST = '127.0.0.1';

async function main() {
  console.log(`[ONP-TS-CLIENT] 🔌 Connecting to ${HOST}:${PORT}...`);
  const startTime = Date.now();

  const socket = await connectOnp(HOST, PORT);
  console.log(`[ONP-TS-CLIENT] ✅ Connected & Handshake established in ${Date.now() - startTime}ms!`);

  socket.on('packet', (packet) => {
    console.log(
      `[ONP-TS-CLIENT] 📥 Received packet: Opcode=${LogicalOpcode[packet.opcode] || packet.opcode}, Data="${packet.data.toString()}"`
    );
  });

  // Send encrypted LobbyJoin action
  console.log('[ONP-TS-CLIENT] 📤 Sending LobbyJoin packet...');
  socket.sendPacket(LogicalOpcode.LobbyJoin, Buffer.from('PLAYER_AUTH_KEY_XYZ'));

  // Send Ping
  setTimeout(() => {
    console.log('[ONP-TS-CLIENT] ⚡ Sending encrypted Ping...');
    socket.sendPacket(LogicalOpcode.SysPing, Buffer.from('PING_TIMESTAMP_' + Date.now()));
  }, 100);

  // Clean shutdown after 500ms
  setTimeout(() => {
    console.log('[ONP-TS-CLIENT] 🚪 Closing connection.');
    socket.close();
    process.exit(0);
  }, 500);
}

main().catch((err) => {
  console.error('[ONP-TS-CLIENT] ❌ Failed to connect:', err);
  process.exit(1);
});
