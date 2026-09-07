"use strict";
/**
 * Standalone ONP Client example in TypeScript.
 */
Object.defineProperty(exports, "__esModule", { value: true });
const src_1 = require("../src");
const PORT = 9095;
const HOST = '127.0.0.1';
async function main() {
    console.log(`[ONP-TS-CLIENT] 🔌 Connecting to ${HOST}:${PORT}...`);
    const startTime = Date.now();
    const socket = await (0, src_1.connectOnp)(HOST, PORT);
    console.log(`[ONP-TS-CLIENT] ✅ Connected & Handshake established in ${Date.now() - startTime}ms!`);
    socket.on('packet', (packet) => {
        console.log(`[ONP-TS-CLIENT] 📥 Received packet: Opcode=${src_1.LogicalOpcode[packet.opcode] || packet.opcode}, Data="${packet.data.toString()}"`);
    });
    // Send encrypted LobbyJoin action
    console.log('[ONP-TS-CLIENT] 📤 Sending LobbyJoin packet...');
    socket.sendPacket(src_1.LogicalOpcode.LobbyJoin, Buffer.from('PLAYER_AUTH_KEY_XYZ'));
    // Send Ping
    setTimeout(() => {
        console.log('[ONP-TS-CLIENT] ⚡ Sending encrypted Ping...');
        socket.sendPacket(src_1.LogicalOpcode.SysPing, Buffer.from('PING_TIMESTAMP_' + Date.now()));
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
