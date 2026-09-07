"use strict";
/**
 * Standalone ONP Server example in TypeScript.
 */
Object.defineProperty(exports, "__esModule", { value: true });
const src_1 = require("../src");
const PORT = 9095;
const HOST = '127.0.0.1';
const server = (0, src_1.createOnpServer)((socket) => {
    console.log('[ONP-TS-SERVER] 🔗 Client connected and authenticated with ephemeral X25519!');
    socket.on('packet', (packet) => {
        console.log(`[ONP-TS-SERVER] 📦 Received packet: Opcode=${src_1.LogicalOpcode[packet.opcode] || packet.opcode} (0x${packet.opcode.toString(16)}), Size=${packet.data.length}B`);
        if (packet.opcode === src_1.LogicalOpcode.SysPing) {
            console.log('[ONP-TS-SERVER] ⚡ Responding to Ping with Pong...');
            socket.sendPacket(src_1.LogicalOpcode.SysPong, packet.data);
        }
        else if (packet.opcode === src_1.LogicalOpcode.LobbyJoin) {
            console.log('[ONP-TS-SERVER] 🎮 Handling LobbyJoin request...');
            const response = Buffer.from(JSON.stringify({ status: 'JOINED', lobbyId: 'ranked-eu-01' }));
            socket.sendPacket(src_1.LogicalOpcode.LobbyState, response);
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
