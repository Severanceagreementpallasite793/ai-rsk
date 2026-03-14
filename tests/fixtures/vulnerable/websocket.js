// Vulnerable: WebSocket server without identity checks
const { WebSocketServer } = require('ws');

const wss = new WebSocketServer({ port: 8080 });

wss.on('connection', (ws) => {
  ws.on('message', (data) => {
    const parsed = JSON.parse(data);
    broadcastToAll(parsed);
  });

  ws.send(JSON.stringify({ type: 'welcome' }));
});
