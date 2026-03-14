// Safe: WebSocket server with authentication via verifyClient
const { WebSocketServer } = require('ws');
const jwt = require('jsonwebtoken');
const { parseCookies } = require('./utils');

const wss = new WebSocketServer({
  port: 8080,
  verifyClient: (info, done) => {
    const cookies = parseCookies(info.req.headers.cookie);
    try {
      jwt.verify(cookies.token, process.env.JWT_SECRET);
      done(true);
    } catch {
      done(false, 401, 'Unauthorized');
    }
  },
});

wss.on('connection', (ws) => {
  ws.on('message', (data) => {
    const parsed = JSON.parse(data);
    broadcastToAll(parsed);
  });
});
