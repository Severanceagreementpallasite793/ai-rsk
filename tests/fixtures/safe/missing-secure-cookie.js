// Safe: cookie set with Secure flag
const express = require('express');
const helmet = require('helmet');
const app = express();

app.disable('x-powered-by');
app.use(helmet());

app.post('/api/login', (req, res) => {
  const token = generateToken(req.body);
  res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'strict' });
  res.json({ success: true });
});
