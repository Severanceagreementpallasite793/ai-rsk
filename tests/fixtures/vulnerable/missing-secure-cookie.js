// Vulnerable: cookie set without Secure flag
const express = require('express');
const app = express();

app.post('/api/login', (req, res) => {
  const token = generateToken(req.body);
  res.cookie('session', token, { httpOnly: true, sameSite: 'strict' });
  res.json({ success: true });
});
