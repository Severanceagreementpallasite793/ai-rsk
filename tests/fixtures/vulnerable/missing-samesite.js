// Vulnerable: cookie set without SameSite flag
const express = require('express');
const app = express();

app.post('/api/login', (req, res) => {
  const token = generateToken(req.body);
  res.cookie('session', token, { httpOnly: true, secure: true });
  res.json({ success: true });
});
