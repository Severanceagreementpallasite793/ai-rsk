// Vulnerable: cookie set without script-access protection
const express = require('express');
const app = express();

app.post('/api/login', (req, res) => {
  const token = generateToken(req.body);
  res.cookie('session', token, { secure: true, sameSite: 'strict' });
  res.json({ success: true });
});
