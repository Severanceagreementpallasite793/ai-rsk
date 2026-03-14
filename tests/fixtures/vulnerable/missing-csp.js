// Vulnerable: Express server without security headers
const express = require('express');
const app = express();

app.use(express.json({ limit: '100kb' }));

app.get('/api/data', (req, res) => {
  res.json({ status: 'ok' });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
