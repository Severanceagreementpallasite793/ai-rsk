// Vulnerable: Express app without disabling X-Powered-By
const express = require('express');
const app = express();

app.use(express.json({ limit: '100kb' }));

app.get('/api/status', (req, res) => {
  res.json({ status: 'ok' });
});

app.listen(3000);
