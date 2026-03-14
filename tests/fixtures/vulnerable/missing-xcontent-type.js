// Vulnerable: Express server without MIME sniffing protection
const express = require('express');
const app = express();

app.use(express.json({ limit: '100kb' }));

app.get('/api/files', (req, res) => {
  res.json({ files: [] });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
