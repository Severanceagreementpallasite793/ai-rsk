// Vulnerable: Express server without clickjacking protection
const express = require('express');
const app = express();

app.use(express.json({ limit: '100kb' }));

app.get('/dashboard', (req, res) => {
  res.send('<html><body>Dashboard</body></html>');
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
