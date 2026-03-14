// Vulnerable: Express server without transport security header
const express = require('express');
const app = express();

app.use(express.json({ limit: '100kb' }));

app.get('/api/users', (req, res) => {
  res.json({ users: [] });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
