// Safe: Express server with helmet (includes X-Content-Type-Options: nosniff)
const express = require('express');
const helmet = require('helmet');
const app = express();

app.use(helmet());
app.use(express.json({ limit: '100kb' }));

app.get('/api/files', (req, res) => {
  res.json({ files: [] });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
