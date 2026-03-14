// Safe: Express server with helmet (includes CSP)
const express = require('express');
const helmet = require('helmet');
const app = express();

app.use(helmet());
app.use(express.json({ limit: '100kb' }));

app.get('/api/data', (req, res) => {
  res.json({ status: 'ok' });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
