// Safe: Express server with helmet (includes X-Frame-Options)
const express = require('express');
const helmet = require('helmet');
const app = express();

app.use(helmet());
app.use(express.json({ limit: '100kb' }));

app.get('/dashboard', (req, res) => {
  res.send('<html><body>Dashboard</body></html>');
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
