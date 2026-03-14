// Safe: Express app with X-Powered-By disabled via helmet
const express = require('express');
const helmet = require('helmet');
const app = express();

app.disable('x-powered-by');
app.use(helmet());
app.use(express.json({ limit: '100kb' }));

app.get('/api/status', (req, res) => {
  res.json({ status: 'ok' });
});

app.listen(3000);
