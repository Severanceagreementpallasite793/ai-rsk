// Safe: body parser with explicit size limit
const express = require('express');
const helmet = require('helmet');
const app = express();

app.disable('x-powered-by');
app.use(helmet());
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));

app.post('/api/data', (req, res) => {
  res.json({ received: true });
});

app.listen(3000);
