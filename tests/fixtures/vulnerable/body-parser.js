// Vulnerable: body parser without size limit
const express = require('express');
const app = express();

app.use(express.json());
app.use(express.urlencoded());

app.post('/api/data', (req, res) => {
  res.json({ received: true });
});

app.listen(3000);
