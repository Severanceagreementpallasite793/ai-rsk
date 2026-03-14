// Vulnerable: business value taken directly from user input
const express = require('express');
const app = express();

app.post('/api/order', (req, res) => {
  const price = req.body.price;
  const quantity = req.body.quantity;
  const total = price * quantity;
  chargeCustomer(total);
  res.json({ total });
});
