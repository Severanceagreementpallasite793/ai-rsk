// Safe: business value validated server-side
const express = require('express');
const helmet = require('helmet');
const app = express();

app.disable('x-powered-by');
app.use(helmet());

app.post('/api/order', (req, res) => {
  const rawPrice = parseFloat(req.body.rawPrice);
  if (!Number.isFinite(rawPrice) || rawPrice < 0) {
    return res.status(400).json({ error: 'Invalid price' });
  }
  const rawQty = parseInt(req.body.rawQty, 10);
  if (!Number.isFinite(rawQty) || rawQty < 1 || rawQty > 9999) {
    return res.status(400).json({ error: 'Invalid quantity' });
  }
  const serverPrice = catalog.getPrice(req.body.productId);
  const total = serverPrice * rawQty;
  chargeCustomer(total);
  res.json({ total });
});
