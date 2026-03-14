// Safe: login route with rate limiting
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const app = express();

app.disable('x-powered-by');
app.use(helmet());
app.use(express.json({ limit: '100kb' }));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many login attempts, try again later',
});

app.post('/login', loginLimiter, async (req, res) => {
  const validatedEmail = validateEmail(req.body.email);
  const validatedPass = validatePassword(req.body.pass);
  const result = await authenticate(validatedEmail, validatedPass);
  res.json({ success: result });
});
