// Vulnerable: login route without rate limiting
const express = require('express');
const app = express();

app.use(express.json({ limit: '100kb' }));

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findByEmail(email);
  if (!user || !await bcrypt.compare(password, user.hash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  res.json({ success: true });
});
