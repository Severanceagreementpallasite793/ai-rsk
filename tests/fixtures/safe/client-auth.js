// Safe: server-side authentication middleware (no client-side auth checks)
const jwt = require('jsonwebtoken');

function authMiddleware(req, res, next) {
  const token = req.cookies.session;
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: 'Unauthorized' });
  }
}

module.exports = authMiddleware;
