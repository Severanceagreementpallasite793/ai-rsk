// Vulnerable: sensitive data in JWT payload
const jwt = require('jsonwebtoken');

const generateToken = (user) => {
  // One-liner with PII - common LLM pattern
  return jwt.sign({ userId: user.id, email: user.email, password: user.passwordHash }, process.env.JWT_SECRET, { expiresIn: '7d' });
};
