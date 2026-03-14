// Safe: minimal JWT payload with only identifiers
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const generateToken = (user) => {
  return jwt.sign({
    sub: user.id,
    jti: uuidv4(),
  }, process.env.JWT_SECRET, { expiresIn: '15m' });
};
