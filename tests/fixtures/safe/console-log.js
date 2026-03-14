// Safe: structured logger with no sensitive data
const pino = require('pino');
const logger = pino({ redact: ['req.headers.authorization'] });

const loginUser = async (req, res) => {
  const { email } = req.body;
  const user = await User.findByEmail(email);
  logger.info({ userId: user.id, action: 'login' }, 'User logged in');
  res.json({ userId: user.id });
};
