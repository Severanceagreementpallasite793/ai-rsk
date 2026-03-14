// Vulnerable: logging sensitive data
const loginUser = async (req, res) => {
  const { email, password } = req.body;
  console.log('Login attempt with password:', password);
  console.log('Request body:', req.body);
  console.log('Environment:', process.env);

  const user = await User.findByEmail(email);
  res.json({ userId: user.id });
};
