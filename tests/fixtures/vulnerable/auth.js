// Vulnerable: token stored in localStorage
const login = async (email, password) => {
  const response = await fetch('/api/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
  const data = await response.json();
  localStorage.setItem('access_token', data.token);
  localStorage.setItem('refresh_token', data.refreshToken);
};
