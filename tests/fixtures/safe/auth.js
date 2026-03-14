// Safe: token handled via HttpOnly cookie server-side
const login = async (email, password) => {
  const response = await fetch('/api/login', {
    method: 'POST',
    credentials: 'include',
    body: JSON.stringify({ email, password }),
  });
  // Server sets HttpOnly cookie, no client-side token storage
  const data = await response.json();
  localStorage.setItem('theme', data.userTheme);
};
