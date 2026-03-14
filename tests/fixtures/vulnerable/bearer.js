// Vulnerable: Bearer token sent in client-side Authorization header
const fetchUserProfile = async () => {
  const token = localStorage.getItem('token');
  const response = await fetch('/api/profile', {
    method: 'GET',
    headers: {
      Authorization: 'Bearer ' + token,
      'Content-Type': 'application/json',
    },
  });
  return response.json();
};
