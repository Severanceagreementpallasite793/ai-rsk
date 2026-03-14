// Safe: authentication sent via HttpOnly cookie, no Bearer in client code
const fetchUserProfile = async () => {
  const response = await fetch('/api/profile', {
    method: 'GET',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
    },
  });
  return response.json();
};
