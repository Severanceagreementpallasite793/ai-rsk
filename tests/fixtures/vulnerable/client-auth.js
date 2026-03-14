// Vulnerable: client-side authentication check
const checkAuth = () => {
  if (localStorage.getItem('token')) {
    showDashboard();
  } else {
    redirectToLogin();
  }
};

const renderAdmin = () => {
  if (isAuthenticated) {
    return renderAdminPanel();
  }
};
