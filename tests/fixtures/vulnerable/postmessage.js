// Vulnerable: postMessage listener without origin check
window.addEventListener('message', (event) => {
  const data = event.data;
  if (data.type === 'UPDATE_CONFIG') {
    updateAppConfig(data.payload);
  }
  if (data.type === 'NAVIGATE') {
    window.location.href = data.url;
  }
});
