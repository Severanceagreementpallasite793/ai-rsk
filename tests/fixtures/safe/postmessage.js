// Safe: postMessage listener with origin validation
const TRUSTED_ORIGIN = 'https://trusted-domain.com';

window.addEventListener('message', (event) => {
  if (event.origin !== TRUSTED_ORIGIN) return;

  const data = event.data;
  if (data.type === 'UPDATE_CONFIG') {
    updateAppConfig(data.payload);
  }
});
