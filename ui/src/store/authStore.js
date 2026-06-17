// Simple auth store using localStorage
// Provides get/set/clear for auth state

const AUTH_KEY   = 'cveintel_auth';

export function getAuth() {
  try {
    const raw = localStorage.getItem(AUTH_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export function setAuth({ token, refresh_token, role, client_id }) {
  localStorage.setItem(AUTH_KEY, JSON.stringify({ token, refresh_token, role, client_id }));
  localStorage.setItem('token', token);
  localStorage.setItem('refresh_token', refresh_token);
}

export function clearAuth() {
  localStorage.removeItem(AUTH_KEY);
  localStorage.removeItem('token');
  localStorage.removeItem('refresh_token');
}

export function isAuthenticated() {
  const auth = getAuth();
  if (!auth?.token) return false;
  try {
    // Check token expiry from JWT payload
    const payload = JSON.parse(atob(auth.token.split('.')[1]));
    return payload.exp * 1000 > Date.now();
  } catch {
    return false;
  }
}

export function getClientId() {
  return getAuth()?.client_id || null;
}
