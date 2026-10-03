const API = import.meta.env.VITE_API_URL || 'http://localhost:4000';
let token = null;
export const setToken = (t) => { token = t; };

async function req(path, { method = 'GET', body } = {}) {
  const res = await fetch(API + path, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}

export const prelogin = (email) => req(`/auth/prelogin?email=${encodeURIComponent(email)}`);
export const register = (b) => req('/auth/register', { method: 'POST', body: b });
export const login = (b) => req('/auth/login', { method: 'POST', body: b });
export const listItems = () => req('/vault');
export const addItem = (b) => req('/vault', { method: 'POST', body: b });
export const deleteItem = (id) => req(`/vault/${id}`, { method: 'DELETE' });