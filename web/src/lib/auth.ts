import { writable, derived } from 'svelte/store';
import { api, type UserResponse } from './api';

export const user = writable<UserResponse | null>(null);
export const isAuthenticated = derived(user, ($user) => $user !== null);

export function saveTokens(accessToken: string, refreshToken: string) {
  localStorage.setItem('access_token', accessToken);
  localStorage.setItem('refresh_token', refreshToken);
}

export function clearTokens() {
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
  user.set(null);
}

export async function loadUser() {
  const token = localStorage.getItem('access_token');
  if (!token) return;

  const res = await api.me();
  if (res.data) {
    user.set(res.data);
  } else {
    // Token might be expired, try refresh
    const refreshToken = localStorage.getItem('refresh_token');
    if (refreshToken) {
      const refreshRes = await api.refresh(refreshToken);
      if (refreshRes.data) {
        saveTokens(refreshRes.data.access_token, refreshRes.data.refresh_token);
        const meRes = await api.me();
        if (meRes.data) {
          user.set(meRes.data);
          return;
        }
      }
    }
    clearTokens();
  }
}

export async function logout() {
  const refreshToken = localStorage.getItem('refresh_token');
  await api.logout(refreshToken || undefined);
  clearTokens();
}
