const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8787';

interface ApiResponse<T> {
  data?: T;
  error?: string;
  status: number;
}

async function request<T>(path: string, options: RequestInit = {}): Promise<ApiResponse<T>> {
  const url = `${API_BASE}${path}`;
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...((options.headers as Record<string, string>) || {}),
  };

  const token = typeof localStorage !== 'undefined' ? localStorage.getItem('access_token') : null;
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const res = await fetch(url, { ...options, headers });
  const body = await res.json().catch(() => null);

  if (!res.ok) {
    return { error: body?.error || `Request failed: ${res.status}`, status: res.status };
  }
  return { data: body as T, status: res.status };
}

export interface SignupResponse {
  id: string;
  email: string;
  created_at: string;
}

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export interface UserResponse {
  id: string;
  email: string;
  created_at: string;
  updated_at: string;
}

export const api = {
  signup(email: string, password: string) {
    return request<SignupResponse>('/api/auth/signup', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
  },

  login(email: string, password: string) {
    return request<LoginResponse>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
  },

  refresh(refresh_token: string) {
    return request<LoginResponse>('/api/auth/refresh', {
      method: 'POST',
      body: JSON.stringify({ refresh_token }),
    });
  },

  logout(refresh_token?: string) {
    return request('/api/auth/logout', {
      method: 'POST',
      body: JSON.stringify({ refresh_token }),
    });
  },

  me() {
    return request<UserResponse>('/api/auth/me');
  },

  changePassword(current_password: string, new_password: string) {
    return request('/api/auth/password', {
      method: 'PUT',
      body: JSON.stringify({ current_password, new_password }),
    });
  },

  sendVerification() {
    return request('/api/auth/send-verification', { method: 'POST' });
  },

  forgotPassword(email: string) {
    return request('/api/auth/forgot-password', {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
  },

  resetPassword(token: string, new_password: string) {
    return request('/api/auth/reset-password', {
      method: 'POST',
      body: JSON.stringify({ token, new_password }),
    });
  },
};
