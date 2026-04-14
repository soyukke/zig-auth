import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
} from '@simplewebauthn/browser';

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

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  user?: { id: string; email: string };
}

export interface UserResponse {
  id: string;
  email: string;
  created_at: string;
  updated_at: string;
}

export interface Passkey {
  id: string;
  name: string;
  device_type: string;
  backed_up: boolean;
  created_at: string;
  last_used_at: string | null;
}

export interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  scopes: string;
  created_at: string;
  last_used_at: string | null;
  expires_at: string | null;
}

export interface ApiKeyCreated extends ApiKey {
  key: string;
}

export const api = {
  // Passkey registration (new user)
  passkeyRegisterOptions(username: string) {
    return request<PublicKeyCredentialCreationOptionsJSON>('/api/auth/passkeys/register/options', {
      method: 'POST',
      body: JSON.stringify({ username }),
    });
  },

  passkeyRegister(response: RegistrationResponseJSON, challenge: string) {
    return request<LoginResponse>('/api/auth/passkeys/register', {
      method: 'POST',
      body: JSON.stringify({ response, challenge }),
    });
  },

  // Passkey add (existing user)
  passkeyAddOptions() {
    return request<PublicKeyCredentialCreationOptionsJSON>('/api/auth/passkeys/add/options', {
      method: 'POST',
    });
  },

  passkeyAdd(response: RegistrationResponseJSON, name?: string) {
    return request<{ passkey: Passkey }>('/api/auth/passkeys/add', {
      method: 'POST',
      body: JSON.stringify({ response, name }),
    });
  },

  // Passkey authentication
  passkeyAuthOptions() {
    return request<PublicKeyCredentialRequestOptionsJSON>('/api/auth/passkeys/authenticate/options', {
      method: 'POST',
    });
  },

  passkeyAuthenticate(response: AuthenticationResponseJSON, challenge: string) {
    return request<LoginResponse>('/api/auth/passkeys/authenticate', {
      method: 'POST',
      body: JSON.stringify({ response, challenge }),
    });
  },

  // Passkey management
  listPasskeys() {
    return request<{ passkeys: Passkey[] }>('/api/auth/passkeys');
  },

  deletePasskey(id: string) {
    return request(`/api/auth/passkeys/${id}`, { method: 'DELETE' });
  },

  // Session
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

  // API keys
  listApiKeys() {
    return request<{ api_keys: ApiKey[] }>('/api/api-keys');
  },

  createApiKey(name: string) {
    return request<ApiKeyCreated>('/api/api-keys', {
      method: 'POST',
      body: JSON.stringify({ name }),
    });
  },

  revokeApiKey(id: string) {
    return request(`/api/api-keys/${id}`, { method: 'DELETE' });
  },
};
