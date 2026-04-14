<script lang="ts">
  import { startAuthentication } from '@simplewebauthn/browser';
  import { api } from '$lib/api';
  import { saveTokens, loadUser, user } from '$lib/auth';
  import { goto } from '$app/navigation';

  let error = $state('');
  let loading = $state(false);
  const apiBase = import.meta.env.VITE_API_URL || 'http://localhost:8787';

  async function handlePasskeyLogin() {
    error = '';
    loading = true;

    try {
      const optionsRes = await api.passkeyAuthOptions();
      if (!optionsRes.data) {
        error = optionsRes.error || 'Failed to get authentication options';
        loading = false;
        return;
      }

      const authResponse = await startAuthentication({ optionsJSON: optionsRes.data });

      const verifyRes = await api.passkeyAuthenticate(authResponse, optionsRes.data.challenge);
      if (verifyRes.data) {
        saveTokens(verifyRes.data.access_token, verifyRes.data.refresh_token);
        await loadUser();
        goto('/dashboard');
      } else {
        error = verifyRes.error || 'Authentication failed';
      }
    } catch (err: any) {
      if (err.name === 'NotAllowedError') {
        error = 'Authentication was cancelled';
      } else {
        error = err.message || 'Authentication failed';
      }
    }
    loading = false;
  }
</script>

<div class="max-w-md mx-auto">
  <h1 class="text-2xl font-bold text-gray-900 mb-6">Login</h1>

  {#if error}
    <div class="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded mb-4">{error}</div>
  {/if}

  <button
    onclick={handlePasskeyLogin}
    disabled={loading}
    class="w-full bg-blue-600 text-white py-3 rounded-lg hover:bg-blue-700 disabled:opacity-50 cursor-pointer text-lg font-medium"
  >
    {loading ? 'Authenticating...' : 'Sign in with Passkey'}
  </button>

  <div class="mt-6">
    <div class="relative">
      <div class="absolute inset-0 flex items-center"><div class="w-full border-t border-gray-300"></div></div>
      <div class="relative flex justify-center text-sm"><span class="bg-gray-50 px-2 text-gray-500">or</span></div>
    </div>

    <div class="mt-4 space-y-3">
      <a
        href="{apiBase}/api/auth/oauth/github"
        class="w-full flex items-center justify-center gap-2 bg-gray-900 text-white py-2 rounded-lg hover:bg-gray-800"
      >
        GitHub
      </a>
      <a
        href="{apiBase}/api/auth/oauth/google"
        class="w-full flex items-center justify-center gap-2 bg-white border border-gray-300 text-gray-700 py-2 rounded-lg hover:bg-gray-50"
      >
        Google
      </a>
    </div>
  </div>

  <p class="mt-4 text-center text-sm text-gray-600">
    Don't have an account? <a href="/register" class="text-blue-600 hover:underline">Register</a>
  </p>
</div>
