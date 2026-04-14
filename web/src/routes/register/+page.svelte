<script lang="ts">
  import { startRegistration } from '@simplewebauthn/browser';
  import { api } from '$lib/api';
  import { saveTokens, loadUser } from '$lib/auth';
  import { goto } from '$app/navigation';

  let username = $state('');
  let error = $state('');
  let loading = $state(false);

  async function handleRegister(e: Event) {
    e.preventDefault();
    error = '';
    loading = true;

    try {
      const optionsRes = await api.passkeyRegisterOptions(username);
      if (!optionsRes.data) {
        error = optionsRes.error || 'Failed to get registration options';
        loading = false;
        return;
      }

      const regResponse = await startRegistration({ optionsJSON: optionsRes.data });

      const verifyRes = await api.passkeyRegister(regResponse, optionsRes.data.challenge);
      if (verifyRes.data) {
        saveTokens(verifyRes.data.access_token, verifyRes.data.refresh_token);
        await loadUser();
        goto('/dashboard');
      } else {
        error = verifyRes.error || 'Registration failed';
      }
    } catch (err: any) {
      if (err.name === 'NotAllowedError') {
        error = 'Registration was cancelled';
      } else {
        error = err.message || 'Registration failed';
      }
    }
    loading = false;
  }
</script>

<div class="max-w-md mx-auto">
  <h1 class="text-2xl font-bold text-gray-900 mb-6">Register</h1>

  {#if error}
    <div class="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded mb-4">{error}</div>
  {/if}

  <form onsubmit={handleRegister} class="space-y-4">
    <div>
      <label for="username" class="block text-sm font-medium text-gray-700 mb-1">Username</label>
      <input
        id="username"
        type="text"
        bind:value={username}
        required
        minlength="1"
        maxlength="64"
        class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
        placeholder="your-username"
      />
    </div>

    <button
      type="submit"
      disabled={loading || !username}
      class="w-full bg-blue-600 text-white py-3 rounded-lg hover:bg-blue-700 disabled:opacity-50 cursor-pointer text-lg font-medium"
    >
      {loading ? 'Creating passkey...' : 'Create account with Passkey'}
    </button>
  </form>

  <p class="mt-2 text-sm text-gray-500">
    A passkey will be created on your device. No password needed.
  </p>

  <p class="mt-4 text-center text-sm text-gray-600">
    Already have an account? <a href="/login" class="text-blue-600 hover:underline">Login</a>
  </p>
</div>
