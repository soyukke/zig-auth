<script lang="ts">
  import { api } from '$lib/api';
  import { saveTokens, loadUser, user } from '$lib/auth';
  import { goto } from '$app/navigation';

  let email = $state('');
  let password = $state('');
  let error = $state('');
  let loading = $state(false);
  let ready = $state(false);
  const apiBase = import.meta.env.VITE_API_URL || 'http://localhost:8787';

  import { onMount } from 'svelte';
  onMount(() => { ready = true; });

  async function handleSubmit(e: Event) {
    e.preventDefault();
    error = '';
    loading = true;

    const res = await api.login(email, password);

    if (res.data) {
      saveTokens(res.data.access_token, res.data.refresh_token);
      // Load user profile, then navigate
      await loadUser();
      if (!$user) {
        // Fallback: parse JWT claims for basic user info
        try {
          const payload = JSON.parse(atob(res.data.access_token.split('.')[1]));
          user.set({ id: payload.sub, email: payload.email, created_at: '', updated_at: '' });
        } catch {}
      }
      goto('/dashboard');
    } else {
      error = res.error || 'Login failed';
    }
    loading = false;
  }
</script>

<div class="max-w-md mx-auto">
  <h1 class="text-2xl font-bold text-gray-900 mb-6">Login</h1>

  {#if error}
    <div class="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded mb-4">{error}</div>
  {/if}

  <form onsubmit={handleSubmit} class="space-y-4">
    <div>
      <label for="email" class="block text-sm font-medium text-gray-700 mb-1">Email</label>
      <input
        id="email"
        type="email"
        bind:value={email}
        required
        class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
        placeholder="you@example.com"
      />
    </div>

    <div>
      <label for="password" class="block text-sm font-medium text-gray-700 mb-1">Password</label>
      <input
        id="password"
        type="password"
        bind:value={password}
        required
        minlength="8"
        class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
      />
    </div>

    <button
      type="submit"
      disabled={!ready || loading}
      class="w-full bg-blue-600 text-white py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50 cursor-pointer"
    >
      {loading ? 'Logging in...' : 'Login'}
    </button>
  </form>

  <p class="mt-2 text-right">
    <a href="/forgot-password" class="text-sm text-gray-500 hover:underline">パスワードを忘れた？</a>
  </p>

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
    Don't have an account? <a href="/signup" class="text-blue-600 hover:underline">Sign up</a>
  </p>
</div>
