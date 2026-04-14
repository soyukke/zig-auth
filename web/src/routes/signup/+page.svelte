<script lang="ts">
  import { api } from '$lib/api';
  import { goto } from '$app/navigation';

  let email = $state('');
  let password = $state('');
  let confirmPassword = $state('');
  let error = $state('');
  let loading = $state(false);
  let ready = $state(false);

  import { onMount } from 'svelte';
  onMount(() => { ready = true; });

  async function handleSubmit(e: SubmitEvent) {
    e.preventDefault();
    error = '';

    if (password !== confirmPassword) {
      error = 'Passwords do not match';
      return;
    }

    loading = true;

    const res = await api.signup(email, password);

    if (res.data) {
      goto('/login?registered=true');
    } else {
      error = res.error || 'Signup failed';
    }
    loading = false;
  }
</script>

<div class="max-w-md mx-auto">
  <h1 class="text-2xl font-bold text-gray-900 mb-6">Sign Up</h1>

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
        maxlength="72"
        class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
      />
      <p class="text-xs text-gray-500 mt-1">8〜72文字</p>
    </div>

    <div>
      <label for="confirm" class="block text-sm font-medium text-gray-700 mb-1">Confirm Password</label>
      <input
        id="confirm"
        type="password"
        bind:value={confirmPassword}
        required
        class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
      />
    </div>

    <button
      type="submit"
      disabled={!ready || loading}
      class="w-full bg-blue-600 text-white py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50 cursor-pointer"
    >
      {loading ? 'Creating account...' : 'Sign Up'}
    </button>
  </form>

  <p class="mt-4 text-center text-sm text-gray-600">
    Already have an account? <a href="/login" class="text-blue-600 hover:underline">Login</a>
  </p>
</div>
