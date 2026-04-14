<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { saveTokens, loadUser } from '$lib/auth';

  let error = $state('');

  onMount(async () => {
    const params = $page.url.searchParams;
    const accessToken = params.get('access_token');
    const refreshToken = params.get('refresh_token');
    const err = params.get('error');

    if (err) {
      error = `OAuth failed: ${err}`;
      return;
    }

    if (accessToken && refreshToken) {
      saveTokens(accessToken, refreshToken);
      await loadUser();
      goto('/dashboard');
    } else {
      error = 'Invalid OAuth callback';
    }
  });
</script>

<div class="max-w-md mx-auto text-center py-20">
  {#if error}
    <div class="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded mb-4">{error}</div>
    <a href="/login" class="text-blue-600 hover:underline">Back to Login</a>
  {:else}
    <p class="text-gray-600">Logging in...</p>
  {/if}
</div>
