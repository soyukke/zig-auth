<script lang="ts">
  import '../app.css';
  import { onMount } from 'svelte';
  import { loadUser, isAuthenticated, user, logout } from '$lib/auth';
  import { goto } from '$app/navigation';

  let { children } = $props();

  onMount(() => {
    loadUser();
  });

  async function handleLogout() {
    await logout();
    goto('/login');
  }
</script>

<div class="min-h-screen bg-gray-50">
  <nav class="bg-white border-b border-gray-200 px-4 py-3">
    <div class="max-w-7xl mx-auto flex justify-between items-center">
      <a href="/" class="text-xl font-bold text-gray-900">Zig Auth</a>
      <div class="flex gap-4 items-center">
        {#if $isAuthenticated}
          <span class="text-sm text-gray-600">{$user?.email}</span>
          <a href="/dashboard" class="text-sm text-blue-600 hover:underline">Dashboard</a>
          <button onclick={handleLogout} class="text-sm text-red-600 hover:underline cursor-pointer">
            Logout
          </button>
        {:else}
          <a href="/login" class="text-sm text-blue-600 hover:underline">Login</a>
          <a href="/signup" class="text-sm text-blue-600 hover:underline">Sign up</a>
        {/if}
      </div>
    </div>
  </nav>
  <main class="max-w-7xl mx-auto py-8 px-4">
    {@render children()}
  </main>
</div>
