<script lang="ts">
  import { onMount } from 'svelte';
  import { user, isAuthenticated } from '$lib/auth';
  import { api } from '$lib/api';
  import { goto } from '$app/navigation';

  let currentPassword = $state('');
  let newPassword = $state('');
  let message = $state('');
  let error = $state('');
  let changingPassword = $state(false);

  onMount(() => {
    if (!$isAuthenticated) {
      goto('/login');
    }
  });

  async function handleChangePassword(e: Event) {
    e.preventDefault();
    error = '';
    message = '';
    changingPassword = true;

    const res = await api.changePassword(currentPassword, newPassword);

    if (res.error) {
      error = res.error;
    } else {
      message = 'Password updated successfully';
      currentPassword = '';
      newPassword = '';
    }
    changingPassword = false;
  }
</script>

{#if $isAuthenticated && $user}
  <div class="space-y-8">
    <div>
      <h1 class="text-2xl font-bold text-gray-900 mb-6">Dashboard</h1>
    </div>

    <!-- Profile -->
    <div class="bg-white rounded-lg border border-gray-200 p-6">
      <h2 class="text-lg font-semibold text-gray-900 mb-4">Profile</h2>
      <dl class="space-y-3">
        <div class="flex">
          <dt class="w-32 text-sm text-gray-500">ID</dt>
          <dd class="text-sm text-gray-900 font-mono">{$user.id}</dd>
        </div>
        <div class="flex">
          <dt class="w-32 text-sm text-gray-500">Email</dt>
          <dd class="text-sm text-gray-900">{$user.email}</dd>
        </div>
        <div class="flex">
          <dt class="w-32 text-sm text-gray-500">Created</dt>
          <dd class="text-sm text-gray-900">{$user.created_at}</dd>
        </div>
        <div class="flex">
          <dt class="w-32 text-sm text-gray-500">Updated</dt>
          <dd class="text-sm text-gray-900">{$user.updated_at}</dd>
        </div>
      </dl>
    </div>

    <!-- Change Password -->
    <div class="bg-white rounded-lg border border-gray-200 p-6">
      <h2 class="text-lg font-semibold text-gray-900 mb-4">Change Password</h2>

      {#if message}
        <div class="bg-green-50 border border-green-200 text-green-700 px-4 py-3 rounded mb-4">{message}</div>
      {/if}
      {#if error}
        <div class="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded mb-4">{error}</div>
      {/if}

      <form onsubmit={handleChangePassword} class="space-y-4 max-w-md">
        <div>
          <label for="current" class="block text-sm font-medium text-gray-700 mb-1">Current Password</label>
          <input
            id="current"
            type="password"
            bind:value={currentPassword}
            required
            class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div>
          <label for="new" class="block text-sm font-medium text-gray-700 mb-1">New Password</label>
          <input
            id="new"
            type="password"
            bind:value={newPassword}
            required
            minlength="8"
            maxlength="72"
            class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <button
          type="submit"
          disabled={changingPassword}
          class="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50 cursor-pointer"
        >
          {changingPassword ? 'Updating...' : 'Update Password'}
        </button>
      </form>
    </div>
  </div>
{/if}
