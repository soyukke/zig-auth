<script lang="ts">
  import { page } from '$app/stores';
  import { api } from '$lib/api';
  import { goto } from '$app/navigation';

  let newPassword = $state('');
  let confirmPassword = $state('');
  let error = $state('');
  let loading = $state(false);

  const token = $page.url.searchParams.get('token');

  async function handleSubmit(e: Event) {
    e.preventDefault();
    error = '';

    if (newPassword !== confirmPassword) {
      error = 'パスワードが一致しません';
      return;
    }

    loading = true;
    const res = await api.resetPassword(token || '', newPassword);

    if (res.error) {
      error = res.error;
    } else {
      goto('/login?reset=true');
    }
    loading = false;
  }
</script>

<div class="max-w-md mx-auto">
  <h1 class="text-2xl font-bold text-gray-900 mb-6">新しいパスワードを設定</h1>

  {#if !token}
    <div class="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded">
      無効なリセットリンクです。
    </div>
    <a href="/forgot-password" class="text-blue-600 hover:underline mt-4 block">再送信する</a>
  {:else}
    {#if error}
      <div class="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded mb-4">{error}</div>
    {/if}

    <form onsubmit={handleSubmit} class="space-y-4">
      <div>
        <label for="password" class="block text-sm font-medium text-gray-700 mb-1">新しいパスワード</label>
        <input
          id="password"
          type="password"
          bind:value={newPassword}
          required
          minlength="8"
          maxlength="72"
          class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
        />
      </div>
      <div>
        <label for="confirm" class="block text-sm font-medium text-gray-700 mb-1">確認</label>
        <input
          id="confirm"
          type="password"
          bind:value={confirmPassword}
          required
          class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
        />
      </div>
      <button
        type="submit"
        disabled={loading}
        class="w-full bg-blue-600 text-white py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50 cursor-pointer"
      >
        {loading ? '設定中...' : 'パスワードを設定'}
      </button>
    </form>
  {/if}
</div>
