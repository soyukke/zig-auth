<script lang="ts">
  import { api } from '$lib/api';

  let email = $state('');
  let sent = $state(false);
  let loading = $state(false);

  async function handleSubmit(e: Event) {
    e.preventDefault();
    loading = true;
    await api.forgotPassword(email);
    sent = true;
    loading = false;
  }
</script>

<div class="max-w-md mx-auto">
  <h1 class="text-2xl font-bold text-gray-900 mb-6">パスワードリセット</h1>

  {#if sent}
    <div class="bg-green-50 border border-green-200 text-green-700 px-4 py-3 rounded mb-4">
      メールアドレスが登録されている場合、リセットリンクを送信しました。
    </div>
    <a href="/login" class="text-blue-600 hover:underline">ログインに戻る</a>
  {:else}
    <p class="text-sm text-gray-600 mb-4">登録済みのメールアドレスを入力してください。</p>
    <form onsubmit={handleSubmit} class="space-y-4">
      <div>
        <label for="email" class="block text-sm font-medium text-gray-700 mb-1">Email</label>
        <input
          id="email"
          type="email"
          bind:value={email}
          required
          class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
          placeholder="you@example.com"
        />
      </div>
      <button
        type="submit"
        disabled={loading}
        class="w-full bg-blue-600 text-white py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50 cursor-pointer"
      >
        {loading ? '送信中...' : 'リセットリンクを送信'}
      </button>
    </form>
    <p class="mt-4 text-center text-sm text-gray-600">
      <a href="/login" class="text-blue-600 hover:underline">ログインに戻る</a>
    </p>
  {/if}
</div>
