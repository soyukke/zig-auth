<script lang="ts">
  import { isAuthenticated } from '$lib/auth';
</script>

<div class="text-center py-20">
  <h1 class="text-4xl font-bold text-gray-900 mb-4">Zig Auth</h1>
  <p class="text-lg text-gray-600 mb-8">Zig + WASM で構築された認証基盤</p>
  {#if $isAuthenticated}
    <a href="/dashboard" class="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700">
      Dashboard
    </a>
  {:else}
    <div class="flex gap-4 justify-center">
      <a href="/login" class="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700">
        Login
      </a>
      <a href="/signup" class="bg-gray-200 text-gray-800 px-6 py-3 rounded-lg hover:bg-gray-300">
        Sign up
      </a>
    </div>
  {/if}
</div>
