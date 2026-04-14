<script lang="ts">
  import { onMount } from 'svelte';
  import { startRegistration } from '@simplewebauthn/browser';
  import { user, isAuthenticated } from '$lib/auth';
  import { api, type Passkey, type ApiKey } from '$lib/api';
  import { goto } from '$app/navigation';

  let passkeys = $state<Passkey[]>([]);
  let apiKeys = $state<ApiKey[]>([]);
  let message = $state('');
  let error = $state('');

  // Passkey add
  let addingPasskey = $state(false);
  let passkeyName = $state('');

  // API key create
  let creatingKey = $state(false);
  let newKeyName = $state('');
  let createdKey = $state('');

  onMount(async () => {
    if (!$isAuthenticated) {
      goto('/login');
      return;
    }
    await loadData();
  });

  async function loadData() {
    const [pkRes, akRes] = await Promise.all([api.listPasskeys(), api.listApiKeys()]);
    if (pkRes.data) passkeys = pkRes.data.passkeys;
    if (akRes.data) apiKeys = akRes.data.api_keys;
  }

  // Passkey management
  async function handleAddPasskey() {
    error = '';
    message = '';
    addingPasskey = true;

    try {
      const optionsRes = await api.passkeyAddOptions();
      if (!optionsRes.data) {
        error = optionsRes.error || 'Failed to get options';
        addingPasskey = false;
        return;
      }

      const regResponse = await startRegistration({ optionsJSON: optionsRes.data });
      const res = await api.passkeyAdd(regResponse, passkeyName || undefined);

      if (res.data) {
        message = 'Passkey added';
        passkeyName = '';
        await loadData();
      } else {
        error = res.error || 'Failed to add passkey';
      }
    } catch (err: any) {
      if (err.name !== 'NotAllowedError') {
        error = err.message || 'Failed to add passkey';
      }
    }
    addingPasskey = false;
  }

  async function handleDeletePasskey(id: string) {
    if (!confirm('Delete this passkey?')) return;
    error = '';
    const res = await api.deletePasskey(id);
    if (res.error) {
      error = res.error;
    } else {
      await loadData();
    }
  }

  // API key management
  async function handleCreateApiKey(e: Event) {
    e.preventDefault();
    error = '';
    createdKey = '';
    creatingKey = true;

    const res = await api.createApiKey(newKeyName);
    if (res.data) {
      createdKey = res.data.key;
      newKeyName = '';
      await loadData();
    } else {
      error = res.error || 'Failed to create API key';
    }
    creatingKey = false;
  }

  async function handleRevokeApiKey(id: string) {
    if (!confirm('Revoke this API key?')) return;
    error = '';
    const res = await api.revokeApiKey(id);
    if (res.error) {
      error = res.error;
    } else {
      await loadData();
    }
  }

  function copyToClipboard(text: string) {
    navigator.clipboard.writeText(text);
    message = 'Copied to clipboard';
    setTimeout(() => { if (message === 'Copied to clipboard') message = ''; }, 2000);
  }
</script>

{#if $isAuthenticated && $user}
  <div class="space-y-8">
    <h1 class="text-2xl font-bold text-gray-900">Dashboard</h1>

    {#if message}
      <div class="bg-green-50 border border-green-200 text-green-700 px-4 py-3 rounded">{message}</div>
    {/if}
    {#if error}
      <div class="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded">{error}</div>
    {/if}

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
      </dl>
    </div>

    <!-- Passkeys -->
    <div class="bg-white rounded-lg border border-gray-200 p-6">
      <h2 class="text-lg font-semibold text-gray-900 mb-4">Passkeys</h2>

      {#if passkeys.length === 0}
        <p class="text-sm text-gray-500 mb-4">No passkeys registered.</p>
      {:else}
        <div class="space-y-3 mb-4">
          {#each passkeys as pk}
            <div class="flex items-center justify-between py-2 px-3 bg-gray-50 rounded">
              <div>
                <span class="text-sm font-medium text-gray-900">{pk.name || 'Unnamed'}</span>
                <span class="text-xs text-gray-500 ml-2">{pk.device_type || ''}</span>
                <span class="text-xs text-gray-400 ml-2">Created: {pk.created_at}</span>
              </div>
              <button
                onclick={() => handleDeletePasskey(pk.id)}
                class="text-sm text-red-600 hover:underline cursor-pointer"
              >Delete</button>
            </div>
          {/each}
        </div>
      {/if}

      <div class="flex gap-2 items-end">
        <div class="flex-1">
          <label for="passkey-name" class="block text-sm text-gray-700 mb-1">Name (optional)</label>
          <input
            id="passkey-name"
            type="text"
            bind:value={passkeyName}
            placeholder="e.g. MacBook"
            class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm"
          />
        </div>
        <button
          onclick={handleAddPasskey}
          disabled={addingPasskey}
          class="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50 cursor-pointer text-sm"
        >
          {addingPasskey ? 'Adding...' : 'Add Passkey'}
        </button>
      </div>
    </div>

    <!-- API Keys -->
    <div class="bg-white rounded-lg border border-gray-200 p-6">
      <h2 class="text-lg font-semibold text-gray-900 mb-4">API Keys</h2>

      {#if createdKey}
        <div class="bg-yellow-50 border border-yellow-200 px-4 py-3 rounded mb-4">
          <p class="text-sm text-yellow-800 font-medium mb-1">API key created. Copy it now - it won't be shown again.</p>
          <div class="flex items-center gap-2">
            <code class="text-sm bg-yellow-100 px-2 py-1 rounded font-mono flex-1 break-all">{createdKey}</code>
            <button
              onclick={() => copyToClipboard(createdKey)}
              class="text-sm bg-yellow-200 px-3 py-1 rounded hover:bg-yellow-300 cursor-pointer"
            >Copy</button>
          </div>
        </div>
      {/if}

      {#if apiKeys.length === 0}
        <p class="text-sm text-gray-500 mb-4">No API keys.</p>
      {:else}
        <div class="space-y-3 mb-4">
          {#each apiKeys as ak}
            <div class="flex items-center justify-between py-2 px-3 bg-gray-50 rounded">
              <div>
                <span class="text-sm font-medium text-gray-900">{ak.name}</span>
                <code class="text-xs text-gray-500 ml-2 font-mono">{ak.prefix}...</code>
                <span class="text-xs text-gray-400 ml-2">Created: {ak.created_at}</span>
              </div>
              <button
                onclick={() => handleRevokeApiKey(ak.id)}
                class="text-sm text-red-600 hover:underline cursor-pointer"
              >Revoke</button>
            </div>
          {/each}
        </div>
      {/if}

      <form onsubmit={handleCreateApiKey} class="flex gap-2 items-end">
        <div class="flex-1">
          <label for="key-name" class="block text-sm text-gray-700 mb-1">Key name</label>
          <input
            id="key-name"
            type="text"
            bind:value={newKeyName}
            required
            placeholder="e.g. CI/CD"
            class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm"
          />
        </div>
        <button
          type="submit"
          disabled={creatingKey || !newKeyName}
          class="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50 cursor-pointer text-sm"
        >
          {creatingKey ? 'Creating...' : 'Create Key'}
        </button>
      </form>
    </div>
  </div>
{/if}
