import { createApiKey, listApiKeys, revokeApiKey } from '../db-apikey.mjs';

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

// POST /api/api-keys
export async function handleCreateApiKey(request, env) {
  const userId = request.claims.sub;
  const body = await request.json();
  const { name, scopes } = body;

  if (!name || name.length < 1 || name.length > 64) {
    return jsonResponse({ error: 'Name is required (1-64 characters)' }, 400);
  }

  // Generate random key: zk_ + 40 hex chars
  const randomBytes = new Uint8Array(20);
  crypto.getRandomValues(randomBytes);
  const hexPart = [...randomBytes].map(b => b.toString(16).padStart(2, '0')).join('');
  const fullKey = `zk_${hexPart}`;
  const prefix = fullKey.substring(0, 11); // "zk_" + 8 hex chars

  // Hash with SHA-256
  const encoder = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(fullKey));
  const keyHash = [...new Uint8Array(hashBuffer)].map(b => b.toString(16).padStart(2, '0')).join('');

  const apiKey = await createApiKey(env.DB, {
    userId,
    name,
    prefix,
    keyHash,
    scopes: scopes || ['*'],
  });

  // Return full key only once
  return jsonResponse({
    ...apiKey,
    key: fullKey,
  }, 201);
}

// GET /api/api-keys
export async function handleListApiKeys(request, env) {
  const userId = request.claims.sub;
  const apiKeys = await listApiKeys(env.DB, userId);
  return jsonResponse({ api_keys: apiKeys });
}

// DELETE /api/api-keys/:id
export async function handleRevokeApiKey(request, env) {
  const userId = request.claims.sub;
  const keyId = request.params?.id;

  const revoked = await revokeApiKey(env.DB, keyId, userId);
  if (!revoked) {
    return jsonResponse({ error: 'API key not found' }, 404);
  }

  return jsonResponse({ message: 'API key revoked' });
}
