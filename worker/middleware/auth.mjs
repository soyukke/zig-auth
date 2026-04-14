import { verifyJwt } from '../wasm-bridge.mjs';
import { isBlocklisted } from '../kv.mjs';
import { getApiKeyByPrefix, updateApiKeyLastUsed } from '../db-apikey.mjs';

export async function authMiddleware(request, env) {
  const authHeader = request.headers.get('Authorization');
  const apiKeyHeader = request.headers.get('X-API-Key');

  // API key authentication
  const apiKey = apiKeyHeader || (authHeader?.startsWith('Bearer zk_') ? authHeader.slice(7) : null);
  if (apiKey) {
    return await authenticateApiKey(request, env, apiKey);
  }

  // JWT authentication
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return jsonError('Missing or invalid Authorization header', 401);
  }

  const token = authHeader.slice(7);
  const now = Math.floor(Date.now() / 1000);

  let claims;
  try {
    claims = await verifyJwt(token, env.JWT_SECRET, now);
  } catch (err) {
    if (err.message === 'TOKEN_EXPIRED') {
      return jsonError('Token expired', 401);
    }
    return jsonError('Invalid token', 401);
  }

  if (claims.jti && await isBlocklisted(env.SESSIONS_KV, claims.jti)) {
    return jsonError('Token revoked', 401);
  }

  request.claims = claims;
  request.token = token;
  return null;
}

async function authenticateApiKey(request, env, apiKey) {
  if (!apiKey.startsWith('zk_') || apiKey.length !== 43) {
    return jsonError('Invalid API key format', 401);
  }

  const prefix = apiKey.substring(0, 11);
  const candidate = await getApiKeyByPrefix(env.DB, prefix);
  if (!candidate || candidate.revoked_at) {
    return jsonError('Invalid API key', 401);
  }

  // Hash and compare
  const encoder = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(apiKey));
  const hashHex = [...new Uint8Array(hashBuffer)].map(b => b.toString(16).padStart(2, '0')).join('');

  if (hashHex !== candidate.key_hash) {
    return jsonError('Invalid API key', 401);
  }

  if (candidate.expires_at && new Date(candidate.expires_at) < new Date()) {
    return jsonError('API key expired', 401);
  }

  request.claims = { sub: candidate.user_id, auth_method: 'api_key', api_key_id: candidate.id };
  request.token = null;

  // Update last_used_at (fire-and-forget)
  updateApiKeyLastUsed(env.DB, candidate.id);

  return null;
}

function jsonError(message, status) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
