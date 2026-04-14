import { addToBlocklist, revokeRefreshToken } from '../kv.mjs';

export async function handleLogout(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    body = {};
  }

  const { claims } = request;

  // Blocklist the current access token
  if (claims.jti && claims.exp) {
    const now = Math.floor(Date.now() / 1000);
    const ttl = Math.max(claims.exp - now, 1);
    await addToBlocklist(env.SESSIONS_KV, claims.jti, ttl);
  }

  // Revoke the refresh token if provided
  if (body.refresh_token) {
    await revokeRefreshToken(env.SESSIONS_KV, body.refresh_token);
  }

  return jsonResponse({ message: 'Logged out' });
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
