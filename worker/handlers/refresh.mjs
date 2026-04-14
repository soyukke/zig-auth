import { createJwt } from '../wasm-bridge.mjs';
import { getUserById } from '../db.mjs';
import { getRefreshToken, revokeRefreshToken, storeRefreshToken } from '../kv.mjs';

export async function handleRefresh(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: 'Invalid JSON' }, 400);
  }

  const { refresh_token } = body;
  if (!refresh_token) {
    return jsonResponse({ error: 'refresh_token is required' }, 400);
  }

  const userId = await getRefreshToken(env.SESSIONS_KV, refresh_token);
  if (!userId) {
    return jsonResponse({ error: 'Invalid or expired refresh token' }, 401);
  }

  const user = await getUserById(env.DB, userId);
  if (!user) {
    await revokeRefreshToken(env.SESSIONS_KV, refresh_token);
    return jsonResponse({ error: 'User not found' }, 401);
  }

  // Rotate refresh token
  await revokeRefreshToken(env.SESSIONS_KV, refresh_token);
  const newRefreshTokenId = crypto.randomUUID();
  await storeRefreshToken(env.SESSIONS_KV, newRefreshTokenId, userId);

  // Create new access token
  const now = Math.floor(Date.now() / 1000);
  const jti = crypto.randomUUID();
  const claims = JSON.stringify({
    sub: user.id,
    email: user.email,
    jti,
    iat: now,
    exp: now + 900,
  });

  const accessToken = await createJwt(claims, env.JWT_SECRET);

  return jsonResponse({
    access_token: accessToken,
    refresh_token: newRefreshTokenId,
    token_type: 'Bearer',
    expires_in: 900,
  });
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
