import { verifyPassword, createJwt, hashPassword } from '../wasm-bridge.mjs';
import { getUserByEmail } from '../db.mjs';
import { storeRefreshToken } from '../kv.mjs';

export async function handleLogin(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: 'Invalid JSON' }, 400);
  }

  const { email, password } = body;
  if (!email || !password) {
    return jsonResponse({ error: 'email and password are required' }, 400);
  }

  const user = await getUserByEmail(env.DB, email);

  if (!user) {
    // Perform a dummy hash to prevent timing-based user enumeration
    const dummySalt = new Uint8Array(16);
    crypto.getRandomValues(dummySalt);
    try { await hashPassword('dummy_password_timing', dummySalt); } catch {}
    return jsonResponse({ error: 'Invalid credentials' }, 401);
  }

  const valid = await verifyPassword(password, user.password_hash);
  if (!valid) {
    return jsonResponse({ error: 'Invalid credentials' }, 401);
  }

  const now = Math.floor(Date.now() / 1000);
  const jti = crypto.randomUUID();

  const claims = JSON.stringify({
    sub: user.id,
    email: user.email,
    jti,
    iat: now,
    exp: now + 900, // 15 minutes
  });

  const accessToken = await createJwt(claims, env.JWT_SECRET);

  const refreshTokenId = crypto.randomUUID();
  await storeRefreshToken(env.SESSIONS_KV, refreshTokenId, user.id);

  return jsonResponse({
    access_token: accessToken,
    refresh_token: refreshTokenId,
    token_type: 'Bearer',
    expires_in: 900,
    email_verified: !!user.email_verified,
  });
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
