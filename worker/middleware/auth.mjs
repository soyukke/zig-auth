import { verifyJwt } from '../wasm-bridge.mjs';
import { isBlocklisted } from '../kv.mjs';

export async function authMiddleware(request, env) {
  const authHeader = request.headers.get('Authorization');
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
  return null; // Continue to next handler
}

function jsonError(message, status) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
