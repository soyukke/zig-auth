import { hashPassword, verifyPassword } from '../wasm-bridge.mjs';
import { getUserPasswordHash, updatePassword } from '../db.mjs';

export async function handleChangePassword(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: 'Invalid JSON' }, 400);
  }

  const { current_password, new_password } = body;
  if (!current_password || !new_password) {
    return jsonResponse({ error: 'current_password and new_password are required' }, 400);
  }

  // Validate in bytes (bcrypt limit is 72 bytes)
  const newPasswordBytes = new TextEncoder().encode(new_password);
  if (newPasswordBytes.length < 8 || newPasswordBytes.length > 72) {
    return jsonResponse({ error: 'New password must be 8-72 bytes' }, 400);
  }

  const { sub: userId } = request.claims;

  const currentHash = await getUserPasswordHash(env.DB, userId);
  if (!currentHash) {
    return jsonResponse({ error: 'User not found' }, 404);
  }

  const valid = await verifyPassword(current_password, currentHash);
  if (!valid) {
    return jsonResponse({ error: 'Current password is incorrect' }, 401);
  }

  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);

  const newHash = await hashPassword(new_password, salt);
  await updatePassword(env.DB, userId, newHash);

  // Note: existing refresh tokens remain valid.
  // For full session invalidation, implement a user-level token version.

  return jsonResponse({ message: 'Password updated' });
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
