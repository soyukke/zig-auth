import { sendPasswordResetEmail } from '../email.mjs';
import { hashPassword } from '../wasm-bridge.mjs';
import { getUserByEmail } from '../db.mjs';

// POST /api/auth/forgot-password — Request password reset
export async function handleForgotPassword(request, env) {
  let body;
  try { body = await request.json(); } catch { return jsonResponse({ error: 'Invalid JSON' }, 400); }

  const { email } = body;
  if (!email) return jsonResponse({ error: 'email is required' }, 400);

  // Always return success to prevent email enumeration
  const user = await getUserByEmail(env.DB, email);
  if (user) {
    const token = crypto.randomUUID();
    await env.SESSIONS_KV.put(`reset:${token}`, user.id, { expirationTtl: 3600 });
    await sendPasswordResetEmail(env, email, token);
  }

  return jsonResponse({ message: 'If that email exists, a reset link has been sent' });
}

// POST /api/auth/reset-password — Reset password with token
export async function handleResetPassword(request, env) {
  let body;
  try { body = await request.json(); } catch { return jsonResponse({ error: 'Invalid JSON' }, 400); }

  const { token, new_password } = body;
  if (!token || !new_password) {
    return jsonResponse({ error: 'token and new_password are required' }, 400);
  }

  const passwordBytes = new TextEncoder().encode(new_password);
  if (passwordBytes.length < 8 || passwordBytes.length > 72) {
    return jsonResponse({ error: 'Password must be 8-72 bytes' }, 400);
  }

  const userId = await env.SESSIONS_KV.get(`reset:${token}`);
  if (!userId) {
    return jsonResponse({ error: 'Invalid or expired reset token' }, 400);
  }

  // Hash new password
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  const newHash = await hashPassword(new_password, salt);

  // Update password
  await env.DB.prepare(
    "UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?"
  ).bind(newHash, userId).run();

  // Clean up token
  await env.SESSIONS_KV.delete(`reset:${token}`);

  return jsonResponse({ message: 'Password reset successful' });
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
