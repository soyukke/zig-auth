import { sendVerificationEmail } from '../email.mjs';

// POST /api/auth/send-verification — Send verification email
export async function handleSendVerification(request, env) {
  const { sub: userId, email } = request.claims;

  // Check if already verified
  const user = await env.DB.prepare(
    'SELECT email_verified FROM users WHERE id = ?'
  ).bind(userId).first();

  if (user?.email_verified) {
    return jsonResponse({ message: 'Email already verified' });
  }

  // Generate token and store in KV (24h TTL)
  const token = crypto.randomUUID();
  await env.SESSIONS_KV.put(`verify:${token}`, userId, { expirationTtl: 86400 });

  await sendVerificationEmail(env, email, token);

  return jsonResponse({ message: 'Verification email sent' });
}

// GET /api/auth/verify?token=xxx — Verify email
export async function handleVerifyEmail(request, env) {
  const url = new URL(request.url);
  const token = url.searchParams.get('token');

  if (!token) {
    return redirectToFrontend(env, '/login?error=missing_token');
  }

  const userId = await env.SESSIONS_KV.get(`verify:${token}`);
  if (!userId) {
    return redirectToFrontend(env, '/login?error=invalid_or_expired_token');
  }

  // Mark as verified
  await env.DB.prepare(
    'UPDATE users SET email_verified = 1 WHERE id = ?'
  ).bind(userId).run();

  // Clean up token
  await env.SESSIONS_KV.delete(`verify:${token}`);

  return redirectToFrontend(env, '/login?verified=true');
}

function redirectToFrontend(env, path) {
  const frontendUrl = env.FRONTEND_URL || 'http://localhost:5173';
  return Response.redirect(`${frontendUrl}${path}`, 302);
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
