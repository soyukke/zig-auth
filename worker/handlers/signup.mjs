import { hashPassword } from '../wasm-bridge.mjs';
import { createUser } from '../db.mjs';
import { sendVerificationEmail } from '../email.mjs';

export async function handleSignup(request, env) {
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

  if (!isValidEmail(email)) {
    return jsonResponse({ error: 'Invalid email format' }, 400);
  }

  // Validate password length in bytes (bcrypt limit is 72 bytes)
  const passwordBytes = new TextEncoder().encode(password);
  if (passwordBytes.length < 8 || passwordBytes.length > 72) {
    return jsonResponse({ error: 'Password must be 8-72 bytes' }, 400);
  }

  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);

  const passwordHash = await hashPassword(password, salt);

  // Rely on DB UNIQUE constraint for email uniqueness (race-safe)
  try {
    const user = await createUser(env.DB, email, passwordHash);

    // Send verification email
    const token = crypto.randomUUID();
    await env.SESSIONS_KV.put(`verify:${token}`, user.id, { expirationTtl: 86400 });
    await sendVerificationEmail(env, email, token);

    return jsonResponse({ id: user.id, email: user.email, created_at: user.created_at, email_verified: false }, 201);
  } catch (err) {
    if (err.message && err.message.includes('UNIQUE')) {
      return jsonResponse({ error: 'Email already registered' }, 409);
    }
    throw err;
  }
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
