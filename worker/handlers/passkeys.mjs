import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { getWebAuthnConfig } from '../webauthn-config.mjs';
import {
  createPasskey, getPasskeysByUserId, getPasskeyByCredentialId,
  updatePasskeyCounter, deletePasskey, countUserPasskeys,
} from '../db-passkey.mjs';
import { createUser, getUserByEmail } from '../db.mjs';
import { createJwt } from '../wasm-bridge.mjs';
import { storeRefreshToken } from '../kv.mjs';

function uint8ToBase64url(uint8) {
  const binStr = String.fromCharCode(...uint8);
  return btoa(binStr).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlToUint8(str) {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = (4 - base64.length % 4) % 4;
  const binStr = atob(base64 + '='.repeat(pad));
  return Uint8Array.from(binStr, c => c.charCodeAt(0));
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

// ── Registration (new user) ──

// POST /api/auth/passkeys/register/options
export async function handleRegisterOptions(request, env) {
  const body = await request.json();
  const { username } = body;
  if (!username || username.length < 1 || username.length > 64) {
    return jsonResponse({ error: 'Username is required (1-64 characters)' }, 400);
  }

  // Check if username (email-like or plain) already exists
  const existing = await getUserByEmail(env.DB, username);
  if (existing) {
    return jsonResponse({ error: 'Username already taken' }, 409);
  }

  const { rpID, rpName } = getWebAuthnConfig(env);

  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userName: username,
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
  });

  // Store challenge + username in KV
  await env.SESSIONS_KV.put(
    `webauthn-reg:${options.challenge}`,
    JSON.stringify({ username, isNewUser: true }),
    { expirationTtl: 300 }
  );

  return jsonResponse(options);
}

// POST /api/auth/passkeys/register
export async function handleRegister(request, env) {
  const body = await request.json();
  const { response: regResponse, challenge } = body;
  if (!regResponse || !challenge) {
    return jsonResponse({ error: 'Missing response or challenge' }, 400);
  }

  // Retrieve stored challenge
  const stored = await env.SESSIONS_KV.get(`webauthn-reg:${challenge}`);
  if (!stored) {
    return jsonResponse({ error: 'Challenge expired or invalid' }, 400);
  }
  await env.SESSIONS_KV.delete(`webauthn-reg:${challenge}`);

  const { username, isNewUser } = JSON.parse(stored);
  const { rpID, origin } = getWebAuthnConfig(env);

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: regResponse,
      expectedChallenge: challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });
  } catch (err) {
    return jsonResponse({ error: 'Verification failed: ' + err.message }, 400);
  }

  if (!verification.verified || !verification.registrationInfo) {
    return jsonResponse({ error: 'Registration verification failed' }, 400);
  }

  const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;

  // Create user and passkey in a batch
  const userId = crypto.randomUUID().replace(/-/g, '').substring(0, 32);
  const passkeyId = crypto.randomUUID().replace(/-/g, '').substring(0, 32);
  const publicKeyB64 = uint8ToBase64url(new Uint8Array(credential.publicKey));
  const transportsJson = regResponse.response?.transports ? JSON.stringify(regResponse.response.transports) : null;

  const [userResult] = await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO users (id, email, password_hash) VALUES (?, ?, '') RETURNING id, email, created_at"
    ).bind(userId, username),
    env.DB.prepare(
      `INSERT INTO passkeys (id, user_id, credential_id, public_key, counter, transports, device_type, backed_up, name)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Default Passkey')`
    ).bind(passkeyId, userId, credential.id, publicKeyB64, credential.counter, transportsJson, credentialDeviceType, credentialBackedUp ? 1 : 0),
  ]);
  const user = userResult.results[0];

  // Issue tokens
  const now = Math.floor(Date.now() / 1000);
  const jti = crypto.randomUUID();
  const claims = JSON.stringify({
    sub: user.id,
    email: username,
    jti,
    iat: now,
    exp: now + 900,
  });

  const accessToken = await createJwt(claims, env.JWT_SECRET);
  const refreshTokenId = crypto.randomUUID();
  await storeRefreshToken(env.SESSIONS_KV, refreshTokenId, user.id);

  return jsonResponse({
    access_token: accessToken,
    refresh_token: refreshTokenId,
    token_type: 'Bearer',
    expires_in: 900,
    user: { id: user.id, email: username },
  }, 201);
}

// ── Add passkey to existing account ──

// POST /api/auth/passkeys/add/options
export async function handleAddOptions(request, env) {
  const userId = request.claims.sub;
  const existingPasskeys = await getPasskeysByUserId(env.DB, userId);
  const { rpID, rpName } = getWebAuthnConfig(env);

  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userName: request.claims.email,
    attestationType: 'none',
    excludeCredentials: existingPasskeys.map(pk => ({
      id: pk.credential_id,
      transports: pk.transports ? JSON.parse(pk.transports) : undefined,
    })),
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
  });

  await env.SESSIONS_KV.put(
    `webauthn-add:${userId}`,
    options.challenge,
    { expirationTtl: 300 }
  );

  return jsonResponse(options);
}

// POST /api/auth/passkeys/add
export async function handleAdd(request, env) {
  const userId = request.claims.sub;
  const body = await request.json();
  const { response: regResponse, name } = body;

  const expectedChallenge = await env.SESSIONS_KV.get(`webauthn-add:${userId}`);
  if (!expectedChallenge) {
    return jsonResponse({ error: 'Challenge expired or invalid' }, 400);
  }
  await env.SESSIONS_KV.delete(`webauthn-add:${userId}`);

  const { rpID, origin } = getWebAuthnConfig(env);

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: regResponse,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });
  } catch (err) {
    return jsonResponse({ error: 'Verification failed: ' + err.message }, 400);
  }

  if (!verification.verified || !verification.registrationInfo) {
    return jsonResponse({ error: 'Registration verification failed' }, 400);
  }

  const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;

  const passkey = await createPasskey(env.DB, {
    userId,
    credentialId: credential.id,
    publicKey: uint8ToBase64url(new Uint8Array(credential.publicKey)),
    counter: credential.counter,
    transports: regResponse.response?.transports,
    deviceType: credentialDeviceType,
    backedUp: credentialBackedUp,
    name: name || `Passkey ${new Date().toLocaleDateString()}`,
  });

  return jsonResponse({ passkey }, 201);
}

// ── Authentication ──

// POST /api/auth/passkeys/authenticate/options
export async function handleAuthenticateOptions(request, env) {
  const { rpID } = getWebAuthnConfig(env);

  const options = await generateAuthenticationOptions({
    rpID,
    userVerification: 'preferred',
  });

  await env.SESSIONS_KV.put(
    `webauthn-auth:${options.challenge}`,
    '1',
    { expirationTtl: 300 }
  );

  return jsonResponse(options);
}

// POST /api/auth/passkeys/authenticate
export async function handleAuthenticate(request, env) {
  const body = await request.json();
  const { response: authResponse, challenge } = body;
  if (!authResponse || !challenge) {
    return jsonResponse({ error: 'Missing response or challenge' }, 400);
  }

  // Verify challenge exists
  const stored = await env.SESSIONS_KV.get(`webauthn-auth:${challenge}`);
  if (!stored) {
    return jsonResponse({ error: 'Challenge expired or invalid' }, 400);
  }
  await env.SESSIONS_KV.delete(`webauthn-auth:${challenge}`);

  // Look up credential
  const credentialId = authResponse.id;
  const passkey = await getPasskeyByCredentialId(env.DB, credentialId);
  if (!passkey) {
    return jsonResponse({ error: 'Passkey not found' }, 401);
  }

  const { rpID, origin } = getWebAuthnConfig(env);

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: authResponse,
      expectedChallenge: challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        id: passkey.credential_id,
        publicKey: base64urlToUint8(passkey.public_key),
        counter: passkey.counter,
        transports: passkey.transports ? JSON.parse(passkey.transports) : undefined,
      },
    });
  } catch (err) {
    return jsonResponse({ error: 'Authentication failed: ' + err.message }, 401);
  }

  if (!verification.verified) {
    return jsonResponse({ error: 'Authentication verification failed' }, 401);
  }

  // Update counter
  await updatePasskeyCounter(env.DB, credentialId, verification.authenticationInfo.newCounter);

  // Issue tokens
  const now = Math.floor(Date.now() / 1000);
  const jti = crypto.randomUUID();
  const claims = JSON.stringify({
    sub: passkey.user_id,
    email: passkey.user_email,
    jti,
    iat: now,
    exp: now + 900,
  });

  const accessToken = await createJwt(claims, env.JWT_SECRET);
  const refreshTokenId = crypto.randomUUID();
  await storeRefreshToken(env.SESSIONS_KV, refreshTokenId, passkey.user_id);

  return jsonResponse({
    access_token: accessToken,
    refresh_token: refreshTokenId,
    token_type: 'Bearer',
    expires_in: 900,
  });
}

// ── Management ──

// GET /api/auth/passkeys
export async function handleListPasskeys(request, env) {
  const userId = request.claims.sub;
  const passkeys = await getPasskeysByUserId(env.DB, userId);

  return jsonResponse({
    passkeys: passkeys.map(pk => ({
      id: pk.id,
      name: pk.name,
      device_type: pk.device_type,
      backed_up: !!pk.backed_up,
      created_at: pk.created_at,
      last_used_at: pk.last_used_at,
    })),
  });
}

// DELETE /api/auth/passkeys/:id
export async function handleDeletePasskey(request, env) {
  const userId = request.claims.sub;
  const passkeyId = request.params?.id;

  const count = await countUserPasskeys(env.DB, userId);
  if (count <= 1) {
    return jsonResponse({ error: 'Cannot delete your only passkey' }, 400);
  }

  const deleted = await deletePasskey(env.DB, passkeyId, userId);
  if (!deleted) {
    return jsonResponse({ error: 'Passkey not found' }, 404);
  }

  return jsonResponse({ message: 'Passkey deleted' });
}
