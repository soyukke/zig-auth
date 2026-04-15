import { getWebAuthnConfig } from '../webauthn-config.mjs';
import {
  createPasskey, getPasskeysByUserId, getPasskeyByCredentialId,
  updatePasskeyCounter, deletePasskey, countUserPasskeys,
} from '../db-passkey.mjs';
import { createUser, getUserByEmail } from '../db.mjs';
import { createJwt, verifyRegistration, verifyAuthentication } from '../wasm-bridge.mjs';
import { storeRefreshToken } from '../kv.mjs';

function uint8ToBase64url(uint8) {
  const binStr = String.fromCharCode(...uint8);
  return btoa(binStr).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

// ── Option generation (inline, no library dependency) ──

function generateRegistrationOptions({ rpName, rpID, userName, attestationType, excludeCredentials, authenticatorSelection }) {
  const challengeBytes = new Uint8Array(32);
  crypto.getRandomValues(challengeBytes);
  const challenge = uint8ToBase64url(challengeBytes);

  const userIdBytes = new Uint8Array(32);
  crypto.getRandomValues(userIdBytes);

  return {
    challenge,
    rp: { name: rpName, id: rpID },
    user: { id: uint8ToBase64url(userIdBytes), name: userName, displayName: userName },
    pubKeyCredParams: [
      { alg: -7, type: 'public-key' },  // ES256
    ],
    timeout: 60000,
    attestation: attestationType || 'none',
    excludeCredentials: (excludeCredentials || []).map(c => ({
      id: c.id,
      type: 'public-key',
      transports: c.transports,
    })),
    authenticatorSelection: authenticatorSelection || {
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
  };
}

function generateAuthenticationOptions({ rpID, userVerification }) {
  const challengeBytes = new Uint8Array(32);
  crypto.getRandomValues(challengeBytes);
  const challenge = uint8ToBase64url(challengeBytes);

  return {
    challenge,
    rpId: rpID,
    timeout: 60000,
    userVerification: userVerification || 'preferred',
    allowCredentials: [],
  };
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

  const options = generateRegistrationOptions({
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

  const { username } = JSON.parse(stored);
  const { rpID, origin } = getWebAuthnConfig(env);

  let result;
  try {
    result = await verifyRegistration(
      regResponse.response.clientDataJSON,
      regResponse.response.attestationObject,
      challenge,
      origin,
      rpID,
    );
  } catch (err) {
    return jsonResponse({ error: 'Verification failed: ' + err.message }, 400);
  }

  if (!result.verified) {
    return jsonResponse({ error: 'Registration verification failed' }, 400);
  }

  // Create user and passkey in a batch
  const userId = crypto.randomUUID().replace(/-/g, '').substring(0, 32);
  const passkeyId = crypto.randomUUID().replace(/-/g, '').substring(0, 32);
  const transportsJson = regResponse.response?.transports ? JSON.stringify(regResponse.response.transports) : null;

  const [userResult] = await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO users (id, email, password_hash) VALUES (?, ?, '') RETURNING id, email, created_at"
    ).bind(userId, username),
    env.DB.prepare(
      `INSERT INTO passkeys (id, user_id, credential_id, public_key, counter, transports, device_type, backed_up, name)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Default Passkey')`
    ).bind(passkeyId, userId, result.credentialId, result.publicKey, result.counter, transportsJson, result.deviceType, result.backedUp ? 1 : 0),
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

  const options = generateRegistrationOptions({
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

  let result;
  try {
    result = await verifyRegistration(
      regResponse.response.clientDataJSON,
      regResponse.response.attestationObject,
      expectedChallenge,
      origin,
      rpID,
    );
  } catch (err) {
    return jsonResponse({ error: 'Verification failed: ' + err.message }, 400);
  }

  if (!result.verified) {
    return jsonResponse({ error: 'Registration verification failed' }, 400);
  }

  const passkey = await createPasskey(env.DB, {
    userId,
    credentialId: result.credentialId,
    publicKey: result.publicKey,
    counter: result.counter,
    transports: regResponse.response?.transports,
    deviceType: result.deviceType,
    backedUp: result.backedUp,
    name: name || `Passkey ${new Date().toLocaleDateString()}`,
  });

  return jsonResponse({ passkey }, 201);
}

// ── Authentication ──

// POST /api/auth/passkeys/authenticate/options
export async function handleAuthenticateOptions(request, env) {
  const { rpID } = getWebAuthnConfig(env);

  const options = generateAuthenticationOptions({
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

  let result;
  try {
    result = await verifyAuthentication(
      authResponse.response.clientDataJSON,
      authResponse.response.authenticatorData,
      authResponse.response.signature,
      passkey.public_key,  // already base64url from DB
      passkey.counter,
      challenge,
      origin,
      rpID,
    );
  } catch (err) {
    return jsonResponse({ error: 'Authentication failed: ' + err.message }, 401);
  }

  if (!result.verified) {
    return jsonResponse({ error: 'Authentication verification failed' }, 401);
  }

  // Update counter
  await updatePasskeyCounter(env.DB, credentialId, result.newCounter);

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
