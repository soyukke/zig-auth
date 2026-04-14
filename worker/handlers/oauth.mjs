import { providers, getCallbackUrl } from '../oauth-providers.mjs';
import { findOAuthAccount, createOAuthUser, linkOAuthAccount } from '../db-oauth.mjs';
import { getUserByEmail } from '../db.mjs';
import { createJwt } from '../wasm-bridge.mjs';
import { storeRefreshToken } from '../kv.mjs';

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

// GET /api/auth/oauth/:provider — Redirect to OAuth provider
export async function handleOAuthRedirect(request, env) {
  const provider = request.params?.provider;
  const config = providers[provider];
  if (!config) return jsonResponse({ error: 'Unknown provider' }, 400);

  const clientId = config.getClientId(env);
  if (!clientId) return jsonResponse({ error: `${provider} not configured` }, 500);

  // Generate state for CSRF protection
  const state = crypto.randomUUID();
  await env.SESSIONS_KV.put(`oauth-state:${state}`, provider, { expirationTtl: 600 });

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: getCallbackUrl(env, provider),
    scope: config.scopes,
    state,
    response_type: 'code',
  });

  return Response.redirect(`${config.authorizeUrl}?${params}`, 302);
}

// GET /api/auth/oauth/:provider/callback — Handle OAuth callback
export async function handleOAuthCallback(request, env) {
  const provider = request.params?.provider;
  const config = providers[provider];
  if (!config) return jsonResponse({ error: 'Unknown provider' }, 400);

  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const error = url.searchParams.get('error');

  if (error) return redirectToFrontend(env, `error=${error}`);
  if (!code || !state) return redirectToFrontend(env, 'error=missing_params');

  // Verify state
  const storedProvider = await env.SESSIONS_KV.get(`oauth-state:${state}`);
  if (storedProvider !== provider) return redirectToFrontend(env, 'error=invalid_state');
  await env.SESSIONS_KV.delete(`oauth-state:${state}`);

  // Exchange code for token
  const tokenRes = await fetch(config.tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: new URLSearchParams({
      client_id: config.getClientId(env),
      client_secret: config.getClientSecret(env),
      code,
      redirect_uri: getCallbackUrl(env, provider),
      grant_type: 'authorization_code',
    }),
  });

  const tokenData = await tokenRes.json();
  if (!tokenData.access_token) return redirectToFrontend(env, 'error=token_exchange_failed');

  // Fetch user info
  const userRes = await fetch(config.userInfoUrl, {
    headers: { Authorization: `Bearer ${tokenData.access_token}` },
  });
  const userData = await userRes.json();
  const oauthUser = config.parseUser(userData);

  if (!oauthUser.email) {
    // GitHub might not return email; fetch from emails endpoint
    if (provider === 'github') {
      const emailsRes = await fetch('https://api.github.com/user/emails', {
        headers: { Authorization: `Bearer ${tokenData.access_token}` },
      });
      const emails = await emailsRes.json();
      const primary = emails.find(e => e.primary && e.verified);
      if (primary) oauthUser.email = primary.email;
    }
    if (!oauthUser.email) return redirectToFrontend(env, 'error=no_email');
  }

  // Find or create user
  let userId;
  const existingOAuth = await findOAuthAccount(env.DB, provider, oauthUser.id);

  if (existingOAuth) {
    userId = existingOAuth.user_id;
  } else {
    const existingUser = await getUserByEmail(env.DB, oauthUser.email);
    if (existingUser) {
      // Link OAuth to existing account
      userId = existingUser.id;
      await linkOAuthAccount(env.DB, userId, provider, oauthUser.id, oauthUser.email);
    } else {
      // Create new user
      const newUser = await createOAuthUser(env.DB, oauthUser.email, provider, oauthUser.id);
      userId = newUser.id;
    }
  }

  // Issue tokens
  const now = Math.floor(Date.now() / 1000);
  const jti = crypto.randomUUID();
  const claims = JSON.stringify({
    sub: userId,
    email: oauthUser.email,
    jti,
    iat: now,
    exp: now + 900,
  });

  const accessToken = await createJwt(claims, env.JWT_SECRET);
  const refreshTokenId = crypto.randomUUID();
  await storeRefreshToken(env.SESSIONS_KV, refreshTokenId, userId);

  // Redirect to frontend with tokens
  return redirectToFrontend(env, `access_token=${accessToken}&refresh_token=${refreshTokenId}`);
}

function redirectToFrontend(env, params) {
  const frontendUrl = env.FRONTEND_URL || 'http://localhost:5173';
  return Response.redirect(`${frontendUrl}/oauth/callback?${params}`, 302);
}
