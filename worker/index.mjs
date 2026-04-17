import { handleRequest } from './bridge.mjs';
import { createRouter } from './router.mjs';
import { withCors, corsHeaders } from './middleware/cors.mjs';
import { authMiddleware } from './middleware/auth.mjs';
import { rateLimit } from './middleware/rate-limit.mjs';
import { handleRefresh } from './handlers/refresh.mjs';
import { handleLogout } from './handlers/logout.mjs';
import { handleMe } from './handlers/me.mjs';
import {
  handleCreateTenant, handleListTenants, handleGetTenant,
  handleAddMember, handleUpdateMember, handleRemoveMember, handleDeleteTenant,
} from './handlers/tenants.mjs';
import { handleOAuthRedirect, handleOAuthCallback } from './handlers/oauth.mjs';
import {
  handleRegisterOptions, handleRegister,
  handleAddOptions, handleAdd,
  handleAuthenticateOptions, handleAuthenticate,
  handleListPasskeys, handleDeletePasskey,
} from './handlers/passkeys.mjs';
import { handleCreateApiKey, handleListApiKeys, handleRevokeApiKey } from './handlers/api-keys.mjs';

const router = createRouter();

// Passkey registration (new user)
router.post('/api/auth/passkeys/register/options', rateLimit(5), handleRegisterOptions);
router.post('/api/auth/passkeys/register', rateLimit(5), handleRegister);

// Passkey add (existing user)
router.post('/api/auth/passkeys/add/options', authMiddleware, handleAddOptions);
router.post('/api/auth/passkeys/add', authMiddleware, handleAdd);

// Passkey authentication
router.post('/api/auth/passkeys/authenticate/options', rateLimit(10), handleAuthenticateOptions);
router.post('/api/auth/passkeys/authenticate', rateLimit(5), handleAuthenticate);

// Passkey management
router.get('/api/auth/passkeys', authMiddleware, handleListPasskeys);
router.delete('/api/auth/passkeys/:id', authMiddleware, handleDeletePasskey);

// OAuth
router.get('/api/auth/oauth/:provider', handleOAuthRedirect);
router.get('/api/auth/oauth/:provider/callback', handleOAuthCallback);

// Session
router.post('/api/auth/refresh', rateLimit(10), handleRefresh);
router.post('/api/auth/logout', authMiddleware, handleLogout);
router.get('/api/auth/me', authMiddleware, handleMe);

// API keys
router.get('/api/api-keys', authMiddleware, handleListApiKeys);
router.post('/api/api-keys', authMiddleware, handleCreateApiKey);
router.delete('/api/api-keys/:id', authMiddleware, handleRevokeApiKey);

// Tenants
router.post('/api/tenants', authMiddleware, handleCreateTenant);
router.get('/api/tenants', authMiddleware, handleListTenants);
router.get('/api/tenants/:id', authMiddleware, handleGetTenant);
router.post('/api/tenants/:id/members', authMiddleware, handleAddMember);
router.put('/api/tenants/:id/members/:userId', authMiddleware, handleUpdateMember);
router.delete('/api/tenants/:id/members/:userId', authMiddleware, handleRemoveMember);
router.delete('/api/tenants/:id', authMiddleware, handleDeleteTenant);

export default {
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(env) });
    }

    try {
      // Try Zig WASM router first
      const zigResponse = await handleRequest(request.clone(), env);
      if (zigResponse) {
        return withCors(zigResponse, env);
      }

      // Fall back to JS router for routes not yet migrated
      const response = await router.handle(request, env, ctx);
      return withCors(response, env);
    } catch (err) {
      console.error('Unhandled error:', err);
      return withCors(
        new Response(JSON.stringify({ error: 'Internal server error' }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        }),
        env,
      );
    }
  },
};
