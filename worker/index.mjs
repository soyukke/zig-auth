import { createRouter } from './router.mjs';
import { withCors, corsHeaders } from './middleware/cors.mjs';
import { authMiddleware } from './middleware/auth.mjs';
import { rateLimit } from './middleware/rate-limit.mjs';
import { handleSignup } from './handlers/signup.mjs';
import { handleLogin } from './handlers/login.mjs';
import { handleRefresh } from './handlers/refresh.mjs';
import { handleLogout } from './handlers/logout.mjs';
import { handleMe } from './handlers/me.mjs';
import { handleChangePassword } from './handlers/password.mjs';
import {
  handleCreateTenant, handleListTenants, handleGetTenant,
  handleAddMember, handleUpdateMember, handleRemoveMember, handleDeleteTenant,
} from './handlers/tenants.mjs';
import { handleOAuthRedirect, handleOAuthCallback } from './handlers/oauth.mjs';
import { handleSendVerification, handleVerifyEmail } from './handlers/verify.mjs';
import { handleForgotPassword, handleResetPassword } from './handlers/reset-password.mjs';

const router = createRouter();

// Public endpoints
router.post('/api/auth/signup', rateLimit(3), handleSignup);
router.post('/api/auth/login', rateLimit(5), handleLogin);
router.post('/api/auth/refresh', rateLimit(10), handleRefresh);

// OAuth endpoints (public)
router.get('/api/auth/oauth/:provider', handleOAuthRedirect);
router.get('/api/auth/oauth/:provider/callback', handleOAuthCallback);

// Email verification (verify endpoint is public, send requires auth)
router.get('/api/auth/verify', handleVerifyEmail);
router.post('/api/auth/send-verification', authMiddleware, handleSendVerification);

// Password reset (public)
router.post('/api/auth/forgot-password', rateLimit(3), handleForgotPassword);
router.post('/api/auth/reset-password', rateLimit(5), handleResetPassword);

// Protected endpoints
router.post('/api/auth/logout', authMiddleware, handleLogout);
router.get('/api/auth/me', authMiddleware, handleMe);
router.put('/api/auth/password', authMiddleware, handleChangePassword);

// Tenant endpoints (all protected)
router.post('/api/tenants', authMiddleware, handleCreateTenant);
router.get('/api/tenants', authMiddleware, handleListTenants);
router.get('/api/tenants/:id', authMiddleware, handleGetTenant);
router.post('/api/tenants/:id/members', authMiddleware, handleAddMember);
router.put('/api/tenants/:id/members/:userId', authMiddleware, handleUpdateMember);
router.delete('/api/tenants/:id/members/:userId', authMiddleware, handleRemoveMember);
router.delete('/api/tenants/:id', authMiddleware, handleDeleteTenant);

export default {
  async fetch(request, env, ctx) {
    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(env) });
    }

    try {
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
