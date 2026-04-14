import {
  createTenant, getTenantById, listUserTenants, listTenantMembers,
  getMembership, addMember, updateMemberRole, removeMember, deleteTenant,
} from '../db-tenant.mjs';
import { getUserByEmail } from '../db.mjs';

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

// POST /api/tenants — Create tenant
export async function handleCreateTenant(request, env) {
  let body;
  try { body = await request.json(); } catch { return jsonResponse({ error: 'Invalid JSON' }, 400); }

  const { name, slug } = body;
  if (!name || !slug) return jsonResponse({ error: 'name and slug are required' }, 400);
  if (!/^[a-z0-9-]+$/.test(slug)) return jsonResponse({ error: 'slug must be lowercase alphanumeric with hyphens' }, 400);

  try {
    const tenant = await createTenant(env.DB, name, slug, request.claims.sub);
    return jsonResponse(tenant, 201);
  } catch (err) {
    if (err.message?.includes('UNIQUE')) return jsonResponse({ error: 'Slug already taken' }, 409);
    throw err;
  }
}

// GET /api/tenants — List user's tenants
export async function handleListTenants(request, env) {
  const tenants = await listUserTenants(env.DB, request.claims.sub);
  return jsonResponse({ tenants });
}

// GET /api/tenants/:id — Get tenant details
export async function handleGetTenant(request, env) {
  const tenantId = request.params?.id;
  const membership = await getMembership(env.DB, tenantId, request.claims.sub);
  if (!membership) return jsonResponse({ error: 'Not a member of this tenant' }, 403);

  const tenant = await getTenantById(env.DB, tenantId);
  if (!tenant) return jsonResponse({ error: 'Tenant not found' }, 404);

  const members = await listTenantMembers(env.DB, tenantId);
  return jsonResponse({ ...tenant, members, your_role: membership.role });
}

// POST /api/tenants/:id/members — Add member (admin/owner only)
export async function handleAddMember(request, env) {
  const tenantId = request.params?.id;
  const membership = await getMembership(env.DB, tenantId, request.claims.sub);
  if (!membership || !['owner', 'admin'].includes(membership.role)) {
    return jsonResponse({ error: 'Insufficient permissions' }, 403);
  }

  let body;
  try { body = await request.json(); } catch { return jsonResponse({ error: 'Invalid JSON' }, 400); }

  const { email, role } = body;
  if (!email) return jsonResponse({ error: 'email is required' }, 400);

  const targetRole = role || 'member';
  if (!['admin', 'member'].includes(targetRole)) {
    return jsonResponse({ error: 'role must be admin or member' }, 400);
  }
  // Only owners can add admins
  if (targetRole === 'admin' && membership.role !== 'owner') {
    return jsonResponse({ error: 'Only owners can add admins' }, 403);
  }

  const user = await getUserByEmail(env.DB, email);
  if (!user) return jsonResponse({ error: 'User not found' }, 404);

  const existing = await getMembership(env.DB, tenantId, user.id);
  if (existing) return jsonResponse({ error: 'User is already a member' }, 409);

  await addMember(env.DB, tenantId, user.id, targetRole);
  return jsonResponse({ message: 'Member added', user_id: user.id, role: targetRole }, 201);
}

// PUT /api/tenants/:id/members/:userId — Update member role (owner only)
export async function handleUpdateMember(request, env) {
  const { id: tenantId, userId } = request.params;
  const membership = await getMembership(env.DB, tenantId, request.claims.sub);
  if (!membership || membership.role !== 'owner') {
    return jsonResponse({ error: 'Only owners can change roles' }, 403);
  }

  if (userId === request.claims.sub) {
    return jsonResponse({ error: 'Cannot change your own role' }, 400);
  }

  let body;
  try { body = await request.json(); } catch { return jsonResponse({ error: 'Invalid JSON' }, 400); }

  const { role } = body;
  if (!['owner', 'admin', 'member'].includes(role)) {
    return jsonResponse({ error: 'Invalid role' }, 400);
  }

  const target = await getMembership(env.DB, tenantId, userId);
  if (!target) return jsonResponse({ error: 'User is not a member' }, 404);

  await updateMemberRole(env.DB, tenantId, userId, role);
  return jsonResponse({ message: 'Role updated', role });
}

// DELETE /api/tenants/:id/members/:userId — Remove member (admin/owner)
export async function handleRemoveMember(request, env) {
  const { id: tenantId, userId } = request.params;
  const membership = await getMembership(env.DB, tenantId, request.claims.sub);
  if (!membership || !['owner', 'admin'].includes(membership.role)) {
    return jsonResponse({ error: 'Insufficient permissions' }, 403);
  }

  const target = await getMembership(env.DB, tenantId, userId);
  if (!target) return jsonResponse({ error: 'User is not a member' }, 404);
  if (target.role === 'owner') return jsonResponse({ error: 'Cannot remove owner' }, 400);
  if (target.role === 'admin' && membership.role !== 'owner') {
    return jsonResponse({ error: 'Only owners can remove admins' }, 403);
  }

  await removeMember(env.DB, tenantId, userId);
  return jsonResponse({ message: 'Member removed' });
}

// DELETE /api/tenants/:id — Delete tenant (owner only)
export async function handleDeleteTenant(request, env) {
  const tenantId = request.params?.id;
  const membership = await getMembership(env.DB, tenantId, request.claims.sub);
  if (!membership || membership.role !== 'owner') {
    return jsonResponse({ error: 'Only owners can delete tenants' }, 403);
  }

  await deleteTenant(env.DB, tenantId);
  return jsonResponse({ message: 'Tenant deleted' });
}
