export async function createTenant(db, name, slug, ownerUserId) {
  const tenant = await db.prepare(
    'INSERT INTO tenants (name, slug) VALUES (?, ?) RETURNING id, name, slug, created_at'
  ).bind(name, slug).first();

  await db.prepare(
    'INSERT INTO tenant_members (tenant_id, user_id, role) VALUES (?, ?, ?)'
  ).bind(tenant.id, ownerUserId, 'owner').run();

  return tenant;
}

export async function getTenantById(db, id) {
  return await db.prepare(
    'SELECT id, name, slug, created_at, updated_at FROM tenants WHERE id = ?'
  ).bind(id).first();
}

export async function getTenantBySlug(db, slug) {
  return await db.prepare(
    'SELECT id, name, slug, created_at, updated_at FROM tenants WHERE slug = ?'
  ).bind(slug).first();
}

export async function listUserTenants(db, userId) {
  return await db.prepare(
    `SELECT t.id, t.name, t.slug, t.created_at, tm.role
     FROM tenants t
     JOIN tenant_members tm ON t.id = tm.tenant_id
     WHERE tm.user_id = ?
     ORDER BY t.created_at DESC`
  ).bind(userId).all().then(r => r.results);
}

export async function listTenantMembers(db, tenantId) {
  return await db.prepare(
    `SELECT u.id, u.email, u.created_at, tm.role
     FROM users u
     JOIN tenant_members tm ON u.id = tm.user_id
     WHERE tm.tenant_id = ?
     ORDER BY tm.created_at ASC`
  ).bind(tenantId).all().then(r => r.results);
}

export async function getMembership(db, tenantId, userId) {
  return await db.prepare(
    'SELECT tenant_id, user_id, role, created_at FROM tenant_members WHERE tenant_id = ? AND user_id = ?'
  ).bind(tenantId, userId).first();
}

export async function addMember(db, tenantId, userId, role = 'member') {
  await db.prepare(
    'INSERT INTO tenant_members (tenant_id, user_id, role) VALUES (?, ?, ?)'
  ).bind(tenantId, userId, role).run();
}

export async function updateMemberRole(db, tenantId, userId, role) {
  await db.prepare(
    'UPDATE tenant_members SET role = ? WHERE tenant_id = ? AND user_id = ?'
  ).bind(role, tenantId, userId).run();
}

export async function removeMember(db, tenantId, userId) {
  await db.prepare(
    'DELETE FROM tenant_members WHERE tenant_id = ? AND user_id = ?'
  ).bind(tenantId, userId).run();
}

export async function deleteTenant(db, tenantId) {
  await db.prepare('DELETE FROM tenants WHERE id = ?').bind(tenantId).run();
}
