export async function createApiKey(db, { userId, name, prefix, keyHash, scopes, expiresAt }) {
  return await db.prepare(
    `INSERT INTO api_keys (user_id, name, prefix, key_hash, scopes, expires_at)
     VALUES (?, ?, ?, ?, ?, ?)
     RETURNING id, name, prefix, scopes, created_at, expires_at`
  ).bind(userId, name, prefix, keyHash, JSON.stringify(scopes || ['*']), expiresAt || null).first();
}

export async function listApiKeys(db, userId) {
  const result = await db.prepare(
    `SELECT id, name, prefix, scopes, created_at, last_used_at, expires_at
     FROM api_keys WHERE user_id = ? AND revoked_at IS NULL
     ORDER BY created_at DESC`
  ).bind(userId).all();
  return result.results;
}

export async function getApiKeyByPrefix(db, prefix) {
  return await db.prepare(
    'SELECT id, user_id, key_hash, scopes, expires_at, revoked_at FROM api_keys WHERE prefix = ?'
  ).bind(prefix).first();
}

export async function revokeApiKey(db, id, userId) {
  const result = await db.prepare(
    "UPDATE api_keys SET revoked_at = datetime('now') WHERE id = ? AND user_id = ? AND revoked_at IS NULL RETURNING id"
  ).bind(id, userId).first();
  return result !== null;
}

export async function updateApiKeyLastUsed(db, id) {
  await db.prepare(
    "UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?"
  ).bind(id).run();
}
