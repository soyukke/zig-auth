export async function findOAuthAccount(db, provider, providerId) {
  return await db.prepare(
    'SELECT oa.*, u.email as user_email FROM oauth_accounts oa JOIN users u ON oa.user_id = u.id WHERE oa.provider = ? AND oa.provider_id = ?'
  ).bind(provider, providerId).first();
}

export async function linkOAuthAccount(db, userId, provider, providerId, email) {
  await db.prepare(
    'INSERT INTO oauth_accounts (user_id, provider, provider_id, email) VALUES (?, ?, ?, ?)'
  ).bind(userId, provider, providerId, email).run();
}

export async function createOAuthUser(db, email, provider, providerId) {
  // Create user with empty password_hash (OAuth-only)
  const user = await db.prepare(
    "INSERT INTO users (email, password_hash) VALUES (?, '') RETURNING id, email, created_at"
  ).bind(email).first();

  await linkOAuthAccount(db, user.id, provider, providerId, email);
  return user;
}

export async function listUserOAuthAccounts(db, userId) {
  return await db.prepare(
    'SELECT id, provider, provider_id, email, created_at FROM oauth_accounts WHERE user_id = ?'
  ).bind(userId).all().then(r => r.results);
}
