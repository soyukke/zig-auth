export async function createPasskey(db, { userId, credentialId, publicKey, counter, transports, deviceType, backedUp, name }) {
  return await db.prepare(
    `INSERT INTO passkeys (user_id, credential_id, public_key, counter, transports, device_type, backed_up, name)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)
     RETURNING id, credential_id, name, device_type, backed_up, created_at`
  ).bind(
    userId, credentialId, publicKey, counter,
    transports ? JSON.stringify(transports) : null,
    deviceType || null, backedUp ? 1 : 0, name || null
  ).first();
}

export async function getPasskeysByUserId(db, userId) {
  const result = await db.prepare(
    'SELECT id, credential_id, public_key, counter, transports, device_type, backed_up, name, created_at, last_used_at FROM passkeys WHERE user_id = ?'
  ).bind(userId).all();
  return result.results;
}

export async function getPasskeyByCredentialId(db, credentialId) {
  return await db.prepare(
    `SELECT p.*, u.email as user_email FROM passkeys p
     JOIN users u ON p.user_id = u.id
     WHERE p.credential_id = ?`
  ).bind(credentialId).first();
}

export async function updatePasskeyCounter(db, credentialId, newCounter) {
  await db.prepare(
    "UPDATE passkeys SET counter = ?, last_used_at = datetime('now') WHERE credential_id = ?"
  ).bind(newCounter, credentialId).run();
}

export async function deletePasskey(db, id, userId) {
  const result = await db.prepare(
    'DELETE FROM passkeys WHERE id = ? AND user_id = ? RETURNING id'
  ).bind(id, userId).first();
  return result !== null;
}

export async function countUserPasskeys(db, userId) {
  const result = await db.prepare(
    'SELECT COUNT(*) as count FROM passkeys WHERE user_id = ?'
  ).bind(userId).first();
  return result.count;
}
