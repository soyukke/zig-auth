export async function createUser(db, email, passwordHash) {
  const result = await db.prepare(
    'INSERT INTO users (email, password_hash) VALUES (?, ?) RETURNING id, email, created_at'
  ).bind(email, passwordHash).first();
  return result;
}

export async function getUserByEmail(db, email) {
  return await db.prepare(
    'SELECT id, email, password_hash, created_at, updated_at FROM users WHERE email = ?'
  ).bind(email).first();
}

export async function getUserById(db, id) {
  return await db.prepare(
    'SELECT id, email, created_at, updated_at FROM users WHERE id = ?'
  ).bind(id).first();
}

