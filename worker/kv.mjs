const REFRESH_PREFIX = 'rt:';
const BLOCKLIST_PREFIX = 'bl:';

export async function storeRefreshToken(kv, tokenId, userId, ttlSeconds = 604800) {
  await kv.put(`${REFRESH_PREFIX}${tokenId}`, userId, { expirationTtl: ttlSeconds });
}

export async function getRefreshToken(kv, tokenId) {
  return await kv.get(`${REFRESH_PREFIX}${tokenId}`);
}

export async function revokeRefreshToken(kv, tokenId) {
  await kv.delete(`${REFRESH_PREFIX}${tokenId}`);
}

export async function addToBlocklist(kv, jti, ttlSeconds) {
  await kv.put(`${BLOCKLIST_PREFIX}${jti}`, '1', { expirationTtl: ttlSeconds });
}

export async function isBlocklisted(kv, jti) {
  const val = await kv.get(`${BLOCKLIST_PREFIX}${jti}`);
  return val !== null;
}
