export function getWebAuthnConfig(env) {
  const frontendUrl = new URL(env.FRONTEND_URL || env.APP_URL);
  return {
    rpID: frontendUrl.hostname,
    rpName: 'Zig Auth',
    origin: frontendUrl.origin,
  };
}
