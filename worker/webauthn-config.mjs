export function getWebAuthnConfig(env) {
  const appUrl = new URL(env.APP_URL);
  return {
    rpID: appUrl.hostname,
    rpName: 'Zig Auth',
    origin: appUrl.origin,
  };
}
