export const providers = {
  github: {
    authorizeUrl: 'https://github.com/login/oauth/authorize',
    tokenUrl: 'https://github.com/login/oauth/access_token',
    userInfoUrl: 'https://api.github.com/user',
    scopes: 'read:user user:email',
    getClientId: (env) => env.GITHUB_CLIENT_ID,
    getClientSecret: (env) => env.GITHUB_CLIENT_SECRET,
    parseUser: (data) => ({
      id: String(data.id),
      email: data.email,
      name: data.name || data.login,
    }),
  },
  google: {
    authorizeUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    userInfoUrl: 'https://www.googleapis.com/oauth2/v2/userinfo',
    scopes: 'openid email profile',
    getClientId: (env) => env.GOOGLE_CLIENT_ID,
    getClientSecret: (env) => env.GOOGLE_CLIENT_SECRET,
    parseUser: (data) => ({
      id: data.id,
      email: data.email,
      name: data.name,
    }),
  },
};

export function getCallbackUrl(env, provider) {
  const base = env.APP_URL || 'http://localhost:8787';
  return `${base}/api/auth/oauth/${provider}/callback`;
}
