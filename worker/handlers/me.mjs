import { getUserById } from '../db.mjs';

export async function handleMe(request, env) {
  const { sub } = request.claims;

  const user = await getUserById(env.DB, sub);
  if (!user) {
    return jsonResponse({ error: 'User not found' }, 404);
  }

  return jsonResponse({
    id: user.id,
    email: user.email,
    created_at: user.created_at,
    updated_at: user.updated_at,
  });
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
