const counters = new Map();

const WINDOW_MS = 60_000; // 1 minute

export function rateLimit(maxRequests) {
  return async (request) => {
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const now = Date.now();
    const key = ip;

    let entry = counters.get(key);
    if (!entry || now - entry.start > WINDOW_MS) {
      entry = { start: now, count: 0 };
      counters.set(key, entry);
    }

    entry.count++;
    if (entry.count > maxRequests) {
      return new Response(JSON.stringify({ error: 'Too many requests' }), {
        status: 429,
        headers: { 'Content-Type': 'application/json', 'Retry-After': '60' },
      });
    }

    return null; // Continue
  };
}
