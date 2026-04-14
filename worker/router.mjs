export function createRouter() {
  const routes = [];

  function addRoute(method, path, ...handlers) {
    // Convert :param to named capture groups
    const paramNames = [];
    const pattern = path.replace(/:(\w+)/g, (_, name) => {
      paramNames.push(name);
      return '([^/]+)';
    });
    const regex = new RegExp(`^${pattern}$`);
    routes.push({ method, regex, paramNames, handlers });
  }

  async function handle(request, env, ctx) {
    const url = new URL(request.url);
    const method = request.method;
    const path = url.pathname;

    for (const route of routes) {
      if (route.method !== method) continue;
      const match = path.match(route.regex);
      if (!match) continue;

      // Extract params
      const params = {};
      route.paramNames.forEach((name, i) => {
        params[name] = match[i + 1];
      });
      request.params = params;

      let response = null;
      for (const handler of route.handlers) {
        response = await handler(request, env, ctx);
        if (response) return response;
      }
      return response || new Response('No response', { status: 500 });
    }

    if (method === 'OPTIONS') {
      return new Response(null, { status: 204 });
    }

    return new Response(JSON.stringify({ error: 'Not found' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  return {
    get: (p, ...h) => addRoute('GET', p, ...h),
    post: (p, ...h) => addRoute('POST', p, ...h),
    put: (p, ...h) => addRoute('PUT', p, ...h),
    delete: (p, ...h) => addRoute('DELETE', p, ...h),
    handle,
  };
}
