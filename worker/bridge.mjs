import wasmModule from './zig-auth.wasm';

let instance = null;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

async function getInstance() {
  if (instance) return instance;
  let memoryRef = null;
  const result = await WebAssembly.instantiate(wasmModule, {
    env: {
      js_get_random_bytes: (ptr, len) => {
        const buf = new Uint8Array(memoryRef.buffer, ptr, len);
        crypto.getRandomValues(buf);
      },
    },
  });
  memoryRef = result.exports.memory;
  instance = result;
  return instance;
}

function writeString(exports, str) {
  const bytes = encoder.encode(str);
  const ptr = exports.alloc(bytes.length);
  if (!ptr) throw new Error('WASM alloc failed');
  new Uint8Array(exports.memory.buffer, ptr, bytes.length).set(bytes);
  return { ptr, len: bytes.length };
}

function readString(exports, ptr, len) {
  if (!ptr || !len) return null;
  const bytes = new Uint8Array(exports.memory.buffer, ptr, len);
  return decoder.decode(bytes);
}

function freeString(exports, ptr, len) {
  if (ptr && len > 0) exports.dealloc(ptr, len);
}

// Command tag constants (must match command.zig Tag enum)
const CMD_RESPONSE       = 0;
const CMD_D1_FIRST       = 1;
const CMD_D1_ALL         = 2;
const CMD_D1_RUN         = 3;
const CMD_D1_BATCH       = 4;
const CMD_KV_GET         = 5;
const CMD_KV_PUT         = 6;
const CMD_KV_DELETE      = 7;
const CMD_HTTP_FETCH     = 8;
const CMD_ENV_GET        = 9;
const CMD_ROUTE_NOT_FOUND = 254;

async function executeCommand(tag, payload, env) {
  switch (tag) {
    case CMD_D1_FIRST:
      return await env.DB.prepare(payload.sql).bind(...payload.params).first() ?? null;

    case CMD_D1_ALL:
      return (await env.DB.prepare(payload.sql).bind(...payload.params).all()).results;

    case CMD_D1_RUN: {
      const r = await env.DB.prepare(payload.sql).bind(...payload.params).run();
      return { changes: r.meta?.changes ?? 0, last_row_id: r.meta?.last_row_id ?? 0 };
    }

    case CMD_D1_BATCH: {
      const stmts = payload.map(q => env.DB.prepare(q.sql).bind(...q.params));
      const results = await env.DB.batch(stmts);
      return results.map(r => r.results ?? []);
    }

    case CMD_KV_GET:
      return await env.SESSIONS_KV.get(payload.key) ?? null;

    case CMD_KV_PUT:
      await env.SESSIONS_KV.put(
        payload.key,
        payload.value,
        payload.ttl ? { expirationTtl: payload.ttl } : undefined,
      );
      return {};

    case CMD_KV_DELETE:
      await env.SESSIONS_KV.delete(payload.key);
      return {};

    case CMD_HTTP_FETCH: {
      const resp = await fetch(payload.url, {
        method: payload.method || 'GET',
        headers: payload.headers || {},
        body: payload.body || undefined,
      });
      return {
        status: resp.status,
        body: await resp.text(),
        headers: Object.fromEntries(resp.headers),
      };
    }

    case CMD_ENV_GET:
      return env[payload.name] ?? null;

    default:
      throw new Error(`Unknown command tag: ${tag}`);
  }
}

/**
 * Handle an HTTP request via the Zig WASM command-response loop.
 * Returns a Response object, or null if the route was not matched by Zig.
 */
export async function handleRequest(request, env) {
  const { exports } = await getInstance();

  const url = new URL(request.url);
  const method = writeString(exports, request.method);
  const path = writeString(exports, url.pathname + url.search);
  const bodyText = request.method !== 'GET' && request.method !== 'HEAD'
    ? await request.text().catch(() => '')
    : '';
  const body = writeString(exports, bodyText);
  const headersObj = Object.fromEntries(request.headers);
  const headers = writeString(exports, JSON.stringify(headersObj));

  let tag;
  try {
    tag = exports.handle_request(
      method.ptr, method.len,
      path.ptr, path.len,
      body.ptr, body.len,
      headers.ptr, headers.len,
    );
  } finally {
    freeString(exports, method.ptr, method.len);
    freeString(exports, path.ptr, path.len);
    freeString(exports, body.ptr, body.len);
    freeString(exports, headers.ptr, headers.len);
  }

  // Route not matched by Zig — let JS router handle it
  if (tag === CMD_ROUTE_NOT_FOUND) {
    return null;
  }

  // Command-response loop
  while (tag !== CMD_RESPONSE) {
    const cmdJson = readString(exports, exports.get_cmd_ptr(), exports.get_cmd_len());
    const payload = JSON.parse(cmdJson);

    let result;
    let errorCode = 0;
    try {
      result = await executeCommand(tag, payload, env);
    } catch (e) {
      console.error(`Command ${tag} failed:`, e.message);
      errorCode = 1;
      result = e.message;
    }

    const resultStr = JSON.stringify(result);
    const resultMem = writeString(exports, resultStr);
    try {
      tag = exports.request_resume(resultMem.ptr, resultMem.len, errorCode);
    } finally {
      freeString(exports, resultMem.ptr, resultMem.len);
    }
  }

  // Read final response
  const respJson = readString(exports, exports.get_cmd_ptr(), exports.get_cmd_len());

  if (!respJson) {
    return new Response(JSON.stringify({ error: 'Empty response from WASM' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const resp = JSON.parse(respJson);

  return new Response(resp.body, {
    status: resp.status,
    headers: resp.headers || { 'Content-Type': 'application/json' },
  });
}
