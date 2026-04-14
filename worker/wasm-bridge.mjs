import wasmModule from './zig-auth.wasm';

let instance = null;

async function getInstance() {
  if (instance) return instance;
  const result = await WebAssembly.instantiate(wasmModule);
  instance = result;
  return instance;
}

function writeString(exports, str) {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(str);
  const ptr = exports.alloc(bytes.length);
  if (!ptr) throw new Error('WASM alloc failed');
  new Uint8Array(exports.memory.buffer, ptr, bytes.length).set(bytes);
  return { ptr, len: bytes.length };
}

function readResult(exports) {
  const ptr = exports.get_result_ptr();
  const len = exports.get_result_len();
  if (!ptr || !len) return null;
  const bytes = new Uint8Array(exports.memory.buffer, ptr, len);
  const result = new TextDecoder().decode(bytes.slice());
  exports.dealloc(ptr, len);
  return result;
}

function freeString(exports, ptr, len) {
  if (ptr && len > 0) exports.dealloc(ptr, len);
}

export async function hashPassword(password, salt) {
  const { exports } = await getInstance();
  const pass = writeString(exports, password);
  const saltPtr = exports.alloc(16);
  if (!saltPtr) throw new Error('WASM alloc failed for salt');
  new Uint8Array(exports.memory.buffer, saltPtr, 16).set(salt);

  try {
    const status = exports.hash_password(pass.ptr, pass.len, saltPtr);
    if (status !== 0) throw new Error(`hash_password failed: status ${status}`);
    return readResult(exports);
  } finally {
    freeString(exports, pass.ptr, pass.len);
    freeString(exports, saltPtr, 16);
  }
}

export async function verifyPassword(password, hashStr) {
  const { exports } = await getInstance();

  // Validate hash length before passing to WASM (must be exactly 60 bytes)
  const encoder = new TextEncoder();
  const hashBytes = encoder.encode(hashStr);
  if (hashBytes.length !== 60) return false;

  const pass = writeString(exports, password);
  const hash = writeString(exports, hashStr);

  try {
    const status = exports.verify_password(pass.ptr, pass.len, hash.ptr);
    return status === 0;
  } finally {
    freeString(exports, pass.ptr, pass.len);
    freeString(exports, hash.ptr, hash.len);
  }
}

export async function createJwt(claimsJson, secret) {
  const { exports } = await getInstance();
  const claims = writeString(exports, claimsJson);
  const sec = writeString(exports, secret);

  try {
    const status = exports.create_jwt(claims.ptr, claims.len, sec.ptr, sec.len);
    if (status !== 0) throw new Error(`create_jwt failed: status ${status}`);
    return readResult(exports);
  } finally {
    freeString(exports, claims.ptr, claims.len);
    freeString(exports, sec.ptr, sec.len);
  }
}

export async function verifyJwt(token, secret, currentTimeSecs = 0) {
  const { exports } = await getInstance();
  const tok = writeString(exports, token);
  const sec = writeString(exports, secret);

  try {
    const status = exports.verify_jwt(tok.ptr, tok.len, sec.ptr, sec.len, BigInt(currentTimeSecs));
    if (status === 2) throw new Error('TOKEN_EXPIRED');
    if (status === 3) throw new Error('INVALID_SIGNATURE');
    if (status !== 0) throw new Error(`verify_jwt failed: status ${status}`);
    return JSON.parse(readResult(exports));
  } finally {
    freeString(exports, tok.ptr, tok.len);
    freeString(exports, sec.ptr, sec.len);
  }
}
