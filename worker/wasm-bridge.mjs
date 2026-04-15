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

export async function verifyRegistration(clientDataJSON, attestationObject, expectedChallenge, expectedOrigin, expectedRPID) {
  const { exports } = await getInstance();
  const cdj = writeString(exports, clientDataJSON);
  const att = writeString(exports, attestationObject);
  const chal = writeString(exports, expectedChallenge);
  const orig = writeString(exports, expectedOrigin);
  const rpid = writeString(exports, expectedRPID);

  try {
    const status = exports.verify_registration(
      cdj.ptr, cdj.len,
      att.ptr, att.len,
      chal.ptr, chal.len,
      orig.ptr, orig.len,
      rpid.ptr, rpid.len,
    );
    if (status !== 0) throw new Error(`verify_registration failed: status ${status}`);
    return JSON.parse(readResult(exports));
  } finally {
    freeString(exports, cdj.ptr, cdj.len);
    freeString(exports, att.ptr, att.len);
    freeString(exports, chal.ptr, chal.len);
    freeString(exports, orig.ptr, orig.len);
    freeString(exports, rpid.ptr, rpid.len);
  }
}

export async function verifyAuthentication(clientDataJSON, authenticatorData, signature, publicKeyCBOR, storedCounter, expectedChallenge, expectedOrigin, expectedRPID) {
  const { exports } = await getInstance();
  const cdj = writeString(exports, clientDataJSON);
  const ad = writeString(exports, authenticatorData);
  const sig = writeString(exports, signature);
  const pk = writeString(exports, publicKeyCBOR);
  const chal = writeString(exports, expectedChallenge);
  const orig = writeString(exports, expectedOrigin);
  const rpid = writeString(exports, expectedRPID);

  try {
    const status = exports.verify_authentication(
      cdj.ptr, cdj.len,
      ad.ptr, ad.len,
      sig.ptr, sig.len,
      pk.ptr, pk.len,
      storedCounter,
      chal.ptr, chal.len,
      orig.ptr, orig.len,
      rpid.ptr, rpid.len,
    );
    if (status !== 0) throw new Error(`verify_authentication failed: status ${status}`);
    return JSON.parse(readResult(exports));
  } finally {
    freeString(exports, cdj.ptr, cdj.len);
    freeString(exports, ad.ptr, ad.len);
    freeString(exports, sig.ptr, sig.len);
    freeString(exports, pk.ptr, pk.len);
    freeString(exports, chal.ptr, chal.len);
    freeString(exports, orig.ptr, orig.len);
    freeString(exports, rpid.ptr, rpid.len);
  }
}
