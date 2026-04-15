const std = @import("std");
const builtin = @import("builtin");
const types = @import("types.zig");
const jwt = @import("jwt.zig");
const base64url = @import("base64url.zig");
const webauthn = @import("webauthn");

const allocator = if (builtin.cpu.arch == .wasm32)
    std.heap.wasm_allocator
else
    std.testing.allocator;

// --- Memory management exports for JS ---

export fn alloc(len: usize) ?[*]u8 {
    const slice = allocator.alloc(u8, len) catch return null;
    return slice.ptr;
}

export fn dealloc(ptr: [*]u8, len: usize) void {
    allocator.free(ptr[0..len]);
}

// --- Result buffer for variable-length returns ---

var result_ptr: ?[*]const u8 = null;
var result_len: usize = 0;

fn clearResult() void {
    result_ptr = null;
    result_len = 0;
}

export fn get_result_ptr() usize {
    return if (result_ptr) |p| @intFromPtr(p) else 0;
}

export fn get_result_len() usize {
    return result_len;
}

// --- JWT exports ---

/// Create a JWT from JSON claims and a secret.
/// On success (returns 0), result is available via get_result_ptr/get_result_len.
/// Caller must dealloc the result when done.
export fn create_jwt(
    claims_ptr: [*]const u8,
    claims_len: usize,
    secret_ptr: [*]const u8,
    secret_len: usize,
) i32 {
    clearResult();
    const claims = claims_ptr[0..claims_len];
    const secret = secret_ptr[0..secret_len];

    const token = jwt.createToken(allocator, claims, secret) catch |err| {
        return @intFromEnum(types.errorToStatus(err));
    };
    result_ptr = token.ptr;
    result_len = token.len;
    return 0;
}

/// Verify a JWT token and return decoded claims.
/// current_time_secs: Unix timestamp for exp check. Pass 0 to skip exp check.
/// On success (returns 0), claims are available via get_result_ptr/get_result_len.
/// Caller must dealloc the result when done.
export fn verify_jwt(
    token_ptr: [*]const u8,
    token_len: usize,
    secret_ptr: [*]const u8,
    secret_len: usize,
    current_time_secs: i64,
) i32 {
    clearResult();
    const token = token_ptr[0..token_len];
    const secret = secret_ptr[0..secret_len];

    const current_time: ?i64 = if (current_time_secs == 0) null else current_time_secs;

    const claims = jwt.verifyToken(allocator, token, secret, current_time) catch |err| {
        return @intFromEnum(types.errorToStatus(err));
    };
    result_ptr = claims.ptr;
    result_len = claims.len;
    return 0;
}

// --- WebAuthn exports ---

/// Verify a WebAuthn registration response.
/// All string inputs are base64url-encoded where applicable.
/// On success (returns 0), JSON result is available via get_result_ptr/get_result_len.
export fn verify_registration(
    cdj_b64_ptr: [*]const u8,
    cdj_b64_len: usize,
    att_obj_b64_ptr: [*]const u8,
    att_obj_b64_len: usize,
    challenge_ptr: [*]const u8,
    challenge_len: usize,
    origin_ptr: [*]const u8,
    origin_len: usize,
    rp_id_ptr: [*]const u8,
    rp_id_len: usize,
) i32 {
    clearResult();

    const cdj_b64 = cdj_b64_ptr[0..cdj_b64_len];
    const att_obj_b64 = att_obj_b64_ptr[0..att_obj_b64_len];
    const challenge = challenge_ptr[0..challenge_len];
    const origin = origin_ptr[0..origin_len];
    const rp_id = rp_id_ptr[0..rp_id_len];

    const json = webauthn.verifyRegistration(
        allocator,
        cdj_b64,
        att_obj_b64,
        challenge,
        origin,
        rp_id,
    ) catch |err| {
        return toWebAuthnStatus(err);
    };

    result_ptr = json.ptr;
    result_len = json.len;
    return 0;
}

/// Verify a WebAuthn authentication response.
/// On success (returns 0), JSON result is available via get_result_ptr/get_result_len.
export fn verify_authentication(
    cdj_b64_ptr: [*]const u8,
    cdj_b64_len: usize,
    auth_data_b64_ptr: [*]const u8,
    auth_data_b64_len: usize,
    sig_b64_ptr: [*]const u8,
    sig_b64_len: usize,
    pub_key_b64_ptr: [*]const u8,
    pub_key_b64_len: usize,
    stored_counter: u32,
    challenge_ptr: [*]const u8,
    challenge_len: usize,
    origin_ptr: [*]const u8,
    origin_len: usize,
    rp_id_ptr: [*]const u8,
    rp_id_len: usize,
) i32 {
    clearResult();

    const cdj_b64 = cdj_b64_ptr[0..cdj_b64_len];
    const auth_data_b64 = auth_data_b64_ptr[0..auth_data_b64_len];
    const sig_b64 = sig_b64_ptr[0..sig_b64_len];
    const pub_key_b64 = pub_key_b64_ptr[0..pub_key_b64_len];
    const challenge = challenge_ptr[0..challenge_len];
    const origin = origin_ptr[0..origin_len];
    const rp_id = rp_id_ptr[0..rp_id_len];

    const json = webauthn.verifyAuthentication(
        allocator,
        cdj_b64,
        auth_data_b64,
        sig_b64,
        pub_key_b64,
        stored_counter,
        challenge,
        origin,
        rp_id,
    ) catch |err| {
        return toWebAuthnStatus(err);
    };

    result_ptr = json.ptr;
    result_len = json.len;
    return 0;
}

fn toWebAuthnStatus(err: webauthn.WebAuthnError) i32 {
    const status: types.StatusCode = switch (err) {
        error.InvalidClientData => .invalid_client_data,
        error.InvalidType => .invalid_type,
        error.InvalidChallenge => .invalid_challenge,
        error.InvalidOrigin => .invalid_origin,
        error.InvalidRpId => .invalid_rp_id,
        error.InvalidAttestation => .invalid_attestation,
        error.InvalidAttestationFormat => .invalid_attestation_format,
        error.UnsupportedAlgorithm => .unsupported_algorithm,
        error.InvalidAuthenticatorData => .invalid_authenticator_data,
        error.InvalidSignature => .invalid_signature,
        error.UserNotPresent => .user_not_present,
        error.CounterNotIncremented => .counter_not_incremented,
        error.InvalidCbor => .invalid_cbor,
        error.InvalidEncoding => .invalid_encoding,
        error.OutOfMemory => .internal_error,
    };
    return @intFromEnum(status);
}

test {
    _ = types;
    _ = jwt;
    _ = base64url;
}
