const std = @import("std");
const builtin = @import("builtin");
const types = @import("types.zig");
const password = @import("password.zig");
const jwt = @import("jwt.zig");
const base64url = @import("base64url.zig");

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

// --- Password exports ---

/// Hash a password with bcrypt. Salt must be exactly 16 bytes at salt_ptr.
/// On success (returns 0), result is available via get_result_ptr/get_result_len.
/// Caller must dealloc the result when done.
export fn hash_password(
    pass_ptr: [*]const u8,
    pass_len: usize,
    salt_ptr: [*]const u8,
) i32 {
    clearResult();
    const pass = pass_ptr[0..pass_len];
    const salt: *const [16]u8 = @ptrCast(salt_ptr);

    const hash_result = password.hashPassword(pass, salt.*) catch |err| {
        return @intFromEnum(types.errorToStatus(err));
    };

    const out = allocator.alloc(u8, hash_result.len) catch
        return @intFromEnum(types.StatusCode.internal_error);
    @memcpy(out, &hash_result);
    result_ptr = out.ptr;
    result_len = out.len;
    return 0;
}

/// Verify a password against a 60-byte bcrypt hash string at hash_ptr.
export fn verify_password(
    pass_ptr: [*]const u8,
    pass_len: usize,
    hash_ptr: [*]const u8,
) i32 {
    const pass = pass_ptr[0..pass_len];
    const hash_str: *const [password.hash_length]u8 = @ptrCast(hash_ptr);

    password.verifyPassword(pass, hash_str) catch |err| {
        return @intFromEnum(types.errorToStatus(err));
    };
    return 0;
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

test {
    _ = types;
    _ = password;
    _ = jwt;
    _ = base64url;
}
