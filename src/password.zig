const std = @import("std");
const crypto = std.crypto;
const pwhash_bcrypt = crypto.pwhash.bcrypt;
const types = @import("types.zig");

pub const hash_length = pwhash_bcrypt.hash_length; // 60
const salt_length = 16;
// Cloudflare Workers free tier: 10ms CPU limit per request.
// bcrypt cost 5 (~2-6ms on WASM) is the highest that fits within the constraint.
// Combined with rate limiting (5 attempts/min/IP) this provides adequate protection.
const rounds_log: u6 = 5;

/// Hash a password with bcrypt using the provided salt.
/// Returns a 60-byte crypt-format hash string.
pub fn hashPassword(password: []const u8, salt: [salt_length]u8) types.AuthError![hash_length]u8 {
    if (password.len == 0 or password.len > 72) return error.InvalidPassword;

    const params = pwhash_bcrypt.Params{
        .rounds_log = rounds_log,
        .silently_truncate_password = false,
    };

    const dk = pwhash_bcrypt.bcrypt(password, salt, params);

    // Encode salt and hash to bcrypt's custom base64
    const bcrypt_alphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".*;
    const Encoder = std.base64.Base64Encoder;
    const encoder = Encoder.init(bcrypt_alphabet, null);

    var salt_str: [22]u8 = undefined;
    _ = encoder.encode(&salt_str, &salt);

    var hash_str: [31]u8 = undefined;
    _ = encoder.encode(&hash_str, &dk);

    // Format: $2b$05$<22-char salt><31-char hash>
    var result: [hash_length]u8 = undefined;
    const s = std.fmt.bufPrint(&result, "$2b${d:0>2}${s}{s}", .{
        @as(u8, rounds_log),
        &salt_str,
        &hash_str,
    }) catch return error.InternalError;
    std.debug.assert(s.len == hash_length);
    return result;
}

/// Verify a password against a bcrypt crypt-format hash string.
pub fn verifyPassword(password: []const u8, hash_str: *const [hash_length]u8) types.AuthError!void {
    pwhash_bcrypt.strVerify(hash_str, password, .{
        .silently_truncate_password = false,
    }) catch return error.InvalidPassword;
}

test "hashPassword returns 60-byte hash string" {
    const password = "testpassword123";
    var salt: [16]u8 = undefined;
    @memset(&salt, 0x42);

    const hash_str = try hashPassword(password, salt);
    try std.testing.expectEqual(@as(usize, 60), hash_str.len);
}

test "hashPassword output starts with bcrypt prefix" {
    const password = "testpassword123";
    var salt: [16]u8 = undefined;
    @memset(&salt, 0x42);

    const hash_str = try hashPassword(password, salt);
    try std.testing.expect(std.mem.startsWith(u8, &hash_str, "$2b$05$"));
}

test "hashPassword same input produces same output" {
    const password = "deterministic_test";
    var salt: [16]u8 = undefined;
    @memset(&salt, 0xAB);

    const hash1 = try hashPassword(password, salt);
    const hash2 = try hashPassword(password, salt);
    try std.testing.expectEqualStrings(&hash1, &hash2);
}

test "verifyPassword accepts correct password" {
    const password = "correct_password";
    var salt: [16]u8 = undefined;
    @memset(&salt, 0x01);

    var hash_str = try hashPassword(password, salt);
    try verifyPassword(password, &hash_str);
}

test "verifyPassword rejects wrong password" {
    const password = "correct_password";
    var salt: [16]u8 = undefined;
    @memset(&salt, 0x02);

    var hash_str = try hashPassword(password, salt);
    const result = verifyPassword("wrong_password", &hash_str);
    try std.testing.expectError(error.InvalidPassword, result);
}

test "hashPassword rejects empty password" {
    var salt: [16]u8 = undefined;
    @memset(&salt, 0x03);

    const result = hashPassword("", salt);
    try std.testing.expectError(error.InvalidPassword, result);
}

test "hashPassword rejects password longer than 72 bytes" {
    var salt: [16]u8 = undefined;
    @memset(&salt, 0x04);

    const long_password = "a" ** 73;
    const result = hashPassword(long_password, salt);
    try std.testing.expectError(error.InvalidPassword, result);
}
