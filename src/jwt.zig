const std = @import("std");
const base64url = @import("base64url.zig");
const types = @import("types.zig");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

const jwt_header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";

/// Create a JWT token from JSON claims and a secret key.
/// Caller owns the returned slice and must free with allocator.
pub fn createToken(
    allocator: std.mem.Allocator,
    claims_json: []const u8,
    secret: []const u8,
) types.AuthError![]const u8 {
    // Encode header
    var header_buf: [64]u8 = undefined;
    const header_b64 = base64url.encode(&header_buf, jwt_header);

    // Encode payload
    const payload_buf = allocator.alloc(u8, base64url.encodeLen(claims_json.len)) catch
        return error.InternalError;
    defer allocator.free(payload_buf);
    const payload_b64 = base64url.encode(payload_buf, claims_json);

    // Build signing input: header.payload
    const signing_input_len = header_b64.len + 1 + payload_b64.len;
    const signing_input = allocator.alloc(u8, signing_input_len) catch
        return error.InternalError;
    defer allocator.free(signing_input);
    @memcpy(signing_input[0..header_b64.len], header_b64);
    signing_input[header_b64.len] = '.';
    @memcpy(signing_input[header_b64.len + 1 ..], payload_b64);

    // Sign with HMAC-SHA256
    var mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&mac, signing_input, secret);

    // Encode signature
    var sig_buf: [64]u8 = undefined;
    const sig_b64 = base64url.encode(&sig_buf, &mac);

    // Build final token: header.payload.signature
    const token_len = signing_input_len + 1 + sig_b64.len;
    const token = allocator.alloc(u8, token_len) catch
        return error.InternalError;
    @memcpy(token[0..signing_input_len], signing_input);
    token[signing_input_len] = '.';
    @memcpy(token[signing_input_len + 1 ..], sig_b64);

    return token;
}

/// Verify a JWT token and return the decoded claims JSON.
/// Checks: header is HS256, signature is valid (constant-time), exp claim if present.
/// Caller owns the returned slice and must free with allocator.
pub fn verifyToken(
    allocator: std.mem.Allocator,
    token: []const u8,
    secret: []const u8,
    current_time: ?i64,
) types.AuthError![]const u8 {
    // Find the two dots
    const first_dot = std.mem.indexOf(u8, token, ".") orelse return error.InvalidToken;
    const rest = token[first_dot + 1 ..];
    const second_dot_rel = std.mem.indexOf(u8, rest, ".") orelse return error.InvalidToken;
    const second_dot = first_dot + 1 + second_dot_rel;

    const header_b64 = token[0..first_dot];
    const signing_input = token[0..second_dot];
    const sig_b64 = token[second_dot + 1 ..];
    const payload_b64 = token[first_dot + 1 .. second_dot];

    // Verify header is HS256
    var header_decode_buf: [128]u8 = undefined;
    const header_json = base64url.decode(&header_decode_buf, header_b64) catch
        return error.InvalidToken;
    if (!std.mem.eql(u8, header_json, jwt_header)) return error.InvalidToken;

    // Compute expected signature
    var expected_sig: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&expected_sig, signing_input, secret);

    // Decode actual signature
    var actual_sig_buf: [HmacSha256.mac_length]u8 = undefined;
    const actual_sig = base64url.decode(&actual_sig_buf, sig_b64) catch
        return error.InvalidToken;

    if (actual_sig.len != HmacSha256.mac_length) return error.InvalidSignature;

    // Constant-time comparison to prevent timing attacks
    if (!std.crypto.timing_safe.eql([HmacSha256.mac_length]u8, actual_sig_buf, expected_sig))
        return error.InvalidSignature;

    // Decode payload
    const payload_max_len = base64url.decodeLen(payload_b64.len);
    const payload_buf = allocator.alloc(u8, payload_max_len) catch
        return error.InternalError;

    const claims_json = base64url.decode(payload_buf, payload_b64) catch {
        allocator.free(payload_buf);
        return error.InvalidToken;
    };

    // Check exp claim if current_time is provided
    if (current_time) |now| {
        if (parseExpClaim(claims_json)) |exp| {
            if (now >= exp) {
                allocator.free(payload_buf);
                return error.ExpiredToken;
            }
        }
    }

    // Shrink to actual size if needed
    if (claims_json.len < payload_buf.len) {
        const exact = allocator.alloc(u8, claims_json.len) catch {
            allocator.free(payload_buf);
            return error.InternalError;
        };
        @memcpy(exact, claims_json);
        allocator.free(payload_buf);
        return exact;
    }

    return claims_json;
}

/// Parse the "exp" field from a JSON claims string.
/// Returns null if not found or not a number.
fn parseExpClaim(json: []const u8) ?i64 {
    // Find "exp": in the JSON
    const exp_key = "\"exp\":";
    const pos = std.mem.indexOf(u8, json, exp_key) orelse return null;
    var start = pos + exp_key.len;

    // Skip whitespace
    while (start < json.len and json[start] == ' ') start += 1;
    if (start >= json.len) return null;

    // Parse integer
    var end = start;
    if (end < json.len and json[end] == '-') end += 1;
    while (end < json.len and json[end] >= '0' and json[end] <= '9') end += 1;
    if (end == start) return null;

    return std.fmt.parseInt(i64, json[start..end], 10) catch null;
}

test "createToken returns valid JWT format (header.payload.signature)" {
    const allocator = std.testing.allocator;
    const claims = "{\"sub\":\"user123\",\"exp\":9999999999}";
    const secret = "test-secret-key-at-least-32-bytes!!";

    const token = try createToken(allocator, claims, secret);
    defer allocator.free(token);

    var dot_count: usize = 0;
    for (token) |c| {
        if (c == '.') dot_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), dot_count);
}

test "createToken header is HS256" {
    const allocator = std.testing.allocator;
    const claims = "{\"sub\":\"user123\"}";
    const secret = "test-secret-key-at-least-32-bytes!!";

    const token = try createToken(allocator, claims, secret);
    defer allocator.free(token);

    const dot_pos = std.mem.indexOf(u8, token, ".") orelse return error.TestUnexpectedResult;
    const header_b64 = token[0..dot_pos];

    var decode_buf: [256]u8 = undefined;
    const header_json = try base64url.decode(&decode_buf, header_b64);

    try std.testing.expectEqualStrings("{\"alg\":\"HS256\",\"typ\":\"JWT\"}", header_json);
}

test "createToken and verifyToken roundtrip" {
    const allocator = std.testing.allocator;
    const claims = "{\"sub\":\"user123\",\"email\":\"test@example.com\"}";
    const secret = "test-secret-key-at-least-32-bytes!!";

    const token = try createToken(allocator, claims, secret);
    defer allocator.free(token);

    const decoded_claims = try verifyToken(allocator, token, secret, null);
    defer allocator.free(decoded_claims);

    try std.testing.expectEqualStrings(claims, decoded_claims);
}

test "verifyToken rejects token with wrong secret" {
    const allocator = std.testing.allocator;
    const claims = "{\"sub\":\"user123\"}";

    const token = try createToken(allocator, claims, "correct-secret-key-32-bytes!!!!!");
    defer allocator.free(token);

    const result = verifyToken(allocator, token, "wrong-secret-key-32-bytes!!!!!!!", null);
    try std.testing.expectError(error.InvalidSignature, result);
}

test "verifyToken rejects tampered payload" {
    const allocator = std.testing.allocator;
    const claims = "{\"sub\":\"user123\"}";
    const secret = "test-secret-key-at-least-32-bytes!!";

    const token = try createToken(allocator, claims, secret);
    defer allocator.free(token);

    var tampered = try allocator.alloc(u8, token.len);
    defer allocator.free(tampered);
    @memcpy(tampered, token);
    const first_dot = std.mem.indexOf(u8, tampered, ".") orelse return error.TestUnexpectedResult;
    if (first_dot + 1 < tampered.len) {
        tampered[first_dot + 1] = if (tampered[first_dot + 1] == 'A') 'B' else 'A';
    }

    const result = verifyToken(allocator, tampered, secret, null);
    try std.testing.expectError(error.InvalidSignature, result);
}

test "verifyToken rejects malformed token (no dots)" {
    const allocator = std.testing.allocator;
    const result = verifyToken(allocator, "nodots", "secret", null);
    try std.testing.expectError(error.InvalidToken, result);
}

test "verifyToken rejects malformed token (one dot)" {
    const allocator = std.testing.allocator;
    const result = verifyToken(allocator, "one.dot", "secret", null);
    try std.testing.expectError(error.InvalidToken, result);
}

test "createToken same input produces same output" {
    const allocator = std.testing.allocator;
    const claims = "{\"sub\":\"deterministic\"}";
    const secret = "test-secret-key-at-least-32-bytes!!";

    const token1 = try createToken(allocator, claims, secret);
    defer allocator.free(token1);
    const token2 = try createToken(allocator, claims, secret);
    defer allocator.free(token2);

    try std.testing.expectEqualStrings(token1, token2);
}

test "verifyToken rejects expired token" {
    const allocator = std.testing.allocator;
    const claims = "{\"sub\":\"user123\",\"exp\":1000}";
    const secret = "test-secret-key-at-least-32-bytes!!";

    const token = try createToken(allocator, claims, secret);
    defer allocator.free(token);

    // Current time > exp
    const result = verifyToken(allocator, token, secret, 2000);
    try std.testing.expectError(error.ExpiredToken, result);
}

test "verifyToken accepts non-expired token" {
    const allocator = std.testing.allocator;
    const claims = "{\"sub\":\"user123\",\"exp\":9999999999}";
    const secret = "test-secret-key-at-least-32-bytes!!";

    const token = try createToken(allocator, claims, secret);
    defer allocator.free(token);

    const decoded = try verifyToken(allocator, token, secret, 1000);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings(claims, decoded);
}

test "verifyToken without time check passes expired token" {
    const allocator = std.testing.allocator;
    const claims = "{\"sub\":\"user123\",\"exp\":1000}";
    const secret = "test-secret-key-at-least-32-bytes!!";

    const token = try createToken(allocator, claims, secret);
    defer allocator.free(token);

    // null means no time check
    const decoded = try verifyToken(allocator, token, secret, null);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings(claims, decoded);
}

test "parseExpClaim parses integer exp" {
    try std.testing.expectEqual(@as(?i64, 1234567890), parseExpClaim("{\"exp\":1234567890}"));
    try std.testing.expectEqual(@as(?i64, 9999999999), parseExpClaim("{\"sub\":\"u\",\"exp\":9999999999}"));
    try std.testing.expectEqual(@as(?i64, null), parseExpClaim("{\"sub\":\"user123\"}"));
}
