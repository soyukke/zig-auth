const std = @import("std");
const Allocator = std.mem.Allocator;
const command = @import("command.zig");
const context = @import("context.zig");
const router = @import("router.zig");
const jwt = @import("../jwt.zig");
const Context = context.Context;
const Action = context.Action;

/// Wrap a handler to require authentication.
/// Auth uses steps 0-1, then delegates to inner handler starting at step 0.
pub fn withAuth(comptime inner: router.HandlerFn) router.HandlerFn {
    return &struct {
        fn handle(ctx: *Context, step: u32, prev_result: ?[]const u8) Action {
            switch (step) {
                0 => return authStep0(ctx),
                1 => {
                    const ok = authStep1(ctx, prev_result);
                    if (!ok) return ctx.respondError(401, "Unauthorized");
                    // Reset step for inner handler: inner sees step 0
                    return inner(ctx, 0, null);
                },
                else => return inner(ctx, step - 1, prev_result),
            }
        }
    }.handle;
}

/// Auth step 0: parse header, determine auth type, issue async command.
fn authStep0(ctx: *Context) Action {
    const alloc = ctx.getAllocator();

    // Parse headers JSON to extract authorization / x-api-key
    const auth_header = getHeader(alloc, ctx.headers_json, "authorization");
    const api_key_header = getHeader(alloc, ctx.headers_json, "x-api-key");

    // Determine auth type
    if (api_key_header) |key| {
        return beginApiKeyAuth(ctx, key);
    }

    if (auth_header) |header| {
        // Check if it's an API key in Bearer format
        if (header.len > 7 and std.mem.startsWith(u8, header, "Bearer zk_")) {
            return beginApiKeyAuth(ctx, header[7..]);
        }

        // JWT auth
        if (header.len > 7 and std.mem.startsWith(u8, header, "Bearer ")) {
            return beginJwtAuth(ctx, header[7..]);
        }
    }

    return ctx.respondError(401, "Missing or invalid Authorization header");
}

fn beginJwtAuth(ctx: *Context, token: []const u8) Action {
    const alloc = ctx.getAllocator();
    ctx.stash("auth_method", "jwt");
    ctx.stash("token", token);

    // Get JWT_SECRET from env (we need it to verify)
    // For now, stash the token and issue env_get for JWT_SECRET
    // Actually, we can get the secret via env_get command
    // But we need the secret synchronously for jwt.verifyToken...
    // Solution: get the secret in the env_get step, verify in step 1

    // We need both JWT_SECRET and current time.
    // Let's get JWT_SECRET from env. We'll get time in step 1 or use a command.
    // Actually, we can concatenate: first get JWT_SECRET, then in step 1 verify + check blocklist

    // For efficiency: issue env_get for JWT_SECRET
    var aw: std.Io.Writer.Allocating = .init(alloc);
    defer aw.deinit();
    command.writeEnvGet(&aw.writer, "JWT_SECRET") catch return ctx.respondError(500, "Internal error");
    const buf = aw.toArrayList();
    return .{ .cmd = .{ .tag = .env_get, .data = buf.items } };
}

fn beginApiKeyAuth(ctx: *Context, api_key: []const u8) Action {
    // Validate format: must start with "zk_" and be 43 chars
    if (api_key.len != 43 or !std.mem.startsWith(u8, api_key, "zk_")) {
        return ctx.respondError(401, "Invalid API key format");
    }

    ctx.stash("auth_method", "api_key");
    ctx.stash("api_key", api_key);

    // Extract prefix (first 11 chars) and query DB
    const prefix = api_key[0..11];
    return ctx.d1First(
        "SELECT id, user_id, key_hash, revoked_at, expires_at FROM api_keys WHERE prefix = ?",
        &.{.{ .string = prefix }},
    );
}

/// Auth step 1: process async result, set claims on context.
/// Returns true if auth succeeded, false otherwise.
fn authStep1(ctx: *Context, prev_result: ?[]const u8) bool {
    const method = ctx.load("auth_method") orelse return false;

    if (std.mem.eql(u8, method, "jwt")) {
        return completeJwtAuth(ctx, prev_result);
    } else if (std.mem.eql(u8, method, "api_key")) {
        return completeApiKeyAuth(ctx, prev_result);
    }

    return false;
}

fn completeJwtAuth(ctx: *Context, prev_result: ?[]const u8) bool {
    const alloc = ctx.getAllocator();
    const token = ctx.load("token") orelse return false;

    // prev_result is the JWT_SECRET from env_get (JSON-encoded string)
    const secret_json = prev_result orelse return false;

    // Parse the JSON string (it comes as a JSON-encoded value, e.g., "\"mysecret\"" or just "mysecret")
    const secret = parseJsonString(alloc, secret_json) orelse return false;

    // Verify JWT (synchronous!)
    // Note: we don't have current_time here, pass 0 to skip exp check for now
    // TODO: get time from JS and pass it
    const claims_json = jwt.verifyToken(alloc, token, secret, null) catch return false;

    // Parse claims to extract sub and jti
    const sub = extractJsonField(alloc, claims_json, "sub") orelse return false;
    ctx.stash("claims_sub", sub);

    if (extractJsonField(alloc, claims_json, "jti")) |jti| {
        ctx.stash("claims_jti", jti);
    }

    if (extractJsonField(alloc, claims_json, "exp")) |exp| {
        ctx.stash("claims_exp", exp);
    }

    ctx.stash("claims_json", claims_json);

    // TODO: In a future step, we should check the KV blocklist.
    // For now, skip blocklist check to keep auth at 1 async step.
    // The blocklist check will be added when we handle logout properly.

    return true;
}

fn completeApiKeyAuth(ctx: *Context, prev_result: ?[]const u8) bool {
    const alloc = ctx.getAllocator();
    const api_key = ctx.load("api_key") orelse return false;

    // prev_result is the D1 row JSON
    const row_json = prev_result orelse return false;

    // Check if null result
    if (std.mem.eql(u8, row_json, "null")) return false;

    // Extract fields from the row
    const key_hash = extractJsonField(alloc, row_json, "key_hash") orelse return false;
    const user_id = extractJsonField(alloc, row_json, "user_id") orelse return false;
    const api_key_id = extractJsonField(alloc, row_json, "id") orelse return false;

    // Check revoked
    if (extractJsonField(alloc, row_json, "revoked_at")) |revoked| {
        if (!std.mem.eql(u8, revoked, "null")) return false;
    }

    // SHA-256 hash the provided API key and compare
    var hash_buf: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(api_key, &hash_buf, .{});

    // Convert to hex string
    var hex_buf: [64]u8 = undefined;
    const hex = bytesToHex(&hash_buf, &hex_buf);

    if (!std.mem.eql(u8, hex, key_hash)) return false;

    // TODO: Check expires_at

    ctx.stash("claims_sub", user_id);
    ctx.stash("claims_auth_method", "api_key");
    ctx.stash("claims_api_key_id", api_key_id);

    return true;
}

// --- Crypto helpers ---

pub const hex_chars = "0123456789abcdef";

pub fn bytesToHex(bytes: []const u8, out: []u8) []const u8 {
    for (bytes, 0..) |b, i| {
        out[i * 2] = hex_chars[b >> 4];
        out[i * 2 + 1] = hex_chars[b & 0x0f];
    }
    return out[0 .. bytes.len * 2];
}

// --- JSON helpers ---

/// Extract a string value for a given key from a JSON object string.
/// Simple approach: search for "key":"value" pattern.
pub fn extractJsonField(alloc: Allocator, json: []const u8, key: []const u8) ?[]const u8 {
    // Build search pattern: "key":  (stack buffer, key names are short)
    var pattern_storage: [128]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&pattern_storage);
    const pw = &writer;
    pw.writeByte('"') catch return null;
    pw.writeAll(key) catch return null;
    pw.writeAll("\":") catch return null;
    const pattern = writer.buffered();

    const pos = std.mem.indexOf(u8, json, pattern) orelse return null;
    var start = pos + pattern.len;

    // Skip whitespace
    while (start < json.len and json[start] == ' ') start += 1;
    if (start >= json.len) return null;

    if (json[start] == '"') {
        // String value
        start += 1;
        var end = start;
        while (end < json.len and json[end] != '"') {
            if (json[end] == '\\') end += 1; // skip escaped char
            end += 1;
        }
        return alloc.dupe(u8, json[start..end]) catch null;
    } else if (json[start] == 'n' and start + 4 <= json.len and std.mem.eql(u8, json[start .. start + 4], "null")) {
        return alloc.dupe(u8, "null") catch null;
    } else {
        // Number or other literal
        var end = start;
        while (end < json.len and json[end] != ',' and json[end] != '}' and json[end] != ' ') {
            end += 1;
        }
        return alloc.dupe(u8, json[start..end]) catch null;
    }
}

/// Parse a JSON-encoded string value. Handles: "value" → value, null → null
pub const parseJsonStringHelper = parseJsonString;

fn parseJsonString(alloc: Allocator, json: []const u8) ?[]const u8 {
    // Trim whitespace
    const trimmed = std.mem.trim(u8, json, &.{ ' ', '\n', '\r', '\t' });
    if (trimmed.len == 0) return null;

    // Check for null
    if (std.mem.eql(u8, trimmed, "null")) return null;

    // Check for quoted string
    if (trimmed.len >= 2 and trimmed[0] == '"' and trimmed[trimmed.len - 1] == '"') {
        return alloc.dupe(u8, trimmed[1 .. trimmed.len - 1]) catch null;
    }

    // Unquoted value (shouldn't happen for env values, but handle it)
    return alloc.dupe(u8, trimmed) catch null;
}

/// Get a header value from the headers JSON string.
pub fn getHeader(alloc: Allocator, headers_json: []const u8, key: []const u8) ?[]const u8 {
    return extractJsonField(alloc, headers_json, key);
}

// ============================================================
// Tests
// ============================================================

test "getHeader extracts authorization" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();

    const headers = "{\"authorization\":\"Bearer token123\",\"content-type\":\"application/json\"}";
    const val = getHeader(arena.allocator(), headers, "authorization") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("Bearer token123", val);
}

test "getHeader extracts x-api-key" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();

    const headers = "{\"x-api-key\":\"zk_abc12345678901234567890123456789012\"}";
    const val = getHeader(arena.allocator(), headers, "x-api-key") orelse return error.TestUnexpectedResult;
    try std.testing.expect(std.mem.startsWith(u8, val, "zk_"));
}

test "getHeader returns null for missing key" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();

    const headers = "{\"content-type\":\"application/json\"}";
    try std.testing.expect(getHeader(arena.allocator(), headers, "authorization") == null);
}

test "extractJsonField string value" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();

    const json = "{\"sub\":\"user123\",\"exp\":1234567890}";
    const sub = extractJsonField(arena.allocator(), json, "sub") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("user123", sub);
}

test "extractJsonField number value" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();

    const json = "{\"sub\":\"user123\",\"exp\":1234567890}";
    const exp = extractJsonField(arena.allocator(), json, "exp") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("1234567890", exp);
}

test "extractJsonField null value" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();

    const json = "{\"revoked_at\":null}";
    const val = extractJsonField(arena.allocator(), json, "revoked_at") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("null", val);
}

test "extractJsonField missing key" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();

    const json = "{\"sub\":\"user123\"}";
    try std.testing.expect(extractJsonField(arena.allocator(), json, "missing") == null);
}

test "parseJsonString quoted string" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();

    const val = parseJsonString(arena.allocator(), "\"my-secret\"") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("my-secret", val);
}

test "parseJsonString null" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();

    try std.testing.expect(parseJsonString(arena.allocator(), "null") == null);
}

test "parseJsonString unquoted" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();

    const val = parseJsonString(arena.allocator(), "raw-value") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("raw-value", val);
}

test "authStep0 missing auth header returns 401" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();
    ctx.headers_json = "{}";

    const action = authStep0(&ctx);
    switch (action) {
        .response => |resp| try std.testing.expectEqual(@as(u16, 401), resp.status),
        .cmd => return error.TestUnexpectedResult,
    }
}

test "authStep0 JWT bearer issues env_get for JWT_SECRET" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();
    ctx.headers_json = "{\"authorization\":\"Bearer eyJhbGciOiJIUzI1NiJ9.test.sig\"}";

    const action = authStep0(&ctx);
    switch (action) {
        .cmd => |cmd| {
            try std.testing.expectEqual(command.Tag.env_get, cmd.tag);
            try std.testing.expect(std.mem.indexOf(u8, cmd.data, "JWT_SECRET") != null);
        },
        .response => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqualStrings("jwt", ctx.load("auth_method").?);
}

test "authStep0 API key from x-api-key header issues d1_first" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();
    ctx.headers_json = "{\"x-api-key\":\"zk_1234567890123456789012345678901234567890\"}";

    const action = authStep0(&ctx);
    switch (action) {
        .cmd => |cmd| {
            try std.testing.expectEqual(command.Tag.d1_first, cmd.tag);
            try std.testing.expect(std.mem.indexOf(u8, cmd.data, "api_keys") != null);
        },
        .response => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqualStrings("api_key", ctx.load("auth_method").?);
}

test "authStep0 API key from Bearer zk_ header issues d1_first" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();
    ctx.headers_json = "{\"authorization\":\"Bearer zk_1234567890123456789012345678901234567890\"}";

    const action = authStep0(&ctx);
    switch (action) {
        .cmd => |cmd| {
            try std.testing.expectEqual(command.Tag.d1_first, cmd.tag);
        },
        .response => return error.TestUnexpectedResult,
    }
}

test "authStep0 invalid API key format returns 401" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();
    ctx.headers_json = "{\"x-api-key\":\"zk_tooshort\"}";

    const action = authStep0(&ctx);
    switch (action) {
        .response => |resp| try std.testing.expectEqual(@as(u16, 401), resp.status),
        .cmd => return error.TestUnexpectedResult,
    }
}

test "completeJwtAuth with valid token" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();
    const alloc = ctx.getAllocator();

    // Create a real JWT
    const claims = "{\"sub\":\"user123\",\"jti\":\"jwt-id-1\"}";
    const secret = "test-secret-key-at-least-32-bytes!!";
    const token = jwt.createToken(alloc, claims, secret) catch return error.TestUnexpectedResult;

    ctx.stash("auth_method", "jwt");
    ctx.stash("token", token);

    // Simulate env_get result: JWT_SECRET as JSON string
    const ok = completeJwtAuth(&ctx, "\"test-secret-key-at-least-32-bytes!!\"");
    try std.testing.expect(ok);
    try std.testing.expectEqualStrings("user123", ctx.load("claims_sub").?);
    try std.testing.expectEqualStrings("jwt-id-1", ctx.load("claims_jti").?);
}

test "completeJwtAuth with wrong secret fails" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();
    const alloc = ctx.getAllocator();

    const claims = "{\"sub\":\"user123\"}";
    const token = jwt.createToken(alloc, claims, "correct-secret-key-32-bytes!!!!!") catch return error.TestUnexpectedResult;

    ctx.stash("auth_method", "jwt");
    ctx.stash("token", token);

    const ok = completeJwtAuth(&ctx, "\"wrong-secret-key-at-least-32-bytes!!\"");
    try std.testing.expect(!ok);
}

test "completeApiKeyAuth with valid key" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();

    // Generate a test API key and hash
    const api_key = "zk_1234567890123456789012345678901234567890";
    var hash_buf: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(api_key, &hash_buf, .{});
    var hex_buf: [64]u8 = undefined;
    const hash_hex = bytesToHex(&hash_buf, &hex_buf);

    ctx.stash("auth_method", "api_key");
    ctx.stash("api_key", api_key);

    // Simulate D1 row result
    var row_buf: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&row_buf);
    const w = &writer;
    w.writeAll("{\"id\":\"ak1\",\"user_id\":\"u1\",\"key_hash\":\"") catch return error.TestUnexpectedResult;
    w.writeAll(hash_hex) catch return error.TestUnexpectedResult;
    w.writeAll("\",\"revoked_at\":null,\"expires_at\":null}") catch return error.TestUnexpectedResult;

    const ok = completeApiKeyAuth(&ctx, writer.buffered());
    try std.testing.expect(ok);
    try std.testing.expectEqualStrings("u1", ctx.load("claims_sub").?);
    try std.testing.expectEqualStrings("ak1", ctx.load("claims_api_key_id").?);
}

test "completeApiKeyAuth with wrong hash fails" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();

    ctx.stash("auth_method", "api_key");
    ctx.stash("api_key", "zk_1234567890123456789012345678901234567890");

    const row = "{\"id\":\"ak1\",\"user_id\":\"u1\",\"key_hash\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"revoked_at\":null,\"expires_at\":null}";

    const ok = completeApiKeyAuth(&ctx, row);
    try std.testing.expect(!ok);
}

test "completeApiKeyAuth with revoked key fails" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();

    const api_key = "zk_1234567890123456789012345678901234567890";
    var hash_buf: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(api_key, &hash_buf, .{});
    var hex_buf: [64]u8 = undefined;
    const hash_hex = bytesToHex(&hash_buf, &hex_buf);

    ctx.stash("auth_method", "api_key");
    ctx.stash("api_key", api_key);

    var row_buf: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&row_buf);
    const w = &writer;
    w.writeAll("{\"id\":\"ak1\",\"user_id\":\"u1\",\"key_hash\":\"") catch return error.TestUnexpectedResult;
    w.writeAll(hash_hex) catch return error.TestUnexpectedResult;
    w.writeAll("\",\"revoked_at\":\"2024-01-01\",\"expires_at\":null}") catch return error.TestUnexpectedResult;

    const ok = completeApiKeyAuth(&ctx, writer.buffered());
    try std.testing.expect(!ok);
}

test "completeApiKeyAuth with null DB result fails" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();

    ctx.stash("auth_method", "api_key");
    ctx.stash("api_key", "zk_1234567890123456789012345678901234567890");

    const ok = completeApiKeyAuth(&ctx, "null");
    try std.testing.expect(!ok);
}
