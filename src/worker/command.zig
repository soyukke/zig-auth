const std = @import("std");
const Allocator = std.mem.Allocator;

/// Command tags for the WASM ↔ JS command-response loop.
/// Returned by handle_request() and resume() to tell JS what async operation to execute.
pub const Tag = enum(u8) {
    /// Processing complete — read final HTTP response from command buffer.
    response = 0,
    /// D1: prepare(sql).bind(params).first() → single row or null
    d1_first = 1,
    /// D1: prepare(sql).bind(params).all() → array of rows
    d1_all = 2,
    /// D1: prepare(sql).bind(params).run() → { changes, last_row_id }
    d1_run = 3,
    /// D1: batch(statements) → array of results
    d1_batch = 4,
    /// KV: get(key) → string value or null
    kv_get = 5,
    /// KV: put(key, value, {expirationTtl}) → void
    kv_put = 6,
    /// KV: delete(key) → void
    kv_delete = 7,
    /// fetch(url, init) → { status, body, headers }
    http_fetch = 8,
    /// Get environment variable by name
    env_get = 9,
    /// Route not found — JS should try the old router
    route_not_found = 254,
};

/// SQL parameter value for D1 bind().
pub const Param = union(enum) {
    string: []const u8,
    integer: i64,
    float: f64,
    boolean: bool,
    null,
};

/// Write a JSON-encoded D1 query command: {"sql":"...","params":[...]}
pub fn writeD1Query(writer: anytype, sql: []const u8, params: []const Param) !void {
    try writer.writeAll("{\"sql\":");
    try writeJsonString(writer, sql);
    try writer.writeAll(",\"params\":[");
    for (params, 0..) |param, i| {
        if (i > 0) try writer.writeByte(',');
        try writeParam(writer, param);
    }
    try writer.writeAll("]}");
}

/// Write a JSON-encoded D1 batch command: [{"sql":"...","params":[...]},...]
pub fn writeD1Batch(writer: anytype, statements: []const D1Statement) !void {
    try writer.writeByte('[');
    for (statements, 0..) |stmt, i| {
        if (i > 0) try writer.writeByte(',');
        try writeD1Query(writer, stmt.sql, stmt.params);
    }
    try writer.writeByte(']');
}

/// Write a JSON object with a single string field: {"field":"value"}
fn writeSingleField(writer: anytype, field: []const u8, value: []const u8) !void {
    try writer.writeAll("{\"");
    try writer.writeAll(field);
    try writer.writeAll("\":");
    try writeJsonString(writer, value);
    try writer.writeByte('}');
}

/// Write a JSON-encoded KV get command: {"key":"..."}
pub fn writeKvGet(writer: anytype, key: []const u8) !void {
    try writeSingleField(writer, "key", key);
}

/// Write a JSON-encoded KV put command: {"key":"...","value":"...","ttl":N}
pub fn writeKvPut(writer: anytype, key: []const u8, value: []const u8, ttl: ?u32) !void {
    try writer.writeAll("{\"key\":");
    try writeJsonString(writer, key);
    try writer.writeAll(",\"value\":");
    try writeJsonString(writer, value);
    if (ttl) |t| {
        try writer.writeAll(",\"ttl\":");
        try std.fmt.format(writer, "{d}", .{t});
    }
    try writer.writeByte('}');
}

/// Write a JSON-encoded KV delete command: {"key":"..."}
pub fn writeKvDelete(writer: anytype, key: []const u8) !void {
    try writeSingleField(writer, "key", key);
}

/// Write a JSON-encoded env get command: {"name":"..."}
pub fn writeEnvGet(writer: anytype, name: []const u8) !void {
    try writeSingleField(writer, "name", name);
}

/// Write a JSON-encoded HTTP fetch command: {"url":"...","method":"...","headers":{...},"body":"..."}
pub fn writeFetch(writer: anytype, url: []const u8, method: []const u8, headers: ?[]const u8, body: ?[]const u8) !void {
    try writer.writeAll("{\"url\":");
    try writeJsonString(writer, url);
    try writer.writeAll(",\"method\":");
    try writeJsonString(writer, method);
    if (headers) |h| {
        try writer.writeAll(",\"headers\":");
        try writer.writeAll(h); // Already JSON object string
    }
    if (body) |b| {
        try writer.writeAll(",\"body\":");
        try writeJsonString(writer, b);
    }
    try writer.writeByte('}');
}

/// Write a JSON-encoded HTTP response (terminal command): {"status":N,"headers":{...},"body":"..."}
pub fn writeResponse(writer: anytype, status: u16, headers_json: []const u8, body: []const u8) !void {
    try writer.writeAll("{\"status\":");
    try std.fmt.format(writer, "{d}", .{status});
    try writer.writeAll(",\"headers\":");
    try writer.writeAll(headers_json);
    try writer.writeAll(",\"body\":");
    try writeJsonString(writer, body);
    try writer.writeByte('}');
}

pub const D1Statement = struct {
    sql: []const u8,
    params: []const Param,
};

// --- JSON helpers ---

fn writeParam(writer: anytype, param: Param) !void {
    switch (param) {
        .string => |s| try writeJsonString(writer, s),
        .integer => |n| try std.fmt.format(writer, "{d}", .{n}),
        .float => |f| {
            try std.fmt.format(writer, "{d}", .{f});
        },
        .boolean => |b| try writer.writeAll(if (b) "true" else "false"),
        .null => try writer.writeAll("null"),
    }
}

/// Write a JSON-escaped string including surrounding quotes.
pub fn writeJsonString(writer: anytype, s: []const u8) !void {
    try writer.writeByte('"');
    for (s) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => {
                if (c < 0x20) {
                    try std.fmt.format(writer, "\\u{x:0>4}", .{c});
                } else {
                    try writer.writeByte(c);
                }
            },
        }
    }
    try writer.writeByte('"');
}

// --- Convenience: allocate command JSON ---

pub fn allocD1Query(allocator: Allocator, sql: []const u8, params: []const Param) ![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    try writeD1Query(buf.writer(allocator), sql, params);
    return buf.toOwnedSlice(allocator);
}

pub fn allocKvGet(allocator: Allocator, key: []const u8) ![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    try writeKvGet(buf.writer(allocator), key);
    return buf.toOwnedSlice(allocator);
}

pub fn allocKvPut(allocator: Allocator, key: []const u8, value: []const u8, ttl: ?u32) ![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    try writeKvPut(buf.writer(allocator), key, value, ttl);
    return buf.toOwnedSlice(allocator);
}

pub fn allocKvDelete(allocator: Allocator, key: []const u8) ![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    try writeKvDelete(buf.writer(allocator), key);
    return buf.toOwnedSlice(allocator);
}

pub fn allocResponse(allocator: Allocator, status: u16, headers_json: []const u8, body: []const u8) ![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    try writeResponse(buf.writer(allocator), status, headers_json, body);
    return buf.toOwnedSlice(allocator);
}

// ============================================================
// Tests
// ============================================================

test "writeJsonString escapes special characters" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try writeJsonString(fbs.writer(), "hello \"world\"\nnew\\line");
    try std.testing.expectEqualStrings("\"hello \\\"world\\\"\\nnew\\\\line\"", fbs.getWritten());
}

test "writeJsonString escapes control characters" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try writeJsonString(fbs.writer(), &.{ 0x01, 0x1f });
    try std.testing.expectEqualStrings("\"\\u0001\\u001f\"", fbs.getWritten());
}

test "writeParam string" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try writeParam(fbs.writer(), .{ .string = "user@example.com" });
    try std.testing.expectEqualStrings("\"user@example.com\"", fbs.getWritten());
}

test "writeParam integer" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try writeParam(fbs.writer(), .{ .integer = 42 });
    try std.testing.expectEqualStrings("42", fbs.getWritten());
}

test "writeParam null" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try writeParam(fbs.writer(), .null);
    try std.testing.expectEqualStrings("null", fbs.getWritten());
}

test "writeParam boolean" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try writeParam(fbs.writer(), .{ .boolean = true });
    try std.testing.expectEqualStrings("true", fbs.getWritten());
}

test "writeD1Query with string params" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try writeD1Query(fbs.writer(), "SELECT * FROM users WHERE email = ?", &.{
        .{ .string = "user@example.com" },
    });
    try std.testing.expectEqualStrings(
        "{\"sql\":\"SELECT * FROM users WHERE email = ?\",\"params\":[\"user@example.com\"]}",
        fbs.getWritten(),
    );
}

test "writeD1Query with mixed params" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try writeD1Query(fbs.writer(), "INSERT INTO t (a, b, c) VALUES (?, ?, ?)", &.{
        .{ .string = "hello" },
        .{ .integer = 42 },
        .null,
    });
    try std.testing.expectEqualStrings(
        "{\"sql\":\"INSERT INTO t (a, b, c) VALUES (?, ?, ?)\",\"params\":[\"hello\",42,null]}",
        fbs.getWritten(),
    );
}

test "writeD1Query with no params" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try writeD1Query(fbs.writer(), "SELECT count(*) FROM users", &.{});
    try std.testing.expectEqualStrings(
        "{\"sql\":\"SELECT count(*) FROM users\",\"params\":[]}",
        fbs.getWritten(),
    );
}

test "writeD1Batch with multiple statements" {
    var buf: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const stmts: []const D1Statement = &.{
        .{ .sql = "INSERT INTO users (id) VALUES (?)", .params = &.{.{ .string = "u1" }} },
        .{ .sql = "INSERT INTO passkeys (user_id) VALUES (?)", .params = &.{.{ .string = "u1" }} },
    };
    try writeD1Batch(fbs.writer(), stmts);
    const result = fbs.getWritten();
    // Should be a JSON array
    try std.testing.expect(result[0] == '[');
    try std.testing.expect(result[result.len - 1] == ']');
    // Should contain both SQL statements
    try std.testing.expect(std.mem.indexOf(u8, result, "INSERT INTO users") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "INSERT INTO passkeys") != null);
}

test "writeKvGet" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try writeKvGet(fbs.writer(), "rt:abc123");
    try std.testing.expectEqualStrings("{\"key\":\"rt:abc123\"}", fbs.getWritten());
}

test "writeKvPut with TTL" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try writeKvPut(fbs.writer(), "rt:abc", "user123", 604800);
    try std.testing.expectEqualStrings(
        "{\"key\":\"rt:abc\",\"value\":\"user123\",\"ttl\":604800}",
        fbs.getWritten(),
    );
}

test "writeKvPut without TTL" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try writeKvPut(fbs.writer(), "key1", "val1", null);
    try std.testing.expectEqualStrings(
        "{\"key\":\"key1\",\"value\":\"val1\"}",
        fbs.getWritten(),
    );
}

test "writeKvDelete" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try writeKvDelete(fbs.writer(), "rt:abc123");
    try std.testing.expectEqualStrings("{\"key\":\"rt:abc123\"}", fbs.getWritten());
}

test "writeResponse" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try writeResponse(fbs.writer(), 200, "{\"Content-Type\":\"application/json\"}", "{\"ok\":true}");
    try std.testing.expectEqualStrings(
        "{\"status\":200,\"headers\":{\"Content-Type\":\"application/json\"},\"body\":\"{\\\"ok\\\":true}\"}",
        fbs.getWritten(),
    );
}

test "writeFetch minimal" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try writeFetch(fbs.writer(), "https://api.github.com/user", "GET", null, null);
    try std.testing.expectEqualStrings(
        "{\"url\":\"https://api.github.com/user\",\"method\":\"GET\"}",
        fbs.getWritten(),
    );
}

test "writeFetch with headers and body" {
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try writeFetch(fbs.writer(), "https://example.com/token", "POST", "{\"Accept\":\"application/json\"}", "code=abc");
    const result = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, result, "\"method\":\"POST\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"body\":\"code=abc\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"headers\":{\"Accept\":\"application/json\"}") != null);
}

test "writeEnvGet" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try writeEnvGet(fbs.writer(), "JWT_SECRET");
    try std.testing.expectEqualStrings("{\"name\":\"JWT_SECRET\"}", fbs.getWritten());
}

test "allocD1Query returns owned slice" {
    const allocator = std.testing.allocator;
    const json = try allocD1Query(allocator, "SELECT 1", &.{});
    defer allocator.free(json);
    try std.testing.expectEqualStrings("{\"sql\":\"SELECT 1\",\"params\":[]}", json);
}

test "allocKvGet returns owned slice" {
    const allocator = std.testing.allocator;
    const json = try allocKvGet(allocator, "test-key");
    defer allocator.free(json);
    try std.testing.expectEqualStrings("{\"key\":\"test-key\"}", json);
}

test "allocResponse returns owned slice" {
    const allocator = std.testing.allocator;
    const json = try allocResponse(allocator, 404, "{}", "not found");
    defer allocator.free(json);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"status\":404") != null);
}

test "Tag enum values" {
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(Tag.response));
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(Tag.d1_first));
    try std.testing.expectEqual(@as(u8, 5), @intFromEnum(Tag.kv_get));
    try std.testing.expectEqual(@as(u8, 8), @intFromEnum(Tag.http_fetch));
    try std.testing.expectEqual(@as(u8, 9), @intFromEnum(Tag.env_get));
}
