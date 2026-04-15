const std = @import("std");
const builtin = @import("builtin");
const command = @import("../command.zig");
const context = @import("../context.zig");
const auth = @import("../auth.zig");
const jwt = @import("../../jwt.zig");
const Context = context.Context;
const Action = context.Action;

/// POST /api/auth/refresh — refresh access token using refresh token.
/// NOT auth-wrapped (public endpoint with rate limiting).
pub fn handle(ctx: *Context, step: u32, prev_result: ?[]const u8) Action {
    switch (step) {
        0 => {
            // Parse body for refresh_token
            const rt = auth.extractJsonField(ctx.getAllocator(), ctx.body, "refresh_token") orelse
                return ctx.respondError(400, "refresh_token is required");
            if (std.mem.eql(u8, rt, "null"))
                return ctx.respondError(400, "refresh_token is required");

            ctx.stash("refresh_token", rt);

            // Look up refresh token in KV
            const key = std.fmt.allocPrint(ctx.getAllocator(), "rt:{s}", .{rt}) catch
                return ctx.respondError(500, "Internal error");
            return ctx.kvGet(key);
        },
        1 => {
            // KV result: userId or null
            const user_id_json = prev_result orelse return ctx.respondError(401, "Invalid or expired refresh token");
            const user_id = auth.parseJsonStringHelper(ctx.getAllocator(), user_id_json) orelse
                return ctx.respondError(401, "Invalid or expired refresh token");
            if (std.mem.eql(u8, user_id, "null"))
                return ctx.respondError(401, "Invalid or expired refresh token");

            ctx.stash("user_id", user_id);

            // Get user from DB
            return ctx.d1First(
                "SELECT id, email FROM users WHERE id = ?",
                &.{.{ .string = user_id }},
            );
        },
        2 => {
            // D1 result: user row or null
            const row = prev_result orelse return ctx.respondError(401, "User not found");
            if (std.mem.eql(u8, row, "null")) return ctx.respondError(401, "User not found");

            ctx.stash("user_row", row);

            // Revoke old refresh token
            const old_rt = ctx.load("refresh_token") orelse return ctx.respondError(500, "Internal error");
            const key = std.fmt.allocPrint(ctx.getAllocator(), "rt:{s}", .{old_rt}) catch
                return ctx.respondError(500, "Internal error");
            return ctx.kvDelete(key);
        },
        3 => {
            // Old refresh token revoked. Get JWT_SECRET to create new tokens.

            return ctx.envGet("JWT_SECRET");
        },
        4 => {
            // Got JWT_SECRET. Create new access token and refresh token.
            const alloc = ctx.getAllocator();
            const secret_json = prev_result orelse return ctx.respondError(500, "JWT_SECRET not configured");
            const secret = auth.parseJsonStringHelper(alloc, secret_json) orelse
                return ctx.respondError(500, "JWT_SECRET not configured");

            const user_id = ctx.load("user_id") orelse return ctx.respondError(500, "Internal error");
            const user_row = ctx.load("user_row") orelse return ctx.respondError(500, "Internal error");
            const email = auth.extractJsonField(alloc, user_row, "email") orelse "unknown";

            // Generate new refresh token ID (random hex)
            var rand_bytes: [16]u8 = undefined;
            getRandomBytes(&rand_bytes);
            var new_rt: [32]u8 = undefined;
            _ = auth.bytesToHex(&rand_bytes, &new_rt);
            ctx.stash("new_refresh_token", &new_rt);

            // Create JWT claims
            // TODO: proper timestamp from JS
            const claims = std.fmt.allocPrint(alloc,
                "{{\"sub\":\"{s}\",\"email\":\"{s}\",\"jti\":\"{s}\",\"exp\":9999999999}}",
                .{ user_id, email, new_rt[0..16] },
            ) catch return ctx.respondError(500, "Internal error");

            const token = jwt.createToken(alloc, claims, secret) catch
                return ctx.respondError(500, "Token creation failed");
            ctx.stash("access_token", token);

            // Store new refresh token in KV
            const kv_key = std.fmt.allocPrint(alloc, "rt:{s}", .{&new_rt}) catch
                return ctx.respondError(500, "Internal error");
            return ctx.kvPut(kv_key, user_id, 604800);
        },
        5 => {
            // KV put done. Build response.

            const alloc = ctx.getAllocator();
            const access_token = ctx.load("access_token") orelse return ctx.respondError(500, "Internal error");
            const refresh_token = ctx.load("new_refresh_token") orelse return ctx.respondError(500, "Internal error");

            const body = std.fmt.allocPrint(alloc,
                "{{\"access_token\":\"{s}\",\"refresh_token\":\"{s}\",\"token_type\":\"Bearer\",\"expires_in\":900}}",
                .{ access_token, refresh_token },
            ) catch return ctx.respondError(500, "Internal error");

            return ctx.respondJson(200, body);
        },
        else => return ctx.respondError(500, "Internal error"),
    }
}

extern "env" fn js_get_random_bytes(ptr: [*]u8, len: usize) void;

fn getRandomBytes(buf: []u8) void {
    if (builtin.cpu.arch == .wasm32) {
        js_get_random_bytes(buf.ptr, buf.len);
    } else {
        std.crypto.random.bytes(buf);
    }
}

// ============================================================
// Tests
// ============================================================

test "handleRefresh step 0 extracts refresh_token and issues KV get" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();
    ctx.body = "{\"refresh_token\":\"rt-abc123\"}";

    const action = handle(&ctx, 0, null);
    switch (action) {
        .cmd => |cmd| {
            try std.testing.expectEqual(command.Tag.kv_get, cmd.tag);
            try std.testing.expect(std.mem.indexOf(u8, cmd.data, "rt:rt-abc123") != null);
        },
        .response => return error.TestUnexpectedResult,
    }
}

test "handleRefresh step 0 missing refresh_token returns 400" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();
    ctx.body = "{}";

    const action = handle(&ctx, 0, null);
    switch (action) {
        .response => |resp| try std.testing.expectEqual(@as(u16, 400), resp.status),
        .cmd => return error.TestUnexpectedResult,
    }
}

test "handleRefresh step 1 with user_id issues D1 query" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();
    ctx.stash("refresh_token", "rt-abc123");

    const action = handle(&ctx, 1, "\"user-456\"");
    switch (action) {
        .cmd => |cmd| {
            try std.testing.expectEqual(command.Tag.d1_first, cmd.tag);
            try std.testing.expect(std.mem.indexOf(u8, cmd.data, "user-456") != null);
        },
        .response => return error.TestUnexpectedResult,
    }
}

test "handleRefresh step 1 with null token returns 401" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();

    const action = handle(&ctx, 1, "null");
    switch (action) {
        .response => |resp| try std.testing.expectEqual(@as(u16, 401), resp.status),
        .cmd => return error.TestUnexpectedResult,
    }
}

test "handleRefresh step 2 with user row issues KV delete" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();
    ctx.stash("refresh_token", "rt-abc123");

    const row = "{\"id\":\"u1\",\"email\":\"test@example.com\"}";
    const action = handle(&ctx, 2, row);
    switch (action) {
        .cmd => |cmd| {
            try std.testing.expectEqual(command.Tag.kv_delete, cmd.tag);
            try std.testing.expect(std.mem.indexOf(u8, cmd.data, "rt:rt-abc123") != null);
        },
        .response => return error.TestUnexpectedResult,
    }
}

test "handleRefresh step 2 with null user returns 401" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();

    const action = handle(&ctx, 2, "null");
    switch (action) {
        .response => |resp| try std.testing.expectEqual(@as(u16, 401), resp.status),
        .cmd => return error.TestUnexpectedResult,
    }
}

test "handleRefresh step 3 issues env_get for JWT_SECRET" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();

    const action = handle(&ctx, 3, null);
    switch (action) {
        .cmd => |cmd| {
            try std.testing.expectEqual(command.Tag.env_get, cmd.tag);
            try std.testing.expect(std.mem.indexOf(u8, cmd.data, "JWT_SECRET") != null);
        },
        .response => return error.TestUnexpectedResult,
    }
}
