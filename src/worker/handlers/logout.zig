const std = @import("std");
const command = @import("../command.zig");
const context = @import("../context.zig");
const auth = @import("../auth.zig");
const Context = context.Context;
const Action = context.Action;

/// POST /api/auth/logout — invalidate current token + optional refresh token.
/// Auth-wrapped: claims are available in store.
pub fn handle(ctx: *Context, step: u32, prev_result: ?[]const u8) Action {
    _ = prev_result;
    switch (step) {
        0 => {
            // Add JWT to blocklist if jti is present
            const jti = ctx.load("claims_jti") orelse {
                // No JTI — skip blocklist, try to revoke refresh token
                return tryRevokeRefreshToken(ctx);
            };

            // Compute TTL: remaining time until exp
            // For now, use a fixed TTL of 900 seconds (max JWT lifetime)
            const ttl: u32 = 900;


            return ctx.kvPut(
                std.fmt.allocPrint(ctx.getAllocator(), "bl:{s}", .{jti}) catch return ctx.respondError(500, "Internal error"),
                "1",
                ttl,
            );
        },
        1 => {
            // KV put done (blocklist). Now try to revoke refresh token.

            return tryRevokeRefreshToken(ctx);
        },
        2 => {
            // KV delete done (refresh token revoked). Return success.

            return ctx.respondJson(200, "{\"message\":\"Logged out\"}");
        },
        else => return ctx.respondError(500, "Internal error"),
    }
}

fn tryRevokeRefreshToken(ctx: *Context) Action {
    // Parse body for refresh_token
    if (ctx.body.len > 0) {
        if (auth.extractJsonField(ctx.getAllocator(), ctx.body, "refresh_token")) |rt| {
            if (!std.mem.eql(u8, rt, "null")) {
                const key = std.fmt.allocPrint(ctx.getAllocator(), "rt:{s}", .{rt}) catch
                    return ctx.respondError(500, "Internal error");
                return ctx.kvDelete(key);
            }
        }
    }
    // No refresh token to revoke — done
    return ctx.respondJson(200, "{\"message\":\"Logged out\"}");
}

// ============================================================
// Tests
// ============================================================

test "handleLogout step 0 with jti adds to blocklist" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();
    ctx.stash("claims_jti", "jwt-id-1");

    const action = handle(&ctx, 0, null);
    switch (action) {
        .cmd => |cmd| {
            try std.testing.expectEqual(command.Tag.kv_put, cmd.tag);
            try std.testing.expect(std.mem.indexOf(u8, cmd.data, "bl:jwt-id-1") != null);
        },
        .response => return error.TestUnexpectedResult,
    }
}

test "handleLogout step 0 without jti returns success directly" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();
    ctx.body = "{}";

    const action = handle(&ctx, 0, null);
    switch (action) {
        .response => |resp| {
            try std.testing.expectEqual(@as(u16, 200), resp.status);
            try std.testing.expect(std.mem.indexOf(u8, resp.body, "Logged out") != null);
        },
        .cmd => return error.TestUnexpectedResult,
    }
}

test "handleLogout step 1 with refresh_token revokes it" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();
    ctx.body = "{\"refresh_token\":\"rt-abc123\"}";

    const action = handle(&ctx, 1, null);
    switch (action) {
        .cmd => |cmd| {
            try std.testing.expectEqual(command.Tag.kv_delete, cmd.tag);
            try std.testing.expect(std.mem.indexOf(u8, cmd.data, "rt:rt-abc123") != null);
        },
        .response => return error.TestUnexpectedResult,
    }
}

test "handleLogout step 1 without refresh_token returns success" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();
    ctx.body = "{}";

    const action = handle(&ctx, 1, null);
    switch (action) {
        .response => |resp| {
            try std.testing.expectEqual(@as(u16, 200), resp.status);
        },
        .cmd => return error.TestUnexpectedResult,
    }
}

test "handleLogout step 2 returns success" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();

    const action = handle(&ctx, 2, null);
    switch (action) {
        .response => |resp| {
            try std.testing.expectEqual(@as(u16, 200), resp.status);
        },
        .cmd => return error.TestUnexpectedResult,
    }
}
