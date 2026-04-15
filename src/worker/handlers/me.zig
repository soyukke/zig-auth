const std = @import("std");
const command = @import("../command.zig");
const context = @import("../context.zig");
const Context = context.Context;
const Action = context.Action;

/// GET /api/auth/me — return current user info.
/// Auth-wrapped: claims_sub is available in store.
pub fn handle(ctx: *Context, step: u32, prev_result: ?[]const u8) Action {
    switch (step) {
        0 => {
            const user_id = ctx.load("claims_sub") orelse
                return ctx.respondError(401, "Unauthorized");
            return ctx.d1First(
                "SELECT id, email, created_at, updated_at FROM users WHERE id = ?",
                &.{.{ .string = user_id }},
            );
        },
        1 => {
            const row = prev_result orelse return ctx.respondError(404, "User not found");
            if (std.mem.eql(u8, row, "null")) return ctx.respondError(404, "User not found");
            return ctx.respondJson(200, row);
        },
        else => return ctx.respondError(500, "Internal error"),
    }
}

// ============================================================
// Tests
// ============================================================

test "handleMe step 0 issues D1 query with user_id" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();
    ctx.stash("claims_sub", "user-123");

    const action = handle(&ctx, 0, null);
    switch (action) {
        .cmd => |cmd| {
            try std.testing.expectEqual(command.Tag.d1_first, cmd.tag);
            try std.testing.expect(std.mem.indexOf(u8, cmd.data, "users") != null);
            try std.testing.expect(std.mem.indexOf(u8, cmd.data, "user-123") != null);
        },
        .response => return error.TestUnexpectedResult,
    }
}

test "handleMe step 0 without claims returns 401" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();

    const action = handle(&ctx, 0, null);
    switch (action) {
        .response => |resp| try std.testing.expectEqual(@as(u16, 401), resp.status),
        .cmd => return error.TestUnexpectedResult,
    }
}

test "handleMe step 1 returns user data" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();

    const row = "{\"id\":\"u1\",\"email\":\"test@example.com\",\"created_at\":\"2024-01-01\",\"updated_at\":\"2024-01-01\"}";
    const action = handle(&ctx, 1, row);
    switch (action) {
        .response => |resp| {
            try std.testing.expectEqual(@as(u16, 200), resp.status);
            try std.testing.expect(std.mem.indexOf(u8, resp.body, "test@example.com") != null);
        },
        .cmd => return error.TestUnexpectedResult,
    }
}

test "handleMe step 1 with null result returns 404" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();

    const action = handle(&ctx, 1, "null");
    switch (action) {
        .response => |resp| try std.testing.expectEqual(@as(u16, 404), resp.status),
        .cmd => return error.TestUnexpectedResult,
    }
}

test "handleMe step 1 with no result returns 404" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();

    const action = handle(&ctx, 1, null);
    switch (action) {
        .response => |resp| try std.testing.expectEqual(@as(u16, 404), resp.status),
        .cmd => return error.TestUnexpectedResult,
    }
}
