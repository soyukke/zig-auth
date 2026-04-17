const std = @import("std");
const Allocator = std.mem.Allocator;
const command = @import("command.zig");

/// Action returned by handler step functions.
/// Either a command to send to JS, or the final HTTP response.
pub const Action = union(enum) {
    /// Issue an async command to JS. Handler will be resumed with the result.
    cmd: struct {
        tag: command.Tag,
        data: []const u8,
    },
    /// Final HTTP response. No more handler steps.
    response: Response,
};

pub const Response = struct {
    status: u16,
    body: []const u8,
    headers_json: []const u8 = "{\"Content-Type\":\"application/json\"}",
};

pub const Method = enum {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    HEAD,
    OPTIONS,

    pub fn fromString(s: []const u8) ?Method {
        if (std.mem.eql(u8, s, "GET")) return .GET;
        if (std.mem.eql(u8, s, "POST")) return .POST;
        if (std.mem.eql(u8, s, "PUT")) return .PUT;
        if (std.mem.eql(u8, s, "DELETE")) return .DELETE;
        if (std.mem.eql(u8, s, "PATCH")) return .PATCH;
        if (std.mem.eql(u8, s, "HEAD")) return .HEAD;
        if (std.mem.eql(u8, s, "OPTIONS")) return .OPTIONS;
        return null;
    }
};

/// Request context for a single HTTP request.
/// Manages state machine progression and provides helpers for issuing commands.
pub const Context = struct {
    arena: std.heap.ArenaAllocator,

    // Request data
    method: Method = .GET,
    path: []const u8 = "",
    body: []const u8 = "",
    headers_json: []const u8 = "{}",

    // Route params (set by router)
    params: std.StringHashMapUnmanaged([]const u8) = .empty,

    // Handler state machine step counter
    step: u32 = 0,

    // Key-value store for intermediate values between steps
    store: std.StringHashMapUnmanaged([]const u8) = .empty,

    pub fn init(child_allocator: Allocator) Context {
        return .{
            .arena = std.heap.ArenaAllocator.init(child_allocator),
        };
    }

    pub fn deinit(self: *Context) void {
        self.arena.deinit();
    }

    pub fn getAllocator(self: *Context) Allocator {
        return self.arena.allocator();
    }

    // --- Store helpers ---

    pub fn stash(self: *Context, key: []const u8, value: []const u8) void {
        const alloc = self.getAllocator();
        const owned_key = alloc.dupe(u8, key) catch return;
        const owned_val = alloc.dupe(u8, value) catch return;
        self.store.put(alloc, owned_key, owned_val) catch return;
    }

    pub fn load(self: *Context, key: []const u8) ?[]const u8 {
        return self.store.get(key);
    }

    // --- Command issuers ---

    pub fn d1First(self: *Context, sql: []const u8, params: []const command.Param) Action {
        return self.makeCmd(.d1_first, command.allocD1Query(self.getAllocator(), sql, params) catch return self.internalError());
    }

    pub fn d1All(self: *Context, sql: []const u8, params: []const command.Param) Action {
        return self.makeCmd(.d1_all, command.allocD1Query(self.getAllocator(), sql, params) catch return self.internalError());
    }

    pub fn d1Run(self: *Context, sql: []const u8, params: []const command.Param) Action {
        return self.makeCmd(.d1_run, command.allocD1Query(self.getAllocator(), sql, params) catch return self.internalError());
    }

    pub fn d1Batch(self: *Context, statements: []const command.D1Statement) Action {
        const alloc = self.getAllocator();
        var aw: std.Io.Writer.Allocating = .init(alloc);
        defer aw.deinit();
        command.writeD1Batch(&aw.writer, statements) catch return self.internalError();
        const buf = aw.toArrayList();
        return self.makeCmd(.d1_batch, buf.items);
    }

    pub fn kvGet(self: *Context, key: []const u8) Action {
        return self.makeCmd(.kv_get, command.allocKvGet(self.getAllocator(), key) catch return self.internalError());
    }

    pub fn kvPut(self: *Context, key: []const u8, value: []const u8, ttl: ?u32) Action {
        return self.makeCmd(.kv_put, command.allocKvPut(self.getAllocator(), key, value, ttl) catch return self.internalError());
    }

    pub fn kvDelete(self: *Context, key: []const u8) Action {
        return self.makeCmd(.kv_delete, command.allocKvDelete(self.getAllocator(), key) catch return self.internalError());
    }

    pub fn httpFetch(self: *Context, url: []const u8, method: []const u8, headers: ?[]const u8, fetch_body: ?[]const u8) Action {
        const alloc = self.getAllocator();
        var aw: std.Io.Writer.Allocating = .init(alloc);
        defer aw.deinit();
        command.writeFetch(&aw.writer, url, method, headers, fetch_body) catch return self.internalError();
        const buf = aw.toArrayList();
        return self.makeCmd(.http_fetch, buf.items);
    }

    pub fn envGet(self: *Context, name: []const u8) Action {
        const alloc = self.getAllocator();
        var aw: std.Io.Writer.Allocating = .init(alloc);
        defer aw.deinit();
        command.writeEnvGet(&aw.writer, name) catch return self.internalError();
        const buf = aw.toArrayList();
        return self.makeCmd(.env_get, buf.items);
    }

    // --- Response builders ---

    pub fn respond(self: *Context, status: u16, body: []const u8) Action {
        _ = self;
        return .{ .response = .{ .status = status, .body = body } };
    }

    pub fn respondJson(self: *Context, status: u16, json_body: []const u8) Action {
        _ = self;
        return .{ .response = .{
            .status = status,
            .body = json_body,
            .headers_json = "{\"Content-Type\":\"application/json\"}",
        } };
    }

    pub fn respondError(self: *Context, status: u16, message: []const u8) Action {
        const alloc = self.getAllocator();
        var aw: std.Io.Writer.Allocating = .init(alloc);
        defer aw.deinit();
        const writer = &aw.writer;
        writer.writeAll("{\"error\":") catch return self.internalError();
        command.writeJsonString(writer, message) catch return self.internalError();
        writer.writeByte('}') catch return self.internalError();
        const buf = aw.toArrayList();
        return .{ .response = .{
            .status = status,
            .body = buf.items,
            .headers_json = "{\"Content-Type\":\"application/json\"}",
        } };
    }

    pub fn respondRedirect(self: *Context, url: []const u8) Action {
        const alloc = self.getAllocator();
        var aw: std.Io.Writer.Allocating = .init(alloc);
        defer aw.deinit();
        const w = &aw.writer;
        w.writeAll("{\"Location\":") catch return self.internalError();
        command.writeJsonString(w, url) catch return self.internalError();
        w.writeByte('}') catch return self.internalError();
        const buf = aw.toArrayList();
        return .{ .response = .{
            .status = 302,
            .body = "",
            .headers_json = buf.items,
        } };
    }

    // --- Internals ---

    fn makeCmd(self: *Context, tag: command.Tag, data: []const u8) Action {
        _ = self;
        return .{ .cmd = .{ .tag = tag, .data = data } };
    }

    fn internalError(self: *Context) Action {
        _ = self;
        return .{ .response = .{
            .status = 500,
            .body = "{\"error\":\"Internal server error\"}",
            .headers_json = "{\"Content-Type\":\"application/json\"}",
        } };
    }

    /// Advance the step counter and return the current step value.
    pub fn nextStep(self: *Context) u32 {
        const current = self.step;
        self.step += 1;
        return current;
    }
};

// ============================================================
// Tests
// ============================================================

test "Context init and deinit" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();

    try std.testing.expectEqual(Method.GET, ctx.method);
    try std.testing.expectEqualStrings("", ctx.path);
    try std.testing.expectEqual(@as(u32, 0), ctx.step);
}

test "Context stash and load" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();

    ctx.stash("user_id", "abc123");
    ctx.stash("challenge", "xyz789");

    try std.testing.expectEqualStrings("abc123", ctx.load("user_id").?);
    try std.testing.expectEqualStrings("xyz789", ctx.load("challenge").?);
    try std.testing.expect(ctx.load("nonexistent") == null);
}

test "Context d1First returns cmd action" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();

    const action = ctx.d1First("SELECT * FROM users WHERE id = ?", &.{
        .{ .string = "u1" },
    });

    switch (action) {
        .cmd => |cmd| {
            try std.testing.expectEqual(command.Tag.d1_first, cmd.tag);
            try std.testing.expect(std.mem.indexOf(u8, cmd.data, "SELECT * FROM users") != null);
            try std.testing.expect(std.mem.indexOf(u8, cmd.data, "\"u1\"") != null);
        },
        .response => return error.TestUnexpectedResult,
    }
}

test "Context d1All returns cmd action" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();

    const action = ctx.d1All("SELECT * FROM passkeys WHERE user_id = ?", &.{
        .{ .string = "u1" },
    });

    switch (action) {
        .cmd => |cmd| {
            try std.testing.expectEqual(command.Tag.d1_all, cmd.tag);
        },
        .response => return error.TestUnexpectedResult,
    }
}

test "Context kvGet returns cmd action" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();

    const action = ctx.kvGet("rt:abc123");

    switch (action) {
        .cmd => |cmd| {
            try std.testing.expectEqual(command.Tag.kv_get, cmd.tag);
            try std.testing.expect(std.mem.indexOf(u8, cmd.data, "rt:abc123") != null);
        },
        .response => return error.TestUnexpectedResult,
    }
}

test "Context kvPut returns cmd action with TTL" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();

    const action = ctx.kvPut("rt:token1", "user123", 604800);

    switch (action) {
        .cmd => |cmd| {
            try std.testing.expectEqual(command.Tag.kv_put, cmd.tag);
            try std.testing.expect(std.mem.indexOf(u8, cmd.data, "604800") != null);
        },
        .response => return error.TestUnexpectedResult,
    }
}

test "Context kvDelete returns cmd action" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();

    const action = ctx.kvDelete("rt:old-token");

    switch (action) {
        .cmd => |cmd| {
            try std.testing.expectEqual(command.Tag.kv_delete, cmd.tag);
        },
        .response => return error.TestUnexpectedResult,
    }
}

test "Context respond returns response action" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();

    const action = ctx.respond(200, "{\"ok\":true}");

    switch (action) {
        .response => |resp| {
            try std.testing.expectEqual(@as(u16, 200), resp.status);
            try std.testing.expectEqualStrings("{\"ok\":true}", resp.body);
        },
        .cmd => return error.TestUnexpectedResult,
    }
}

test "Context respondJson sets content-type" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();

    const action = ctx.respondJson(201, "{\"id\":\"new\"}");

    switch (action) {
        .response => |resp| {
            try std.testing.expectEqual(@as(u16, 201), resp.status);
            try std.testing.expect(std.mem.indexOf(u8, resp.headers_json, "application/json") != null);
        },
        .cmd => return error.TestUnexpectedResult,
    }
}

test "Context respondError produces JSON error" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();

    const action = ctx.respondError(400, "Bad request");

    switch (action) {
        .response => |resp| {
            try std.testing.expectEqual(@as(u16, 400), resp.status);
            try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"error\"") != null);
            try std.testing.expect(std.mem.indexOf(u8, resp.body, "Bad request") != null);
        },
        .cmd => return error.TestUnexpectedResult,
    }
}

test "Context nextStep advances step counter" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();

    try std.testing.expectEqual(@as(u32, 0), ctx.nextStep());
    try std.testing.expectEqual(@as(u32, 1), ctx.nextStep());
    try std.testing.expectEqual(@as(u32, 2), ctx.nextStep());
    try std.testing.expectEqual(@as(u32, 3), ctx.step);
}

test "Method.fromString" {
    try std.testing.expectEqual(Method.GET, Method.fromString("GET").?);
    try std.testing.expectEqual(Method.POST, Method.fromString("POST").?);
    try std.testing.expectEqual(Method.PUT, Method.fromString("PUT").?);
    try std.testing.expectEqual(Method.DELETE, Method.fromString("DELETE").?);
    try std.testing.expect(Method.fromString("INVALID") == null);
}
