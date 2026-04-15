const std = @import("std");
const builtin = @import("builtin");
const command = @import("command.zig");
const context = @import("context.zig");
const router = @import("router.zig");
const auth = @import("auth.zig");
const handlers_me = @import("handlers/me.zig");
const handlers_logout = @import("handlers/logout.zig");
const handlers_refresh = @import("handlers/refresh.zig");
const Context = context.Context;
const Action = context.Action;
const Method = context.Method;

const is_wasm = builtin.cpu.arch == .wasm32;
const wasm_allocator = if (is_wasm) std.heap.wasm_allocator else undefined;

// --- Global state (per-request, single-threaded WASM) ---

var ctx: ?Context = null;
var cmd_data: ?[]const u8 = null;
var current_handler: ?router.HandlerFn = null;

// --- Health check handler ---

fn handleHealth(c: *Context, step: u32, _: ?[]const u8) Action {
    _ = step;
    return c.respondJson(200, "{\"status\":\"ok\"}");
}

// --- Route table ---

const routes: []const router.Route = &.{
    // Health check
    .{ .method = .GET, .segments = router.compilePattern("/health"), .handler = &handleHealth },
    .{ .method = .GET, .segments = router.compilePattern("/api/health"), .handler = &handleHealth },

    // Session management
    .{ .method = .GET, .segments = router.compilePattern("/api/auth/me"), .handler = auth.withAuth(handlers_me.handle) },
    .{ .method = .POST, .segments = router.compilePattern("/api/auth/logout"), .handler = auth.withAuth(handlers_logout.handle) },
    .{ .method = .POST, .segments = router.compilePattern("/api/auth/refresh"), .handler = &handlers_refresh.handle },
};

const app_router = router.Router{ .routes = routes };

// --- WASM exports ---

/// Start handling an HTTP request.
/// JS passes request data as ptr+len strings.
/// Returns a command tag (0 = response ready, >0 = needs async operation).
export fn handle_request(
    method_ptr: [*]const u8,
    method_len: usize,
    path_ptr: [*]const u8,
    path_len: usize,
    body_ptr: [*]const u8,
    body_len: usize,
    headers_ptr: [*]const u8,
    headers_len: usize,
) u8 {
    // Clean up any previous request
    cleanup();

    const alloc = if (is_wasm) wasm_allocator else return 0;

    // Initialize context
    ctx = Context.init(alloc);
    var c = &ctx.?;

    const method_str = method_ptr[0..method_len];
    c.method = Method.fromString(method_str) orelse {
        setErrorResponse(c, 405, "Method not allowed");
        return @intFromEnum(command.Tag.response);
    };
    c.path = path_ptr[0..path_len];
    c.body = body_ptr[0..body_len];
    c.headers_json = headers_ptr[0..headers_len];

    // Route the request
    if (app_router.match(c.getAllocator(), c.method, c.path)) |match_result| {
        current_handler = match_result.handler;
        c.params = match_result.params;
    } else {
        // No route matched — signal JS to try the old router
        return @intFromEnum(command.Tag.route_not_found);
    }

    // Run step 0
    return runHandler(c, null);
}

/// Continue handling after JS completes an async operation.
/// JS passes the result as ptr+len string. error_code: 0 = success, >0 = error.
/// Returns next command tag.
export fn request_resume(result_ptr: [*]const u8, result_len: usize, error_code: u32) u8 {
    const c = &(ctx orelse return @intFromEnum(command.Tag.response));

    const result: ?[]const u8 = if (error_code != 0)
        null
    else if (result_len > 0)
        result_ptr[0..result_len]
    else
        null;

    return runHandler(c, result);
}

/// Get pointer to the current command payload data.
export fn get_cmd_ptr() usize {
    return if (cmd_data) |d| @intFromPtr(d.ptr) else 0;
}

/// Get length of the current command payload data.
export fn get_cmd_len() usize {
    return if (cmd_data) |d| d.len else 0;
}

// --- Internal helpers ---

fn runHandler(c: *Context, prev_result: ?[]const u8) u8 {
    const handler = current_handler orelse {
        setErrorResponse(c, 500, "No handler");
        return @intFromEnum(command.Tag.response);
    };

    const step = c.nextStep();
    const action = handler(c, step, prev_result);

    return handleAction(c, action);
}

fn handleAction(c: *Context, action: Action) u8 {
    switch (action) {
        .cmd => |cmd_info| {
            cmd_data = cmd_info.data;
            return @intFromEnum(cmd_info.tag);
        },
        .response => |resp| {
            // Serialize the response as the command payload
            const alloc = c.getAllocator();
            cmd_data = command.allocResponse(alloc, resp.status, resp.headers_json, resp.body) catch blk: {
                break :blk "{\"status\":500,\"headers\":{\"Content-Type\":\"application/json\"},\"body\":\"{\\\"error\\\":\\\"Internal server error\\\"}\"}";
            };
            return @intFromEnum(command.Tag.response);
        },
    }
}

fn setErrorResponse(c: *Context, status: u16, message: []const u8) void {
    const action = c.respondError(status, message);
    _ = handleAction(c, action);
}

fn cleanup() void {
    cmd_data = null;
    current_handler = null;
    if (ctx) |*c| {
        c.deinit();
        ctx = null;
    }
}
