const std = @import("std");
const Allocator = std.mem.Allocator;
const context = @import("context.zig");
const Context = context.Context;
const Action = context.Action;
const Method = context.Method;

/// Handler function type: (context, step, previous async result) → next action
pub const HandlerFn = *const fn (ctx: *Context, step: u32, prev_result: ?[]const u8) Action;

pub const Route = struct {
    method: Method,
    /// Pattern segments, e.g. "/api/auth/passkeys/:id" → ["api","auth","passkeys",":id"]
    segments: []const []const u8,
    handler: HandlerFn,
};

pub const MatchResult = struct {
    handler: HandlerFn,
    params: std.StringHashMapUnmanaged([]const u8),
};

pub const Router = struct {
    routes: []const Route,

    /// Match a method + path against registered routes.
    /// Returns the handler and extracted path parameters, or null if no match.
    pub fn match(self: *const Router, alloc: Allocator, method: Method, path: []const u8) ?MatchResult {
        const path_segments = splitPath(path);

        for (self.routes) |route| {
            if (route.method != method) continue;

            if (matchSegments(alloc, route.segments, path_segments)) |params| {
                return .{
                    .handler = route.handler,
                    .params = params,
                };
            }
        }
        return null;
    }
};

/// Split a URL path into segments, ignoring leading slash and query string.
/// e.g. "/api/auth/passkeys/123?foo=bar" → iterator over ["api","auth","passkeys","123"]
fn splitPath(path: []const u8) PathIterator {
    // Strip leading slash
    var start: usize = 0;
    if (path.len > 0 and path[0] == '/') start = 1;

    // Strip query string
    var end = path.len;
    if (std.mem.indexOf(u8, path, "?")) |q| {
        end = q;
    }

    return .{
        .path = path[start..end],
        .pos = 0,
    };
}

const PathIterator = struct {
    path: []const u8,
    pos: usize,

    fn next(self: *PathIterator) ?[]const u8 {
        if (self.pos >= self.path.len) return null;

        const start = self.pos;
        while (self.pos < self.path.len and self.path[self.pos] != '/') {
            self.pos += 1;
        }
        const segment = self.path[start..self.pos];

        // Skip the slash
        if (self.pos < self.path.len) self.pos += 1;

        return segment;
    }

    fn count(self: *PathIterator) usize {
        var copy = self.*;
        var n: usize = 0;
        while (copy.next()) |_| n += 1;
        return n;
    }
};

/// Match route pattern segments against path segments.
/// Pattern segments starting with ':' are params (match any non-empty segment).
/// Returns extracted params hashmap on match, null on mismatch.
fn matchSegments(alloc: Allocator, pattern: []const []const u8, path_iter_orig: PathIterator) ?std.StringHashMapUnmanaged([]const u8) {
    var path_iter = path_iter_orig;
    var params: std.StringHashMapUnmanaged([]const u8) = .empty;

    for (pattern) |pat_seg| {
        const path_seg = path_iter.next() orelse {
            // Path has fewer segments than pattern
            return null;
        };

        if (pat_seg.len > 0 and pat_seg[0] == ':') {
            // Parameter segment — store value
            const param_name = pat_seg[1..];
            params.put(alloc, param_name, path_seg) catch {
                params.deinit(alloc);
                return null;
            };
        } else {
            // Literal segment — must match exactly
            if (!std.mem.eql(u8, pat_seg, path_seg)) {
                params.deinit(alloc);
                return null;
            }
        }
    }

    // Path must have no extra segments
    if (path_iter.next() != null) {
        params.deinit(alloc);
        return null;
    }

    return params;
}

/// Compile-time helper: split a route pattern string into segments.
/// Returns a comptime-known slice of string slices.
pub fn compilePattern(comptime pattern: []const u8) []const []const u8 {
    return comptime blk: {
        // First pass: count segments
        var count: usize = 0;
        var cs: usize = if (pattern.len > 0 and pattern[0] == '/') 1 else 0;
        var ci: usize = cs;
        while (ci <= pattern.len) : (ci += 1) {
            if (ci == pattern.len or pattern[ci] == '/') {
                if (ci > cs) count += 1;
                cs = ci + 1;
            }
        }

        // Second pass: collect segments
        var segments: [count][]const u8 = undefined;
        var idx: usize = 0;
        cs = if (pattern.len > 0 and pattern[0] == '/') 1 else 0;
        ci = cs;
        while (ci <= pattern.len) : (ci += 1) {
            if (ci == pattern.len or pattern[ci] == '/') {
                if (ci > cs) {
                    segments[idx] = pattern[cs..ci];
                    idx += 1;
                }
                cs = ci + 1;
            }
        }

        const final = segments;
        break :blk &final;
    };
}

// ============================================================
// Tests
// ============================================================

fn dummyHandler(_: *Context, _: u32, _: ?[]const u8) context.Action {
    return .{ .response = .{ .status = 200, .body = "ok" } };
}

fn dummyHandler2(_: *Context, _: u32, _: ?[]const u8) context.Action {
    return .{ .response = .{ .status = 201, .body = "created" } };
}

test "compilePattern basic" {
    const segments = compilePattern("/api/auth/passkeys");
    try std.testing.expectEqual(@as(usize, 3), segments.len);
    try std.testing.expectEqualStrings("api", segments[0]);
    try std.testing.expectEqualStrings("auth", segments[1]);
    try std.testing.expectEqualStrings("passkeys", segments[2]);
}

test "compilePattern with params" {
    const segments = compilePattern("/api/tenants/:id/members/:userId");
    try std.testing.expectEqual(@as(usize, 5), segments.len);
    try std.testing.expectEqualStrings("api", segments[0]);
    try std.testing.expectEqualStrings("tenants", segments[1]);
    try std.testing.expectEqualStrings(":id", segments[2]);
    try std.testing.expectEqualStrings("members", segments[3]);
    try std.testing.expectEqualStrings(":userId", segments[4]);
}

test "splitPath basic" {
    var iter = splitPath("/api/auth/passkeys");
    try std.testing.expectEqualStrings("api", iter.next().?);
    try std.testing.expectEqualStrings("auth", iter.next().?);
    try std.testing.expectEqualStrings("passkeys", iter.next().?);
    try std.testing.expect(iter.next() == null);
}

test "splitPath strips query string" {
    var iter = splitPath("/api/auth/oauth/github?code=abc&state=xyz");
    try std.testing.expectEqualStrings("api", iter.next().?);
    try std.testing.expectEqualStrings("auth", iter.next().?);
    try std.testing.expectEqualStrings("oauth", iter.next().?);
    try std.testing.expectEqualStrings("github", iter.next().?);
    try std.testing.expect(iter.next() == null);
}

test "splitPath root" {
    var iter = splitPath("/");
    try std.testing.expect(iter.next() == null);
}

test "Router match exact path" {
    const routes: []const Route = &.{
        .{ .method = .GET, .segments = compilePattern("/api/auth/me"), .handler = &dummyHandler },
        .{ .method = .POST, .segments = compilePattern("/api/auth/logout"), .handler = &dummyHandler2 },
    };
    const router = Router{ .routes = routes };

    var result = router.match(std.testing.allocator, .GET, "/api/auth/me").?;
    defer result.params.deinit(std.testing.allocator);
    try std.testing.expect(result.handler == &dummyHandler);
}

test "Router match with params" {
    const routes: []const Route = &.{
        .{ .method = .DELETE, .segments = compilePattern("/api/auth/passkeys/:id"), .handler = &dummyHandler },
    };
    const router = Router{ .routes = routes };

    var result = router.match(std.testing.allocator, .DELETE, "/api/auth/passkeys/pk_abc123").?;
    defer result.params.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("pk_abc123", result.params.get("id").?);
}

test "Router match with multiple params" {
    const routes: []const Route = &.{
        .{ .method = .PUT, .segments = compilePattern("/api/tenants/:id/members/:userId"), .handler = &dummyHandler },
    };
    const router = Router{ .routes = routes };

    var result = router.match(std.testing.allocator, .PUT, "/api/tenants/t1/members/u2").?;
    defer result.params.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("t1", result.params.get("id").?);
    try std.testing.expectEqualStrings("u2", result.params.get("userId").?);
}

test "Router no match wrong method" {
    const routes: []const Route = &.{
        .{ .method = .GET, .segments = compilePattern("/api/auth/me"), .handler = &dummyHandler },
    };
    const router = Router{ .routes = routes };

    const result = router.match(std.testing.allocator, .POST, "/api/auth/me");
    try std.testing.expect(result == null);
}

test "Router no match wrong path" {
    const routes: []const Route = &.{
        .{ .method = .GET, .segments = compilePattern("/api/auth/me"), .handler = &dummyHandler },
    };
    const router = Router{ .routes = routes };

    const result = router.match(std.testing.allocator, .GET, "/api/auth/you");
    try std.testing.expect(result == null);
}

test "Router no match extra segments" {
    const routes: []const Route = &.{
        .{ .method = .GET, .segments = compilePattern("/api/auth/me"), .handler = &dummyHandler },
    };
    const router = Router{ .routes = routes };

    const result = router.match(std.testing.allocator, .GET, "/api/auth/me/extra");
    try std.testing.expect(result == null);
}

test "Router no match fewer segments" {
    const routes: []const Route = &.{
        .{ .method = .GET, .segments = compilePattern("/api/auth/me"), .handler = &dummyHandler },
    };
    const router = Router{ .routes = routes };

    const result = router.match(std.testing.allocator, .GET, "/api/auth");
    try std.testing.expect(result == null);
}

test "Router strips query string for matching" {
    const routes: []const Route = &.{
        .{ .method = .GET, .segments = compilePattern("/api/auth/oauth/:provider/callback"), .handler = &dummyHandler },
    };
    const router = Router{ .routes = routes };

    var result = router.match(std.testing.allocator, .GET, "/api/auth/oauth/github/callback?code=abc&state=xyz").?;
    defer result.params.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("github", result.params.get("provider").?);
}

test "Router first match wins" {
    const routes: []const Route = &.{
        .{ .method = .GET, .segments = compilePattern("/api/health"), .handler = &dummyHandler },
        .{ .method = .GET, .segments = compilePattern("/api/health"), .handler = &dummyHandler2 },
    };
    const router = Router{ .routes = routes };

    const result = router.match(std.testing.allocator, .GET, "/api/health");
    try std.testing.expect(result != null);
    try std.testing.expect(result.?.handler == &dummyHandler);
}
