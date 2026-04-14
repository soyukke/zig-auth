const std = @import("std");
const argon2 = std.crypto.pwhash.argon2;
const bcrypt_mod = std.crypto.pwhash.bcrypt;
const timer = std.time;

pub fn main() !void {
    const password = "benchmarkpassword123";
    var salt: [16]u8 = undefined;
    @memset(&salt, 0x42);

    // bcrypt cost 5
    {
        const start = timer.nanoTimestamp();
        _ = bcrypt_mod.bcrypt(password, salt, .{ .rounds_log = 5, .silently_truncate_password = false });
        const elapsed_ms = @as(f64, @floatFromInt(timer.nanoTimestamp() - start)) / 1_000_000.0;
        std.debug.print("bcrypt cost=5:             {d:.1}ms\n", .{elapsed_ms});
    }

    // bcrypt cost 10 (OWASP recommended)
    {
        const start = timer.nanoTimestamp();
        _ = bcrypt_mod.bcrypt(password, salt, .{ .rounds_log = 10, .silently_truncate_password = false });
        const elapsed_ms = @as(f64, @floatFromInt(timer.nanoTimestamp() - start)) / 1_000_000.0;
        std.debug.print("bcrypt cost=10:            {d:.1}ms\n", .{elapsed_ms});
    }

    // Argon2id - minimal (t=1, m=4KB)
    {
        const start = timer.nanoTimestamp();
        var out: [32]u8 = undefined;
        argon2.kdf(std.heap.page_allocator, &out, password, &salt, .{ .t = 1, .m = 4, .p = 1 }, .argon2id) catch {};
        const elapsed_ms = @as(f64, @floatFromInt(timer.nanoTimestamp() - start)) / 1_000_000.0;
        std.debug.print("argon2id t=1,m=4KB:        {d:.1}ms\n", .{elapsed_ms});
    }

    // Argon2id - light (t=2, m=64KB)
    {
        const start = timer.nanoTimestamp();
        var out: [32]u8 = undefined;
        argon2.kdf(std.heap.page_allocator, &out, password, &salt, .{ .t = 2, .m = 64, .p = 1 }, .argon2id) catch {};
        const elapsed_ms = @as(f64, @floatFromInt(timer.nanoTimestamp() - start)) / 1_000_000.0;
        std.debug.print("argon2id t=2,m=64KB:       {d:.1}ms\n", .{elapsed_ms});
    }

    // Argon2id - moderate (t=2, m=1MB)
    {
        const start = timer.nanoTimestamp();
        var out: [32]u8 = undefined;
        argon2.kdf(std.heap.page_allocator, &out, password, &salt, .{ .t = 2, .m = 1024, .p = 1 }, .argon2id) catch {};
        const elapsed_ms = @as(f64, @floatFromInt(timer.nanoTimestamp() - start)) / 1_000_000.0;
        std.debug.print("argon2id t=2,m=1MB:        {d:.1}ms\n", .{elapsed_ms});
    }

    // Argon2id - OWASP (t=2, m=19MB)
    {
        const start = timer.nanoTimestamp();
        var out: [32]u8 = undefined;
        argon2.kdf(std.heap.page_allocator, &out, password, &salt, .{ .t = 2, .m = 19456, .p = 1 }, .argon2id) catch {};
        const elapsed_ms = @as(f64, @floatFromInt(timer.nanoTimestamp() - start)) / 1_000_000.0;
        std.debug.print("argon2id t=2,m=19MB(OWASP):{d:.1}ms\n", .{elapsed_ms});
    }
}
