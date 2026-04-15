const std = @import("std");
const Allocator = std.mem.Allocator;

pub const CborError = error{
    InvalidMajorType,
    UnexpectedEndOfInput,
    InvalidAdditionalInfo,
    Overflow,
    MaxDepthExceeded,
    OutOfMemory,
};

const MAX_NESTING_DEPTH: usize = 16;

pub const CborValue = union(enum) {
    unsigned: u64,
    negative: i65,
    bytes: []const u8,
    text: []const u8,
    array: []const CborValue,
    map: []const MapEntry,

    pub const MapEntry = struct {
        key: CborValue,
        value: CborValue,
    };
};

pub const DecodeResult = struct {
    value: CborValue,
    bytes_consumed: usize,
};

/// Decode the first CBOR item from `data`, returning the value and byte count consumed.
pub fn decodeFirst(allocator: Allocator, data: []const u8) CborError!DecodeResult {
    return decodeFirstWithDepth(allocator, data, 0);
}

fn decodeFirstWithDepth(allocator: Allocator, data: []const u8, depth: usize) CborError!DecodeResult {
    if (data.len == 0) return error.UnexpectedEndOfInput;

    const initial_byte = data[0];
    const major_type: u3 = @intCast(initial_byte >> 5);
    const additional_info: u5 = @intCast(initial_byte & 0x1f);

    return switch (major_type) {
        0 => decodeUnsigned(data, additional_info),
        1 => decodeNegative(data, additional_info),
        2 => decodeBytes(data, additional_info),
        3 => decodeText(data, additional_info),
        4 => decodeArray(allocator, data, additional_info, depth),
        5 => decodeMap(allocator, data, additional_info, depth),
        else => error.InvalidMajorType,
    };
}

/// Convenience: decode all bytes as a single CBOR value.
pub fn decodeAll(allocator: Allocator, data: []const u8) CborError!CborValue {
    const result = try decodeFirst(allocator, data);
    return result.value;
}

// --- Lookup helpers for maps ---

/// Look up a text key in a CBOR map.
pub fn mapGetTextKey(entries: []const CborValue.MapEntry, key: []const u8) ?CborValue {
    for (entries) |entry| {
        switch (entry.key) {
            .text => |t| if (std.mem.eql(u8, t, key)) return entry.value,
            else => {},
        }
    }
    return null;
}

/// Look up an integer key (positive or negative) in a CBOR map.
pub fn mapGetIntKey(entries: []const CborValue.MapEntry, key: i66) ?CborValue {
    for (entries) |entry| {
        switch (entry.key) {
            .unsigned => |u| {
                if (key >= 0 and @as(u64, @intCast(key)) == u) return entry.value;
            },
            .negative => |n| {
                if (key < 0 and @as(i65, @intCast(key)) == n) return entry.value;
            },
            else => {},
        }
    }
    return null;
}

// --- Internal decoders ---

fn readArgument(data: []const u8, additional_info: u5) CborError!struct { value: u64, header_len: usize } {
    if (additional_info < 24) {
        return .{ .value = additional_info, .header_len = 1 };
    } else if (additional_info == 24) {
        if (data.len < 2) return error.UnexpectedEndOfInput;
        return .{ .value = data[1], .header_len = 2 };
    } else if (additional_info == 25) {
        if (data.len < 3) return error.UnexpectedEndOfInput;
        return .{ .value = std.mem.readInt(u16, data[1..3], .big), .header_len = 3 };
    } else if (additional_info == 26) {
        if (data.len < 5) return error.UnexpectedEndOfInput;
        return .{ .value = std.mem.readInt(u32, data[1..5], .big), .header_len = 5 };
    } else if (additional_info == 27) {
        if (data.len < 9) return error.UnexpectedEndOfInput;
        return .{ .value = std.mem.readInt(u64, data[1..9], .big), .header_len = 9 };
    }
    return error.InvalidAdditionalInfo;
}

fn decodeUnsigned(data: []const u8, additional_info: u5) CborError!DecodeResult {
    const arg = try readArgument(data, additional_info);
    return .{
        .value = .{ .unsigned = arg.value },
        .bytes_consumed = arg.header_len,
    };
}

fn decodeNegative(data: []const u8, additional_info: u5) CborError!DecodeResult {
    const arg = try readArgument(data, additional_info);
    // CBOR negative: -1 - n
    const value: i65 = -1 - @as(i65, @intCast(arg.value));
    return .{
        .value = .{ .negative = value },
        .bytes_consumed = arg.header_len,
    };
}

fn decodeBytes(data: []const u8, additional_info: u5) CborError!DecodeResult {
    const arg = try readArgument(data, additional_info);
    const len: usize = std.math.cast(usize, arg.value) orelse return error.Overflow;
    if (data.len < arg.header_len + len) return error.UnexpectedEndOfInput;
    return .{
        .value = .{ .bytes = data[arg.header_len .. arg.header_len + len] },
        .bytes_consumed = arg.header_len + len,
    };
}

fn decodeText(data: []const u8, additional_info: u5) CborError!DecodeResult {
    const arg = try readArgument(data, additional_info);
    const len: usize = std.math.cast(usize, arg.value) orelse return error.Overflow;
    if (data.len < arg.header_len + len) return error.UnexpectedEndOfInput;
    return .{
        .value = .{ .text = data[arg.header_len .. arg.header_len + len] },
        .bytes_consumed = arg.header_len + len,
    };
}

fn decodeArray(allocator: Allocator, data: []const u8, additional_info: u5, depth: usize) CborError!DecodeResult {
    if (depth >= MAX_NESTING_DEPTH) return error.MaxDepthExceeded;
    const arg = try readArgument(data, additional_info);
    const count: usize = std.math.cast(usize, arg.value) orelse return error.Overflow;
    const items = try allocator.alloc(CborValue, count);

    var offset = arg.header_len;
    for (0..count) |i| {
        if (offset >= data.len) return error.UnexpectedEndOfInput;
        const item = try decodeFirstWithDepth(allocator, data[offset..], depth + 1);
        items[i] = item.value;
        offset += item.bytes_consumed;
    }

    return .{
        .value = .{ .array = items },
        .bytes_consumed = offset,
    };
}

fn decodeMap(allocator: Allocator, data: []const u8, additional_info: u5, depth: usize) CborError!DecodeResult {
    if (depth >= MAX_NESTING_DEPTH) return error.MaxDepthExceeded;
    const arg = try readArgument(data, additional_info);
    const count: usize = std.math.cast(usize, arg.value) orelse return error.Overflow;
    const entries = try allocator.alloc(CborValue.MapEntry, count);

    var offset = arg.header_len;
    for (0..count) |i| {
        if (offset >= data.len) return error.UnexpectedEndOfInput;
        const key = try decodeFirstWithDepth(allocator, data[offset..], depth + 1);
        offset += key.bytes_consumed;

        if (offset >= data.len) return error.UnexpectedEndOfInput;
        const val = try decodeFirstWithDepth(allocator, data[offset..], depth + 1);
        offset += val.bytes_consumed;

        entries[i] = .{ .key = key.value, .value = val.value };
    }

    return .{
        .value = .{ .map = entries },
        .bytes_consumed = offset,
    };
}

// ============================================================
// Tests
// ============================================================

test "decode unsigned integers" {
    // 0 → 0x00
    const r0 = try decodeFirst(std.testing.allocator, &.{0x00});
    try std.testing.expectEqual(@as(u64, 0), r0.value.unsigned);
    try std.testing.expectEqual(@as(usize, 1), r0.bytes_consumed);

    // 23 → 0x17
    const r23 = try decodeFirst(std.testing.allocator, &.{0x17});
    try std.testing.expectEqual(@as(u64, 23), r23.value.unsigned);

    // 24 → 0x18, 0x18
    const r24 = try decodeFirst(std.testing.allocator, &.{ 0x18, 0x18 });
    try std.testing.expectEqual(@as(u64, 24), r24.value.unsigned);
    try std.testing.expectEqual(@as(usize, 2), r24.bytes_consumed);

    // 256 → 0x19, 0x01, 0x00
    const r256 = try decodeFirst(std.testing.allocator, &.{ 0x19, 0x01, 0x00 });
    try std.testing.expectEqual(@as(u64, 256), r256.value.unsigned);
    try std.testing.expectEqual(@as(usize, 3), r256.bytes_consumed);

    // 1000000 → 0x1a, 0x00, 0x0f, 0x42, 0x40
    const r1m = try decodeFirst(std.testing.allocator, &.{ 0x1a, 0x00, 0x0f, 0x42, 0x40 });
    try std.testing.expectEqual(@as(u64, 1000000), r1m.value.unsigned);
    try std.testing.expectEqual(@as(usize, 5), r1m.bytes_consumed);
}

test "decode negative integers" {
    // -1 → 0x20
    const r = try decodeFirst(std.testing.allocator, &.{0x20});
    try std.testing.expectEqual(@as(i65, -1), r.value.negative);
    try std.testing.expectEqual(@as(usize, 1), r.bytes_consumed);

    // -7 → 0x26
    const r7 = try decodeFirst(std.testing.allocator, &.{0x26});
    try std.testing.expectEqual(@as(i65, -7), r7.value.negative);

    // -8 → 0x27
    const r8 = try decodeFirst(std.testing.allocator, &.{0x27});
    try std.testing.expectEqual(@as(i65, -8), r8.value.negative);

    // -257 → 0x39, 0x01, 0x00
    const r257 = try decodeFirst(std.testing.allocator, &.{ 0x39, 0x01, 0x00 });
    try std.testing.expectEqual(@as(i65, -257), r257.value.negative);
    try std.testing.expectEqual(@as(usize, 3), r257.bytes_consumed);
}

test "decode byte strings" {
    // empty bytes → 0x40
    const r0 = try decodeFirst(std.testing.allocator, &.{0x40});
    try std.testing.expectEqual(@as(usize, 0), r0.value.bytes.len);
    try std.testing.expectEqual(@as(usize, 1), r0.bytes_consumed);

    // 4 bytes → 0x44, 0x01, 0x02, 0x03, 0x04
    const r4 = try decodeFirst(std.testing.allocator, &.{ 0x44, 0x01, 0x02, 0x03, 0x04 });
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03, 0x04 }, r4.value.bytes);
    try std.testing.expectEqual(@as(usize, 5), r4.bytes_consumed);
}

test "decode text strings" {
    // empty text → 0x60
    const r0 = try decodeFirst(std.testing.allocator, &.{0x60});
    try std.testing.expectEqualStrings("", r0.value.text);
    try std.testing.expectEqual(@as(usize, 1), r0.bytes_consumed);

    // "none" → 0x64, 'n', 'o', 'n', 'e'
    const r = try decodeFirst(std.testing.allocator, &.{ 0x64, 'n', 'o', 'n', 'e' });
    try std.testing.expectEqualStrings("none", r.value.text);
    try std.testing.expectEqual(@as(usize, 5), r.bytes_consumed);
}

test "decode array" {
    // [1, 2, 3] → 0x83, 0x01, 0x02, 0x03
    const r = try decodeFirst(std.testing.allocator, &.{ 0x83, 0x01, 0x02, 0x03 });
    defer std.testing.allocator.free(r.value.array);
    try std.testing.expectEqual(@as(usize, 3), r.value.array.len);
    try std.testing.expectEqual(@as(u64, 1), r.value.array[0].unsigned);
    try std.testing.expectEqual(@as(u64, 2), r.value.array[1].unsigned);
    try std.testing.expectEqual(@as(u64, 3), r.value.array[2].unsigned);
    try std.testing.expectEqual(@as(usize, 4), r.bytes_consumed);
}

test "decode map with text keys" {
    // {"a": 1} → 0xa1, 0x61, 0x61, 0x01
    const r = try decodeFirst(std.testing.allocator, &.{ 0xa1, 0x61, 'a', 0x01 });
    defer std.testing.allocator.free(r.value.map);
    try std.testing.expectEqual(@as(usize, 1), r.value.map.len);
    try std.testing.expectEqualStrings("a", r.value.map[0].key.text);
    try std.testing.expectEqual(@as(u64, 1), r.value.map[0].value.unsigned);
    try std.testing.expectEqual(@as(usize, 4), r.bytes_consumed);
}

test "decode map with integer keys (COSE-like)" {
    // {1: 2, 3: -7, -1: 1, -2: h'0102', -3: h'0304'}
    // This mimics a COSE EC2 key map structure
    const data = [_]u8{
        0xa5, // map(5)
        0x01, 0x02, // 1: 2 (kty: EC2)
        0x03, 0x26, // 3: -7 (alg: ES256)
        0x20, 0x01, // -1: 1 (crv: P-256)
        0x21, 0x42, 0x01, 0x02, // -2: h'0102' (x)
        0x22, 0x42, 0x03, 0x04, // -3: h'0304' (y)
    };
    const r = try decodeFirst(std.testing.allocator, &data);
    defer std.testing.allocator.free(r.value.map);
    try std.testing.expectEqual(@as(usize, 5), r.value.map.len);

    // kty = 2
    const kty = mapGetIntKey(r.value.map, 1).?;
    try std.testing.expectEqual(@as(u64, 2), kty.unsigned);

    // alg = -7
    const alg = mapGetIntKey(r.value.map, 3).?;
    try std.testing.expectEqual(@as(i65, -7), alg.negative);

    // crv = 1
    const crv = mapGetIntKey(r.value.map, -1).?;
    try std.testing.expectEqual(@as(u64, 1), crv.unsigned);

    // x = h'0102'
    const x = mapGetIntKey(r.value.map, -2).?;
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02 }, x.bytes);

    // y = h'0304'
    const y = mapGetIntKey(r.value.map, -3).?;
    try std.testing.expectEqualSlices(u8, &.{ 0x03, 0x04 }, y.bytes);
}

test "decode nested map (attestation object-like)" {
    // {"fmt": "none", "attStmt": {}, "authData": h'0102'}
    const data = [_]u8{
        0xa3, // map(3)
        0x63, 'f', 'm', 't', // text(3) "fmt"
        0x64, 'n', 'o', 'n', 'e', // text(4) "none"
        0x67, 'a', 't', 't', 'S', 't', 'm', 't', // text(7) "attStmt"
        0xa0, // map(0) - empty
        0x68, 'a', 'u', 't', 'h', 'D', 'a', 't', 'a', // text(8) "authData"
        0x42, 0x01, 0x02, // bytes(2) h'0102'
    };
    const r = try decodeFirst(std.testing.allocator, &data);
    defer {
        // Free inner empty map
        for (r.value.map) |entry| {
            switch (entry.value) {
                .map => |m| std.testing.allocator.free(m),
                else => {},
            }
        }
        std.testing.allocator.free(r.value.map);
    }

    const fmt = mapGetTextKey(r.value.map, "fmt").?;
    try std.testing.expectEqualStrings("none", fmt.text);

    const att_stmt = mapGetTextKey(r.value.map, "attStmt").?;
    try std.testing.expectEqual(@as(usize, 0), att_stmt.map.len);

    const auth_data = mapGetTextKey(r.value.map, "authData").?;
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02 }, auth_data.bytes);
}

test "decodeFirst returns correct bytes_consumed with trailing data" {
    // 0x01 (uint 1) followed by extra bytes
    const data = [_]u8{ 0x01, 0xff, 0xff };
    const r = try decodeFirst(std.testing.allocator, &data);
    try std.testing.expectEqual(@as(u64, 1), r.value.unsigned);
    try std.testing.expectEqual(@as(usize, 1), r.bytes_consumed);
}

test "error on empty input" {
    const r = decodeFirst(std.testing.allocator, &.{});
    try std.testing.expectError(error.UnexpectedEndOfInput, r);
}

test "error on truncated byte string" {
    // Declares 4 bytes but only has 2
    const r = decodeFirst(std.testing.allocator, &.{ 0x44, 0x01, 0x02 });
    try std.testing.expectError(error.UnexpectedEndOfInput, r);
}

test "error on truncated uint argument" {
    // 0x19 means 2-byte uint follows, but only 1 byte available
    const r = decodeFirst(std.testing.allocator, &.{0x19, 0x01});
    try std.testing.expectError(error.UnexpectedEndOfInput, r);
}

test "error on max nesting depth exceeded" {
    // Build deeply nested arrays: [[[[...17 levels deep...]]]
    // Each 0x81 is array(1), so 17 nested single-element arrays
    // Use arena because error paths leak partial CBOR allocations
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var data: [MAX_NESTING_DEPTH + 2]u8 = undefined;
    for (0..MAX_NESTING_DEPTH + 1) |i| {
        data[i] = 0x81; // array(1)
    }
    data[MAX_NESTING_DEPTH + 1] = 0x01; // innermost value: uint 1
    const r = decodeFirst(arena.allocator(), &data);
    try std.testing.expectError(error.MaxDepthExceeded, r);
}

test "nesting at max depth succeeds" {
    // Build arrays nested exactly MAX_NESTING_DEPTH levels (should succeed)
    // Use arena for easy cleanup of nested allocations
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var data: [MAX_NESTING_DEPTH + 1]u8 = undefined;
    for (0..MAX_NESTING_DEPTH) |i| {
        data[i] = 0x81; // array(1)
    }
    data[MAX_NESTING_DEPTH] = 0x01; // innermost value: uint 1
    const r = try decodeFirst(arena.allocator(), &data);
    // Traverse to innermost value
    var current = r.value;
    for (0..MAX_NESTING_DEPTH) |_| {
        current = current.array[0];
    }
    try std.testing.expectEqual(@as(u64, 1), current.unsigned);
}
