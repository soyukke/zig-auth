const std = @import("std");
const base64 = std.base64.url_safe_no_pad;

pub fn encode(dest: []u8, source: []const u8) []const u8 {
    return base64.Encoder.encode(dest, source);
}

pub fn encodeLen(source_len: usize) usize {
    return base64.Encoder.calcSize(source_len);
}

pub fn decode(dest: []u8, source: []const u8) ![]const u8 {
    const len = base64.Decoder.calcSizeForSlice(source) catch return error.InvalidEncoding;
    if (len > dest.len) return error.InvalidEncoding;
    base64.Decoder.decode(dest[0..len], source) catch return error.InvalidEncoding;
    return dest[0..len];
}

pub fn decodeLen(source_len: usize) usize {
    return base64.Decoder.calcSizeUpperBound(source_len) catch source_len;
}

test "encode empty input" {
    var buf: [4]u8 = undefined;
    const result = encode(&buf, "");
    try std.testing.expectEqualStrings("", result);
}

test "encode RFC 4648 test vectors" {
    var buf: [64]u8 = undefined;

    try std.testing.expectEqualStrings("Zg", encode(&buf, "f"));
    try std.testing.expectEqualStrings("Zm8", encode(&buf, "fo"));
    try std.testing.expectEqualStrings("Zm9v", encode(&buf, "foo"));
    try std.testing.expectEqualStrings("Zm9vYg", encode(&buf, "foob"));
    try std.testing.expectEqualStrings("Zm9vYmE", encode(&buf, "fooba"));
    try std.testing.expectEqualStrings("Zm9vYmFy", encode(&buf, "foobar"));
}

test "encode URL-unsafe characters use - and _ instead of + and /" {
    var buf: [64]u8 = undefined;
    const input = &[_]u8{ 0xfb, 0xff, 0xfe };
    const result = encode(&buf, input);
    try std.testing.expect(std.mem.indexOf(u8, result, "+") == null);
    try std.testing.expect(std.mem.indexOf(u8, result, "/") == null);
}

test "encode no padding" {
    var buf: [64]u8 = undefined;
    const result = encode(&buf, "f");
    try std.testing.expect(std.mem.indexOf(u8, result, "=") == null);
}

test "decode roundtrip" {
    var encode_buf: [64]u8 = undefined;
    var decode_buf: [64]u8 = undefined;

    const original = "Hello, Zig Auth!";
    const encoded = encode(&encode_buf, original);
    const decoded = try decode(&decode_buf, encoded);
    try std.testing.expectEqualStrings(original, decoded);
}

test "decode invalid input" {
    var buf: [64]u8 = undefined;
    const result = decode(&buf, "!!!!");
    try std.testing.expectError(error.InvalidEncoding, result);
}

test "encodeLen returns correct buffer size" {
    try std.testing.expectEqual(@as(usize, 0), encodeLen(0));
    try std.testing.expectEqual(@as(usize, 2), encodeLen(1));
    try std.testing.expectEqual(@as(usize, 3), encodeLen(2));
    try std.testing.expectEqual(@as(usize, 4), encodeLen(3));
    try std.testing.expectEqual(@as(usize, 8), encodeLen(6));
}

test "decodeLen returns correct buffer size" {
    try std.testing.expectEqual(@as(usize, 0), decodeLen(0));
    // decodeLen returns upper bound, so may be >= actual
    try std.testing.expect(decodeLen(2) >= 1);
    try std.testing.expect(decodeLen(3) >= 2);
    try std.testing.expect(decodeLen(4) >= 3);
    try std.testing.expect(decodeLen(8) >= 6);
}
