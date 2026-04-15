const std = @import("std");
const cbor = @import("cbor.zig");
const Allocator = std.mem.Allocator;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

pub const CoseError = error{
    UnsupportedKeyType,
    UnsupportedAlgorithm,
    UnsupportedCurve,
    MissingField,
    InvalidFieldLength,
    InvalidPublicKey,
    InvalidCbor,
    OutOfMemory,
};

// COSE key map labels
const COSE_KTY = 1;
const COSE_ALG = 3;
const COSE_CRV = -1;
const COSE_X = -2;
const COSE_Y = -3;

// COSE key type values
pub const KTY_EC2 = 2;

// COSE algorithm values
pub const ALG_ES256: i65 = -7;

// COSE curve values
pub const CRV_P256 = 1;

pub const CoseKey = struct {
    kty: u64,
    alg: i65,
    /// EC2 P-256 x-coordinate (32 bytes)
    x: [32]u8,
    /// EC2 P-256 y-coordinate (32 bytes)
    y: [32]u8,
};

/// Parse a CBOR-encoded COSE public key into a CoseKey.
/// Only EC2 keys with ES256 algorithm and P-256 curve are supported.
/// Uses an internal ArenaAllocator; the backing allocator is only used temporarily.
pub fn parseCoseKey(backing_allocator: Allocator, cbor_bytes: []const u8) CoseError!CoseKey {
    var arena = std.heap.ArenaAllocator.init(backing_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const value = cbor.decodeAll(allocator, cbor_bytes) catch return error.InvalidCbor;

    const entries = switch (value) {
        .map => |m| m,
        else => return error.InvalidCbor,
    };

    // kty (label 1) — must be EC2 (2)
    const kty_val = cbor.mapGetIntKey(entries, COSE_KTY) orelse return error.MissingField;
    const kty = switch (kty_val) {
        .unsigned => |u| u,
        else => return error.InvalidCbor,
    };
    if (kty != KTY_EC2) return error.UnsupportedKeyType;

    // alg (label 3) — must be ES256 (-7)
    const alg_val = cbor.mapGetIntKey(entries, COSE_ALG) orelse return error.MissingField;
    const alg: i65 = switch (alg_val) {
        .negative => |n| n,
        .unsigned => |u| @intCast(u),
        else => return error.InvalidCbor,
    };
    if (alg != ALG_ES256) return error.UnsupportedAlgorithm;

    // crv (label -1) — must be P-256 (1)
    const crv_val = cbor.mapGetIntKey(entries, COSE_CRV) orelse return error.MissingField;
    const crv = switch (crv_val) {
        .unsigned => |u| u,
        else => return error.InvalidCbor,
    };
    if (crv != CRV_P256) return error.UnsupportedCurve;

    // x (label -2) — 32 bytes
    const x_val = cbor.mapGetIntKey(entries, COSE_X) orelse return error.MissingField;
    const x_bytes = switch (x_val) {
        .bytes => |b| b,
        else => return error.InvalidCbor,
    };
    if (x_bytes.len != 32) return error.InvalidFieldLength;

    // y (label -3) — 32 bytes
    const y_val = cbor.mapGetIntKey(entries, COSE_Y) orelse return error.MissingField;
    const y_bytes = switch (y_val) {
        .bytes => |b| b,
        else => return error.InvalidCbor,
    };
    if (y_bytes.len != 32) return error.InvalidFieldLength;

    var key: CoseKey = undefined;
    key.kty = kty;
    key.alg = alg;
    @memcpy(&key.x, x_bytes);
    @memcpy(&key.y, y_bytes);
    return key;
}

/// Convert a CoseKey to an EcdsaP256Sha256 public key.
/// Constructs the uncompressed SEC1 representation: 0x04 || x || y (65 bytes).
pub fn toEcdsaPublicKey(key: CoseKey) CoseError!EcdsaP256Sha256.PublicKey {
    var sec1: [65]u8 = undefined;
    sec1[0] = 0x04; // uncompressed point indicator
    @memcpy(sec1[1..33], &key.x);
    @memcpy(sec1[33..65], &key.y);
    return EcdsaP256Sha256.PublicKey.fromSec1(&sec1) catch return error.InvalidPublicKey;
}

/// Encode an EC2 P-256 public key as CBOR-encoded COSE key.
/// Returns the CBOR bytes written into the provided buffer.
pub fn encodeCoseKey(x: []const u8, y: []const u8, buf: []u8) CoseError![]const u8 {
    if (x.len != 32 or y.len != 32) return error.InvalidFieldLength;
    // {1: 2, 3: -7, -1: 1, -2: bstr(32), -3: bstr(32)}
    // map(5) = 0xa5
    // 1: 2 → 0x01 0x02
    // 3: -7 → 0x03 0x26
    // -1: 1 → 0x20 0x01
    // -2: bstr(32) → 0x21 0x58 0x20 <32 bytes>
    // -3: bstr(32) → 0x22 0x58 0x20 <32 bytes>
    const needed = 1 + 2 + 2 + 2 + 3 + 32 + 3 + 32; // = 77
    if (buf.len < needed) return error.InvalidFieldLength;

    var pos: usize = 0;
    buf[pos] = 0xa5;
    pos += 1;
    buf[pos] = 0x01;
    pos += 1;
    buf[pos] = 0x02;
    pos += 1;
    buf[pos] = 0x03;
    pos += 1;
    buf[pos] = 0x26;
    pos += 1;
    buf[pos] = 0x20;
    pos += 1;
    buf[pos] = 0x01;
    pos += 1;
    buf[pos] = 0x21;
    pos += 1;
    buf[pos] = 0x58;
    pos += 1;
    buf[pos] = 0x20;
    pos += 1;
    @memcpy(buf[pos .. pos + 32], x);
    pos += 32;
    buf[pos] = 0x22;
    pos += 1;
    buf[pos] = 0x58;
    pos += 1;
    buf[pos] = 0x20;
    pos += 1;
    @memcpy(buf[pos .. pos + 32], y);
    pos += 32;

    return buf[0..pos];
}

// ============================================================
// Tests
// ============================================================

test "parse valid EC2 P-256 COSE key" {
    const kp = EcdsaP256Sha256.KeyPair.generate();
    const sec1 = kp.public_key.toUncompressedSec1();
    const x = sec1[1..33];
    const y = sec1[33..65];

    var buf: [256]u8 = undefined;
    const cbor_data = try encodeCoseKey(x, y, &buf);

    const cose_key = try parseCoseKey(std.testing.allocator, cbor_data);
    try std.testing.expectEqual(@as(u64, 2), cose_key.kty);
    try std.testing.expectEqual(@as(i65, -7), cose_key.alg);
    try std.testing.expectEqualSlices(u8, x, &cose_key.x);
    try std.testing.expectEqualSlices(u8, y, &cose_key.y);
}

test "parseCoseKey then toEcdsaPublicKey round-trip with signature verification" {
    const kp = EcdsaP256Sha256.KeyPair.generate();
    const sec1 = kp.public_key.toUncompressedSec1();

    var buf: [256]u8 = undefined;
    const cbor_data = try encodeCoseKey(sec1[1..33], sec1[33..65], &buf);

    const cose_key = try parseCoseKey(std.testing.allocator, cbor_data);
    const pub_key = try toEcdsaPublicKey(cose_key);

    const msg = "test message";
    const sig = try kp.sign(msg, null);
    try sig.verify(msg, pub_key);
}

test "toEcdsaPublicKey converts and verifies signature" {
    const kp = EcdsaP256Sha256.KeyPair.generate();
    const sec1 = kp.public_key.toUncompressedSec1();

    var key: CoseKey = undefined;
    key.kty = KTY_EC2;
    key.alg = ALG_ES256;
    @memcpy(&key.x, sec1[1..33]);
    @memcpy(&key.y, sec1[33..65]);

    const pub_key = try toEcdsaPublicKey(key);

    const msg = "test message";
    const sig = try kp.sign(msg, null);
    try sig.verify(msg, pub_key);
}

test "reject unsupported key type" {
    // kty = 1 (OKP) instead of 2 (EC2)
    const data = [_]u8{
        0xa5,
        0x01, 0x01, // kty: 1 (OKP)
        0x03, 0x26, // alg: -7
        0x20, 0x01, // crv: 1
        0x21, 0x58, 0x20, // -2: bstr(32)
    } ++ [_]u8{0} ** 32 ++ [_]u8{
        0x22, 0x58, 0x20, // -3: bstr(32)
    } ++ [_]u8{0} ** 32;
    const r = parseCoseKey(std.testing.allocator, &data);
    try std.testing.expectError(error.UnsupportedKeyType, r);
}

test "reject unsupported algorithm" {
    // alg = -8 (EdDSA) instead of -7 (ES256)
    const data = [_]u8{
        0xa5,
        0x01, 0x02, // kty: 2
        0x03, 0x27, // alg: -8 (EdDSA)
        0x20, 0x01, // crv: 1
        0x21, 0x58, 0x20,
    } ++ [_]u8{0} ** 32 ++ [_]u8{
        0x22, 0x58, 0x20,
    } ++ [_]u8{0} ** 32;
    const r = parseCoseKey(std.testing.allocator, &data);
    try std.testing.expectError(error.UnsupportedAlgorithm, r);
}

test "reject missing x field" {
    const data = [_]u8{
        0xa3,
        0x01, 0x02, // kty: 2
        0x03, 0x26, // alg: -7
        0x20, 0x01, // crv: 1
    };
    const r = parseCoseKey(std.testing.allocator, &data);
    try std.testing.expectError(error.MissingField, r);
}

test "reject wrong x length" {
    const data = [_]u8{
        0xa5,
        0x01, 0x02, // kty: 2
        0x03, 0x26, // alg: -7
        0x20, 0x01, // crv: 1
        0x21, 0x50, // -2: bstr(16)
    } ++ [_]u8{0} ** 16 ++ [_]u8{
        0x22, 0x58, 0x20, // -3: bstr(32)
    } ++ [_]u8{0} ** 32;
    const r = parseCoseKey(std.testing.allocator, &data);
    try std.testing.expectError(error.InvalidFieldLength, r);
}
