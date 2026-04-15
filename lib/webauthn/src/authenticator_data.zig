const std = @import("std");
const cbor = @import("cbor.zig");
const Allocator = std.mem.Allocator;

pub const ParseError = error{
    DataTooShort,
    InvalidFlags,
    InvalidCredentialData,
    InvalidCbor,
    OutOfMemory,
};

pub const Flags = packed struct(u8) {
    up: bool, // bit 0: User Present
    _rfu1: bool, // bit 1: reserved
    uv: bool, // bit 2: User Verified
    be: bool, // bit 3: Backup Eligibility
    bs: bool, // bit 4: Backup State
    _rfu2: bool, // bit 5: reserved
    at: bool, // bit 6: Attested Credential Data
    ed: bool, // bit 7: Extension Data
};

pub const AttestedCredentialData = struct {
    aaguid: [16]u8,
    credential_id: []const u8,
    /// Raw CBOR bytes of the COSE public key (slice into input buffer)
    credential_public_key_bytes: []const u8,
};

pub const AuthenticatorData = struct {
    rp_id_hash: [32]u8,
    flags: Flags,
    sign_count: u32,
    attested_credential_data: ?AttestedCredentialData,
    /// Raw bytes of the full authenticatorData (for signature verification)
    raw: []const u8,
};

/// Returns "singleDevice" or "multiDevice" based on the BE flag.
pub fn deviceType(flags: Flags) []const u8 {
    return if (flags.be) "multiDevice" else "singleDevice";
}

/// Returns whether the credential is backed up (BS flag).
pub fn backedUp(flags: Flags) bool {
    return flags.bs;
}

const MIN_AUTH_DATA_LEN = 37; // 32 (rpIdHash) + 1 (flags) + 4 (counter)

/// Parse authenticatorData binary format.
/// The returned slices reference the input `data` buffer.
/// The allocator is only used temporarily for CBOR parsing (to determine public key extent).
pub fn parse(backing_allocator: Allocator, data: []const u8) ParseError!AuthenticatorData {
    if (data.len < MIN_AUTH_DATA_LEN) return error.DataTooShort;

    var result: AuthenticatorData = undefined;
    result.raw = data;

    // rpIdHash: first 32 bytes
    @memcpy(&result.rp_id_hash, data[0..32]);

    // flags: byte 32
    result.flags = @bitCast(data[32]);

    // signCount: bytes 33-36, big-endian
    result.sign_count = std.mem.readInt(u32, data[33..37], .big);

    // Attested credential data (if AT flag set)
    if (result.flags.at) {
        var offset: usize = 37;

        // aaguid: 16 bytes
        if (data.len < offset + 16) return error.DataTooShort;
        var aaguid: [16]u8 = undefined;
        @memcpy(&aaguid, data[offset .. offset + 16]);
        offset += 16;

        // credentialIdLength: 2 bytes, big-endian
        if (data.len < offset + 2) return error.DataTooShort;
        const cred_id_len = std.mem.readInt(u16, data[offset..][0..2], .big);
        offset += 2;

        // credentialId
        if (data.len < offset + cred_id_len) return error.DataTooShort;
        const credential_id = data[offset .. offset + cred_id_len];
        offset += cred_id_len;

        // credentialPublicKey: CBOR-encoded, use decodeFirst to find extent
        if (offset >= data.len) return error.DataTooShort;
        // Use arena for temporary CBOR allocations (only need bytes_consumed)
        var arena = std.heap.ArenaAllocator.init(backing_allocator);
        defer arena.deinit();
        const cbor_result = cbor.decodeFirst(arena.allocator(), data[offset..]) catch return error.InvalidCbor;
        const pub_key_bytes = data[offset .. offset + cbor_result.bytes_consumed];

        result.attested_credential_data = .{
            .aaguid = aaguid,
            .credential_id = credential_id,
            .credential_public_key_bytes = pub_key_bytes,
        };
    } else {
        result.attested_credential_data = null;
    }

    return result;
}

// ============================================================
// Tests
// ============================================================

test "parse minimal authenticatorData (37 bytes, no AT)" {
    var data: [37]u8 = undefined;
    // rpIdHash: 32 bytes of 0xAA
    @memset(data[0..32], 0xAA);
    // flags: UP=true (0x01)
    data[32] = 0x01;
    // counter: 42 (big-endian)
    std.mem.writeInt(u32, data[33..37], 42, .big);

    const result = try parse(std.testing.allocator, &data);
    for (result.rp_id_hash) |b| try std.testing.expectEqual(@as(u8, 0xAA), b);
    try std.testing.expect(result.flags.up);
    try std.testing.expect(!result.flags.uv);
    try std.testing.expect(!result.flags.at);
    try std.testing.expect(!result.flags.ed);
    try std.testing.expectEqual(@as(u32, 42), result.sign_count);
    try std.testing.expect(result.attested_credential_data == null);
}

test "parse flags correctly" {
    var data: [37]u8 = undefined;
    @memset(data[0..32], 0);
    // flags: UP=1, UV=1, BE=1, AT=1 → bit0 + bit2 + bit3 + bit6 = 0x01 | 0x04 | 0x08 | 0x40 = 0x4D
    data[32] = 0x4D;
    std.mem.writeInt(u32, data[33..37], 0, .big);

    // We can't parse this as-is because AT flag is set but no credential data follows.
    // Instead test with AT=0.
    data[32] = 0x0D; // UP=1, UV=1, BE=1
    const result = try parse(std.testing.allocator, &data);
    try std.testing.expect(result.flags.up);
    try std.testing.expect(result.flags.uv);
    try std.testing.expect(result.flags.be);
    try std.testing.expect(!result.flags.bs);
    try std.testing.expect(!result.flags.at);
}

test "parse authenticatorData with attested credential data" {
    const cose = @import("cose.zig");
    const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

    // Generate a real key for COSE encoding
    const kp = EcdsaP256Sha256.KeyPair.generate();
    const sec1 = kp.public_key.toUncompressedSec1();

    var cose_buf: [256]u8 = undefined;
    const cose_bytes = try cose.encodeCoseKey(sec1[1..33], sec1[33..65], &cose_buf);

    // Build authenticatorData with AT flag
    const cred_id = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 }; // 8-byte credential ID

    var data: [512]u8 = undefined;
    var pos: usize = 0;

    // rpIdHash
    @memset(data[0..32], 0xBB);
    pos += 32;
    // flags: UP=1, UV=1, AT=1 → 0x01 | 0x04 | 0x40 = 0x45
    data[pos] = 0x45;
    pos += 1;
    // counter: 100
    std.mem.writeInt(u32, data[pos..][0..4], 100, .big);
    pos += 4;
    // aaguid: 16 bytes of 0xCC
    @memset(data[pos .. pos + 16], 0xCC);
    pos += 16;
    // credentialIdLength: 8
    std.mem.writeInt(u16, data[pos..][0..2], 8, .big);
    pos += 2;
    // credentialId
    @memcpy(data[pos .. pos + 8], &cred_id);
    pos += 8;
    // credentialPublicKey (CBOR)
    @memcpy(data[pos .. pos + cose_bytes.len], cose_bytes);
    pos += cose_bytes.len;

    const result = try parse(std.testing.allocator, data[0..pos]);
    try std.testing.expect(result.flags.up);
    try std.testing.expect(result.flags.uv);
    try std.testing.expect(result.flags.at);
    try std.testing.expectEqual(@as(u32, 100), result.sign_count);

    const acd = result.attested_credential_data.?;
    for (acd.aaguid) |b| try std.testing.expectEqual(@as(u8, 0xCC), b);
    try std.testing.expectEqualSlices(u8, &cred_id, acd.credential_id);
    try std.testing.expectEqualSlices(u8, cose_bytes, acd.credential_public_key_bytes);
}

test "big-endian counter parsing" {
    var data: [37]u8 = undefined;
    @memset(data[0..32], 0);
    data[32] = 0x01; // flags: UP
    // counter = 0x01020304 = 16909060
    data[33] = 0x01;
    data[34] = 0x02;
    data[35] = 0x03;
    data[36] = 0x04;

    const result = try parse(std.testing.allocator, &data);
    try std.testing.expectEqual(@as(u32, 0x01020304), result.sign_count);
}

test "deviceType and backedUp" {
    // BE=0, BS=0 → singleDevice, not backed up
    const f1: Flags = @bitCast(@as(u8, 0x01)); // UP only
    try std.testing.expectEqualStrings("singleDevice", deviceType(f1));
    try std.testing.expect(!backedUp(f1));

    // BE=1, BS=1 → multiDevice, backed up
    const f2: Flags = @bitCast(@as(u8, 0x19)); // UP + BE + BS = 0x01 | 0x08 | 0x10
    try std.testing.expectEqualStrings("multiDevice", deviceType(f2));
    try std.testing.expect(backedUp(f2));
}

test "error on data too short" {
    const r = parse(std.testing.allocator, &[_]u8{ 0x00, 0x01 });
    try std.testing.expectError(error.DataTooShort, r);
}

test "error on AT flag with truncated credential data" {
    var data: [37]u8 = undefined;
    @memset(data[0..32], 0);
    data[32] = 0x41; // AT flag set, UP
    std.mem.writeInt(u32, data[33..37], 0, .big);
    // AT flag set but no credential data follows
    const r = parse(std.testing.allocator, &data);
    try std.testing.expectError(error.DataTooShort, r);
}
