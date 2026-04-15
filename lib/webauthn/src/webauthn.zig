const std = @import("std");
const cbor = @import("cbor.zig");
const cose = @import("cose.zig");
const auth_data = @import("authenticator_data.zig");
const base64url = @import("base64url.zig");
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

pub const WebAuthnError = error{
    InvalidClientData,
    InvalidType,
    InvalidChallenge,
    InvalidOrigin,
    InvalidRpId,
    InvalidAttestation,
    InvalidAttestationFormat,
    UnsupportedAlgorithm,
    InvalidAuthenticatorData,
    InvalidSignature,
    UserNotPresent,
    CounterNotIncremented,
    InvalidCbor,
    InvalidEncoding,
    OutOfMemory,
};

// ── Registration Verification ──

pub const RegistrationResult = struct {
    credential_id: []const u8,
    public_key: []const u8,
    counter: u32,
    device_type: []const u8,
    backed_up: bool,
    aaguid: [16]u8,
};

/// Verify a WebAuthn registration response.
/// All base64url-encoded inputs are decoded internally.
/// Returns a JSON string on success. Caller owns the returned memory.
pub fn verifyRegistration(
    backing_allocator: Allocator,
    client_data_json_b64: []const u8,
    attestation_object_b64: []const u8,
    expected_challenge: []const u8,
    expected_origin: []const u8,
    expected_rp_id: []const u8,
) WebAuthnError![]const u8 {
    var arena = std.heap.ArenaAllocator.init(backing_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // 1. Decode and parse clientDataJSON
    const cdj_bytes = decodeBase64url(allocator, client_data_json_b64) catch return error.InvalidClientData;
    const client_data = parseClientDataJSON(allocator, cdj_bytes) catch return error.InvalidClientData;

    // 2. Verify type
    if (!std.mem.eql(u8, client_data.type, "webauthn.create"))
        return error.InvalidType;

    // 3. Verify challenge
    if (!std.mem.eql(u8, client_data.challenge, expected_challenge))
        return error.InvalidChallenge;

    // 4. Verify origin
    if (!std.mem.eql(u8, client_data.origin, expected_origin))
        return error.InvalidOrigin;

    // 5. Decode attestation object (CBOR)
    const att_bytes = decodeBase64url(allocator, attestation_object_b64) catch return error.InvalidAttestation;
    const att_value = cbor.decodeAll(allocator, att_bytes) catch return error.InvalidCbor;
    const att_map = switch (att_value) {
        .map => |m| m,
        else => return error.InvalidAttestation,
    };

    // 6. Extract fmt, attStmt, authData
    const fmt_val = cbor.mapGetTextKey(att_map, "fmt") orelse return error.InvalidAttestation;
    const fmt = switch (fmt_val) {
        .text => |t| t,
        else => return error.InvalidAttestation,
    };

    const auth_data_val = cbor.mapGetTextKey(att_map, "authData") orelse return error.InvalidAttestation;
    const auth_data_bytes = switch (auth_data_val) {
        .bytes => |b| b,
        else => return error.InvalidAttestation,
    };

    // 7. Parse authenticatorData
    const parsed_auth = auth_data.parse(allocator, auth_data_bytes) catch return error.InvalidAuthenticatorData;

    // 8. Verify rpIdHash
    var expected_rp_hash: [32]u8 = undefined;
    Sha256.hash(expected_rp_id, &expected_rp_hash, .{});
    if (!std.mem.eql(u8, &parsed_auth.rp_id_hash, &expected_rp_hash))
        return error.InvalidRpId;

    // 9. Check UP flag
    if (!parsed_auth.flags.up)
        return error.UserNotPresent;

    // 10. Check AT flag (required for registration)
    if (!parsed_auth.flags.at)
        return error.InvalidAuthenticatorData;

    const acd = parsed_auth.attested_credential_data orelse return error.InvalidAuthenticatorData;

    // 11. Verify public key algorithm
    const cose_key = cose.parseCoseKey(allocator, acd.credential_public_key_bytes) catch return error.UnsupportedAlgorithm;
    if (cose_key.alg != cose.ALG_ES256) return error.UnsupportedAlgorithm;

    // 12. Verify attestation format
    if (std.mem.eql(u8, fmt, "none")) {
        // For "none" attestation, attStmt must be empty
        const att_stmt_val = cbor.mapGetTextKey(att_map, "attStmt") orelse return error.InvalidAttestation;
        switch (att_stmt_val) {
            .map => |m| if (m.len != 0) return error.InvalidAttestationFormat,
            else => return error.InvalidAttestationFormat,
        }
    } else {
        return error.InvalidAttestationFormat;
    }

    // 13. Build result JSON
    const dt = auth_data.deviceType(parsed_auth.flags);
    const bu = auth_data.backedUp(parsed_auth.flags);

    // Encode credential ID and public key as base64url
    const cred_id_b64_buf = try allocator.alloc(u8, base64url.encodeLen(acd.credential_id.len));
    const cred_id_b64 = base64url.encode(cred_id_b64_buf, acd.credential_id);

    const pub_key_b64_buf = try allocator.alloc(u8, base64url.encodeLen(acd.credential_public_key_bytes.len));
    const pub_key_b64 = base64url.encode(pub_key_b64_buf, acd.credential_public_key_bytes);

    // Format aaguid as hex
    const hex_chars = "0123456789abcdef";
    var aaguid_hex: [32]u8 = undefined;
    for (acd.aaguid, 0..) |byte, i| {
        aaguid_hex[i * 2] = hex_chars[byte >> 4];
        aaguid_hex[i * 2 + 1] = hex_chars[byte & 0x0f];
    }

    const json = std.fmt.allocPrint(backing_allocator,
        \\{{"verified":true,"credentialId":"{s}","publicKey":"{s}","publicKeyAlgorithm":-7,"counter":{d},"deviceType":"{s}","backedUp":{s},"aaguid":"{s}"}}
    , .{ cred_id_b64, pub_key_b64, parsed_auth.sign_count, dt, if (bu) "true" else "false", &aaguid_hex }) catch return error.OutOfMemory;

    return json;
}

// ── Authentication Verification ──

/// Verify a WebAuthn authentication response.
/// Returns a JSON string on success. Caller owns the returned memory.
pub fn verifyAuthentication(
    backing_allocator: Allocator,
    client_data_json_b64: []const u8,
    authenticator_data_b64: []const u8,
    signature_b64: []const u8,
    public_key_cbor_b64: []const u8,
    stored_counter: u32,
    expected_challenge: []const u8,
    expected_origin: []const u8,
    expected_rp_id: []const u8,
) WebAuthnError![]const u8 {
    var arena = std.heap.ArenaAllocator.init(backing_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // 1. Decode and parse clientDataJSON
    const cdj_bytes = decodeBase64url(allocator, client_data_json_b64) catch return error.InvalidClientData;
    const client_data = parseClientDataJSON(allocator, cdj_bytes) catch return error.InvalidClientData;

    // 2. Verify type
    if (!std.mem.eql(u8, client_data.type, "webauthn.get"))
        return error.InvalidType;

    // 3. Verify challenge
    if (!std.mem.eql(u8, client_data.challenge, expected_challenge))
        return error.InvalidChallenge;

    // 4. Verify origin
    if (!std.mem.eql(u8, client_data.origin, expected_origin))
        return error.InvalidOrigin;

    // 5. Decode and parse authenticatorData
    const auth_data_bytes = decodeBase64url(allocator, authenticator_data_b64) catch return error.InvalidAuthenticatorData;
    const parsed_auth = auth_data.parse(allocator, auth_data_bytes) catch return error.InvalidAuthenticatorData;

    // 6. Verify rpIdHash
    var expected_rp_hash: [32]u8 = undefined;
    Sha256.hash(expected_rp_id, &expected_rp_hash, .{});
    if (!std.mem.eql(u8, &parsed_auth.rp_id_hash, &expected_rp_hash))
        return error.InvalidRpId;

    // 7. Check UP flag
    if (!parsed_auth.flags.up)
        return error.UserNotPresent;

    // 8. Verify counter
    if (parsed_auth.sign_count > 0 or stored_counter > 0) {
        if (parsed_auth.sign_count <= stored_counter)
            return error.CounterNotIncremented;
    }

    // 9. Compute clientDataHash = SHA-256(clientDataJSON raw bytes)
    var client_data_hash: [32]u8 = undefined;
    Sha256.hash(cdj_bytes, &client_data_hash, .{});

    // 10. signatureBase = authenticatorData || clientDataHash
    const sig_base = try allocator.alloc(u8, auth_data_bytes.len + 32);
    @memcpy(sig_base[0..auth_data_bytes.len], auth_data_bytes);
    @memcpy(sig_base[auth_data_bytes.len..], &client_data_hash);

    // 11. Decode signature (DER-encoded)
    const sig_bytes = decodeBase64url(allocator, signature_b64) catch return error.InvalidSignature;
    const signature = EcdsaP256Sha256.Signature.fromDer(sig_bytes) catch return error.InvalidSignature;

    // 12. Decode stored public key
    const pub_key_cbor = decodeBase64url(allocator, public_key_cbor_b64) catch return error.InvalidSignature;
    const cose_key = cose.parseCoseKey(allocator, pub_key_cbor) catch return error.UnsupportedAlgorithm;
    const pub_key = cose.toEcdsaPublicKey(cose_key) catch return error.InvalidSignature;

    // 13. Verify signature
    signature.verify(sig_base, pub_key) catch return error.InvalidSignature;

    // 14. Build result JSON
    const dt = auth_data.deviceType(parsed_auth.flags);
    const bu = auth_data.backedUp(parsed_auth.flags);

    const json = std.fmt.allocPrint(backing_allocator,
        \\{{"verified":true,"newCounter":{d},"deviceType":"{s}","backedUp":{s}}}
    , .{ parsed_auth.sign_count, dt, if (bu) "true" else "false" }) catch return error.OutOfMemory;

    return json;
}

// ── Internal helpers ──

const ClientData = struct {
    type: []const u8,
    challenge: []const u8,
    origin: []const u8,
};

/// Parse clientDataJSON. The allocator must outlive the returned ClientData
/// (the returned string slices reference memory owned by the allocator).
fn parseClientDataJSON(allocator: Allocator, json_bytes: []const u8) !ClientData {
    // Use the caller's allocator (arena) — no deinit needed, arena handles cleanup
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_bytes, .{}) catch return error.InvalidClientData;

    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return error.InvalidClientData,
    };

    const type_val = obj.get("type") orelse return error.InvalidClientData;
    const challenge_val = obj.get("challenge") orelse return error.InvalidClientData;
    const origin_val = obj.get("origin") orelse return error.InvalidClientData;

    return .{
        .type = switch (type_val) {
            .string => |s| s,
            else => return error.InvalidClientData,
        },
        .challenge = switch (challenge_val) {
            .string => |s| s,
            else => return error.InvalidClientData,
        },
        .origin = switch (origin_val) {
            .string => |s| s,
            else => return error.InvalidClientData,
        },
    };
}

fn decodeBase64url(allocator: Allocator, encoded: []const u8) ![]const u8 {
    const buf = try allocator.alloc(u8, base64url.decodeLen(encoded.len));
    return base64url.decode(buf, encoded) catch return error.InvalidEncoding;
}

// ============================================================
// Tests
// ============================================================

// Helper: build a CBOR-encoded attestation object with "none" format
fn buildAttestationObject(allocator: Allocator, auth_data_bytes: []const u8) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    try buf.append(allocator, 0xa3);

    try buf.append(allocator, 0x63);
    try buf.appendSlice(allocator, "fmt");
    try buf.append(allocator, 0x64);
    try buf.appendSlice(allocator, "none");

    try buf.append(allocator, 0x67);
    try buf.appendSlice(allocator, "attStmt");
    try buf.append(allocator, 0xa0);

    try buf.append(allocator, 0x68);
    try buf.appendSlice(allocator, "authData");
    if (auth_data_bytes.len < 24) {
        try buf.append(allocator, @as(u8, 0x40) | @as(u8, @intCast(auth_data_bytes.len)));
    } else if (auth_data_bytes.len <= 0xff) {
        try buf.append(allocator, 0x58);
        try buf.append(allocator, @intCast(auth_data_bytes.len));
    } else {
        try buf.append(allocator, 0x59);
        const len16: u16 = @intCast(auth_data_bytes.len);
        try buf.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeTo(u16, len16, .big)));
    }
    try buf.appendSlice(allocator, auth_data_bytes);

    return buf.toOwnedSlice(allocator);
}

// Helper: build authenticatorData with a credential
fn buildAuthenticatorData(allocator: Allocator, rp_id: []const u8, counter: u32, cose_key_bytes: ?[]const u8, cred_id: ?[]const u8) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;

    var rp_hash: [32]u8 = undefined;
    Sha256.hash(rp_id, &rp_hash, .{});
    try buf.appendSlice(allocator, &rp_hash);

    var flags: u8 = 0x01; // UP
    flags |= 0x04; // UV
    if (cose_key_bytes != null) flags |= 0x40; // AT
    try buf.append(allocator, flags);

    try buf.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeTo(u32, counter, .big)));

    if (cose_key_bytes) |ck| {
        const cid = cred_id orelse &[_]u8{ 0x01, 0x02, 0x03, 0x04 };
        try buf.appendNTimes(allocator, 0, 16);
        const cid_len: u16 = @intCast(cid.len);
        try buf.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeTo(u16, cid_len, .big)));
        try buf.appendSlice(allocator, cid);
        try buf.appendSlice(allocator, ck);
    }

    return buf.toOwnedSlice(allocator);
}

fn buildClientDataJSON(allocator: Allocator, typ: []const u8, challenge: []const u8, origin: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator,
        \\{{"type":"{s}","challenge":"{s}","origin":"{s}"}}
    , .{ typ, challenge, origin }) catch return error.OutOfMemory;
}

fn encodeToBase64url(allocator: Allocator, data: []const u8) ![]u8 {
    const buf = try allocator.alloc(u8, base64url.encodeLen(data.len));
    const encoded = base64url.encode(buf, data);
    // encode returns a slice of buf, so buf.ptr == encoded.ptr
    // If encoded.len < buf.len, free the tail
    if (encoded.len < buf.len) {
        allocator.free(buf[encoded.len..]);
    }
    return buf[0..encoded.len];
}

test "verifyRegistration succeeds with valid synthetic data" {
    const allocator = std.testing.allocator;
    const rp_id = "example.com";
    const origin = "https://example.com";
    const challenge = "test-challenge-123";

    // Generate key pair
    const kp = EcdsaP256Sha256.KeyPair.generate();
    const sec1 = kp.public_key.toUncompressedSec1();

    // Encode COSE key
    var cose_buf: [256]u8 = undefined;
    const cose_bytes = cose.encodeCoseKey(sec1[1..33], sec1[33..65], &cose_buf) catch unreachable;

    // Build authenticatorData
    const auth_data_bytes = try buildAuthenticatorData(allocator, rp_id, 0, cose_bytes, null);
    defer allocator.free(auth_data_bytes);

    // Build attestation object
    const att_obj = try buildAttestationObject(allocator, auth_data_bytes);
    defer allocator.free(att_obj);

    // Build clientDataJSON
    const cdj = try buildClientDataJSON(allocator, "webauthn.create", challenge, origin);
    defer allocator.free(cdj);

    // Base64url encode
    const cdj_b64 = try encodeToBase64url(allocator, cdj);
    defer allocator.free(cdj_b64);
    const att_b64 = try encodeToBase64url(allocator, att_obj);
    defer allocator.free(att_b64);

    // Verify
    const result = try verifyRegistration(allocator, cdj_b64, att_b64, challenge, origin, rp_id);
    defer allocator.free(result);

    // Check result contains expected fields
    try std.testing.expect(std.mem.indexOf(u8, result, "\"verified\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"counter\":0") != null);
}

test "verifyRegistration rejects wrong challenge" {
    const allocator = std.testing.allocator;
    const rp_id = "example.com";
    const origin = "https://example.com";

    const kp = EcdsaP256Sha256.KeyPair.generate();
    const sec1 = kp.public_key.toUncompressedSec1();

    var cose_buf: [256]u8 = undefined;
    const cose_bytes = cose.encodeCoseKey(sec1[1..33], sec1[33..65], &cose_buf) catch unreachable;
    const auth_data_bytes = try buildAuthenticatorData(allocator, rp_id, 0, cose_bytes, null);
    defer allocator.free(auth_data_bytes);
    const att_obj = try buildAttestationObject(allocator, auth_data_bytes);
    defer allocator.free(att_obj);
    const cdj = try buildClientDataJSON(allocator, "webauthn.create", "correct-challenge", origin);
    defer allocator.free(cdj);
    const cdj_b64 = try encodeToBase64url(allocator, cdj);
    defer allocator.free(cdj_b64);
    const att_b64 = try encodeToBase64url(allocator, att_obj);
    defer allocator.free(att_b64);

    const r = verifyRegistration(allocator, cdj_b64, att_b64, "wrong-challenge", origin, rp_id);
    try std.testing.expectError(error.InvalidChallenge, r);
}

test "verifyRegistration rejects wrong origin" {
    const allocator = std.testing.allocator;
    const rp_id = "example.com";
    const challenge = "ch";

    const kp = EcdsaP256Sha256.KeyPair.generate();
    const sec1 = kp.public_key.toUncompressedSec1();
    var cose_buf: [256]u8 = undefined;
    const cose_bytes = cose.encodeCoseKey(sec1[1..33], sec1[33..65], &cose_buf) catch unreachable;
    const auth_data_bytes = try buildAuthenticatorData(allocator, rp_id, 0, cose_bytes, null);
    defer allocator.free(auth_data_bytes);
    const att_obj = try buildAttestationObject(allocator, auth_data_bytes);
    defer allocator.free(att_obj);
    const cdj = try buildClientDataJSON(allocator, "webauthn.create", challenge, "https://evil.com");
    defer allocator.free(cdj);
    const cdj_b64 = try encodeToBase64url(allocator, cdj);
    defer allocator.free(cdj_b64);
    const att_b64 = try encodeToBase64url(allocator, att_obj);
    defer allocator.free(att_b64);

    const r = verifyRegistration(allocator, cdj_b64, att_b64, challenge, "https://example.com", rp_id);
    try std.testing.expectError(error.InvalidOrigin, r);
}

test "verifyRegistration rejects wrong rpId" {
    const allocator = std.testing.allocator;
    const origin = "https://example.com";
    const challenge = "ch";

    const kp = EcdsaP256Sha256.KeyPair.generate();
    const sec1 = kp.public_key.toUncompressedSec1();
    var cose_buf: [256]u8 = undefined;
    const cose_bytes = cose.encodeCoseKey(sec1[1..33], sec1[33..65], &cose_buf) catch unreachable;
    // Build auth data with rpId "wrong.com"
    const auth_data_bytes = try buildAuthenticatorData(allocator, "wrong.com", 0, cose_bytes, null);
    defer allocator.free(auth_data_bytes);
    const att_obj = try buildAttestationObject(allocator, auth_data_bytes);
    defer allocator.free(att_obj);
    const cdj = try buildClientDataJSON(allocator, "webauthn.create", challenge, origin);
    defer allocator.free(cdj);
    const cdj_b64 = try encodeToBase64url(allocator, cdj);
    defer allocator.free(cdj_b64);
    const att_b64 = try encodeToBase64url(allocator, att_obj);
    defer allocator.free(att_b64);

    const r = verifyRegistration(allocator, cdj_b64, att_b64, challenge, origin, "example.com");
    try std.testing.expectError(error.InvalidRpId, r);
}

test "verifyAuthentication succeeds with valid synthetic data" {
    const allocator = std.testing.allocator;
    const rp_id = "example.com";
    const origin = "https://example.com";
    const challenge = "auth-challenge-456";

    // Generate key pair
    const kp = EcdsaP256Sha256.KeyPair.generate();
    const sec1 = kp.public_key.toUncompressedSec1();

    // Encode COSE public key (as stored in DB)
    var cose_buf: [256]u8 = undefined;
    const cose_bytes = cose.encodeCoseKey(sec1[1..33], sec1[33..65], &cose_buf) catch unreachable;
    const pub_key_b64 = try encodeToBase64url(allocator, cose_bytes);
    defer allocator.free(pub_key_b64);

    // Build authenticatorData (no AT flag for authentication)
    const auth_data_bytes = try buildAuthenticatorData(allocator, rp_id, 1, null, null);
    defer allocator.free(auth_data_bytes);

    // Build clientDataJSON
    const cdj = try buildClientDataJSON(allocator, "webauthn.get", challenge, origin);
    defer allocator.free(cdj);

    // Compute signatureBase = authData || SHA-256(clientDataJSON)
    var cdj_hash: [32]u8 = undefined;
    Sha256.hash(cdj, &cdj_hash, .{});
    var sig_base = try allocator.alloc(u8, auth_data_bytes.len + 32);
    defer allocator.free(sig_base);
    @memcpy(sig_base[0..auth_data_bytes.len], auth_data_bytes);
    @memcpy(sig_base[auth_data_bytes.len..], &cdj_hash);

    // Sign
    const sig = try kp.sign(sig_base, null);
    var der_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const sig_der_slice = sig.toDer(&der_buf);

    // Base64url encode
    const cdj_b64 = try encodeToBase64url(allocator, cdj);
    defer allocator.free(cdj_b64);
    const auth_data_b64 = try encodeToBase64url(allocator, auth_data_bytes);
    defer allocator.free(auth_data_b64);
    const sig_b64 = try encodeToBase64url(allocator, sig_der_slice);
    defer allocator.free(sig_b64);

    // Verify
    const result = try verifyAuthentication(
        allocator,
        cdj_b64,
        auth_data_b64,
        sig_b64,
        pub_key_b64,
        0, // stored counter
        challenge,
        origin,
        rp_id,
    );
    defer allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "\"verified\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"newCounter\":1") != null);
}

test "verifyAuthentication rejects invalid signature" {
    const allocator = std.testing.allocator;
    const rp_id = "example.com";
    const origin = "https://example.com";
    const challenge = "ch";

    const kp = EcdsaP256Sha256.KeyPair.generate();
    const sec1 = kp.public_key.toUncompressedSec1();
    var cose_buf: [256]u8 = undefined;
    const cose_bytes = cose.encodeCoseKey(sec1[1..33], sec1[33..65], &cose_buf) catch unreachable;
    const pub_key_b64 = try encodeToBase64url(allocator, cose_bytes);
    defer allocator.free(pub_key_b64);

    const auth_data_bytes = try buildAuthenticatorData(allocator, rp_id, 1, null, null);
    defer allocator.free(auth_data_bytes);
    const cdj = try buildClientDataJSON(allocator, "webauthn.get", challenge, origin);
    defer allocator.free(cdj);

    // Sign WRONG data (not the proper signatureBase)
    const wrong_kp = EcdsaP256Sha256.KeyPair.generate();
    const wrong_sig = try wrong_kp.sign("wrong data", null);
    var wrong_der_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const wrong_der = wrong_sig.toDer(&wrong_der_buf);

    const cdj_b64 = try encodeToBase64url(allocator, cdj);
    defer allocator.free(cdj_b64);
    const auth_data_b64 = try encodeToBase64url(allocator, auth_data_bytes);
    defer allocator.free(auth_data_b64);
    const sig_b64 = try encodeToBase64url(allocator, wrong_der);
    defer allocator.free(sig_b64);

    const r = verifyAuthentication(allocator, cdj_b64, auth_data_b64, sig_b64, pub_key_b64, 0, challenge, origin, rp_id);
    try std.testing.expectError(error.InvalidSignature, r);
}

test "verifyAuthentication rejects counter not incremented" {
    const allocator = std.testing.allocator;
    const rp_id = "example.com";
    const origin = "https://example.com";
    const challenge = "ch";

    const kp = EcdsaP256Sha256.KeyPair.generate();
    const sec1 = kp.public_key.toUncompressedSec1();
    var cose_buf: [256]u8 = undefined;
    const cose_bytes = cose.encodeCoseKey(sec1[1..33], sec1[33..65], &cose_buf) catch unreachable;
    const pub_key_b64 = try encodeToBase64url(allocator, cose_bytes);
    defer allocator.free(pub_key_b64);

    // counter = 5, but stored_counter = 10 → should fail
    const auth_data_bytes = try buildAuthenticatorData(allocator, rp_id, 5, null, null);
    defer allocator.free(auth_data_bytes);
    const cdj = try buildClientDataJSON(allocator, "webauthn.get", challenge, origin);
    defer allocator.free(cdj);

    var cdj_hash: [32]u8 = undefined;
    Sha256.hash(cdj, &cdj_hash, .{});
    var sig_base = try allocator.alloc(u8, auth_data_bytes.len + 32);
    defer allocator.free(sig_base);
    @memcpy(sig_base[0..auth_data_bytes.len], auth_data_bytes);
    @memcpy(sig_base[auth_data_bytes.len..], &cdj_hash);

    const sig = try kp.sign(sig_base, null);
    var der_buf3: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const sig_der = sig.toDer(&der_buf3);

    const cdj_b64 = try encodeToBase64url(allocator, cdj);
    defer allocator.free(cdj_b64);
    const auth_data_b64 = try encodeToBase64url(allocator, auth_data_bytes);
    defer allocator.free(auth_data_b64);
    const sig_b64 = try encodeToBase64url(allocator, sig_der);
    defer allocator.free(sig_b64);

    const r = verifyAuthentication(allocator, cdj_b64, auth_data_b64, sig_b64, pub_key_b64, 10, challenge, origin, rp_id);
    try std.testing.expectError(error.CounterNotIncremented, r);
}

// ============================================================
// Real-world test vectors from fido2-helpers
// https://github.com/apowers313/fido2-helpers
// MIT License, Copyright (c) 2018 Adam Powers
// ============================================================

test "verifyRegistration with real fido2-helpers attestation-none data" {
    const allocator = std.testing.allocator;

    // Real attestation response captured from a browser (attestation: "none")
    const cdj_b64 = "eyJjaGFsbGVuZ2UiOiIzM0VIYXYtaloxdjlxd0g3ODNhVS1qMEFSeDZyNW8tWUhoLXdkN0M2alBiZDdXaDZ5dGJJWm9zSUlBQ2Vod2Y5LXM2aFhoeVNITy1ISFVqRXdaUzI5dyIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0";
    const att_b64 = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBJkmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAKIACKLdXqwahqjNbtNs1piUlonluvxOsF9Feeh9k7qXay5zdrm239cW4WQUD_l5ptTzRLU9bSbghnv0FLaRA7tly7La9_QRKDXwZMsbWajlhKQh2ovYnjh6C37qtyPs151ITDFr-67FRgG0c2dJCoOa2hQB8z0tJYuXrkGMpVk0ZSn1qjfeYxJ1V9BDRsfN7r0lVC8sF_w5OJlSomw64qampRylAQIDJiABIVgguxHN3W6ehp0VWXKaMNie1J82MVJCFZYScau74o17cx8iWCDb1jkTLi7lYZZbgwUwpqAk8QmIiPMTVQUVkhGEyGrKww";
    const challenge = "33EHav-jZ1v9qwH783aU-j0ARx6r5o-YHh-wd7C6jPbd7Wh6ytbIZosIIACehwf9-s6hXhySHO-HHUjEwZS29w";
    const origin = "https://localhost:8443";
    const rp_id = "localhost";

    const result = try verifyRegistration(allocator, cdj_b64, att_b64, challenge, origin, rp_id);
    defer allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "\"verified\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"counter\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"publicKeyAlgorithm\":-7") != null);
}

test "verifyAuthentication with real fido2-helpers assertion data" {
    const allocator = std.testing.allocator;

    // Real assertion response captured from a browser, with COSE public key converted from PEM
    const cdj_b64 = "eyJjaGFsbGVuZ2UiOiJlYVR5VU5ueVBERGRLOFNORWdURVV2ejFROGR5bGtqalRpbVlkNVg3UUFvLUY4X1oxbHNKaTNCaWxVcEZaSGtJQ05EV1k4cjlpdm5UZ1c3LVhaQzNxUSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uZ2V0In0";
    const auth_data_b64 = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAABaw";
    const sig_b64 = "MEYCIQD6dF3B0ZoaLA0r78oyRdoMNR0bN93Zi4cF_75hFAH6pQIhALY0UIsrh03u_f4yKOwzwD6Cj3_GWLJiioTT9580s1a7";
    // Public key from fido2-helpers assnPublicKey (PEM EC P-256), converted to COSE CBOR
    const pub_key_b64 = "pQECAyYgASFYIEXs_WjtsAQFjueDLhmxKknVmoUpxjAIN-QQjZGhN4_EIlggPjv2YYSqk3iCpuxJe9BBuno7eLINWWqEORC4PJN8sE4";
    const challenge = "eaTyUNnyPDDdK8SNEgTEUvz1Q8dylkjjTimYd5X7QAo-F8_Z1lsJi3BilUpFZHkICNDWY8r9ivnTgW7-XZC3qQ";
    const origin = "https://localhost:8443";
    const rp_id = "localhost";

    const result = try verifyAuthentication(
        allocator,
        cdj_b64,
        auth_data_b64,
        sig_b64,
        pub_key_b64,
        0, // stored counter; real counter in authData is 363
        challenge,
        origin,
        rp_id,
    );
    defer allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "\"verified\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"newCounter\":363") != null);
}

test "verifyAuthentication rejects wrong type" {
    const allocator = std.testing.allocator;
    const rp_id = "example.com";
    const origin = "https://example.com";
    const challenge = "ch";

    const kp = EcdsaP256Sha256.KeyPair.generate();
    const sec1 = kp.public_key.toUncompressedSec1();
    var cose_buf: [256]u8 = undefined;
    const cose_bytes = cose.encodeCoseKey(sec1[1..33], sec1[33..65], &cose_buf) catch unreachable;
    const pub_key_b64 = try encodeToBase64url(allocator, cose_bytes);
    defer allocator.free(pub_key_b64);

    const auth_data_bytes = try buildAuthenticatorData(allocator, rp_id, 1, null, null);
    defer allocator.free(auth_data_bytes);
    // Wrong type: "webauthn.create" instead of "webauthn.get"
    const cdj = try buildClientDataJSON(allocator, "webauthn.create", challenge, origin);
    defer allocator.free(cdj);

    const cdj_b64 = try encodeToBase64url(allocator, cdj);
    defer allocator.free(cdj_b64);
    const auth_data_b64 = try encodeToBase64url(allocator, auth_data_bytes);
    defer allocator.free(auth_data_b64);
    const sig_b64 = try encodeToBase64url(allocator, "fake-sig");
    defer allocator.free(sig_b64);

    const r = verifyAuthentication(allocator, cdj_b64, auth_data_b64, sig_b64, pub_key_b64, 0, challenge, origin, rp_id);
    try std.testing.expectError(error.InvalidType, r);
}

// ============================================================
// Security / vulnerability tests
// ============================================================

test "security: empty base64url inputs rejected" {
    const allocator = std.testing.allocator;
    // Empty clientDataJSON
    try std.testing.expectError(
        error.InvalidClientData,
        verifyRegistration(allocator, "", "dGVzdA", "ch", "https://x.com", "x.com"),
    );
    // Empty attestationObject
    const cdj = try buildClientDataJSON(allocator, "webauthn.create", "ch", "https://x.com");
    defer allocator.free(cdj);
    const cdj_b64 = try encodeToBase64url(allocator, cdj);
    defer allocator.free(cdj_b64);
    try std.testing.expectError(
        error.InvalidCbor,
        verifyRegistration(allocator, cdj_b64, "", "ch", "https://x.com", "x.com"),
    );
}

test "security: garbage base64url data rejected" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        error.InvalidClientData,
        verifyRegistration(allocator, "!!!invalid!!!", "dGVzdA", "ch", "https://x.com", "x.com"),
    );
}

test "security: truncated attestationObject CBOR rejected" {
    const allocator = std.testing.allocator;
    const rp_id = "example.com";
    const origin = "https://example.com";
    const challenge = "ch";

    const cdj = try buildClientDataJSON(allocator, "webauthn.create", challenge, origin);
    defer allocator.free(cdj);
    const cdj_b64 = try encodeToBase64url(allocator, cdj);
    defer allocator.free(cdj_b64);

    // CBOR map header (0xa3 = 3 entries) but no body → truncated
    const truncated = try encodeToBase64url(allocator, &[_]u8{0xa3});
    defer allocator.free(truncated);
    try std.testing.expectError(
        error.InvalidCbor,
        verifyRegistration(allocator, cdj_b64, truncated, challenge, origin, rp_id),
    );
}

test "security: clientDataJSON missing required fields rejected" {
    const allocator = std.testing.allocator;

    // JSON with no "type" field
    const json_no_type =
        \\{"challenge":"ch","origin":"https://x.com"}
    ;
    const b64 = try encodeToBase64url(allocator, json_no_type);
    defer allocator.free(b64);
    try std.testing.expectError(
        error.InvalidClientData,
        verifyRegistration(allocator, b64, "dGVzdA", "ch", "https://x.com", "x.com"),
    );
}

test "security: clientDataJSON non-JSON input rejected" {
    const allocator = std.testing.allocator;

    const not_json = try encodeToBase64url(allocator, "this is not json at all");
    defer allocator.free(not_json);
    try std.testing.expectError(
        error.InvalidClientData,
        verifyRegistration(allocator, not_json, "dGVzdA", "ch", "https://x.com", "x.com"),
    );
}

test "security: registration rejects cleared UP flag (user not present)" {
    const allocator = std.testing.allocator;
    const rp_id = "example.com";
    const origin = "https://example.com";
    const challenge = "ch";

    const kp = EcdsaP256Sha256.KeyPair.generate();
    const sec1 = kp.public_key.toUncompressedSec1();
    var cose_buf: [256]u8 = undefined;
    const cose_bytes = cose.encodeCoseKey(sec1[1..33], sec1[33..65], &cose_buf) catch unreachable;

    // Build authenticatorData with AT flag but manually clear UP flag
    const auth_data_bytes = try buildAuthenticatorData(allocator, rp_id, 0, cose_bytes, null);
    defer allocator.free(auth_data_bytes);
    // Clear UP flag (bit 0 of flags byte at offset 32)
    auth_data_bytes[32] &= ~@as(u8, 0x01);

    const att_obj = try buildAttestationObject(allocator, auth_data_bytes);
    defer allocator.free(att_obj);
    const cdj = try buildClientDataJSON(allocator, "webauthn.create", challenge, origin);
    defer allocator.free(cdj);
    const cdj_b64 = try encodeToBase64url(allocator, cdj);
    defer allocator.free(cdj_b64);
    const att_b64 = try encodeToBase64url(allocator, att_obj);
    defer allocator.free(att_b64);

    try std.testing.expectError(
        error.UserNotPresent,
        verifyRegistration(allocator, cdj_b64, att_b64, challenge, origin, rp_id),
    );
}

test "security: registration rejects cleared AT flag (no credential data)" {
    const allocator = std.testing.allocator;
    const rp_id = "example.com";
    const origin = "https://example.com";
    const challenge = "ch";

    // Build authenticatorData WITHOUT credential data (no COSE key)
    const auth_data_bytes = try buildAuthenticatorData(allocator, rp_id, 0, null, null);
    defer allocator.free(auth_data_bytes);

    const att_obj = try buildAttestationObject(allocator, auth_data_bytes);
    defer allocator.free(att_obj);
    const cdj = try buildClientDataJSON(allocator, "webauthn.create", challenge, origin);
    defer allocator.free(cdj);
    const cdj_b64 = try encodeToBase64url(allocator, cdj);
    defer allocator.free(cdj_b64);
    const att_b64 = try encodeToBase64url(allocator, att_obj);
    defer allocator.free(att_b64);

    try std.testing.expectError(
        error.InvalidAuthenticatorData,
        verifyRegistration(allocator, cdj_b64, att_b64, challenge, origin, rp_id),
    );
}

test "security: authentication rejects cleared UP flag" {
    const allocator = std.testing.allocator;
    const rp_id = "example.com";
    const origin = "https://example.com";
    const challenge = "ch";

    const kp = EcdsaP256Sha256.KeyPair.generate();
    const sec1 = kp.public_key.toUncompressedSec1();
    var cose_buf: [256]u8 = undefined;
    const cose_bytes = cose.encodeCoseKey(sec1[1..33], sec1[33..65], &cose_buf) catch unreachable;
    const pub_key_b64 = try encodeToBase64url(allocator, cose_bytes);
    defer allocator.free(pub_key_b64);

    const auth_data_bytes = try buildAuthenticatorData(allocator, rp_id, 1, null, null);
    defer allocator.free(auth_data_bytes);
    // Clear UP flag
    auth_data_bytes[32] &= ~@as(u8, 0x01);

    const cdj = try buildClientDataJSON(allocator, "webauthn.get", challenge, origin);
    defer allocator.free(cdj);

    // Sign with tampered auth data (to isolate the UP check, not signature check)
    var cdj_hash: [32]u8 = undefined;
    Sha256.hash(cdj, &cdj_hash, .{});
    var sig_base = try allocator.alloc(u8, auth_data_bytes.len + 32);
    defer allocator.free(sig_base);
    @memcpy(sig_base[0..auth_data_bytes.len], auth_data_bytes);
    @memcpy(sig_base[auth_data_bytes.len..], &cdj_hash);
    const sig = try kp.sign(sig_base, null);
    var der_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const sig_der = sig.toDer(&der_buf);

    const cdj_b64 = try encodeToBase64url(allocator, cdj);
    defer allocator.free(cdj_b64);
    const auth_data_b64 = try encodeToBase64url(allocator, auth_data_bytes);
    defer allocator.free(auth_data_b64);
    const sig_b64 = try encodeToBase64url(allocator, sig_der);
    defer allocator.free(sig_b64);

    try std.testing.expectError(
        error.UserNotPresent,
        verifyAuthentication(allocator, cdj_b64, auth_data_b64, sig_b64, pub_key_b64, 0, challenge, origin, rp_id),
    );
}

test "security: signature bit-flip attack rejected" {
    const allocator = std.testing.allocator;
    const rp_id = "example.com";
    const origin = "https://example.com";
    const challenge = "sig-flip-test";

    const kp = EcdsaP256Sha256.KeyPair.generate();
    const sec1 = kp.public_key.toUncompressedSec1();
    var cose_buf: [256]u8 = undefined;
    const cose_bytes = cose.encodeCoseKey(sec1[1..33], sec1[33..65], &cose_buf) catch unreachable;
    const pub_key_b64 = try encodeToBase64url(allocator, cose_bytes);
    defer allocator.free(pub_key_b64);

    const auth_data_bytes = try buildAuthenticatorData(allocator, rp_id, 1, null, null);
    defer allocator.free(auth_data_bytes);
    const cdj = try buildClientDataJSON(allocator, "webauthn.get", challenge, origin);
    defer allocator.free(cdj);

    var cdj_hash: [32]u8 = undefined;
    Sha256.hash(cdj, &cdj_hash, .{});
    var sig_base = try allocator.alloc(u8, auth_data_bytes.len + 32);
    defer allocator.free(sig_base);
    @memcpy(sig_base[0..auth_data_bytes.len], auth_data_bytes);
    @memcpy(sig_base[auth_data_bytes.len..], &cdj_hash);

    // Create valid signature then flip one bit
    const sig = try kp.sign(sig_base, null);
    var der_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const sig_der = sig.toDer(&der_buf);
    var tampered_sig = try allocator.alloc(u8, sig_der.len);
    defer allocator.free(tampered_sig);
    @memcpy(tampered_sig, sig_der);
    // Flip one bit in the middle of the signature
    tampered_sig[tampered_sig.len / 2] ^= 0x01;

    const cdj_b64 = try encodeToBase64url(allocator, cdj);
    defer allocator.free(cdj_b64);
    const auth_data_b64 = try encodeToBase64url(allocator, auth_data_bytes);
    defer allocator.free(auth_data_b64);
    const sig_b64 = try encodeToBase64url(allocator, tampered_sig);
    defer allocator.free(sig_b64);

    try std.testing.expectError(
        error.InvalidSignature,
        verifyAuthentication(allocator, cdj_b64, auth_data_b64, sig_b64, pub_key_b64, 0, challenge, origin, rp_id),
    );
}

test "security: authentication with wrong public key rejected" {
    const allocator = std.testing.allocator;
    const rp_id = "example.com";
    const origin = "https://example.com";
    const challenge = "wrong-key-test";

    const kp = EcdsaP256Sha256.KeyPair.generate();
    // Use a DIFFERENT key for verification
    const wrong_kp = EcdsaP256Sha256.KeyPair.generate();
    const wrong_sec1 = wrong_kp.public_key.toUncompressedSec1();
    var cose_buf: [256]u8 = undefined;
    const cose_bytes = cose.encodeCoseKey(wrong_sec1[1..33], wrong_sec1[33..65], &cose_buf) catch unreachable;
    const wrong_pub_key_b64 = try encodeToBase64url(allocator, cose_bytes);
    defer allocator.free(wrong_pub_key_b64);

    const auth_data_bytes = try buildAuthenticatorData(allocator, rp_id, 1, null, null);
    defer allocator.free(auth_data_bytes);
    const cdj = try buildClientDataJSON(allocator, "webauthn.get", challenge, origin);
    defer allocator.free(cdj);

    var cdj_hash: [32]u8 = undefined;
    Sha256.hash(cdj, &cdj_hash, .{});
    var sig_base = try allocator.alloc(u8, auth_data_bytes.len + 32);
    defer allocator.free(sig_base);
    @memcpy(sig_base[0..auth_data_bytes.len], auth_data_bytes);
    @memcpy(sig_base[auth_data_bytes.len..], &cdj_hash);

    // Sign with the CORRECT key
    const sig = try kp.sign(sig_base, null);
    var der_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const sig_der = sig.toDer(&der_buf);

    const cdj_b64 = try encodeToBase64url(allocator, cdj);
    defer allocator.free(cdj_b64);
    const auth_data_b64 = try encodeToBase64url(allocator, auth_data_bytes);
    defer allocator.free(auth_data_b64);
    const sig_b64 = try encodeToBase64url(allocator, sig_der);
    defer allocator.free(sig_b64);

    // Verify with the WRONG public key → should fail
    try std.testing.expectError(
        error.InvalidSignature,
        verifyAuthentication(allocator, cdj_b64, auth_data_b64, sig_b64, wrong_pub_key_b64, 0, challenge, origin, rp_id),
    );
}

test "security: counter both zero skips counter check" {
    const allocator = std.testing.allocator;
    const rp_id = "example.com";
    const origin = "https://example.com";
    const challenge = "counter-zero";

    const kp = EcdsaP256Sha256.KeyPair.generate();
    const sec1 = kp.public_key.toUncompressedSec1();
    var cose_buf: [256]u8 = undefined;
    const cose_bytes = cose.encodeCoseKey(sec1[1..33], sec1[33..65], &cose_buf) catch unreachable;
    const pub_key_b64 = try encodeToBase64url(allocator, cose_bytes);
    defer allocator.free(pub_key_b64);

    // Both counters = 0 → spec says counter check should be skipped
    const auth_data_bytes = try buildAuthenticatorData(allocator, rp_id, 0, null, null);
    defer allocator.free(auth_data_bytes);
    const cdj = try buildClientDataJSON(allocator, "webauthn.get", challenge, origin);
    defer allocator.free(cdj);

    var cdj_hash: [32]u8 = undefined;
    Sha256.hash(cdj, &cdj_hash, .{});
    var sig_base = try allocator.alloc(u8, auth_data_bytes.len + 32);
    defer allocator.free(sig_base);
    @memcpy(sig_base[0..auth_data_bytes.len], auth_data_bytes);
    @memcpy(sig_base[auth_data_bytes.len..], &cdj_hash);

    const sig = try kp.sign(sig_base, null);
    var der_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const sig_der = sig.toDer(&der_buf);

    const cdj_b64 = try encodeToBase64url(allocator, cdj);
    defer allocator.free(cdj_b64);
    const auth_data_b64 = try encodeToBase64url(allocator, auth_data_bytes);
    defer allocator.free(auth_data_b64);
    const sig_b64 = try encodeToBase64url(allocator, sig_der);
    defer allocator.free(sig_b64);

    // stored_counter = 0, authData counter = 0 → should succeed (skip check)
    const result = try verifyAuthentication(allocator, cdj_b64, auth_data_b64, sig_b64, pub_key_b64, 0, challenge, origin, rp_id);
    defer allocator.free(result);
    try std.testing.expect(std.mem.indexOf(u8, result, "\"verified\":true") != null);
}

test "security: non-empty attStmt with fmt=none rejected" {
    const allocator = std.testing.allocator;
    const rp_id = "example.com";
    const origin = "https://example.com";
    const challenge = "ch";

    const kp = EcdsaP256Sha256.KeyPair.generate();
    const sec1 = kp.public_key.toUncompressedSec1();
    var cose_buf: [256]u8 = undefined;
    const cose_bytes = cose.encodeCoseKey(sec1[1..33], sec1[33..65], &cose_buf) catch unreachable;

    const auth_data_bytes = try buildAuthenticatorData(allocator, rp_id, 0, cose_bytes, null);
    defer allocator.free(auth_data_bytes);

    // Build malicious attestation object: fmt="none" but attStmt has content
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    try buf.append(allocator, 0xa3); // map(3)
    try buf.append(allocator, 0x63); // text(3)
    try buf.appendSlice(allocator, "fmt");
    try buf.append(allocator, 0x64); // text(4)
    try buf.appendSlice(allocator, "none");
    try buf.append(allocator, 0x67); // text(7)
    try buf.appendSlice(allocator, "attStmt");
    // Non-empty map: {"fake": "data"}
    try buf.append(allocator, 0xa1); // map(1)
    try buf.append(allocator, 0x64); // text(4)
    try buf.appendSlice(allocator, "fake");
    try buf.append(allocator, 0x64); // text(4)
    try buf.appendSlice(allocator, "data");
    try buf.append(allocator, 0x68); // text(8)
    try buf.appendSlice(allocator, "authData");
    if (auth_data_bytes.len <= 0xff) {
        try buf.append(allocator, 0x58);
        try buf.append(allocator, @intCast(auth_data_bytes.len));
    } else {
        try buf.append(allocator, 0x59);
        const len16: u16 = @intCast(auth_data_bytes.len);
        try buf.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeTo(u16, len16, .big)));
    }
    try buf.appendSlice(allocator, auth_data_bytes);
    const att_obj = try buf.toOwnedSlice(allocator);
    defer allocator.free(att_obj);

    const cdj = try buildClientDataJSON(allocator, "webauthn.create", challenge, origin);
    defer allocator.free(cdj);
    const cdj_b64 = try encodeToBase64url(allocator, cdj);
    defer allocator.free(cdj_b64);
    const att_b64 = try encodeToBase64url(allocator, att_obj);
    defer allocator.free(att_b64);

    try std.testing.expectError(
        error.InvalidAttestationFormat,
        verifyRegistration(allocator, cdj_b64, att_b64, challenge, origin, rp_id),
    );
}

test "security: unsupported attestation format rejected" {
    const allocator = std.testing.allocator;
    const rp_id = "example.com";
    const origin = "https://example.com";
    const challenge = "ch";

    const kp = EcdsaP256Sha256.KeyPair.generate();
    const sec1 = kp.public_key.toUncompressedSec1();
    var cose_buf: [256]u8 = undefined;
    const cose_bytes = cose.encodeCoseKey(sec1[1..33], sec1[33..65], &cose_buf) catch unreachable;

    const auth_data_bytes = try buildAuthenticatorData(allocator, rp_id, 0, cose_bytes, null);
    defer allocator.free(auth_data_bytes);

    // Build attestation object with fmt="packed" (unsupported)
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    try buf.append(allocator, 0xa3);
    try buf.append(allocator, 0x63);
    try buf.appendSlice(allocator, "fmt");
    try buf.append(allocator, 0x66); // text(6)
    try buf.appendSlice(allocator, "packed");
    try buf.append(allocator, 0x67);
    try buf.appendSlice(allocator, "attStmt");
    try buf.append(allocator, 0xa0); // empty map
    try buf.append(allocator, 0x68);
    try buf.appendSlice(allocator, "authData");
    if (auth_data_bytes.len <= 0xff) {
        try buf.append(allocator, 0x58);
        try buf.append(allocator, @intCast(auth_data_bytes.len));
    } else {
        try buf.append(allocator, 0x59);
        const len16: u16 = @intCast(auth_data_bytes.len);
        try buf.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeTo(u16, len16, .big)));
    }
    try buf.appendSlice(allocator, auth_data_bytes);
    const att_obj = try buf.toOwnedSlice(allocator);
    defer allocator.free(att_obj);

    const cdj = try buildClientDataJSON(allocator, "webauthn.create", challenge, origin);
    defer allocator.free(cdj);
    const cdj_b64 = try encodeToBase64url(allocator, cdj);
    defer allocator.free(cdj_b64);
    const att_b64 = try encodeToBase64url(allocator, att_obj);
    defer allocator.free(att_b64);

    try std.testing.expectError(
        error.InvalidAttestationFormat,
        verifyRegistration(allocator, cdj_b64, att_b64, challenge, origin, rp_id),
    );
}
