pub const AuthError = error{
    InvalidPassword,
    ExpiredToken,
    InvalidSignature,
    InvalidToken,
    BufferTooSmall,
    InternalError,
};

pub const StatusCode = enum(i32) {
    ok = 0,
    invalid_password = 1,
    expired_token = 2,
    invalid_signature = 3,
    invalid_token = 4,
    buffer_too_small = 5,
    internal_error = 6,
    // WebAuthn status codes (used by main.zig glue layer)
    invalid_client_data = 7,
    invalid_type = 8,
    invalid_challenge = 9,
    invalid_origin = 10,
    invalid_rp_id = 11,
    invalid_attestation = 12,
    invalid_attestation_format = 13,
    unsupported_algorithm = 14,
    invalid_authenticator_data = 15,
    user_not_present = 16,
    counter_not_incremented = 17,
    invalid_cbor = 18,
    invalid_encoding = 19,
};

pub fn errorToStatus(err: AuthError) StatusCode {
    return switch (err) {
        error.InvalidPassword => .invalid_password,
        error.ExpiredToken => .expired_token,
        error.InvalidSignature => .invalid_signature,
        error.InvalidToken => .invalid_token,
        error.BufferTooSmall => .buffer_too_small,
        error.InternalError => .internal_error,
    };
}

test "errorToStatus maps all errors" {
    const std = @import("std");
    try std.testing.expectEqual(StatusCode.invalid_password, errorToStatus(error.InvalidPassword));
    try std.testing.expectEqual(StatusCode.expired_token, errorToStatus(error.ExpiredToken));
    try std.testing.expectEqual(StatusCode.invalid_signature, errorToStatus(error.InvalidSignature));
    try std.testing.expectEqual(StatusCode.invalid_token, errorToStatus(error.InvalidToken));
    try std.testing.expectEqual(StatusCode.buffer_too_small, errorToStatus(error.BufferTooSmall));
    try std.testing.expectEqual(StatusCode.internal_error, errorToStatus(error.InternalError));
}
