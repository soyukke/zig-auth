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
