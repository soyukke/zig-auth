const webauthn_impl = @import("webauthn.zig");

// ── Primary API ──
pub const verifyRegistration = webauthn_impl.verifyRegistration;
pub const verifyAuthentication = webauthn_impl.verifyAuthentication;
pub const WebAuthnError = webauthn_impl.WebAuthnError;
pub const RegistrationResult = webauthn_impl.RegistrationResult;

// ── Sub-modules (advanced usage) ──
pub const cbor = @import("cbor.zig");
pub const cose = @import("cose.zig");
pub const authenticator_data = @import("authenticator_data.zig");
pub const base64url = @import("base64url.zig");

test {
    _ = webauthn_impl;
    _ = cbor;
    _ = cose;
    _ = authenticator_data;
    _ = base64url;
}
