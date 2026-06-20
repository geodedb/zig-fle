// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");
const backend = @import("crypto_backend");

/// Default salt used in the FLE key hierarchy.
/// Kept consistent with Geode for interoperability.
pub const default_salt = "geode-fle-salt";

/// General-purpose HKDF-SHA256 key derivation (RFC 5869).
///
/// Delegates to the FIPS seam (`crypto_backend.Kdf.hkdf`). Under
/// -Dfips=true this is OpenSSL's FIPS HKDF (SP 800-56C); under
/// -Dfips=false it is std.crypto's HKDF. Output length is bounded by
/// HKDF's 255*HashLen limit; the seam returns error.OpensslFailure on
/// over-length output.
///
/// Parameters:
///   out  - output buffer (any length up to 255 * 32 bytes)
///   ikm  - input keying material (e.g., master key, shared secret, signature)
///   salt - optional salt (use a fixed domain string if no random salt)
///   info - context/application-specific info string for domain separation
pub fn hkdfSha256(
    out: []u8,
    ikm: []const u8,
    salt: []const u8,
    info: []const u8,
) !void {
    try backend.Kdf.hkdf(.sha256, ikm, salt, info, out);
}

/// Derive a 32-byte key from input keying material with salt and context.
///
/// Convenience wrapper around `hkdfSha256` for the common case of
/// deriving a single 256-bit key. Suitable for any HKDF-SHA256 use case
/// (HSM wrapping keys, session keys, etc.), not only the FLE hierarchy.
pub fn deriveKey32(
    master: []const u8,
    salt: []const u8,
    context: []const u8,
) ![32]u8 {
    var out: [32]u8 = undefined;
    try hkdfSha256(&out, master, salt, context);
    return out;
}

/// Derive TRK (Tenant Root Key) from master.
/// Context prefix kept consistent with Geode for interoperability.
pub fn deriveTRK(master: []const u8, tenant_id: []const u8) ![32]u8 {
    var context_buf: [256]u8 = undefined;
    const context = try std.fmt.bufPrint(&context_buf, "geode/trk/{s}", .{tenant_id});
    return deriveKey32(master, default_salt, context);
}

/// Derive SK (Schema Key) from TRK
pub fn deriveSK(trk: []const u8, schema: []const u8) ![32]u8 {
    var context_buf: [256]u8 = undefined;
    const context = try std.fmt.bufPrint(&context_buf, "geode/sk/{s}", .{schema});
    return deriveKey32(trk, default_salt, context);
}

/// Derive FEK (Field Encryption Key) from SK
pub fn deriveFEK(sk: []const u8, field: []const u8) ![32]u8 {
    var context_buf: [256]u8 = undefined;
    const context = try std.fmt.bufPrint(&context_buf, "geode/fek/{s}", .{field});
    return deriveKey32(sk, default_salt, context);
}

/// Derive FEK with version for key rotation support
pub fn deriveFEKVersioned(sk: []const u8, field: []const u8, version: u16) ![32]u8 {
    var context_buf: [256]u8 = undefined;
    const context = try std.fmt.bufPrint(&context_buf, "geode/fek/{s}/v{d}", .{ field, version });
    return deriveKey32(sk, default_salt, context);
}

/// Derive BIK (Blind Index Key) from SK
pub fn deriveBIK(sk: []const u8, field: []const u8) ![32]u8 {
    var context_buf: [256]u8 = undefined;
    const context = try std.fmt.bufPrint(&context_buf, "geode/bi/{s}", .{field});
    return deriveKey32(sk, default_salt, context);
}

/// Derive BIK with version for key rotation support
pub fn deriveBIKVersioned(sk: []const u8, field: []const u8, version: u16) ![32]u8 {
    var context_buf: [256]u8 = undefined;
    const context = try std.fmt.bufPrint(&context_buf, "geode/bi/{s}/v{d}", .{ field, version });
    return deriveKey32(sk, default_salt, context);
}

test "HKDF-SHA256 RFC 5869 test case 1" {
    // RFC 5869 Appendix A, Test Case 1
    const ikm = [_]u8{0x0b} ** 22;
    const salt = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };
    const info = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9 };
    const expected_okm = [_]u8{
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
        0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
        0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
        0x58, 0x65,
    };

    var okm: [42]u8 = undefined;
    try hkdfSha256(&okm, &ikm, &salt, &info);
    try std.testing.expectEqualSlices(u8, &expected_okm, &okm);
}

test "HKDF-SHA256 RFC 5869 test case 2 (long inputs)" {
    // IKM = 0x00..0x4f (80 bytes), salt = 0x60..0xaf (80 bytes), info = 0xb0..0xff (80 bytes), L = 82
    var ikm: [80]u8 = undefined;
    for (&ikm, 0..) |*b, i| b.* = @intCast(i);
    var salt: [80]u8 = undefined;
    for (&salt, 0..) |*b, i| b.* = @intCast(0x60 + i);
    var info: [80]u8 = undefined;
    for (&info, 0..) |*b, i| b.* = @intCast(0xb0 + i);

    var okm: [82]u8 = undefined;
    try hkdfSha256(&okm, &ikm, &salt, &info);

    const expected = [_]u8{
        0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1, 0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a, 0x49, 0x34,
        0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8, 0xa0, 0x50, 0xcc, 0x4c, 0x19, 0xaf, 0xa9, 0x7c,
        0x59, 0x04, 0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72, 0x71, 0xcb, 0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09,
        0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8, 0x36, 0x77, 0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71,
        0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec, 0x3e, 0x87, 0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f,
        0x1d, 0x87,
    };
    try std.testing.expectEqualSlices(u8, &expected, &okm);
}

test "HKDF-SHA256 RFC 5869 test case 3 (zero-length salt and info)" {
    const ikm = [_]u8{0x0b} ** 22;
    var okm: [42]u8 = undefined;
    try hkdfSha256(&okm, &ikm, "", "");

    const expected = [_]u8{
        0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f, 0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c, 0x5a, 0x31,
        0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e, 0xc3, 0x45, 0x4e, 0x5f, 0x3c, 0x73, 0x8d, 0x2d,
        0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a, 0x96, 0xc8,
    };
    try std.testing.expectEqualSlices(u8, &expected, &okm);
}

test "HKDF-SHA256 derivation" {
    const testing = std.testing;

    const ikm = "input keying material";
    const salt = "salt";
    const info = "context info";

    var out: [42]u8 = undefined;
    try hkdfSha256(&out, ikm, salt, info);

    // Verify output is non-zero and deterministic
    var all_zero = true;
    for (out) |byte| {
        if (byte != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);

    // Same inputs produce same output
    var out2: [42]u8 = undefined;
    try hkdfSha256(&out2, ikm, salt, info);
    try testing.expectEqualSlices(u8, &out, &out2);

    // Different info produces different output
    var out3: [42]u8 = undefined;
    try hkdfSha256(&out3, ikm, salt, "different");
    try testing.expect(!std.mem.eql(u8, &out, &out3));
}

test "Key hierarchy derivation" {
    const testing = std.testing;

    var master: [32]u8 = undefined;
    // fips-exempt: non-security — test/example fixture key generation
    std.Io.Threaded.global_single_threaded.io().random(&master);

    const tenant_id = "tenant-123";
    const schema = "Person";
    const field = "ssn";

    const trk = try deriveTRK(&master, tenant_id);
    const sk = try deriveSK(&trk, schema);
    const fek = try deriveFEK(&sk, field);
    const bik = try deriveBIK(&sk, field);

    // All keys should be different
    try testing.expect(!std.mem.eql(u8, &trk, &sk));
    try testing.expect(!std.mem.eql(u8, &sk, &fek));
    try testing.expect(!std.mem.eql(u8, &fek, &bik));

    // Same inputs produce same keys
    const fek2 = try deriveFEK(&sk, field);
    try testing.expectEqualSlices(u8, &fek, &fek2);
}

test "hkdfSha256 routes through the FIPS seam (RFC 5869 TC1)" {
    const ikm = [_]u8{0x0b} ** 22;
    const salt = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };
    const info = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9 };
    var seam_okm: [42]u8 = undefined;
    try backend.Kdf.hkdf(.sha256, &ikm, &salt, &info, &seam_okm);
    var our_okm: [42]u8 = undefined;
    try hkdfSha256(&our_okm, &ikm, &salt, &info);
    try std.testing.expectEqualSlices(u8, &seam_okm, &our_okm);
}
