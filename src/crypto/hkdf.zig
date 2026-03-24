// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");

/// Default salt used in the FLE key hierarchy.
/// Kept consistent with Geode for interoperability.
pub const default_salt = "geode-fle-salt";

/// General-purpose HKDF-SHA256 key derivation (RFC 5869).
///
/// Derives output keying material of arbitrary length from input keying
/// material, salt, and info context. Usable for any key derivation need,
/// not only the FLE key hierarchy.
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
    const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;

    // Extract: PRK = HMAC-SHA256(salt, IKM)
    var prk: [32]u8 = undefined;
    var extract_hmac = Hmac.init(salt);
    extract_hmac.update(ikm);
    extract_hmac.final(&prk);
    defer std.crypto.secureZero(u8, &prk);

    // Expand: OKM = T(1) || T(2) || ... || T(N)
    var okm_pos: usize = 0;
    var counter: u8 = 1;
    var t_prev: [32]u8 = undefined;
    var t_prev_len: usize = 0;

    while (okm_pos < out.len) {
        var expand_hmac = Hmac.init(&prk);

        if (counter > 1) {
            expand_hmac.update(t_prev[0..t_prev_len]);
        }

        expand_hmac.update(info);
        expand_hmac.update(&[_]u8{counter});

        var t: [32]u8 = undefined;
        expand_hmac.final(&t);

        const copy_len = @min(32, out.len - okm_pos);
        @memcpy(out[okm_pos .. okm_pos + copy_len], t[0..copy_len]);

        @memcpy(&t_prev, &t);
        std.crypto.secureZero(u8, &t);
        t_prev_len = 32;
        okm_pos += copy_len;
        counter += 1;

        if (counter == 0) return error.HkdfOutputTooLong;
    }
    std.crypto.secureZero(u8, &t_prev);
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
    std.crypto.random.bytes(&master);

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
