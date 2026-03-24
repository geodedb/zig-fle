// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");

/// Compute HMAC-SHA256 blind index token
pub fn blindIndexHmac256(out: *[32]u8, bik: []const u8, normalized: []const u8) void {
    const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
    var mac = Hmac.init(bik);
    mac.update(normalized);
    mac.final(out);
}

/// Normalize value for blind index: ASCII lowercase + trim.
/// Provides deterministic matching for searchable encrypted fields.
pub fn normalizeForBlindIndex(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    // Trim whitespace
    var start: usize = 0;
    var end: usize = value.len;

    while (start < end and std.ascii.isWhitespace(value[start])) {
        start += 1;
    }

    while (end > start and std.ascii.isWhitespace(value[end - 1])) {
        end -= 1;
    }

    const trimmed = value[start..end];

    // Convert to lowercase
    const normalized = try allocator.alloc(u8, trimmed.len);
    for (trimmed, 0..) |c, i| {
        normalized[i] = std.ascii.toLower(c);
    }

    return normalized;
}

/// Convert blind index token to hex string (64 chars, lowercase)
pub fn tokenToHex(allocator: std.mem.Allocator, token: [32]u8) ![]u8 {
    const hex_digits = "0123456789abcdef";
    var hex = try allocator.alloc(u8, 64);

    for (token, 0..) |byte, i| {
        hex[i * 2] = hex_digits[byte >> 4];
        hex[i * 2 + 1] = hex_digits[byte & 0x0F];
    }

    return hex;
}

/// Parse hex string back to token
pub fn hexToToken(hex: []const u8) ![32]u8 {
    if (hex.len != 64) return error.InvalidHexLength;

    var token: [32]u8 = undefined;
    for (0..32) |i| {
        const hi = try std.fmt.charToDigit(hex[i * 2], 16);
        const lo = try std.fmt.charToDigit(hex[i * 2 + 1], 16);
        token[i] = @as(u8, hi) * 16 + @as(u8, lo);
    }

    return token;
}

test "HMAC-SHA256 RFC 4231 test vector - Jefe" {
    const testing = std.testing;

    const key = "Jefe";
    const msg = "what do ya want for nothing?";

    var out: [32]u8 = undefined;
    blindIndexHmac256(&out, key, msg);

    const expected = [_]u8{
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
        0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
        0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
    };

    try testing.expectEqualSlices(u8, &expected, &out);
}

test "Normalization for blind index" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const normalized = try normalizeForBlindIndex(allocator, "  Alice@Example.COM  ");
    defer allocator.free(normalized);

    try testing.expectEqualStrings("alice@example.com", normalized);
}

test "Token hex conversion round-trip" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const token = [_]u8{
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
        0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
        0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
    };

    const hex = try tokenToHex(allocator, token);
    defer allocator.free(hex);

    try testing.expectEqualStrings("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", hex);

    const token2 = try hexToToken(hex);
    try testing.expectEqualSlices(u8, &token, &token2);
}
