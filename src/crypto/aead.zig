// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");

/// Supported AEAD algorithms.
/// Wire values are stable for serialized envelopes and cross-project use.
pub const Alg = enum(u8) {
    aes256_gcm = 1,
    chacha20_poly1305 = 2,
    xchacha20_poly1305 = 3,

    /// Nonce size in bytes for this algorithm.
    pub fn nonceSz(self: Alg) usize {
        return switch (self) {
            .aes256_gcm, .chacha20_poly1305 => 12,
            .xchacha20_poly1305 => 24,
        };
    }

    /// Human-readable algorithm name.
    pub fn name(self: Alg) []const u8 {
        return switch (self) {
            .aes256_gcm => "aes-256-gcm",
            .chacha20_poly1305 => "chacha20-poly1305",
            .xchacha20_poly1305 => "xchacha20-poly1305",
        };
    }
};

/// AEAD-related errors
pub const Error = error{
    InvalidAlg,
    InvalidKey,
    NonceReuse,
    AEADAuthFailed,
    InvalidEnvelope,
    InvalidInput,
    OutOfMemory,
    SearchNotPermitted,
};

/// Envelope V1 format for encrypted fields
/// Format: [alg_id:u8][key_version:u16 LE][nonce:12][tag:16][ciphertext_len:u32 LE][ciphertext]
pub const EnvelopeV1 = struct {
    alg_id: u8,
    key_version: u16,
    nonce: [12]u8,
    tag: [16]u8,
    ciphertext: []u8,

    pub fn deinit(self: *EnvelopeV1, allocator: std.mem.Allocator) void {
        allocator.free(self.ciphertext);
    }

    /// Serialize envelope to binary format
    pub fn serialize(self: EnvelopeV1, allocator: std.mem.Allocator) ![]u8 {
        const total_len = 1 + 2 + 12 + 16 + 4 + self.ciphertext.len;
        var buffer = try allocator.alloc(u8, total_len);

        buffer[0] = self.alg_id;
        std.mem.writeInt(u16, buffer[1..3], self.key_version, .little);
        @memcpy(buffer[3..15], &self.nonce);
        @memcpy(buffer[15..31], &self.tag);
        std.mem.writeInt(u32, buffer[31..35], @intCast(self.ciphertext.len), .little);
        @memcpy(buffer[35..], self.ciphertext);

        return buffer;
    }

    /// Deserialize envelope from binary format
    pub fn deserialize(allocator: std.mem.Allocator, data: []const u8) !EnvelopeV1 {
        if (data.len < 35) return Error.InvalidEnvelope;

        const alg_id = data[0];
        const key_version = std.mem.readInt(u16, data[1..3], .little);
        var nonce: [12]u8 = undefined;
        @memcpy(&nonce, data[3..15]);
        var tag: [16]u8 = undefined;
        @memcpy(&tag, data[15..31]);
        const ciphertext_len = std.mem.readInt(u32, data[31..35], .little);

        if (data.len < 35 + ciphertext_len) return Error.InvalidEnvelope;

        const ciphertext = try allocator.alloc(u8, ciphertext_len);
        @memcpy(ciphertext, data[35 .. 35 + ciphertext_len]);

        return EnvelopeV1{
            .alg_id = alg_id,
            .key_version = key_version,
            .nonce = nonce,
            .tag = tag,
            .ciphertext = ciphertext,
        };
    }
};

/// Construct Additional Authenticated Data (AAD) binding ciphertext to context.
/// Uses length-prefixed encoding to prevent injection: each field is preceded
/// by its length as a 4-byte little-endian u32. This is canonically unambiguous
/// regardless of field content.
/// Format: [len:u32 LE][tenant_id][len:u32 LE][schema][len:u32 LE][field][len:u32 LE][record_id][key_version:u16 LE]
pub fn makeAAD(
    allocator: std.mem.Allocator,
    tenant_id: []const u8,
    schema: []const u8,
    field: []const u8,
    record_id: []const u8,
    key_version: u16,
) ![]u8 {
    const total_len = 4 + tenant_id.len + 4 + schema.len + 4 + field.len + 4 + record_id.len + 2;
    var aad = try allocator.alloc(u8, total_len);

    var pos: usize = 0;
    inline for (.{ tenant_id, schema, field, record_id }) |s| {
        std.mem.writeInt(u32, aad[pos..][0..4], @intCast(s.len), .little);
        pos += 4;
        @memcpy(aad[pos .. pos + s.len], s);
        pos += s.len;
    }
    std.mem.writeInt(u16, aad[pos..][0..2], key_version, .little);

    return aad;
}

/// Maximum plaintext size for field encryption (64 KiB).
pub const max_plaintext_size: usize = 64 * 1024;

/// Encrypt field data with AEAD.
/// Nonces are always generated randomly from the OS CSPRNG.
/// Only AES-256-GCM and ChaCha20-Poly1305 are supported through this API;
/// use `wrapKey32` for XChaCha20-Poly1305 key wrapping.
pub fn encryptField(
    allocator: std.mem.Allocator,
    alg: Alg,
    fek: []const u8,
    aad: []const u8,
    plaintext: []const u8,
    key_version: u16,
) !EnvelopeV1 {
    if (fek.len != 32) return Error.InvalidKey;
    if (plaintext.len > max_plaintext_size) return Error.InvalidInput;

    var nonce: [12]u8 = undefined;
    std.crypto.random.bytes(&nonce);

    const ciphertext = try allocator.alloc(u8, plaintext.len);
    errdefer allocator.free(ciphertext);

    var tag: [16]u8 = undefined;

    switch (alg) {
        .aes256_gcm => {
            const AES = std.crypto.aead.aes_gcm.Aes256Gcm;
            AES.encrypt(ciphertext, &tag, plaintext, aad, nonce, fek[0..32].*);
        },
        .chacha20_poly1305 => {
            const ChaCha = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
            ChaCha.encrypt(ciphertext, &tag, plaintext, aad, nonce, fek[0..32].*);
        },
        .xchacha20_poly1305 => {
            // XChaCha20 requires 24-byte nonces; not compatible with EnvelopeV1.
            // Use wrapKey32 or the raw XChaCha20Poly1305 primitive directly.
            // errdefer above handles freeing ciphertext on error return.
            return Error.InvalidAlg;
        },
    }

    return EnvelopeV1{
        .alg_id = @intFromEnum(alg),
        .key_version = key_version,
        .nonce = nonce,
        .tag = tag,
        .ciphertext = ciphertext,
    };
}

/// Decrypt field data from envelope
pub fn decryptField(
    allocator: std.mem.Allocator,
    fek: []const u8,
    aad: []const u8,
    envelope: EnvelopeV1,
) ![]u8 {
    if (fek.len != 32) return Error.InvalidKey;

    const plaintext = try allocator.alloc(u8, envelope.ciphertext.len);

    const alg = std.meta.intToEnum(Alg, envelope.alg_id) catch {
        std.crypto.secureZero(u8, plaintext);
        allocator.free(plaintext);
        return Error.InvalidAlg;
    };

    switch (alg) {
        .aes256_gcm => {
            const AES = std.crypto.aead.aes_gcm.Aes256Gcm;
            AES.decrypt(
                plaintext,
                envelope.ciphertext,
                envelope.tag,
                aad,
                envelope.nonce,
                fek[0..32].*,
            ) catch {
                std.crypto.secureZero(u8, plaintext);
                allocator.free(plaintext);
                return Error.AEADAuthFailed;
            };
        },
        .chacha20_poly1305 => {
            const ChaCha = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
            ChaCha.decrypt(
                plaintext,
                envelope.ciphertext,
                envelope.tag,
                aad,
                envelope.nonce,
                fek[0..32].*,
            ) catch {
                std.crypto.secureZero(u8, plaintext);
                allocator.free(plaintext);
                return Error.AEADAuthFailed;
            };
        },
        .xchacha20_poly1305 => {
            // XChaCha20 uses 24-byte nonces; not compatible with EnvelopeV1 (12-byte nonce).
            // Use unwrapKey32 for key unwrapping or the raw primitive directly.
            std.crypto.secureZero(u8, plaintext);
            allocator.free(plaintext);
            return Error.InvalidAlg;
        },
    }

    return plaintext;
}

// ============================================================================
// Standalone key wrapping (stack-only, no allocator)
// ============================================================================

/// Size of a wrapped 32-byte key: nonce(24) + tag(16) + ciphertext(32) = 72 bytes.
pub const wrapped_key_size: usize = 24 + 16 + 32;

/// Wrap a 32-byte key using XChaCha20-Poly1305.
/// Returns a fixed 72-byte array: nonce(24) || tag(16) || ciphertext(32).
/// Stack-only operation — no allocator required.
pub fn wrapKey32(key: [32]u8, wrapping_key: [32]u8) [wrapped_key_size]u8 {
    const XChaCha = std.crypto.aead.chacha_poly.XChaCha20Poly1305;
    var result: [wrapped_key_size]u8 = undefined;

    var nonce: [24]u8 = undefined;
    std.crypto.random.bytes(&nonce);
    @memcpy(result[0..24], &nonce);

    var tag: [16]u8 = undefined;
    XChaCha.encrypt(result[40..72], &tag, &key, "", nonce, wrapping_key);
    @memcpy(result[24..40], &tag);

    return result;
}

/// Unwrap a 32-byte key from a 72-byte wrapped blob.
/// Input format: nonce(24) || tag(16) || ciphertext(32).
/// Stack-only operation — no allocator required.
pub fn unwrapKey32(wrapped: *const [wrapped_key_size]u8, wrapping_key: [32]u8) ![32]u8 {
    const XChaCha = std.crypto.aead.chacha_poly.XChaCha20Poly1305;

    const nonce = wrapped[0..24].*;
    const tag = wrapped[24..40].*;
    const ciphertext = wrapped[40..72];

    var plaintext: [32]u8 = undefined;
    XChaCha.decrypt(&plaintext, ciphertext, tag, "", nonce, wrapping_key) catch {
        std.crypto.secureZero(u8, &plaintext);
        return Error.AEADAuthFailed;
    };

    return plaintext;
}

test "AEAD round-trip with AES-256-GCM" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fek: [32]u8 = undefined;
    std.crypto.random.bytes(&fek);

    const plaintext = "sensitive data";
    const aad = try makeAAD(allocator, "tenant1", "Person", "ssn", "node123", 1);
    defer allocator.free(aad);

    var envelope = try encryptField(allocator, .aes256_gcm, &fek, aad, plaintext, 1);
    defer envelope.deinit(allocator);

    const decrypted = try decryptField(allocator, &fek, aad, envelope);
    defer {
        std.crypto.secureZero(u8, decrypted);
        allocator.free(decrypted);
    }

    try testing.expectEqualStrings(plaintext, decrypted);
}

test "AEAD auth fails with wrong AAD" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fek: [32]u8 = undefined;
    std.crypto.random.bytes(&fek);

    const plaintext = "sensitive data";
    const aad1 = try makeAAD(allocator, "tenant1", "Person", "ssn", "node123", 1);
    defer allocator.free(aad1);
    const aad2 = try makeAAD(allocator, "tenant2", "Person", "ssn", "node123", 1);
    defer allocator.free(aad2);

    var envelope = try encryptField(allocator, .aes256_gcm, &fek, aad1, plaintext, 1);
    defer envelope.deinit(allocator);

    const result = decryptField(allocator, &fek, aad2, envelope);
    try testing.expectError(Error.AEADAuthFailed, result);
}

test "Envelope serialization round-trip" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var envelope = EnvelopeV1{
        .alg_id = 1,
        .key_version = 2,
        .nonce = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 },
        .tag = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        .ciphertext = try allocator.dupe(u8, "abcd"),
    };
    defer envelope.deinit(allocator);

    const serialized = try envelope.serialize(allocator);
    defer allocator.free(serialized);

    var deserialized = try EnvelopeV1.deserialize(allocator, serialized);
    defer deserialized.deinit(allocator);

    try testing.expectEqual(envelope.alg_id, deserialized.alg_id);
    try testing.expectEqual(envelope.key_version, deserialized.key_version);
    try testing.expectEqualSlices(u8, &envelope.nonce, &deserialized.nonce);
    try testing.expectEqualSlices(u8, &envelope.tag, &deserialized.tag);
    try testing.expectEqualSlices(u8, envelope.ciphertext, deserialized.ciphertext);
}

test "wrapKey32/unwrapKey32 round-trip" {
    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);
    var wrapping_key: [32]u8 = undefined;
    std.crypto.random.bytes(&wrapping_key);

    const wrapped = wrapKey32(key, wrapping_key);
    const unwrapped = try unwrapKey32(&wrapped, wrapping_key);

    try std.testing.expectEqualSlices(u8, &key, &unwrapped);
}

test "unwrapKey32 rejects wrong wrapping key" {
    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);
    var wrapping_key: [32]u8 = undefined;
    std.crypto.random.bytes(&wrapping_key);

    const wrapped = wrapKey32(key, wrapping_key);

    var wrong_key: [32]u8 = undefined;
    std.crypto.random.bytes(&wrong_key);

    const result = unwrapKey32(&wrapped, wrong_key);
    try std.testing.expectError(Error.AEADAuthFailed, result);
}

test "Alg nonceSz and name" {
    try std.testing.expectEqual(@as(usize, 12), Alg.aes256_gcm.nonceSz());
    try std.testing.expectEqual(@as(usize, 12), Alg.chacha20_poly1305.nonceSz());
    try std.testing.expectEqual(@as(usize, 24), Alg.xchacha20_poly1305.nonceSz());
    try std.testing.expectEqualStrings("aes-256-gcm", Alg.aes256_gcm.name());
    try std.testing.expectEqualStrings("xchacha20-poly1305", Alg.xchacha20_poly1305.name());
}

test "encryptField rejects xchacha20_poly1305" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var fek: [32]u8 = undefined;
    std.crypto.random.bytes(&fek);

    const aad = try makeAAD(allocator, "t", "s", "f", "r", 1);
    defer allocator.free(aad);

    const result = encryptField(allocator, .xchacha20_poly1305, &fek, aad, "data", 1);
    try testing.expectError(Error.InvalidAlg, result);
}

test "makeAAD length-prefixed format" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const aad = try makeAAD(allocator, "t1", "Person", "ssn", "r1", 42);
    defer allocator.free(aad);

    // Verify length-prefixed format: [len:u32 LE][data] per field + [version:u16 LE]
    var pos: usize = 0;

    // tenant: "t1" (len=2)
    try testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, aad[pos..][0..4], .little));
    pos += 4;
    try testing.expectEqualStrings("t1", aad[pos .. pos + 2]);
    pos += 2;

    // schema: "Person" (len=6)
    try testing.expectEqual(@as(u32, 6), std.mem.readInt(u32, aad[pos..][0..4], .little));
    pos += 4;
    try testing.expectEqualStrings("Person", aad[pos .. pos + 6]);
    pos += 6;

    // field: "ssn" (len=3)
    try testing.expectEqual(@as(u32, 3), std.mem.readInt(u32, aad[pos..][0..4], .little));
    pos += 4;
    try testing.expectEqualStrings("ssn", aad[pos .. pos + 3]);
    pos += 3;

    // record_id: "r1" (len=2)
    try testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, aad[pos..][0..4], .little));
    pos += 4;
    try testing.expectEqualStrings("r1", aad[pos .. pos + 2]);
    pos += 2;

    // key_version: 42 as u16 LE
    try testing.expectEqual(@as(u16, 42), std.mem.readInt(u16, aad[pos..][0..2], .little));
    pos += 2;

    try testing.expectEqual(aad.len, pos);
}
